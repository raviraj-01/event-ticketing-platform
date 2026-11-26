// End to end in a real (headless) browser: after a free booking and after a
// paid one, reloading the page always renders (no stuck session-restoring
// overlay) and the buyer sees exactly one ticket per booking. The paid ticket
// is confirmed only through the stored pending order ID + the instant check
// (POST /orders/:id/check), with a local stub playing PayU's verify API.
// Skips when no Chrome/Edge is installed (set CHROME_PATH to point at one).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const bcrypt = require("bcrypt");
const { startTestServer, TEST_PAYU } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");
const { launchBrowser } = require("./helpers/browser");
const { makeApiHash } = require("../src/services/payu");

const PASSWORD = "Reload-Test-Pass-1";
let server;
let browser;
let stub;
let buyer;
let freeEventId;
let paidEventId;

function startPayuStub() {
  const answers = {};
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      const form = Object.fromEntries(new URLSearchParams(raw));
      const valid = form.command === "verify_payment"
        && form.hash === makeApiHash(TEST_PAYU.key, "verify_payment", form.var1 || "", TEST_PAYU.salt);
      const details = {};
      for (const txnid of String(form.var1 || "").split("|")) details[txnid] = answers[txnid] || { status: "Not Found" };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(valid ? { status: 1, transaction_details: details } : { status: 0, msg: "Invalid Hash." }));
    });
  });
  return new Promise((resolve) => srv.listen(0, () => resolve({
    answers, url: `http://localhost:${srv.address().port}/verify`, close: () => srv.close(),
  })));
}

before(async () => {
  stub = await startPayuStub();
  server = await startTestServer({ PAYU_VERIFY_URL: stub.url });
  const fx = makeFixtures(server.db);
  const creator = await fx.createCreator();
  freeEventId = await fx.createEvent({ creatorId: creator.id, tiers: [{ name: "Free Entry", price: 0, qty: 50 }] });
  paidEventId = await fx.createEvent({ creatorId: creator.id, tiers: [{ name: "General", price: 500, qty: 50 }] });
  buyer = await fx.createBuyer();
  await server.db.query("UPDATE users SET password = $1 WHERE id = $2", [await bcrypt.hash(PASSWORD, 4), buyer.id]);
  browser = await launchBrowser();
});
after(async () => {
  if (browser) await browser.close();
  if (server) await server.stop();
  if (stub) stub.close();
});

// Shared in-page helpers.
const PAGE_HELPERS = `
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { const v = await fn(); if (v) return v; await sleep(100); } return null; };
`;

// After a (re)load: wait for the app to settle, then report what the buyer sees.
async function settledState() {
  return browser.run(`${PAGE_HELPERS}
    const shown = () => !document.body.classList.contains('session-restoring')
      && document.querySelector('.page.active') && document.querySelector('.page.active').checkVisibility();
    await until(shown);
    await sleep(1500); // restore + pending-payment check finish
    const active = document.querySelector('.page.active');
    return {
      restoring: document.body.classList.contains('session-restoring'),
      page: active && active.id,
      visible: !!(active && active.checkVisibility()),
      pendingOrder: localStorage.getItem('VYBERA_PENDING_ORDER'),
    };`);
}

// Tickets the buyer sees on "My tickets", grouped by event ID.
async function ticketsShown() {
  return browser.run(`${PAGE_HELPERS}
    showPage('page-mytickets');
    await until(() => document.querySelector('#ticketsList .tl-card') || document.querySelector('#ticketsList .ui-state:not([aria-busy])'));
    await sleep(300);
    return document.querySelectorAll('#ticketsList .tl-card').length;`);
}

async function bookingsPerEvent() {
  const { rows } = await server.db.query(
    "SELECT event_id, COUNT(*)::int AS n FROM bookings WHERE user_id = $1 GROUP BY event_id", [buyer.id]);
  return Object.fromEntries(rows.map((row) => [row.event_id, row.n]));
}

async function reloadAndCheck(times, expectedTickets) {
  for (let i = 1; i <= times; i++) {
    await browser.reload();
    const state = await settledState();
    assert.equal(state.restoring, false, `reload ${i}: restore overlay gone`);
    assert.equal(state.visible, true, `reload ${i}: a page is shown (${state.page})`);
    assert.equal(await ticketsShown(), expectedTickets, `reload ${i}: tickets on My tickets`);
  }
}

test("free booking, then 3 reloads: the page always renders and shows exactly one ticket", async (t) => {
  if (!browser) return t.skip("no Chrome/Edge found (set CHROME_PATH)");
  await browser.goto(`${server.baseUrl}/`);
  await settledState();
  await browser.run(`${PAGE_HELPERS}
    selectLoginRole('buyer'); showPage('page-login');
    document.getElementById('siEmail').value = ${JSON.stringify(buyer.email)};
    document.getElementById('siPassword').value = ${JSON.stringify(PASSWORD)};
    await doLogin();
    await until(() => hasSession('buyer'));`);

  const reached = await browser.run(`${PAGE_HELPERS}
    await loadPublishedEvents();
    const ev = await until(() => (STORE.events || []).find((e) => e.id === ${JSON.stringify(freeEventId)}));
    openEventDetail(ev); await sleep(300);
    showPage('page-booking'); await sleep(300);
    document.querySelector('#page-booking .ticket-option').click();
    nextBStep(2); nextBStep(3);
    document.getElementById('payNowBtn').click();
    return await until(() => document.querySelector('.page.active').id === 'page-success' && 'page-success');`);
  assert.equal(reached, "page-success");
  assert.deepEqual(await bookingsPerEvent(), { [freeEventId]: 1 });

  await reloadAndCheck(3, 1);
  assert.deepEqual(await bookingsPerEvent(), { [freeEventId]: 1 }, "reloads never book again");
});

test("paid booking confirmed by the instant check on reload, then 3 more reloads: one ticket, never stuck", async (t) => {
  if (!browser) return t.skip("no Chrome/Edge found (set CHROME_PATH)");
  // What the checkout does before handing over to PayU: create the order and
  // remember its ID. The buyer then never comes back through ?payment=.
  const start = await browser.run(`
    const resp = await fetch(apiUrl('/orders'), { method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders('buyer')),
      body: JSON.stringify({ eventId: ${JSON.stringify(paidEventId)}, tierName: 'General', qty: 1 }) });
    const data = await resp.json();
    if (!resp.ok) throw new Error(JSON.stringify(data));
    rememberPendingOrder(data.order.id);
    return { orderId: data.order.id, txnid: data.payment.fields.txnid, amount: data.payment.fields.amount };`);
  // PayU captured the payment.
  stub.answers[start.txnid] = {
    mihpayid: "PAYU-RELOAD-1", txnid: start.txnid, amt: start.amount, transaction_amount: start.amount,
    status: "success", unmappedstatus: "captured", udf1: start.orderId, error_Message: "NO ERROR",
  };

  await browser.reload();
  const first = await browser.run(`${PAGE_HELPERS}
    await until(() => !localStorage.getItem('VYBERA_PENDING_ORDER'));
    return { page: document.querySelector('.page.active').id, pending: localStorage.getItem('VYBERA_PENDING_ORDER') };`);
  assert.equal(first.pending, null, "the instant check finished the order and forgot its ID");
  const order = (await server.db.query("SELECT status FROM orders WHERE id = $1", [start.orderId])).rows[0];
  assert.equal(order.status, "paid");
  assert.deepEqual(await bookingsPerEvent(), { [freeEventId]: 1, [paidEventId]: 1 });

  await reloadAndCheck(3, 2);
  assert.deepEqual(await bookingsPerEvent(), { [freeEventId]: 1, [paidEventId]: 1 }, "one ticket per booking");
});
