// H19: paid orders are confirmed even when the buyer's browser never comes back
// from PayU. A local stub plays PayU's verify_payment API.
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const { startTestServer, api, TEST_PAYU } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");
const { makeApiHash } = require("../src/services/payu");
const { reconcilePayuOrders } = require("../src/services/payuReconcile");

let server;
let fx;
let stub;
let payu;
let creator;

// Fake PayU: answers verify_payment from `stub.answers`, and refuses any
// request whose hash is not key|command|var1|salt (so the real hash is tested).
function startStub() {
  const state = { answers: {}, calls: [] };
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      const form = Object.fromEntries(new URLSearchParams(raw));
      state.calls.push(form);
      const expected = makeApiHash(TEST_PAYU.key, "verify_payment", form.var1 || "", TEST_PAYU.salt);
      if (form.command !== "verify_payment" || form.key !== TEST_PAYU.key || form.hash !== expected) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ status: 0, msg: "Invalid Hash." }));
      }
      const details = {};
      for (const txnid of String(form.var1).split("|")) {
        details[txnid] = state.answers[txnid] || { mihpayid: "Not Found", status: "Not Found" };
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: 1, msg: "fetched", transaction_details: details }));
    });
  });
  return new Promise((resolve) => srv.listen(0, () => resolve({ ...state, state, url: `http://localhost:${srv.address().port}/verify`, close: () => srv.close() })));
}

before(async () => {
  stub = await startStub();
  server = await startTestServer({ PAYU_VERIFY_URL: stub.url });
  fx = makeFixtures(server.db);
  payu = { key: TEST_PAYU.key, salt: TEST_PAYU.salt, verifyUrl: stub.url };
  creator = await fx.createCreator();
});
after(async () => {
  if (server) await server.stop();
  if (stub) stub.close();
});
beforeEach(async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
});

const success = (start, extra = {}) => ({
  mihpayid: `PAYU${Date.now()}`, txnid: start.txnid, amt: start.amount, transaction_amount: start.amount,
  status: "success", unmappedstatus: "captured", udf1: start.orderId, error_Message: "NO ERROR", ...extra,
});

// A PayU checkout the buyer started (then, in these tests, never came back from).
async function startCheckout(buyer, eventId, tierName = "General") {
  const res = await api(server.baseUrl, "POST", "/orders", { token: buyer.token, json: { eventId, tierName, qty: 1 } });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  const { fields } = res.body.payment;
  return { orderId: res.body.order.id, txnid: fields.txnid, amount: fields.amount };
}
const orderRow = async (id) => (await server.db.query("SELECT * FROM orders WHERE id = $1", [id])).rows[0];
const bookings = async (orderId) => (await server.db.query("SELECT * FROM bookings WHERE order_id = $1", [orderId])).rows;
const age = (orderId, minutes) =>
  server.db.query("UPDATE orders SET created_at = NOW() - make_interval(mins => $2) WHERE id = $1", [orderId, minutes]);

test("H19: browser never came back, PayU says success -> the poll confirms the order and issues one ticket", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const start = await startCheckout(buyer, eventId);
  stub.state.answers[start.txnid] = success(start);
  await age(start.orderId, 3);

  const results = await reconcilePayuOrders(server.db, { payu });
  const mine = results.find((r) => r.orderId === start.orderId);
  assert.deepEqual({ gatewayStatus: mine.gatewayStatus, outcome: mine.outcome }, { gatewayStatus: "success", outcome: "paid" });
  assert.equal((await orderRow(start.orderId)).status, "paid");
  assert.equal((await bookings(start.orderId)).length, 1);
  const payment = await server.db.query("SELECT status, verified FROM payment_transactions WHERE txnid = $1", [start.txnid]);
  assert.deepEqual(payment.rows[0], { status: "Success", verified: true });

  // Settled: not asked again, and never a second ticket.
  const calls = stub.state.calls.length;
  await reconcilePayuOrders(server.db, { payu });
  assert.ok(!stub.state.calls.slice(calls).some((c) => c.var1.split("|").includes(start.txnid)));
  assert.equal((await bookings(start.orderId)).length, 1);
});

test("H19: an order expired by a newer checkout but paid at PayU still gets its ticket while seats remain", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const first = await startCheckout(buyer, eventId);
  await startCheckout(buyer, eventId); // releases the first hold (status 'expired')
  assert.equal((await orderRow(first.orderId)).status, "expired");
  stub.state.answers[first.txnid] = success(first);

  const [result] = await reconcilePayuOrders(server.db, { payu, txnids: [first.txnid] });
  assert.equal(result.outcome, "paid");
  assert.equal((await bookings(first.orderId)).length, 1);
});

test("H19: paid at PayU after the seats were sold -> paid_needs_refund, no ticket", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id, capacity: 1, tiers: [{ name: "General", price: 500, qty: 1 }] });
  const buyer = await fx.createBuyer();
  const start = await startCheckout(buyer, eventId);
  await server.db.query("UPDATE orders SET status = 'expired', expires_at = NOW() - interval '1 minute' WHERE id = $1", [start.orderId]);
  await fx.createBooking({ eventId }); // someone else took the only seat meanwhile
  stub.state.answers[start.txnid] = success(start);

  const [result] = await reconcilePayuOrders(server.db, { payu, txnids: [start.txnid] });
  assert.equal(result.outcome, "paid_needs_refund");
  assert.equal((await orderRow(start.orderId)).status, "paid_needs_refund");
  assert.equal((await bookings(start.orderId)).length, 0);
});

test("H19: PayU's answer must be about this order and amount", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const wrongOrder = await startCheckout(buyer, eventId);
  stub.state.answers[wrongOrder.txnid] = success(wrongOrder, { udf1: "ORD-someone-else" });
  assert.equal((await reconcilePayuOrders(server.db, { payu, txnids: [wrongOrder.txnid] }))[0].outcome, "mismatch");

  const buyer2 = await fx.createBuyer();
  const wrongAmount = await startCheckout(buyer2, eventId);
  stub.state.answers[wrongAmount.txnid] = success(wrongAmount, { amt: "1.00", transaction_amount: "1.00" });
  assert.equal((await reconcilePayuOrders(server.db, { payu, txnids: [wrongAmount.txnid] }))[0].outcome, "amount_mismatch");
  assert.equal((await bookings(wrongOrder.orderId)).length + (await bookings(wrongAmount.orderId)).length, 0);
});

test("H19: failed or cancelled at PayU -> nothing issued, and the order is not asked about again", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const start = await startCheckout(buyer, eventId);
  stub.state.answers[start.txnid] = { ...success(start), status: "failure", unmappedstatus: "failed" };
  await age(start.orderId, 3);
  await reconcilePayuOrders(server.db, { payu });
  const row = await orderRow(start.orderId);
  assert.equal(row.gateway_status, "failure");
  assert.equal((await bookings(start.orderId)).length, 0);
  await server.db.query("UPDATE orders SET gateway_checked_at = NOW() - interval '1 hour' WHERE id = $1", [start.orderId]);
  const calls = stub.state.calls.length;
  await reconcilePayuOrders(server.db, { payu });
  assert.ok(!stub.state.calls.slice(calls).some((c) => c.var1.split("|").includes(start.txnid)));
});

test("H19 webhook: the posted status is ignored, PayU's verify answer decides", async () => {
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const start = await startCheckout(buyer, eventId);
  const forged = { txnid: start.txnid, status: "success", amount: start.amount, hash: "forged" };

  stub.state.answers[start.txnid] = { ...success(start), status: "pending", unmappedstatus: "initiated" };
  const first = await api(server.baseUrl, "POST", "/payments/payu/webhook", { form: forged });
  assert.deepEqual([first.status, first.body], [200, { received: true }]);
  assert.equal((await orderRow(start.orderId)).status, "pending");
  assert.equal((await bookings(start.orderId)).length, 0);

  stub.state.answers[start.txnid] = success(start);
  await api(server.baseUrl, "POST", "/payments/payu/webhook", { form: { txnid: start.txnid } });
  assert.equal((await orderRow(start.orderId)).status, "paid");
  assert.equal((await bookings(start.orderId)).length, 1);

  // Unknown txnid: same answer, nothing revealed.
  const unknown = await api(server.baseUrl, "POST", "/payments/payu/webhook", { form: { txnid: "TXN-does-not-exist" } });
  assert.deepEqual([unknown.status, unknown.body], [200, { received: true }]);
});
