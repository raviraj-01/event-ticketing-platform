// Integration tests for C4: server-side orders, inventory, free tiers,
// PayU callback verification and staff referral credit. Real PostgreSQL.
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { startTestServer, signTestToken, api, TEST_PAYU } = require("./helpers/testServer");
const { makeResponseHash } = require("../src/services/payu");

let server;
let db;
let seq = 0;
const uid = () => `${Date.now()}${++seq}`;

before(async () => {
  server = await startTestServer();
  db = server.db;
  await db.query(
    `INSERT INTO creator_accounts (id, name, email, phone, category, about, password, kyc_status)
     VALUES (1, 'Test Creator', 'creator@test.local', '9000000000', 'Music', 'x', 'x', 'Approved')`,
  );
  // Warm up the server's DB pool so concurrent test requests really overlap.
  await Promise.all(Array.from({ length: 10 }, () => api(server.baseUrl, "GET", "/events")));
});

// Fire `count` buyers at the same seat at the same moment.
async function raceForSeat(eventId, tierName, count = 8) {
  const buyers = await Promise.all(Array.from({ length: count }, () => createBuyer()));
  return Promise.all(buyers.map((buyer) => order(buyer, { eventId, tierName, qty: 1 })));
}

after(async () => {
  if (server) await server.stop();
});

// Each test is independent of the shared rate-limit counters.
beforeEach(async () => {
  await db.query("DELETE FROM rate_limit_hits");
});

async function createBuyer({ email, phone } = {}) {
  const result = await db.query(
    `INSERT INTO users (username, first_name, email, password, phone)
     VALUES ('Buyer', 'Buyer', $1, 'x', $2) RETURNING id, email`,
    [email || `buyer${uid()}@test.local`, phone || null],
  );
  const user = result.rows[0];
  return { ...user, token: await signTestToken({ sub: user.id, email: user.email }) };
}

async function createEvent({ capacity = 100, tiers = [{ name: "General", price: 500, qty: 100 }] } = {}) {
  const id = `EVT-test-${uid()}`;
  await db.query(
    `INSERT INTO creator_events (id, creator_id, creator_name, name, category, description, event_date,
       start_time, venue, city, capacity, banner_url, banner_key, status, tickets)
     VALUES ($1, 1, 'Test Creator', 'Test Event', 'Music', 'd', '2099-12-31', '19:00', 'Hall', 'City', $2,
       '/b.png', 'b', 'live', $3)`,
    [id, capacity, JSON.stringify(tiers)],
  );
  return id;
}

const order = (buyer, body) => api(server.baseUrl, "POST", "/orders", { token: buyer.token, json: body });

// Build the form PayU would post back, signed with the test salt.
function payuCallbackForm(payment, overrides = {}) {
  const fields = payment.fields;
  const form = {
    key: fields.key,
    txnid: fields.txnid,
    amount: fields.amount,
    productinfo: fields.productinfo,
    firstname: fields.firstname,
    email: fields.email,
    udf1: fields.udf1,
    status: "success",
    mihpayid: `PAYU${uid()}`,
    ...overrides,
  };
  form.hash = overrides.hash || makeResponseHash(form, TEST_PAYU.salt);
  return form;
}

const orderRow = async (id) => (await db.query("SELECT * FROM orders WHERE id = $1", [id])).rows[0];
const bookingCount = async (orderId) =>
  Number((await db.query("SELECT COUNT(*) FROM bookings WHERE order_id = $1", [orderId])).rows[0].count);

test("old client-trusting endpoints are gone", async () => {
  assert.equal((await api(server.baseUrl, "POST", "/bookings", { json: { id: "X", price: 0 } })).status, 404);
  assert.equal((await api(server.baseUrl, "POST", "/payments/payu/initiate", { json: { amount: 1 } })).status, 404);
});

test("creating an order requires a logged-in buyer", async () => {
  const eventId = await createEvent();
  const res = await api(server.baseUrl, "POST", "/orders", { json: { eventId, tierName: "General", qty: 1 } });
  assert.equal(res.status, 401);
});

test("price comes from the database, never from the request", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent({ tiers: [{ name: "General", price: 500, qty: 100 }] });
  const res = await order(buyer, { eventId, tierName: "General", qty: 2, price: 1, amount: 1, total: 1 });
  assert.equal(res.status, 201);
  // 2 × 500 = 1000, + 8% fee (80) + 18% GST on the fee (14.40)
  assert.equal(res.body.order.subtotal, 1000);
  assert.equal(res.body.order.amount, 1094.4);
  assert.equal(res.body.payment.fields.amount, "1094.40");
  assert.equal(res.body.order.status, "pending");
  assert.ok(res.body.order.id.startsWith("ORD-"));
});

test("quantity above the per-order maximum is rejected", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent();
  assert.equal((await order(buyer, { eventId, tierName: "General", qty: 11 })).status, 400);
  assert.equal((await order(buyer, { eventId, tierName: "General", qty: 0 })).status, 400);
});

test("buyers racing for the last seat: exactly one order is created", async () => {
  const eventId = await createEvent({ capacity: 1, tiers: [{ name: "General", price: 500, qty: 1 }] });
  const results = await raceForSeat(eventId, "General");
  assert.equal(results.filter((r) => r.status === 201).length, 1);
  assert.equal(results.filter((r) => r.status === 409).length, results.length - 1);
  const held = await db.query("SELECT COUNT(*) FROM orders WHERE event_id = $1 AND status = 'pending'", [eventId]);
  assert.equal(Number(held.rows[0].count), 1);
});

test("an expired hold no longer blocks the seat", async () => {
  const eventId = await createEvent({ capacity: 1, tiers: [{ name: "General", price: 500, qty: 1 }] });
  const [a, b] = [await createBuyer(), await createBuyer()];
  const first = await order(a, { eventId, tierName: "General", qty: 1 });
  assert.equal(first.status, 201);
  assert.equal((await order(b, { eventId, tierName: "General", qty: 1 })).status, 409);
  await db.query("UPDATE orders SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [first.body.order.id]);
  assert.equal((await order(b, { eventId, tierName: "General", qty: 1 })).status, 201);
});

test("free tier: confirmed instantly, capacity 1 with concurrent requests gives one ticket", async () => {
  const eventId = await createEvent({ capacity: 1, tiers: [{ name: "Free", price: 0, qty: 1 }] });
  const results = await raceForSeat(eventId, "Free");
  assert.equal(results.filter((r) => r.status === 201).length, 1);
  const winner = results.find((r) => r.status === 201);
  assert.equal(winner.body.order.status, "paid");
  assert.equal(winner.body.order.paymentMethod, "free");
  assert.equal(winner.body.order.amount, 0);
  assert.ok(winner.body.booking && winner.body.booking.qrPayload, "ticket issued immediately");
});

test("free tier: one user cannot exceed the per-user limit (2)", async () => {
  const eventId = await createEvent({ capacity: 50, tiers: [{ name: "Free", price: 0, qty: 50 }] });
  const buyer = await createBuyer();
  assert.equal((await order(buyer, { eventId, tierName: "Free", qty: 2 })).status, 201);
  const again = await order(buyer, { eventId, tierName: "Free", qty: 1 });
  assert.equal(again.status, 409);
  assert.match(again.body.error, /at most 2 free tickets/);
});

test("verified PayU success issues exactly one ticket, and a retried callback is idempotent", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent();
  const created = await order(buyer, { eventId, tierName: "General", qty: 1 });
  const form = payuCallbackForm(created.body.payment);

  const first = await api(server.baseUrl, "POST", "/payments/payu/success", { form });
  assert.equal(first.status, 303);
  assert.match(first.headers.get("location"), new RegExp(`payment=payu&order=${created.body.order.id}$`));
  assert.equal((await orderRow(created.body.order.id)).status, "paid");
  assert.equal(await bookingCount(created.body.order.id), 1);

  const retry = await api(server.baseUrl, "POST", "/payments/payu/success", { form });
  assert.equal(retry.status, 303);
  assert.equal(await bookingCount(created.body.order.id), 1, "no second ticket on retry");

  const mine = await api(server.baseUrl, "GET", `/orders/${created.body.order.id}`, { token: buyer.token });
  assert.equal(mine.status, 200);
  assert.equal(mine.body.order.status, "paid");
  assert.ok(mine.body.booking.qrPayload);
});

test("callback with a forged hash changes nothing", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent();
  const created = await order(buyer, { eventId, tierName: "General", qty: 1 });
  const form = payuCallbackForm(created.body.payment, { hash: "a".repeat(128) });
  const res = await api(server.baseUrl, "POST", "/payments/payu/success", { form });
  assert.equal(res.status, 303);
  assert.match(res.headers.get("location"), /status=failed/);
  assert.equal((await orderRow(created.body.order.id)).status, "pending");
  assert.equal(await bookingCount(created.body.order.id), 0);
});

test("callback with a different amount (even correctly signed) is not applied", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent();
  const created = await order(buyer, { eventId, tierName: "General", qty: 1 });
  const form = payuCallbackForm(created.body.payment, { amount: "1.00" });
  await api(server.baseUrl, "POST", "/payments/payu/success", { form });
  assert.equal((await orderRow(created.body.order.id)).status, "pending");
  assert.equal(await bookingCount(created.body.order.id), 0);
});

test("a failed payment releases the hold", async () => {
  const buyer = await createBuyer();
  const eventId = await createEvent();
  const created = await order(buyer, { eventId, tierName: "General", qty: 1 });
  const form = payuCallbackForm(created.body.payment, { status: "failure" });
  await api(server.baseUrl, "POST", "/payments/payu/failure", { form });
  assert.equal((await orderRow(created.body.order.id)).status, "expired");
});

test("late payment: issued if seats remain, otherwise paid_needs_refund", async () => {
  // Seats still available → ticket issued even though the hold expired.
  const eventA = await createEvent({ capacity: 5, tiers: [{ name: "General", price: 500, qty: 5 }] });
  const buyerA = await createBuyer();
  const late = await order(buyerA, { eventId: eventA, tierName: "General", qty: 1 });
  await db.query("UPDATE orders SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [late.body.order.id]);
  await api(server.baseUrl, "POST", "/payments/payu/success", { form: payuCallbackForm(late.body.payment) });
  assert.equal((await orderRow(late.body.order.id)).status, "paid");

  // Seat taken by someone else after the hold expired → money taken, no ticket.
  const eventB = await createEvent({ capacity: 1, tiers: [{ name: "General", price: 500, qty: 1 }] });
  const [slow, fast] = [await createBuyer(), await createBuyer()];
  const slowOrder = await order(slow, { eventId: eventB, tierName: "General", qty: 1 });
  await db.query("UPDATE orders SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [slowOrder.body.order.id]);
  const fastOrder = await order(fast, { eventId: eventB, tierName: "General", qty: 1 });
  await api(server.baseUrl, "POST", "/payments/payu/success", { form: payuCallbackForm(fastOrder.body.payment) });
  await api(server.baseUrl, "POST", "/payments/payu/success", { form: payuCallbackForm(slowOrder.body.payment) });
  assert.equal((await orderRow(fastOrder.body.order.id)).status, "paid");
  assert.equal((await orderRow(slowOrder.body.order.id)).status, "paid_needs_refund");
  assert.equal(await bookingCount(slowOrder.body.order.id), 0);
});

test("another buyer's order returns 404", async () => {
  const [owner, other] = [await createBuyer(), await createBuyer()];
  const eventId = await createEvent();
  const created = await order(owner, { eventId, tierName: "General", qty: 1 });
  const res = await api(server.baseUrl, "GET", `/orders/${created.body.order.id}`, { token: other.token });
  assert.equal(res.status, 404);
});

// ── staff referral ──
async function createStaff({ email = null, phone = null, assignedTier = "General", eventId }) {
  const id = `STF-test-${uid()}`;
  const shareToken = `share-${crypto.randomBytes(6).toString("hex")}`;
  await db.query(
    `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, share_token, status)
     VALUES ($1, 1, 'Staff', $2, $3, $4, 'x', $5, 'active')`,
    [id, `login${uid()}`, email, phone, shareToken],
  );
  if (assignedTier) {
    await db.query(
      `INSERT INTO staff_assignments (id, creator_id, staff_id, event_id, event_name, tier_name, qty, price, commission_rate)
       VALUES ($1, 1, $2, $3, 'Test Event', $4, 10, 500, 10)`,
      [`ASN-test-${uid()}`, id, eventId, assignedTier],
    );
  }
  return { id, shareToken };
}

const commissionRows = async (staffId) =>
  (await db.query("SELECT * FROM staff_sales WHERE staff_id = $1", [staffId])).rows;

test("referral: credited only after a verified payment, at 10% of the ticket subtotal", async () => {
  const eventId = await createEvent();
  const staff = await createStaff({ eventId });
  const buyer = await createBuyer();
  const created = await order(buyer, { eventId, tierName: "General", qty: 2, shareToken: staff.shareToken });
  assert.equal((await commissionRows(staff.id)).length, 0, "nothing before payment");
  await api(server.baseUrl, "POST", "/payments/payu/success", { form: payuCallbackForm(created.body.payment) });
  const rows = await commissionRows(staff.id);
  assert.equal(rows.length, 1);
  assert.equal(Number(rows[0].commission), 100); // 10% of 1000
  assert.equal(rows[0].status, "active");
});

test("referral: invalid or unassigned share token gives no credit", async () => {
  const eventId = await createEvent();
  const unassigned = await createStaff({ eventId, assignedTier: null });
  const buyer = await createBuyer();
  for (const shareToken of ["not-a-real-token", unassigned.shareToken]) {
    const created = await order(buyer, { eventId, tierName: "General", qty: 1, shareToken });
    assert.equal(created.status, 201);
    await api(server.baseUrl, "POST", "/payments/payu/success", { form: payuCallbackForm(created.body.payment) });
    assert.equal((await orderRow(created.body.order.id)).referral_staff_id, null);
  }
  assert.equal((await commissionRows(unassigned.id)).length, 0);
});

test("referral: self-referral (same email or phone) gives no credit", async () => {
  const eventId = await createEvent();
  const email = `self${uid()}@test.local`;
  const staffByEmail = await createStaff({ eventId, email });
  const staffByPhone = await createStaff({ eventId, phone: "+91 98765 00001" });
  const buyer = await createBuyer({ email, phone: "9876500001" });
  for (const staff of [staffByEmail, staffByPhone]) {
    const created = await order(buyer, { eventId, tierName: "General", qty: 1, shareToken: staff.shareToken });
    assert.equal((await orderRow(created.body.order.id)).referral_staff_id, null);
  }
});

test("public events show availability that counts sales and live holds", async () => {
  const eventId = await createEvent({ capacity: 10, tiers: [{ name: "General", price: 500, qty: 10 }] });
  const buyer = await createBuyer();
  await order(buyer, { eventId, tierName: "General", qty: 3 });
  const res = await api(server.baseUrl, "GET", "/events");
  const event = res.body.events.find((e) => e.id === eventId);
  assert.equal(event.tickets[0].available, 7);
});
