// Q6 / D20: event approval, plus Ravi's two rules:
//   1. changing a live event's price/date never alters existing paid orders;
//   2. sending an event back for re-approval pauses NEW sales only: existing
//      ticket holders still see their tickets and can still get in.
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api, TEST_PAYU } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");
const { makeResponseHash } = require("../src/services/payu");

let server;
let fx;

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});
beforeEach(() => server.db.query("DELETE FROM rate_limit_hits"));

const call = (method, path, token, json) => api(server.baseUrl, method, path, { token, json });

function newEventBody(name) {
  return {
    name, category: "Music", description: "d", date: "2099-12-31", time: "19:00",
    venue: "Hall", city: "City", capacity: 50, banner: "/b.png", bannerKey: "event-banners/b.png",
    tickets: [{ name: "General", price: 500, qty: 50 }],
  };
}

async function submitEvent(creator) {
  const res = await call("POST", "/creator/events", creator.token, newEventBody(`Event ${fx.uid()}`));
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body.event;
}

const publicIds = async () => (await call("GET", "/events")).body.events.map((e) => e.id);

// Pay for one General ticket through the real order flow + a signed PayU callback.
async function buyPaidTicket(buyer, eventId) {
  const created = await call("POST", "/orders", buyer.token, { eventId, tierName: "General", qty: 1 });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const fields = created.body.payment.fields;
  const form = {
    key: fields.key, txnid: fields.txnid, amount: fields.amount, productinfo: fields.productinfo,
    firstname: fields.firstname, email: fields.email, udf1: fields.udf1,
    status: "success", mihpayid: `PAYU${fx.uid()}`,
  };
  form.hash = makeResponseHash(form, TEST_PAYU.salt);
  const callback = await api(server.baseUrl, "POST", "/payments/payu/success", { form });
  assert.equal(callback.status, 303);
  const order = await server.db.query("SELECT * FROM orders WHERE id=$1", [created.body.order.id]);
  assert.equal(order.rows[0].status, "paid");
  return order.rows[0];
}

test("Q6: a new event starts pending: not listed, not bookable", async () => {
  const creator = await fx.createCreator();
  const buyer = await fx.createBuyer();
  const event = await submitEvent(creator);
  assert.equal(event.status, "pending");
  assert.ok(!(await publicIds()).includes(event.id));
  const orderRes = await call("POST", "/orders", buyer.token, { eventId: event.id, tierName: "General", qty: 1 });
  assert.equal(orderRes.status, 404);
  // The creator still sees it in their own list, with its status.
  const mine = await call("GET", "/creator/events", creator.token);
  assert.equal(mine.body.events.find((e) => e.id === event.id).status, "pending");
});

test("Q6: admin approval makes it live and bookable; only pending events can be approved", async () => {
  const creator = await fx.createCreator();
  const admin = await fx.createAdmin();
  const buyer = await fx.createBuyer();
  const event = await submitEvent(creator);

  const approved = await call("POST", `/admin/events/${event.id}/approve`, admin.token);
  assert.equal(approved.status, 200);
  assert.equal(approved.body.event.status, "live");
  assert.ok((await publicIds()).includes(event.id));
  assert.equal((await call("POST", "/orders", buyer.token, { eventId: event.id, tierName: "General", qty: 1 })).status, 201);

  assert.equal((await call("POST", `/admin/events/${event.id}/approve`, admin.token)).status, 409);
  assert.equal((await call("POST", "/admin/events/EVT-missing/approve", admin.token)).status, 404);
  assert.equal((await call("POST", `/admin/events/${event.id}/approve`, buyer.token)).status, 401);
  const log = await server.db.query("SELECT 1 FROM admin_audit_log WHERE action='event.approve' AND target_id=$1", [event.id]);
  assert.equal(log.rows.length, 1);
});

test("Q6: rejection needs a reason, which the creator can see", async () => {
  const creator = await fx.createCreator();
  const admin = await fx.createAdmin();
  const event = await submitEvent(creator);
  assert.equal((await call("POST", `/admin/events/${event.id}/reject`, admin.token, {})).status, 400);
  const rejected = await call("POST", `/admin/events/${event.id}/reject`, admin.token, { reason: "Banner is not the event" });
  assert.equal(rejected.status, 200);
  assert.equal(rejected.body.event.status, "rejected");
  const mine = await call("GET", "/creator/events", creator.token);
  const row = mine.body.events.find((e) => e.id === event.id);
  assert.equal(row.status, "rejected");
  assert.equal(row.reviewNote, "Banner is not the event");
  assert.ok(!(await publicIds()).includes(event.id));
});

test("D20 rule 1: changing a live event's price/date does not touch paid orders", async () => {
  const creator = await fx.createCreator();
  const buyer = await fx.createBuyer();
  const eventId = await fx.createEvent({ creatorId: creator.id, tiers: [{ name: "General", price: 500, qty: 10 }] });
  const paid = await buyPaidTicket(buyer, eventId);

  // Whatever path changes the event later, it can only change the event row.
  await server.db.query(
    "UPDATE creator_events SET tickets=$2, event_date='2099-11-30' WHERE id=$1",
    [eventId, JSON.stringify([{ name: "General", price: 900, qty: 10 }])],
  );
  const after = await server.db.query("SELECT unit_price, amount, status FROM orders WHERE id=$1", [paid.id]);
  assert.equal(Number(after.rows[0].unit_price), 500);
  assert.equal(Number(after.rows[0].amount), Number(paid.amount));
  assert.equal(after.rows[0].status, "paid");
  const tickets = await call("GET", "/bookings/mine", buyer.token);
  assert.equal(Number(tickets.body.bookings[0].price), 500);
});

test("D20 rule 2: back to pending stops new sales; holders keep their ticket and can still get in", async () => {
  const creator = await fx.createCreator();
  const admin = await fx.createAdmin();
  const holder = await fx.createBuyer();
  const newcomer = await fx.createBuyer();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  await buyPaidTicket(holder, eventId);

  // Status changes are destructive admin actions: confirm the password first.
  await server.db.query("UPDATE admin_accounts SET reauth_until = NOW() + INTERVAL '5 minutes' WHERE id=$1", [admin.id]);
  const back = await call("PATCH", `/admin/events/${eventId}/status`, admin.token, { status: "pending" });
  assert.equal(back.status, 200, JSON.stringify(back.body));

  assert.equal((await call("POST", "/orders", newcomer.token, { eventId, tierName: "General", qty: 1 })).status, 404);
  assert.ok(!(await publicIds()).includes(eventId));

  const mine = await call("GET", "/bookings/mine", holder.token);
  assert.equal(mine.status, 200);
  const ticket = mine.body.bookings.find((b) => b.eventId === eventId);
  assert.ok(ticket, "holder still sees the ticket");
  const one = await call("GET", `/bookings/${ticket.id}/ticket`, holder.token);
  assert.equal(one.status, 200);
  const scan = await call("POST", "/bookings/scan", creator.token, { qrPayload: one.body.booking.qrPayload });
  assert.equal(scan.status, 200, JSON.stringify(scan.body));
});
