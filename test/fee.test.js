// M8 / D5: one platform fee setting (PLATFORM_FEE_PERCENT), started at 10% so
// any leftover hardcoded 8% or 94% shows up. Q16: the buyer pays the fee + GST
// on top; the organizer keeps the full ticket subtotal (net = gross).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
before(async () => {
  server = await startTestServer({ PLATFORM_FEE_PERCENT: "10" });
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

test("M8 + Q16: buyer pays fee + GST on top; organizer analytics, finance and admin show net = gross", async () => {
  assert.equal((await api(server.baseUrl, "GET", "/config/public")).body.platformFeePercent, 10);

  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id, tiers: [{ name: "General", price: 500, qty: 10 }] });
  // Two ₹500 tickets already sold → gross 1000.
  await fx.createBooking({ eventId });
  await fx.createBooking({ eventId });

  // Checkout: 500 + 10% fee (50) + 18% GST on the fee (9).
  const buyer = await fx.createBuyer();
  const order = await api(server.baseUrl, "POST", "/orders", { token: buyer.token, json: { eventId, tierName: "General", qty: 1 } });
  assert.equal(order.status, 201, JSON.stringify(order.body));
  assert.equal(order.body.order.platformFee, 50);
  assert.equal(order.body.order.amount, 559);

  const analytics = await api(server.baseUrl, "GET", "/creator/analytics", { token: creator.token });
  assert.equal(analytics.status, 200);
  assert.deepEqual(
    { gross: analytics.body.summary.gross, fee: analytics.body.summary.fee, net: analytics.body.summary.net, buyerFeePercent: analytics.body.summary.buyerFeePercent },
    { gross: 1000, fee: 0, net: 1000, buyerFeePercent: 10 },
  );

  // M16: the PIN is set explicitly, with the account password.
  await server.db.query("UPDATE creator_accounts SET password=$2 WHERE id=$1", [creator.id, await require("bcrypt").hash("Creator-pass-1", 4)]);
  assert.equal((await api(server.baseUrl, "POST", "/creator/finance/pin", { token: creator.token, json: { pin: "4321", password: "Creator-pass-1" } })).status, 200);
  const finance = await api(server.baseUrl, "POST", "/creator/finance/unlock", { token: creator.token, json: { pin: "4321" } });
  assert.equal(finance.status, 200, JSON.stringify(finance.body));
  assert.equal(finance.body.net, 1000);
  assert.equal(finance.body.net, analytics.body.summary.net, "finance used to say 94% while analytics said 92%");

  const admin = await fx.createAdmin();
  const snapshot = await api(server.baseUrl, "GET", "/admin/snapshot", { token: admin.token });
  const row = snapshot.body.creators.find((c) => c.creatorId === creator.id);
  assert.equal(row.fee, 0, "organizers are not charged a fee (Q16)");
});
