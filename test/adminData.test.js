// M4 + M8: admin totals are computed by the server over all rows (refunded
// bookings excluded); lists come one page at a time.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
let admin;
let superAdmin;
before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
  admin = await fx.createAdmin();
  superAdmin = await fx.createAdmin({ superAdmin: true });
});
after(async () => {
  if (server) await server.stop();
});

const get = (path, who = admin) => api(server.baseUrl, "GET", path, { token: who.token });

test("M4/M8: stats cover every row and ignore refunded bookings", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const before = (await get("/admin/snapshot")).body.stats;
  await fx.createBooking({ eventId });
  await fx.createBooking({ eventId });
  const refunded = await fx.createBooking({ eventId });
  await server.db.query("UPDATE bookings SET status='refunded' WHERE id=$1", [refunded]);

  const stats = (await get("/admin/snapshot")).body.stats;
  assert.equal(stats.gmv - before.gmv, 1000, "two ₹500 tickets; the refunded one is not revenue");
  assert.equal(stats.tickets - before.tickets, 2);
  assert.equal(stats.bookingCount - before.bookingCount, 3, "stored bookings still counts every row");
  const month = new Date().toLocaleDateString("en-CA", { timeZone: "Asia/Kolkata" }).slice(0, 7);
  assert.ok(stats.monthly.some((m) => m.month === month && m.revenue >= 1000), JSON.stringify(stats.monthly));
  assert.ok(stats.topEvents.some((e) => e.id === eventId));
  for (const key of ["daily", "categories", "cities", "creatorLeaderboard"]) assert.ok(Array.isArray(stats[key]), key);
});

test("M4: lists are paged; GET /admin/list/:kind loads the next page", async () => {
  for (let i = 0; i < 3; i += 1) await fx.createBuyer();
  const first = await get("/admin/list/buyers?limit=2");
  assert.equal(first.status, 200);
  assert.equal(first.body.items.length, 2);
  assert.equal(first.body.paging.nextOffset, 2);
  const second = await get("/admin/list/buyers?limit=2&offset=2");
  const ids = new Set([...first.body.items, ...second.body.items].map((b) => b.id));
  assert.equal(ids.size, first.body.items.length + second.body.items.length);

  const snapshot = (await get("/admin/snapshot")).body;
  for (const kind of ["buyers", "creators", "events", "ledger", "staff"]) {
    assert.ok(Array.isArray(snapshot[kind]), kind);
    assert.ok(snapshot.paging[kind] && snapshot.paging[kind].limit === 100, kind);
  }
  assert.equal(snapshot.bookings, undefined, "the full booking list is no longer sent");
  assert.equal((await get("/admin/list/nope")).status, 404);
  const buyer = await fx.createBuyer();
  assert.equal((await api(server.baseUrl, "GET", "/admin/list/buyers", { token: buyer.token })).status, 401);
});

test("M4: the Pending tab gets pending events from the server; the ledger shows payment-only rows and filters by status", async () => {
  const creator = await fx.createCreator();
  const pendingId = await fx.createEvent({ creatorId: creator.id });
  await server.db.query("UPDATE creator_events SET status='pending' WHERE id=$1", [pendingId]);
  const pending = await get("/admin/list/events?status=pending");
  assert.ok(pending.body.items.length >= 1);
  assert.ok(pending.body.items.every((e) => e.status === "pending"));
  assert.ok(pending.body.items.some((e) => e.id === pendingId));

  const txnid = `TXN-failed-${fx.uid()}`;
  await server.db.query(
    `INSERT INTO payment_transactions (txnid, booking_id, event_id, qty, buyer_email, amount, status, verified)
     VALUES ($1, $2, $3, 1, 'x@test.local', 559, 'Failed', TRUE)`,
    [txnid, `ORD-none-${fx.uid()}`, pendingId],
  );
  const failed = await get("/admin/list/ledger?status=Failed");
  const row = failed.body.items.find((r) => r.payment && r.payment.txnid === txnid);
  assert.ok(row, "payment record without a booking is listed");
  assert.equal(row._paymentOnly, true);
  assert.equal(row.total, 559);
  assert.ok(failed.body.items.every((r) => r.payment && r.payment.status === "Failed"));

  const creator2 = await fx.createCreator();
  const ev2 = await fx.createEvent({ creatorId: creator2.id });
  const refundedId = await fx.createBooking({ eventId: ev2 });
  await server.db.query("UPDATE bookings SET status='refunded' WHERE id=$1", [refundedId]);
  const refundedRows = await get("/admin/list/ledger?status=Refunded");
  const refundedRow = refundedRows.body.items.find((r) => r.id === refundedId);
  assert.ok(refundedRow, "the Refunded filter finds refunded bookings");
  assert.equal(refundedRow.paymentStatus, "Refunded");
});

test("H14 still holds on the paged list: KYC documents for super admins only", async () => {
  const creator = await fx.createCreator();
  await server.db.query(
    `INSERT INTO creator_kyc_documents (creator_id, document_type, file_name, object_key, storage, content_type)
     VALUES ($1, 'pan', 'pan.pdf', 'kyc-documents/x/pan.pdf', 'r2', 'application/pdf')`,
    [creator.id],
  );
  const find = (res) => res.body.items.find((c) => c.creatorId === creator.id);
  assert.equal(find(await get("/admin/list/creators")).documents.length, 0);
  assert.equal(find(await get("/admin/list/creators", superAdmin)).documents.length, 1);
});
