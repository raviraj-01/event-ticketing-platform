// M3: database constraints (NOT VALID: enforced for new rows, old rows untouched)
// and the read-only duplicate report.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");
const { findDuplicateEmails, findDuplicatePhones } = require("../scripts/report-duplicate-phones");

let server;
let fx;
before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

const insertBooking = (overrides) => server.db.query(
  `INSERT INTO bookings (id, event_id, event_name, ticket_type, price, qty, total, status, qr_token)
   VALUES ($1, $2, 'E', 'General', $3, $4, $5, 'upcoming', 'tok')`,
  [`BKG-int-${fx.uid()}`, overrides.eventId, overrides.price ?? 500, overrides.qty ?? 1, overrides.total ?? 500],
);

test("M3: constraints exist and are NOT VALID (existing rows are never checked or changed)", async () => {
  const rows = await server.db.query(
    `SELECT conname, convalidated FROM pg_constraint
     WHERE conname IN ('bookings_event_fk','bookings_qty_positive','staff_assignments_commission_range',
                       'payment_transactions_amount_not_negative','creator_events_capacity_positive',
                       'staff_withdrawals_amount_positive')`,
  );
  assert.equal(rows.rows.length, 6);
  assert.ok(rows.rows.every((r) => r.convalidated === false), JSON.stringify(rows.rows));
});

test("M3: new rows must satisfy them", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  await assert.rejects(insertBooking({ eventId, qty: 0 }), (err) => err.code === "23514");
  await assert.rejects(insertBooking({ eventId, total: -1 }), (err) => err.code === "23514");
  await assert.rejects(insertBooking({ eventId: "EVT-does-not-exist" }), (err) => err.code === "23503");
  await insertBooking({ eventId });
});

test("L5: a commission over 100% is a clear 400, not a database error", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const staffId = await fx.createStaff({ creatorId: creator.id, eventId });
  const res = await api(server.baseUrl, "POST", `/creator/staff/${staffId}/assignments`, {
    token: creator.token,
    json: { eventId, tierName: "General", qty: 1, commissionRate: 150 },
  });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /between 0 and 100/);
});

test("M3: the duplicate report finds emails that differ only in case, read-only", async () => {
  const stamp = fx.uid();
  await fx.createBuyer({ email: `Case${stamp}@Test.local` });
  await fx.createBuyer({ email: `case${stamp}@test.local` });
  const client = await server.db.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const emails = await findDuplicateEmails(client);
    await findDuplicatePhones(client);
    await client.query("ROLLBACK");
    const group = emails.find((g) => g.table === "users" && g.email === `case${stamp}@test.local`);
    assert.ok(group, JSON.stringify(emails));
    assert.equal(group.accounts.length, 2);
  } finally {
    client.release();
  }
});
