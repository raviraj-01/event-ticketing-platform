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

test("M3: emails that differ only in case: refused by the unique index; the report finds old ones", async () => {
  const stamp = fx.uid();
  await fx.createBuyer({ email: `Case${stamp}@Test.local` });
  await assert.rejects(fx.createBuyer({ email: `case${stamp}@test.local` }), { code: "23505", constraint: "users_email_lower_unique" });

  // A database from before 0019 can hold such pairs: recreate that state in a
  // transaction that is rolled back.
  const client = await server.db.connect();
  try {
    await client.query("BEGIN");
    await client.query("DROP INDEX users_email_lower_unique");
    await client.query("INSERT INTO users (username, email, password) VALUES ('Buyer', $1, 'x')", [`case${stamp}@test.local`]);
    const emails = await findDuplicateEmails(client);
    await findDuplicatePhones(client);
    const group = emails.find((g) => g.table === "users" && g.email === `case${stamp}@test.local`);
    assert.ok(group, JSON.stringify(emails));
    assert.equal(group.accounts.length, 2);
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
});

test("M3: Google login's upsert treats Mixed@Case and mixed@case as one account (ON CONFLICT on LOWER(email))", async () => {
  const stamp = fx.uid();
  const existing = await fx.createBuyer({ email: `Google${stamp}@Test.local` });
  // The statement shape used by upsertGoogleBuyer() in src/routes/buyerAuth.js.
  const result = await server.db.query(
    `INSERT INTO users (username, first_name, last_name, email, password, auth_provider, profile_image_url)
     VALUES ('G', 'G', '', $1, 'oauth-provider', 'google', '')
     ON CONFLICT ((LOWER(email))) DO UPDATE SET auth_provider = EXCLUDED.auth_provider
     RETURNING id`,
    [`google${stamp}@test.local`],
  );
  assert.equal(result.rows[0].id, existing.id);
  const count = await server.db.query("SELECT COUNT(*)::int AS n FROM users WHERE LOWER(email) = $1", [`google${stamp}@test.local`]);
  assert.equal(count.rows[0].n, 1);
});
