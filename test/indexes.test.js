// M2: the indexes match the shape of the queries the routes run. With
// sequential scans disabled, the planner must be able to answer each query
// through the named index; if an index's expression didn't match the query
// (e.g. email vs LOWER(email)), it could not, and this test fails.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer } = require("./helpers/testServer");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

const CASES = [
  ["bookings_event_idx", "SELECT * FROM bookings WHERE event_id = 'EVT-1'"],
  ["bookings_user_booked_idx", "SELECT * FROM bookings WHERE user_id = 1 ORDER BY booked_at DESC"],
  ["bookings_buyer_email_lower_idx", "SELECT * FROM bookings WHERE LOWER(buyer_email) = LOWER('a@b.c')"],
  ["creator_events_creator_idx", "SELECT * FROM creator_events WHERE creator_id = 1"],
  ["staff_assignments_staff_event_idx", "SELECT * FROM staff_assignments WHERE staff_id = 'S' AND event_id = 'E'"],
  ["staff_assignments_creator_idx", "SELECT * FROM staff_assignments WHERE creator_id = 1"],
  ["staff_sales_staff_idx", "SELECT * FROM staff_sales WHERE staff_id = 'S'"],
  ["staff_sales_booking_idx", "SELECT * FROM staff_sales WHERE booking_id = 'B'"],
  ["staff_withdrawals_staff_idx", "SELECT * FROM staff_withdrawals WHERE staff_id = 'S'"],
  ["staff_accounts_creator_idx", "SELECT * FROM staff_accounts WHERE creator_id = 1"],
  ["creator_kyc_documents_creator_idx", "SELECT * FROM creator_kyc_documents WHERE creator_id = 1"],
  ["payment_transactions_booking_idx", "SELECT * FROM payment_transactions WHERE booking_id = 'ORD-1'"],
  ["users_email_lower_idx", "SELECT * FROM users WHERE LOWER(email) = LOWER('a@b.c')"],
  ["creator_accounts_email_lower_idx", "SELECT * FROM creator_accounts WHERE LOWER(email) = 'a@b.c'"],
  ["admin_accounts_email_lower_idx", "SELECT * FROM admin_accounts WHERE LOWER(email) = 'a@b.c'"],
  ["super_admin_accounts_email_lower_idx", "SELECT * FROM super_admin_accounts WHERE LOWER(email) = 'a@b.c'"],
  ["staff_accounts_email_lower_idx", "SELECT * FROM staff_accounts WHERE LOWER(email) = LOWER('a@b.c')"],
  ["orders_pending_expiry_idx", "SELECT id FROM orders WHERE status = 'pending' AND expires_at < NOW()"],
];

test("M2: each lookup can use its index", async () => {
  const client = await server.db.connect();
  try {
    await client.query("SET enable_seqscan = off");
    for (const [index, sql] of CASES) {
      const plan = (await client.query(`EXPLAIN ${sql}`)).rows.map((r) => r["QUERY PLAN"]).join("\n");
      assert.ok(plan.includes(index), `${index} not used for: ${sql}\n${plan}`);
    }
  } finally {
    await client.query("RESET enable_seqscan");
    client.release();
  }
});
