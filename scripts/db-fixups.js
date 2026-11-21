// One-off data repairs that used to run on every startup (M22). They change
// existing rows, so they only run by hand, and only with --apply:
//
//   npm run db:fixups            (dry run: shows what would change, changes nothing)
//   npm run db:fixups -- --apply (makes the changes)
//
// 1. Recount creator_events.booking_count / revenue from bookings.
// 2. Copy legacy "Super Admin" rows from admin_accounts into
//    super_admin_accounts and delete them from admin_accounts.
const path = require("path");
const { Pool } = require("pg");

async function main() {
  if (process.env.SKIP_ENV_FILE !== "true") require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
  const apply = process.argv.includes("--apply");
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  const pool = new Pool({
    connectionString,
    ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
  });
  const client = await pool.connect();
  try {
    // Everything runs in one transaction; a dry run rolls it back.
    await client.query("BEGIN");
    const counts = await client.query(`
      UPDATE creator_events e SET
        booking_count=COALESCE(s.tickets,0),
        revenue=COALESCE(s.revenue,0)
      FROM (
        SELECT event_id,
          COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
          COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
        FROM bookings
        WHERE event_id IS NOT NULL
        GROUP BY event_id
      ) s
      WHERE e.id=s.event_id
        AND (e.booking_count IS DISTINCT FROM COALESCE(s.tickets,0) OR e.revenue IS DISTINCT FROM COALESCE(s.revenue,0))
      RETURNING e.id`);
    const copied = await client.query(`
      INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
      SELECT name, email, password, status, last_login, created_at
      FROM admin_accounts
      WHERE role='Super Admin'
      ON CONFLICT (email) DO NOTHING
      RETURNING email`);
    const removed = await client.query("DELETE FROM admin_accounts WHERE role='Super Admin' RETURNING email");
    console.log(`Event counters to fix: ${counts.rowCount}`);
    console.log(`Legacy super admins to copy: ${copied.rowCount}, to remove from admin_accounts: ${removed.rowCount}`);
    if (apply) {
      await client.query("COMMIT");
      console.log("Applied.");
    } else {
      await client.query("ROLLBACK");
      console.log("Dry run: nothing was changed. Run with --apply to make these changes.");
    }
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Fix-ups failed:", err.message);
  process.exit(1);
});
