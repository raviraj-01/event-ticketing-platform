// Data fix-ups that run at startup after the migrations (schema changes live
// in migrations/, never here).
const { pool } = require("./pool");
const bcrypt = require("bcrypt");

const initDb = async () => {
  // Schema lives in migrations/ (run before this). This only fixes up data.
  await pool.query(`
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
  `);

  // Legacy rows: copy old "Super Admin" admin_accounts into super_admin_accounts
  // without ever overwriting an existing super admin (M1).
  await pool.query(`
    INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
    SELECT name, email, password, status, last_login, created_at
    FROM admin_accounts
    WHERE role='Super Admin'
    ON CONFLICT (email) DO NOTHING
  `);
  await pool.query("DELETE FROM admin_accounts WHERE role='Super Admin'");

  // First super admin from SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD. Insert-only:
  // an existing super admin is never touched, so a password changed in the app
  // or reset with scripts/reset-super-admin.js survives restarts (M1, Q4).
  const superAdminEmail = String(process.env.SUPERADMIN_EMAIL || "").trim().toLowerCase();
  const superAdminPassword = process.env.SUPERADMIN_PASSWORD;
  if (!superAdminEmail || !superAdminPassword) return;
  const created = await pool.query(
    `INSERT INTO super_admin_accounts (name, email, password, status)
     VALUES ('Super Admin', $1, $2, 'Active')
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [superAdminEmail, await bcrypt.hash(superAdminPassword, 10)],
  );
  if (created.rows.length) console.log(`Created the first super admin (${superAdminEmail}).`);
};

module.exports = { initDb };
