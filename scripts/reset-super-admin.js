// Super admin recovery (decision Q4). Super admins have no self-service
// password reset; whoever can reach the database runs this on the server:
//
//   npm run reset-super-admin -- superadmin@example.com
//
// It sets a temporary password (printed once), forces a password change at
// the next login, clears any lockout, ends all sessions and writes an audit
// log entry. The next login still requires the emailed one-time code.
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { Pool } = require("pg");
const { setTemporaryPassword } = require("../src/services/passwordReset");

async function main() {
  const email = String(process.argv[2] || "").trim().toLowerCase();
  if (!email) {
    console.error("Usage: npm run reset-super-admin -- <super admin email>");
    process.exit(1);
  }
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  const pool = new Pool({
    connectionString,
    ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
  });
  try {
    const found = await pool.query("SELECT id FROM super_admin_accounts WHERE LOWER(email) = $1", [email]);
    if (!found.rows.length) {
      console.error(`No super admin with email ${email}. (The first one is created from SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD at startup.)`);
      process.exitCode = 1;
      return;
    }
    const id = found.rows[0].id;
    const temporaryPassword = await setTemporaryPassword(pool, { role: "admin", accountId: id, adminType: "super" });
    await pool.query(
      `INSERT INTO admin_audit_log (admin_type, admin_id, admin_email, action, target_type, target_id, details)
       VALUES ('super', $1, $2, 'super_admin.cli_reset', 'admin', $1, '{"via":"cli"}')`,
      [String(id), email],
    );
    console.log(`Temporary password for ${email}: ${temporaryPassword}`);
    console.log("They must choose a new password after logging in (the emailed code is still required).");
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Reset failed:", err.message);
  process.exit(1);
});
