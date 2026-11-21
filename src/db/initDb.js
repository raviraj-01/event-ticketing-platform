// Startup data step, after the migrations. M22: starting the app never
// changes or deletes rows that already exist. The only thing done here is to
// create the first super admin when SUPERADMIN_EMAIL has no account yet (a new
// row). One-off data repairs live in scripts/db-fixups.js and run only by hand.
const { pool } = require("./pool");
const bcrypt = require("bcrypt");

const initDb = async () => {
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
