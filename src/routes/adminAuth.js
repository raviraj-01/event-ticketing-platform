// Admin login (H6): password + lockout, emailed one-time code, step-up
// re-confirmation, and the admin session check.
const express = require("express");
const bcrypt = require("bcrypt");
const { pool } = require("../db/pool");
const { adminTable } = require("../utils/accounts");
const crypto = require("crypto");
const { hasSmtpConfig, createMailTransporter } = require("../services/mail");
const { recordAdminAction } = require("../services/adminAudit");
const { publicAdmin } = require("../utils/serializers");
const { startSession } = require("../services/sessions");
const { rateLimit } = require("../middleware/rateLimit");
const { requireAdmin, ADMIN_REAUTH_MINUTES } = require("../middleware/auth");

const router = express.Router();

// ── Admin login (H6) ───────────────────────────────────────────────────────
// Rate limited per IP and per email; 5 wrong passwords in a row lock the
// account for 15 minutes. Locked accounts and rate limits get the same 429
// message, so the response does not reveal which emails are admins.
const ADMIN_LOCKOUT = { maxFailures: 5, lockMinutes: 15 };
const TOO_MANY_ATTEMPTS = "Too many attempts. Please try again later.";
// Compared against when the email is unknown, so both cases take about as long.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("not-a-real-password", 10);

// Super admins live in their own table; check it first.
async function findAdminByEmail(email) {
  const superAdmin = await pool.query(
    "SELECT *, 'super' AS admin_type FROM super_admin_accounts WHERE LOWER(email)=$1",
    [email],
  );
  if (superAdmin.rows.length) return superAdmin.rows[0];
  const admin = await pool.query("SELECT *, 'admin' AS admin_type FROM admin_accounts WHERE LOWER(email)=$1", [email]);
  return admin.rows[0] || null;
}

// One atomic UPDATE: count the failure, and on the 5th lock the account and
// reset the counter. Returns true when this failure locked the account.
async function registerFailedAdminLogin(account) {
  const result = await pool.query(
    `UPDATE ${adminTable(account.admin_type)} SET
       locked_until = CASE WHEN failed_login_count + 1 >= $2
                           THEN NOW() + make_interval(mins => $3) ELSE locked_until END,
       failed_login_count = CASE WHEN failed_login_count + 1 >= $2 THEN 0 ELSE failed_login_count + 1 END
     WHERE id=$1
     RETURNING locked_until`,
    [account.id, ADMIN_LOCKOUT.maxFailures, ADMIN_LOCKOUT.lockMinutes],
  );
  const lockedUntil = result.rows[0] && result.rows[0].locked_until;
  return Boolean(lockedUntil && new Date(lockedUntil) > new Date());
}

// ── Second factor: emailed one-time code (H6 part 3) ──
const ADMIN_OTP = { ttlMinutes: 5, maxAttempts: 5 };
const otpHash = (challengeId, code) => crypto.createHash("sha256").update(`${challengeId}:${code}`).digest("hex");
// Local development without SMTP may show the code in the response. Never in production.
const adminOtpDevMode = () => process.env.ADMIN_OTP_DEV_MODE === "true" && process.env.NODE_ENV !== "production";
const maskEmail = (email) => String(email).replace(/^(.)[^@]*(@.*)$/, "$1***$2");

async function startAdminOtpChallenge(req, res, account) {
  if (!hasSmtpConfig() && !adminOtpDevMode()) {
    return res.status(503).json({ error: "Admin login needs the email service (SMTP) to send the login code." });
  }
  const challengeId = crypto.randomBytes(16).toString("hex");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await pool.query(
    `INSERT INTO admin_login_challenges (id, admin_type, admin_id, code_hash, expires_at)
     VALUES ($1, $2, $3, $4, NOW() + make_interval(mins => $5))`,
    [challengeId, account.admin_type, String(account.id), otpHash(challengeId, code), ADMIN_OTP.ttlMinutes],
  );
  if (hasSmtpConfig()) {
    await createMailTransporter().sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: account.email,
      subject: "Your admin login code",
      text: `Your admin login code is ${code}. It expires in ${ADMIN_OTP.ttlMinutes} minutes. If you did not try to log in, change your password.`,
    });
  }
  await recordAdminAction(pool, req, { action: "login.otp_sent", admin: { sub: account.id, adminType: account.admin_type, email: account.email } });
  res.json({
    otpRequired: true,
    challengeId,
    sentTo: maskEmail(account.email),
    ...(adminOtpDevMode() && !hasSmtpConfig() ? { devCode: code } : {}),
  });
}

// Password and second factor verified: start the session.
async function completeAdminLogin(req, res, account) {
  const adminType = account.admin_type;
  const fresh = await pool.query(`UPDATE ${adminTable(adminType)} SET last_login=NOW() WHERE id=$1 RETURNING *`, [account.id]);
  await recordAdminAction(pool, req, { action: "login.success", admin: { sub: account.id, adminType, email: account.email } });
  res.json({
    message: adminType === "super" ? "Super admin login successful" : "Admin login successful",
    admin: publicAdmin(adminType === "super" ? { ...fresh.rows[0], role: "Super Admin", is_super_admin: true } : fresh.rows[0]),
    ...(await startSession(pool, req, res, { role: "admin", accountId: account.id, adminType })),
  });
}

const adminLoginEmail = (req) => String((req.body && req.body.email) || "").trim().toLowerCase();

router.post(
  "/admin/login",
  rateLimit({ name: "admin-login-ip", windowSeconds: 600, max: 20, key: (req) => req.ip, message: TOO_MANY_ATTEMPTS }),
  rateLimit({ name: "admin-login-email", windowSeconds: 600, max: 10, key: (req) => adminLoginEmail(req) || null, message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    try {
      const email = adminLoginEmail(req);
      const password = String((req.body && req.body.password) || "");
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }
      const account = await findAdminByEmail(email);
      if (account && account.locked_until && new Date(account.locked_until) > new Date()) {
        await recordAdminAction(pool, req, { action: "login.blocked_locked", email }).catch(() => {});
        return res.status(429).json({ error: TOO_MANY_ATTEMPTS });
      }
      const storedHash = account && String(account.password || "").startsWith("$2") ? account.password : DUMMY_PASSWORD_HASH;
      const passwordOk = await bcrypt.compare(password, storedHash);
      if (!account || account.status !== "Active" || !passwordOk) {
        if (account && account.status === "Active") {
          const locked = await registerFailedAdminLogin(account);
          if (locked) await recordAdminAction(pool, req, { action: "login.locked", email }).catch(() => {});
        }
        await recordAdminAction(pool, req, { action: "login.failed", email }).catch(() => {});
        return res.status(401).json({ error: "Invalid admin email or password" });
      }
      await pool.query(
        `UPDATE ${adminTable(account.admin_type)} SET failed_login_count=0, locked_until=NULL WHERE id=$1`,
        [account.id],
      );
      // The password alone is not enough: send the second-factor code.
      await startAdminOtpChallenge(req, res, account);
    } catch (err) {
      console.error("Admin login failed:", err);
      res.status(500).json({ error: "Admin login failed" });
    }
  },
);


router.post(
  "/admin/reauth",
  requireAdmin,
  rateLimit({ name: "admin-reauth", windowSeconds: 600, max: 10, key: (req) => req.admin && String(req.admin.sub), message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    try {
      const password = String((req.body && req.body.password) || "");
      const table = adminTable(req.admin.adminType);
      const found = await pool.query(`SELECT *, $2::text AS admin_type FROM ${table} WHERE id=$1`, [req.admin.sub, req.admin.adminType]);
      const account = found.rows[0];
      const ok = account && String(account.password || "").startsWith("$2") && (await bcrypt.compare(password, account.password));
      if (!ok) {
        // Wrong confirmations count towards the same lockout as logins.
        if (account) await registerFailedAdminLogin(account);
        await recordAdminAction(pool, req, { action: "reauth.failed" }).catch(() => {});
        return res.status(401).json({ error: "Wrong password" });
      }
      await pool.query(
        `UPDATE ${table} SET reauth_until = NOW() + make_interval(mins => $2), failed_login_count = 0 WHERE id=$1`,
        [req.admin.sub, ADMIN_REAUTH_MINUTES],
      );
      await recordAdminAction(pool, req, { action: "reauth.success" });
      res.json({ success: true, validForMinutes: ADMIN_REAUTH_MINUTES });
    } catch (err) {
      console.error("Admin re-auth failed:", err);
      res.status(500).json({ error: "Could not confirm password" });
    }
  },
);

// Step 2 of admin login: the emailed code. The challenge row is locked so two
// parallel guesses cannot both be counted as the "first" attempt.
router.post(
  "/admin/login/verify",
  rateLimit({ name: "admin-otp-ip", windowSeconds: 600, max: 30, key: (req) => req.ip, message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    const challengeId = String((req.body && req.body.challengeId) || "");
    const code = String((req.body && req.body.code) || "").replace(/\D/g, "");
    if (!challengeId || code.length !== 6) return res.status(400).json({ error: "Enter the 6-digit code" });
    const client = await pool.connect();
    let account = null;
    try {
      await client.query("BEGIN");
      const found = await client.query("SELECT * FROM admin_login_challenges WHERE id=$1 FOR UPDATE", [challengeId]);
      const challenge = found.rows[0];
      const usable = challenge && !challenge.used_at && new Date(challenge.expires_at) > new Date()
        && challenge.attempts < ADMIN_OTP.maxAttempts;
      if (!usable) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "The code has expired. Please log in again." });
      }
      const expected = Buffer.from(challenge.code_hash, "hex");
      const actual = Buffer.from(otpHash(challengeId, code), "hex");
      if (!crypto.timingSafeEqual(expected, actual)) {
        await client.query("UPDATE admin_login_challenges SET attempts = attempts + 1 WHERE id=$1", [challengeId]);
        await client.query("COMMIT");
        await recordAdminAction(pool, req, { action: "login.otp_failed", admin: { sub: challenge.admin_id, adminType: challenge.admin_type } }).catch(() => {});
        return res.status(401).json({ error: "Wrong code" });
      }
      await client.query("UPDATE admin_login_challenges SET used_at = NOW() WHERE id=$1", [challengeId]);
      const row = await client.query(
        `SELECT *, $2::text AS admin_type FROM ${adminTable(challenge.admin_type)} WHERE id=$1 AND status='Active'`,
        [challenge.admin_id, challenge.admin_type],
      );
      await client.query("COMMIT");
      account = row.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Admin OTP verification failed:", err);
      return res.status(500).json({ error: "Could not verify the code" });
    } finally {
      client.release();
    }
    if (!account) return res.status(401).json({ error: "Admin account not active" });
    try {
      await completeAdminLogin(req, res, account);
    } catch (err) {
      console.error("Admin login completion failed:", err);
      res.status(500).json({ error: "Admin login failed" });
    }
  },
);

router.get("/admin/session", requireAdmin, async (req, res) => {
  try {
    if (req.admin.adminType === "super") {
      const superResult = await pool.query(
        "SELECT * FROM super_admin_accounts WHERE id=$1",
        [req.admin.sub],
      );
      if (
        !superResult.rows.length ||
        superResult.rows[0].status !== "Active"
      ) {
        return res.status(401).json({ error: "Admin account not found" });
      }
      return res.json({
        admin: publicAdmin({
          ...superResult.rows[0],
          role: "Super Admin",
          is_super_admin: true,
        }),
      });
    }
    const result = await pool.query(
      "SELECT * FROM admin_accounts WHERE id=$1",
      [req.admin.sub],
    );
    if (!result.rows.length || result.rows[0].status !== "Active") {
      return res.status(401).json({ error: "Admin account not found" });
    }
    res.json({ admin: publicAdmin(result.rows[0]) });
  } catch (err) {
    console.error("Admin session restore failed:", err);
    res.status(500).json({ error: "Could not restore admin session" });
  }
});

module.exports = router;
