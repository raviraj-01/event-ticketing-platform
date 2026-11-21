// Account routes shared by all roles: forgot / reset / change password, the
// buyer session check, and the session lifecycle (refresh, logout).
const express = require("express");
const { rateLimit } = require("../middleware/rateLimit");
const { hasSmtpConfig, createMailTransporter, resetEmailHtml } = require("../services/mail");
const {
  RESET_ROLES,
  findResetTargets,
  createResetToken,
  resetPasswordWithToken,
  ResetError,
} = require("../services/passwordReset");
const { pool } = require("../db/pool");
const { APP_BASE_URL } = require("../config");
const bcrypt = require("bcrypt");
const { requireRole, requireBuyer } = require("../middleware/auth");
const {
  ROLES,
  revokeAllSessions,
  startSession,
  rotateSession,
  AuthError,
  endSession,
} = require("../services/sessions");
const { recordAdminAction } = require("../services/adminAudit");
const { publicUser } = require("../utils/serializers");

const router = express.Router();

// ── Forgot Password: Send reset email ──────────────────────────────────────
// Each request can send an email, so limit it per address and per IP (H3).
const forgotPasswordLimits = [
  rateLimit({ name: "forgot-email", windowSeconds: 3600, max: 3,
    key: (req) => String((req.body && req.body.email) || "").trim().toLowerCase() || null }),
  rateLimit({ name: "forgot-ip", windowSeconds: 3600, max: 10, key: (req) => req.ip }),
];

// The answer is the same whether or not the email exists.
router.post("/auth/forgot-password", ...forgotPasswordLimits, async (req, res) => {
  try {
    if (!hasSmtpConfig()) {
      return res.status(500).json({ error: "Email service is not configured on this server" });
    }
    const email = String((req.body && req.body.email) || "").trim().toLowerCase();
    const role = String((req.body && req.body.role) || "buyer");
    if (!email) return res.status(400).json({ error: "Email is required" });
    if (!RESET_ROLES[role]) return res.status(400).json({ error: "Password reset by email is not available for this account type" });

    const accounts = await findResetTargets(pool, role, email);
    if (accounts.length) {
      const ttlMinutes = Number(process.env.PASSWORD_RESET_TTL_MINUTES || 10);
      const links = [];
      for (const account of accounts) {
        const token = await createResetToken(role, account, ttlMinutes);
        links.push({ url: `${APP_BASE_URL}/?reset_token=${encodeURIComponent(token)}`, loginId: account.login_id || "" });
      }
      await createMailTransporter().sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: "Reset your password",
        html: resetEmailHtml(links, ttlMinutes, RESET_ROLES[role].label),
      });
    }
    res.json({ success: true, message: "If that email is registered, a reset link has been sent." });
  } catch (err) {
    console.error("Forgot password failed:", err);
    res.status(500).json({ error: "Could not send reset email. Please try again later." });
  }
});

// Step 2: the link's token + a new password. Works once (password_version).
router.post("/auth/reset-password-by-token", async (req, res) => {
  try {
    const token = String((req.body && req.body.token) || "").trim();
    const newPassword = String((req.body && req.body.password) || "");
    if (!token) return res.status(400).json({ error: "Reset token is required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    const role = await resetPasswordWithToken(pool, token, await bcrypt.hash(newPassword, 10));
    res.json({ success: true, role, message: "Password updated successfully. You can now sign in with your new password." });
  } catch (err) {
    if (err instanceof ResetError) return res.status(err.status).json({ error: err.message });
    console.error("Token password reset failed:", err);
    res.status(500).json({ error: "Could not reset password" });
  }
});

// Change your own password (also the forced change after a temporary
// password). Ends all sessions and starts a fresh one for this client.
const PASSWORD_TABLES = {
  buyer: "users", creator: "creator_accounts", staff: "staff_accounts",
  admin: "admin_accounts", super: "super_admin_accounts",
};
router.post(
  "/auth/change-password",
  requireRole(ROLES, (req, s) => { req.session = s; }, { allowPasswordChange: true }),
  rateLimit({ name: "change-password", windowSeconds: 600, max: 10, key: (req) => `${req.session.role}:${req.session.payload.sub}` }),
  async (req, res) => {
    try {
      const { role, payload, account } = req.session;
      const currentPassword = String((req.body && req.body.currentPassword) || "");
      const newPassword = String((req.body && req.body.newPassword) || "");
      if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });
      if (newPassword === currentPassword) return res.status(400).json({ error: "Choose a password different from the current one" });
      if (!String(account.password || "").startsWith("$2") || !(await bcrypt.compare(currentPassword, account.password))) {
        return res.status(401).json({ error: "Current password is wrong" });
      }
      const table = PASSWORD_TABLES[role === "admin" && payload.adminType === "super" ? "super" : role];
      const hasForcedFlag = ["staff_accounts", "admin_accounts", "super_admin_accounts"].includes(table);
      const hasVersion = ["users", "creator_accounts", "staff_accounts"].includes(table);
      await pool.query(
        `UPDATE ${table} SET password = $1${hasForcedFlag ? ", must_change_password = FALSE" : ""}${hasVersion ? ", password_version = password_version + 1" : ""} WHERE id = $2`,
        [await bcrypt.hash(newPassword, 10), payload.sub],
      );
      await revokeAllSessions(pool, { role, accountId: payload.sub, adminType: payload.adminType });
      if (role === "admin") await recordAdminAction(pool, req, { action: "password.change" });
      res.json({
        success: true,
        ...(await startSession(pool, req, res, { role, accountId: payload.sub, adminType: payload.adminType })),
      });
    } catch (err) {
      console.error("Password change failed:", err);
      res.status(500).json({ error: "Could not change password" });
    }
  },
);

// The logged-in buyer's profile. Only buyer sessions are accepted, so a
// creator/admin token with the same numeric id can no longer read a buyer (H12).
router.get("/session", requireBuyer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, status
       FROM users WHERE id=$1`,
      [req.buyer.sub],
    );
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error("Session load failed:", err);
    res.status(500).json({ error: "Could not load session" });
  }
});

// ── Session lifecycle (H5) ─────────────────────────────────────────────────
const sessionRole = (req) => {
  const role = String((req.body && req.body.role) || "");
  return ROLES.includes(role) ? role : null;
};

// New access token (and a rotated refresh token) for a valid refresh token.
router.post(
  "/auth/refresh",
  rateLimit({ name: "refresh-ip", windowSeconds: 600, max: 120, key: (req) => req.ip }),
  async (req, res) => {
    const role = sessionRole(req);
    if (!role) return res.status(400).json({ error: "Valid role is required" });
    try {
      res.json(await rotateSession(pool, req, res, role));
    } catch (err) {
      if (!(err instanceof AuthError)) console.error("Session refresh failed:", err);
      res.status(401).json({ error: "Session expired. Please log in again." });
    }
  },
);

// End this login (revokes its refresh token family, clears cookies).
router.post("/auth/logout", async (req, res) => {
  const role = sessionRole(req);
  if (!role) return res.status(400).json({ error: "Valid role is required" });
  try {
    await endSession(pool, req, res, role);
    res.json({ success: true });
  } catch (err) {
    console.error("Logout failed:", err);
    res.status(500).json({ error: "Logout failed" });
  }
});

// Log this account out on every device.
router.post(
  "/auth/logout-all",
  requireRole(ROLES, (req, s) => { req.session = s; }, { allowPasswordChange: true }),
  async (req, res) => {
    try {
      const { role, payload } = req.session;
      await revokeAllSessions(pool, { role, accountId: payload.sub, adminType: payload.adminType });
      await endSession(pool, req, res, role);
      res.json({ success: true });
    } catch (err) {
      console.error("Logout everywhere failed:", err);
      res.status(500).json({ error: "Could not log out everywhere" });
    }
  },
);

module.exports = router;
