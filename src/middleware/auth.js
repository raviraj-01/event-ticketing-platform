// Route guards: who is calling (role + live DB check), super admin check,
// and the admin step-up confirmation.
const { authenticateRequest, AuthError } = require("../services/sessions");
const { pool } = require("../db/pool");
const { adminTable } = require("../utils/accounts");

// Authentication middleware. Every request re-checks the account in the DB
// (exists, active, same token_version), so suspensions and "log out
// everywhere" take effect immediately (H4, H5).
// { allowPasswordChange: true } only for the change-password and logout-all routes.
const requireRole = (roles, attach, { allowPasswordChange = false } = {}) => async (req, res, next) => {
  try {
    const session = await authenticateRequest(pool, req, roles);
    // Q4: after a reset by someone else, the only thing allowed is choosing a new password.
    if (session.account.must_change_password && !allowPasswordChange) {
      return res.status(403).json({ error: "Please choose a new password to continue", passwordChangeRequired: true });
    }
    attach(req, session);
    next();
  } catch (err) {
    if (!(err instanceof AuthError)) console.error("Authentication failed:", err);
    res.status(401).json({ error: "Login required" });
  }
};

const requireCreator = requireRole(["creator"], (req, s) => { req.creator = s.payload; });
const requireAdmin = requireRole(["admin"], (req, s) => { req.admin = s.payload; });
const requireSuperAdmin = async (req, res, next) => {
  try {
    if (!req.admin) {
      return res.status(403).json({ error: "Super Admin access required" });
    }
    let result =
      req.admin.adminType === "super"
        ? await pool.query(
            "SELECT id, status FROM super_admin_accounts WHERE id=$1",
            [req.admin.sub],
          )
        : await pool.query(
            "SELECT id, status FROM super_admin_accounts WHERE LOWER(email)=LOWER($1)",
            [req.admin.email || ""],
          );
    // Legacy data: an old "Super Admin" row in admin_accounts. Accepted as it
    // is; it used to be copied over and DELETED here on first use (M22: the
    // app never changes or deletes existing rows on its own).
    if (!result.rows.length) {
      result = await pool.query(
        `SELECT id, status FROM admin_accounts
         WHERE role='Super Admin' AND (id=$1 OR LOWER(email)=LOWER($2))
         ORDER BY (id=$1) DESC LIMIT 1`,
        [Number(req.admin.sub) || 0, req.admin.email || ""],
      );
    }
    const admin = result.rows[0];
    if (!admin || admin.status !== "Active") {
      return res.status(403).json({ error: "Super Admin access required" });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: "Could not verify admin access" });
  }
};

const requireStaff = requireRole(["staff"], (req, s) => { req.staff = s.payload; });
const requireBuyer = requireRole(["buyer"], (req, s) => { req.buyer = s.payload; });
const requireScanIdentity = requireRole(["creator", "staff"], (req, s) => {
  req.scanIdentity = { type: s.role, payload: s.payload };
});

// ── Step-up confirmation for destructive admin actions (H6 part 4) ──
const ADMIN_REAUTH_MINUTES = 5;

// Destructive routes need the admin's password confirmed in the last 5 minutes.
const requireRecentReauth = async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT reauth_until FROM ${adminTable(req.admin.adminType)} WHERE id=$1`,
      [req.admin.sub],
    );
    const until = result.rows[0] && result.rows[0].reauth_until;
    if (until && new Date(until) > new Date()) return next();
    res.status(403).json({ error: "Please confirm your password to continue", reauthRequired: true });
  } catch (err) {
    console.error("Re-auth check failed:", err);
    res.status(500).json({ error: "Could not verify confirmation" });
  }
};

// Short name used on admin routes: `confirmed` = password re-entered recently.
const confirmed = requireRecentReauth;

// Who may see a ticket (and its QR payload): the buyer who owns it, the
// creator of its event, or staff assigned to its event. Anyone else gets 404
// (never 403), so booking IDs cannot be probed.
const requireTicketViewer = requireRole(["buyer", "creator", "staff"], (req, s) => {
  req.ticketViewer = { type: s.role, id: s.payload.sub };
});

module.exports = {
  requireCreator,
  requireStaff,
  requireAdmin,
  ADMIN_REAUTH_MINUTES,
  requireSuperAdmin,
  confirmed,
  requireBuyer,
  requireTicketViewer,
  requireScanIdentity,
  requireRole,
};
