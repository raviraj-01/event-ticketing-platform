// Admin audit log (H6): an append-only record of admin logins and every
// admin change, with who, what, target, when and from which IP.

async function recordAdminAction(db, req, { action, targetType = null, targetId = null, details = {}, admin = null, email = null }) {
  const who = admin || req.admin || {};
  await db.query(
    `INSERT INTO admin_audit_log (admin_type, admin_id, admin_email, action, target_type, target_id, details, ip, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      who.adminType || null,
      who.sub != null ? String(who.sub) : null,
      String(who.email || email || "").toLowerCase() || null,
      action,
      targetType,
      targetId != null ? String(targetId) : null,
      JSON.stringify(details || {}),
      req.ip || null,
      String(req.headers["user-agent"] || "").slice(0, 300) || null,
    ],
  );
}

// Route middleware: log the action once the response has succeeded.
// `describe(req)` returns { targetType, targetId, details }.
const audited = (db, action, describe = () => ({})) => (req, res, next) => {
  res.on("finish", () => {
    if (res.statusCode >= 400) return;
    let info = {};
    try {
      info = describe(req) || {};
    } catch (_) {
      info = {};
    }
    recordAdminAction(db, req, { action, ...info }).catch((err) =>
      console.error(`Audit log write failed (${action}):`, err.message),
    );
  });
  next();
};

async function listAdminActions(db, { limit = 50, beforeId = null } = {}) {
  const cleanLimit = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const result = await db.query(
    `SELECT id, admin_type, admin_id, admin_email, action, target_type, target_id, details, ip, created_at
     FROM admin_audit_log
     WHERE ($1::bigint IS NULL OR id < $1)
     ORDER BY id DESC
     LIMIT $2`,
    [beforeId ? Number(beforeId) : null, cleanLimit],
  );
  return result.rows;
}

module.exports = { recordAdminAction, audited, listAdminActions };
