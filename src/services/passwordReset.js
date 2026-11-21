// Emailed, single-use password reset links (H2 + decision Q4).
//
// Who can use it:  buyers, organizers (creators) and staff who have an email.
// Who cannot:      staff without email (their organizer or an admin resets them),
//                  admins (a super admin resets them), super admins (CLI script).
//
// The link carries { role, sub: account id, pv: password_version }. The reset
// is one UPDATE that only matches while password_version still equals pv and
// then increments it, so a link works exactly once.
const { AUDIENCE, signToken, verifyToken } = require("../utils/tokens");
const { revokeAllSessions } = require("./sessions");

// table + SQL condition for "this account may still reset its password"
const RESET_ROLES = {
  buyer: { table: "users", activeSql: "COALESCE(status,'Active') NOT IN ('Suspended','Blocked','Inactive')", label: "buyer account" },
  creator: { table: "creator_accounts", activeSql: "kyc_status NOT IN ('Rejected','Suspended')", label: "organizer account" },
  staff: { table: "staff_accounts", activeSql: "status = 'active'", label: "staff account" },
};

class ResetError extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}

// Accounts of this role that use this email (staff emails are not unique, so
// there can be several staff accounts).
async function findResetTargets(db, role, email) {
  const config = RESET_ROLES[role];
  if (!config) return [];
  const loginColumn = role === "staff" ? ", staff_id AS login_id" : "";
  const result = await db.query(
    `SELECT id, password_version${loginColumn} FROM ${config.table}
     WHERE LOWER(email) = LOWER($1) AND ${config.activeSql}`,
    [email],
  );
  return result.rows;
}

const createResetToken = (role, account, ttlMinutes) =>
  signToken(
    { role, sub: account.id, pv: Number(account.password_version || 0) },
    { audience: AUDIENCE.passwordReset, expiresInSeconds: ttlMinutes * 60 },
  );

// Returns the role so the caller can tell the user where to sign in.
async function resetPasswordWithToken(db, token, passwordHash) {
  let payload;
  try {
    payload = await verifyToken(token, { audience: AUDIENCE.passwordReset });
  } catch (_) {
    throw new ResetError("Reset link is invalid or has expired. Please request a new one.");
  }
  const config = RESET_ROLES[payload.role];
  if (!config || !payload.sub || !Number.isInteger(payload.pv)) throw new ResetError("Invalid reset link");
  const result = await db.query(
    `UPDATE ${config.table}
     SET password = $1, password_version = password_version + 1
     WHERE id = $2 AND password_version = $3 AND ${config.activeSql}
     RETURNING id`,
    [passwordHash, payload.sub, payload.pv],
  );
  if (!result.rows.length) {
    throw new ResetError("Reset link is invalid or has already been used. Please request a new one.");
  }
  // A new password ends every existing session of that account (H5).
  await revokeAllSessions(db, { role: payload.role, accountId: result.rows[0].id });
  return payload.role;
}

module.exports = { RESET_ROLES, ResetError, findResetTargets, createResetToken, resetPasswordWithToken };
