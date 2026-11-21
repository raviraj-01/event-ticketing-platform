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
  const clearForcedChange = payload.role === "staff" ? ", must_change_password = FALSE" : "";
  const result = await db.query(
    `UPDATE ${config.table}
     SET password = $1, password_version = password_version + 1${clearForcedChange}
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

// ── Temporary passwords (Q4) ──────────────────────────────────────────────
// Staff without email are reset by their organizer or an admin; admins by a
// super admin. The account gets a random temporary password and must choose
// a new one at its next login (must_change_password).
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const TEMP_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"; // no 0/O/1/l/I
function generateTemporaryPassword(length = 12) {
  let out = "";
  for (let i = 0; i < length; i += 1) out += TEMP_PASSWORD_ALPHABET[crypto.randomInt(TEMP_PASSWORD_ALPHABET.length)];
  return out;
}

const TEMP_PASSWORD_TABLES = {
  staff: { table: "staff_accounts", extra: ", password_version = password_version + 1" }, // also kills emailed links
  admin: { table: "admin_accounts", extra: ", failed_login_count = 0, locked_until = NULL" },
  super: { table: "super_admin_accounts", extra: ", failed_login_count = 0, locked_until = NULL" },
};

// Returns the temporary password (shown once to the person who reset it).
async function setTemporaryPassword(db, { role, accountId, adminType }) {
  const key = role === "admin" ? (adminType === "super" ? "super" : "admin") : role;
  const config = TEMP_PASSWORD_TABLES[key];
  if (!config) throw new ResetError("This account type cannot get a temporary password");
  const temporaryPassword = generateTemporaryPassword();
  const result = await db.query(
    `UPDATE ${config.table} SET password = $1, must_change_password = TRUE${config.extra} WHERE id = $2 RETURNING id`,
    [await bcrypt.hash(temporaryPassword, 10), accountId],
  );
  if (!result.rows.length) throw new ResetError("Account not found");
  await revokeAllSessions(db, { role, accountId, adminType });
  return temporaryPassword;
}

module.exports = {
  RESET_ROLES,
  ResetError,
  findResetTargets,
  createResetToken,
  resetPasswordWithToken,
  generateTemporaryPassword,
  setTemporaryPassword,
};
