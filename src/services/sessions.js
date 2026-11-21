// Sessions (H5): 15-minute access tokens + rotating refresh tokens.
//
// Roles: buyer | creator | staff | admin (admin has adminType 'admin' or 'super').
//
// Web browsers get both tokens as httpOnly cookies (JavaScript cannot read
// them, so an XSS bug cannot steal a session):
//   at_<role>  access token,  path /,     15 minutes
//   rt_<role>  refresh token, path /auth, 30 days
// The Android app (request header "X-Client: app") calls the API cross-site,
// where WebView cookies are unreliable, so it receives the tokens in the JSON
// body and sends "Authorization: Bearer <access token>" (decision D7).
//
// Every access token carries tv = the account's token_version. Each request
// re-checks the account in the database (active? same token_version?), so
// suspending an account or bumping token_version takes effect immediately.
const crypto = require("crypto");
const { AUDIENCE, signToken, verifyToken } = require("../utils/tokens");
const { parseCookies } = require("../utils/cookies");
const { isUserActive } = require("../utils/accounts");

const intFromEnv = (name, fallback) => {
  const value = Number(process.env[name]);
  return Number.isInteger(value) && value >= 0 ? value : fallback;
};

const SESSION_SETTINGS = {
  accessTtlSeconds: intFromEnv("ACCESS_TOKEN_TTL_SECONDS", 15 * 60),
  refreshTtlSeconds: intFromEnv("REFRESH_TOKEN_TTL_SECONDS", 30 * 24 * 60 * 60),
  // Two browser tabs may refresh with the same cookie at the same moment; a
  // second use within this window is treated as that race, not as theft.
  reuseGraceSeconds: intFromEnv("REFRESH_REUSE_GRACE_SECONDS", 30),
};

const ROLES = ["buyer", "creator", "staff", "admin"];

class AuthError extends Error {
  constructor(message = "Login required") {
    super(message);
    this.status = 401;
  }
}

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const isAppClient = (req) => String(req.headers["x-client"] || "").toLowerCase() === "app";
const roleOfPayload = (payload) => (payload.scope ? payload.scope : "buyer");

// Which table holds the account, and when is it allowed in.
function accountSource(role, adminType) {
  switch (role) {
    case "buyer": return { table: "users", isActive: (row) => isUserActive(row.status) };
    case "creator": return { table: "creator_accounts", isActive: (row) => row.kyc_status === "Approved" };
    case "staff": return { table: "staff_accounts", isActive: (row) => row.status === "active" };
    case "admin":
      return {
        table: adminType === "super" ? "super_admin_accounts" : "admin_accounts",
        isActive: (row) => row.status === "Active",
      };
    default: throw new AuthError();
  }
}

async function loadAccount(db, role, accountId, adminType) {
  const source = accountSource(role, adminType);
  const result = await db.query(`SELECT * FROM ${source.table} WHERE id = $1`, [accountId]);
  const row = result.rows[0];
  return row && source.isActive(row) ? row : null;
}

// Token from "Authorization: Bearer" (app) or from the role's cookie (web).
// For endpoints that accept several roles, the web page names the role it is
// acting as in the X-Session-Role header.
function readAccessToken(req, roles) {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  const cookies = parseCookies(req);
  const wanted = String(req.headers["x-session-role"] || "");
  if (roles.includes(wanted) && cookies[`at_${wanted}`]) return cookies[`at_${wanted}`];
  const role = roles.find((r) => cookies[`at_${r}`]);
  return role ? cookies[`at_${role}`] : "";
}

// Verify the token and the account behind it. Returns { role, payload, account }.
async function authenticateRequest(db, req, roles) {
  const token = readAccessToken(req, roles);
  if (!token) throw new AuthError();
  let payload;
  try {
    payload = await verifyToken(token, { audience: AUDIENCE.session });
  } catch (_) {
    throw new AuthError();
  }
  const role = roleOfPayload(payload);
  if (!roles.includes(role) || !payload.sub) throw new AuthError();
  const account = await loadAccount(db, role, payload.sub, payload.adminType);
  if (!account || Number(account.token_version) !== Number(payload.tv)) throw new AuthError();
  return { role, payload, account };
}

function accessClaims(role, account, adminType) {
  switch (role) {
    case "buyer": return { sub: account.id, email: account.email };
    case "creator": return { sub: account.id, email: account.email, scope: "creator" };
    case "staff": return { sub: account.id, staffId: account.staff_id, creatorId: account.creator_id, scope: "staff" };
    case "admin": return { sub: account.id, email: account.email, scope: "admin", adminType };
    default: throw new AuthError();
  }
}

const signAccessToken = (role, account, adminType) =>
  signToken(
    { ...accessClaims(role, account, adminType), tv: Number(account.token_version || 0) },
    { audience: AUDIENCE.session, expiresInSeconds: SESSION_SETTINGS.accessTtlSeconds },
  );

async function insertRefreshToken(db, { role, accountId, adminType, familyId }) {
  const raw = crypto.randomBytes(32).toString("base64url");
  await db.query(
    `INSERT INTO refresh_tokens (token_hash, family_id, role, account_id, admin_type, expires_at)
     VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(secs => $6))`,
    [sha256(raw), familyId, role, String(accountId), adminType || null, SESSION_SETTINGS.refreshTtlSeconds],
  );
  return raw;
}

// --- cookies (web) ---
function cookieOptions(req, maxAgeSeconds, path) {
  const baseUrl = String(process.env.APP_BASE_URL || "");
  return {
    httpOnly: true,
    sameSite: "strict",
    secure: req.secure || baseUrl.startsWith("https://"),
    path,
    maxAge: maxAgeSeconds * 1000,
  };
}
function setSessionCookies(req, res, role, accessToken, refreshToken) {
  res.cookie(`at_${role}`, accessToken, cookieOptions(req, SESSION_SETTINGS.accessTtlSeconds, "/"));
  if (refreshToken) res.cookie(`rt_${role}`, refreshToken, cookieOptions(req, SESSION_SETTINGS.refreshTtlSeconds, "/auth"));
}
function clearSessionCookies(req, res, role) {
  res.clearCookie(`at_${role}`, { ...cookieOptions(req, 0, "/"), maxAge: undefined });
  res.clearCookie(`rt_${role}`, { ...cookieOptions(req, 0, "/auth"), maxAge: undefined });
}

// What a login/refresh response carries: cookies for the web, tokens for the app.
function deliver(req, res, role, accessToken, refreshToken) {
  if (isAppClient(req)) {
    return { accessToken, refreshToken, expiresIn: SESSION_SETTINGS.accessTtlSeconds };
  }
  setSessionCookies(req, res, role, accessToken, refreshToken);
  return { expiresIn: SESSION_SETTINGS.accessTtlSeconds };
}

// Called by every login route after the password/ID token was checked.
async function startSession(db, req, res, { role, accountId, adminType }) {
  const account = await loadAccount(db, role, accountId, adminType);
  if (!account) throw new AuthError();
  const accessToken = await signAccessToken(role, account, adminType);
  const refreshToken = await insertRefreshToken(db, {
    role, accountId: account.id, adminType, familyId: crypto.randomUUID(),
  });
  const delivered = deliver(req, res, role, accessToken, refreshToken);
  // Q4: tell the client straight away that a new password must be chosen.
  return account.must_change_password ? { ...delivered, mustChangePassword: true } : delivered;
}

const readRefreshToken = (req, role) =>
  isAppClient(req) ? String((req.body && req.body.refreshToken) || "") : parseCookies(req)[`rt_${role}`] || "";

// POST /auth/refresh: swap a refresh token for a new access + refresh token.
async function rotateSession(pool, req, res, role) {
  const raw = readRefreshToken(req, role);
  if (!raw) throw new AuthError();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query("SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE", [sha256(raw)]);
    const row = found.rows[0];
    if (!row || row.role !== role || row.revoked_at || new Date(row.expires_at) <= new Date()) {
      await client.query("ROLLBACK");
      throw new AuthError();
    }
    const account = await loadAccount(client, role, row.account_id, row.admin_type);
    if (!account) {
      await client.query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL", [row.family_id]);
      await client.query("COMMIT");
      throw new AuthError();
    }
    if (row.used_at) {
      const ageSeconds = (Date.now() - new Date(row.used_at).getTime()) / 1000;
      if (ageSeconds > SESSION_SETTINGS.reuseGraceSeconds) {
        // An already-rotated token came back: assume it was stolen.
        await client.query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL", [row.family_id]);
        await client.query("COMMIT");
        throw new AuthError();
      }
      // Parallel refresh from another tab: give a fresh access token only.
      await client.query("COMMIT");
      return deliver(req, res, role, await signAccessToken(role, account, row.admin_type), null);
    }
    await client.query("UPDATE refresh_tokens SET used_at = NOW() WHERE id = $1", [row.id]);
    const refreshToken = await insertRefreshToken(client, {
      role, accountId: row.account_id, adminType: row.admin_type, familyId: row.family_id,
    });
    await client.query("COMMIT");
    return deliver(req, res, role, await signAccessToken(role, account, row.admin_type), refreshToken);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// POST /auth/logout: end this login (its whole refresh family) and clear cookies.
async function endSession(db, req, res, role) {
  const raw = readRefreshToken(req, role);
  if (raw) {
    await db.query(
      `UPDATE refresh_tokens SET revoked_at = NOW()
       WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1) AND revoked_at IS NULL`,
      [sha256(raw)],
    );
  }
  if (!isAppClient(req)) clearSessionCookies(req, res, role);
}

// Log the account out everywhere: old access tokens fail at once (token_version)
// and no refresh token can be used again.
async function revokeAllSessions(db, { role, accountId, adminType }) {
  const { table } = accountSource(role, adminType);
  await db.query(`UPDATE ${table} SET token_version = token_version + 1 WHERE id = $1`, [accountId]);
  await db.query(
    "UPDATE refresh_tokens SET revoked_at = NOW() WHERE role = $1 AND account_id = $2 AND revoked_at IS NULL",
    [role, String(accountId)],
  );
}

module.exports = {
  ROLES,
  SESSION_SETTINGS,
  AuthError,
  authenticateRequest,
  startSession,
  rotateSession,
  endSession,
  revokeAllSessions,
  clearSessionCookies,
};
