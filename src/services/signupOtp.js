// Signup phone verification: Twilio Verify, a local-development fallback
// (M7), and the short-lived token that proves a phone was verified.
const { signToken, AUDIENCE, verifyToken } = require("../utils/tokens");
const { HttpError } = require("../utils/httpError");
const crypto = require("crypto");

const hasTwilioVerifyConfig = () =>
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN &&
  process.env.TWILIO_VERIFY_SERVICE_SID;

const localOtpStore = new Map();

if (!hasTwilioVerifyConfig()) {
  console.warn(
    "Signup OTP is disabled until TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID are added to .env.",
  );
}

const twilioVerifyUrl = (suffix = "") =>
  `https://verify.twilio.com/v2/Services/${encodeURIComponent(
    process.env.TWILIO_VERIFY_SERVICE_SID || "",
  )}/Verification${suffix}`;

const twilioAuthHeader = () =>
  `Basic ${Buffer.from(
    `${process.env.TWILIO_ACCOUNT_SID || ""}:${process.env.TWILIO_AUTH_TOKEN || ""}`,
  ).toString("base64")}`;

const providerErrorMessage = (data, fallback) => {
  if (!data || typeof data !== "object") return fallback;
  return data.message || data.error || data.error_message || data.description || fallback;
};

// Server-side problems (missing config, our Twilio credentials rejected,
// Twilio down) are internal errors: logged, never shown to the user (M5).
const assertTwilioConfig = () => {
  if (!hasTwilioVerifyConfig()) {
    const err = new Error(
      "OTP service is not configured. Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID to .env, then restart the server.",
    );
    err.status = 503;
    throw err;
  }
};

const assertProviderSuccess = (response, data, fallback) => {
  if (!response.ok || data.error || data.error_message) {
    const status = response.ok ? 400 : response.status;
    const detail = providerErrorMessage(data, fallback);
    if (status === 429) throw new HttpError(429, "Too many attempts. Please try again later.");
    if (status === 400 || status === 404) {
      console.warn(`${fallback} (${status}):`, detail);
      throw new HttpError(400, "That number or code was not accepted. Please check it and try again.");
    }
    const err = new Error(`${fallback} (${status}): ${detail}`);
    err.status = status; // the local-dev fallback looks at 401/403
    throw err;
  }
};

const isLocalOtpFallbackAllowed = (req) => {
  const host = String(req.hostname || req.headers.host || "").toLowerCase();
  return (
    host.includes("localhost") ||
    host.includes("127.0.0.1") ||
    host.includes("::1")
  );
};

const pruneLocalOtpStore = () => {
  const now = Date.now();
  for (const [identifier, entry] of localOtpStore.entries()) {
    if (!entry || entry.expiresAt <= now) localOtpStore.delete(identifier);
  }
};

const createLocalOtpEntry = (identifier) => {
  pruneLocalOtpStore();
  const code = String(Math.floor(100000 + Math.random() * 900000));
  localOtpStore.set(identifier, {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  return code;
};

const verifyLocalOtpEntry = (identifier, otp) => {
  pruneLocalOtpStore();
  const entry = localOtpStore.get(identifier);
  if (!entry || entry.expiresAt <= Date.now()) {
    localOtpStore.delete(identifier);
    return false;
  }
  if (String(entry.code) !== String(otp)) return false;
  localOtpStore.delete(identifier);
  return true;
};

// jti: unique id so the token can be used for one signup only (M17).
const makeSignupOtpToken = (identifier) =>
  signToken({ identifier, jti: crypto.randomUUID() }, { audience: AUDIENCE.signupOtp, expiresInSeconds: 10 * 60 });

// M17: mark the token used, inside the caller's signup transaction. Returns
// false when it was already used. Rolling back the transaction (e.g. the email
// already exists) leaves the token usable.
async function claimSignupToken(client, payload) {
  if (!payload || !payload.jti) throw new HttpError(400, "Phone verification expired. Please verify your number again.");
  const claimed = await client.query(
    "INSERT INTO used_signup_tokens (jti) VALUES ($1) ON CONFLICT (jti) DO NOTHING RETURNING jti",
    [String(payload.jti)],
  );
  return claimed.rows.length === 1;
}

// Housekeeping: used ids are only needed while the token could still be valid.
async function pruneUsedSignupTokens(pool) {
  await pool.query("DELETE FROM used_signup_tokens WHERE used_at < NOW() - INTERVAL '1 day'");
}

// A bad, expired or mismatched token is the user's problem (400), not a
// server error (M5; it used to answer 500).
const verifySignupOtpToken = async (token, countryCode, phone) => {
  const identifier = `${String(countryCode || "+91").replace(/\D/g, "")}${String(phone || "").replace(/\D/g, "")}`;
  let payload;
  try {
    payload = await verifyToken(token, { audience: AUDIENCE.signupOtp });
  } catch (err) {
    throw new HttpError(400, "Phone verification expired. Please verify your number again.");
  }
  if (payload.identifier !== identifier) {
    throw new HttpError(400, "Phone verification does not match this phone number");
  }
  return payload;
};

module.exports = {
  isLocalOtpFallbackAllowed,
  hasTwilioVerifyConfig,
  assertTwilioConfig,
  createLocalOtpEntry,
  twilioVerifyUrl,
  twilioAuthHeader,
  assertProviderSuccess,
  verifyLocalOtpEntry,
  makeSignupOtpToken,
  verifySignupOtpToken,
  pruneUsedSignupTokens,
  claimSignupToken,
};
