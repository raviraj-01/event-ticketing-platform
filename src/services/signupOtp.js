// Signup phone verification: Twilio Verify, a local-development fallback
// (M7), and the short-lived token that proves a phone was verified.
const { signToken, AUDIENCE, verifyToken } = require("../utils/tokens");

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

const assertTwilioConfig = () => {
  if (!hasTwilioVerifyConfig()) {
    const err = new Error(
      "OTP service is not configured. Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID to .env, then restart the server.",
    );
    err.status = 500;
    throw err;
  }
};

const assertProviderSuccess = (response, data, fallback) => {
  if (!response.ok || data.error || data.error_message) {
    const err = new Error(providerErrorMessage(data, fallback));
    err.status = response.ok ? 400 : response.status;
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

const makeSignupOtpToken = (identifier) =>
  signToken({ identifier }, { audience: AUDIENCE.signupOtp, expiresInSeconds: 10 * 60 });

const verifySignupOtpToken = async (token, countryCode, phone) => {
  const identifier = `${String(countryCode || "+91").replace(/\D/g, "")}${String(phone || "").replace(/\D/g, "")}`;
  try {
    const payload = await verifyToken(token, { audience: AUDIENCE.signupOtp });
    if (payload.identifier !== identifier) {
      throw new Error("OTP verification does not match this phone number");
    }
    return payload;
  } catch (err) {
    throw err;
  }
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
};
