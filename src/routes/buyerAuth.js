// Buyer accounts: signup OTP, signup, Google sign-in, password login.
const express = require("express");
const { OAuth2Client } = require("google-auth-library");
const {
  otpDevMode,
  hasTwilioVerifyConfig,
  assertTwilioConfig,
  createLocalOtpEntry,
  twilioVerifyUrl,
  twilioAuthHeader,
  assertProviderSuccess,
  verifyLocalOtpEntry,
  makeSignupOtpToken,
  verifySignupOtpToken,
  claimSignupToken,
} = require("../services/signupOtp");
const { verifyToken, AUDIENCE } = require("../utils/tokens");
const { rateLimit } = require("../middleware/rateLimit");
const bcrypt = require("bcrypt");
const { pool } = require("../db/pool");
const { isUserActive } = require("../utils/accounts");
const { USER_NOT_FOUND_ERROR, publicUser } = require("../utils/serializers");
const { startSession } = require("../services/sessions");
const { requireBuyer } = require("../middleware/auth");
const { payablePhone } = require("../services/orders");
const { sendError, HttpError } = require("../utils/httpError");
const { passwordProblem, DUMMY_PASSWORD_HASH, isBcryptHash } = require("../utils/passwords");

const router = express.Router();

const googleClientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
const googleOAuthClient = googleClientId ? new OAuth2Client(googleClientId) : null;

const sendSignupOtp = async (req, res) => {
  try {
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    if (!/^91\d{10}$/.test(identifier)) {
      return res.status(400).json({ error: "A valid India mobile number with country code is required" });
    }
    // Development without Twilio: only with OTP_DEV_MODE=true (M7).
    if (!hasTwilioVerifyConfig()) {
      if (!otpDevMode()) {
        assertTwilioConfig();
      }
      const devOtp = createLocalOtpEntry(identifier);
      return res.json({
        sent: true,
        identifier,
        provider: "local-dev",
        devOtp,
        data: { status: "pending", channel: "local-dev" },
      });
    }
    const params = new URLSearchParams({
      To: `+${identifier}`,
      Channel: process.env.TWILIO_VERIFY_CHANNEL || "sms",
    });
    const response = await fetch(twilioVerifyUrl("s"), {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });
    const data = await response.json().catch(() => ({}));
    assertProviderSuccess(response, data, "Twilio OTP send failed");
    res.json({ sent: true, identifier, data });
  } catch (err) {
    // M7: a Twilio error never switches to the development code.
    sendError(res, err, { status: 503, message: "OTP service is unavailable. Please try again later.", log: "Twilio OTP send failed", body: { sent: false } });
  }
};

const verifySignupOtp = async (req, res) => {
  try {
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    const otp = String((req.body && req.body.otp) || "").trim();
    if (!/^91\d{10}$/.test(identifier) || !/^\d{4,8}$/.test(otp)) {
      return res.status(400).json({ verified: false, error: "A valid mobile number and OTP are required" });
    }
    if (verifyLocalOtpEntry(identifier, otp)) {
      return res.json({
        verified: true,
        accessToken: await makeSignupOtpToken(identifier),
        data: { status: "approved", channel: "local-dev" },
      });
    }
    assertTwilioConfig();
    const params = new URLSearchParams({ To: `+${identifier}`, Code: otp });
    const response = await fetch(twilioVerifyUrl("Check"), {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });
    const data = await response.json().catch(() => ({}));
    assertProviderSuccess(response, data, "Twilio OTP verification failed");
    if (data.status !== "approved" && !data.valid) {
      return res.status(400).json({ verified: false, error: "Invalid OTP. Try again.", data });
    }
    res.json({ verified: true, accessToken: await makeSignupOtpToken(identifier), data });
  } catch (err) {
    sendError(res, err, { status: 503, message: "OTP service is unavailable. Please try again later.", log: "Twilio OTP verification failed", body: { verified: false } });
  }
};

const verifySignupOtpAccessToken = async (req, res) => {
  try {
    const accessToken = String(
      (req.body && (req.body.accessToken || req.body["access-token"])) || "",
    ).trim();
    if (!accessToken) {
      return res.status(400).json({ verified: false, error: "OTP access token is required" });
    }
    let payload;
    try {
      payload = await verifyToken(accessToken, { audience: AUDIENCE.signupOtp });
    } catch (verifyErr) {
      return res.status(400).json({ verified: false, error: "Invalid OTP token" });
    }
    res.json({ verified: true, data: payload });
  } catch (err) {
    sendError(res, err, { message: "OTP token verification failed", log: "OTP token verification failed", body: { verified: false } });
  }
};

// Every OTP costs an SMS, so sending is limited per phone and per IP (H3).
// (The unused /otp/msg91/* aliases were removed.)
const otpPhoneKey = (req) => String((req.body && req.body.identifier) || "").replace(/\D/g, "") || null;
router.post(
  "/otp/twilio/send",
  rateLimit({ name: "otp-send-phone", windowSeconds: 600, max: 3, key: otpPhoneKey,
    message: "Too many OTP requests for this number. Please wait a few minutes." }),
  rateLimit({ name: "otp-send-ip", windowSeconds: 3600, max: 10, key: (req) => req.ip,
    message: "Too many OTP requests. Please try again later." }),
  sendSignupOtp,
);
router.post(
  "/otp/twilio/verify",
  rateLimit({ name: "otp-verify-phone", windowSeconds: 600, max: 10, key: otpPhoneKey,
    message: "Too many attempts. Request a new OTP in a few minutes." }),
  verifySignupOtp,
);
router.post("/otp/twilio/verify-token", verifySignupOtpAccessToken);

// SIGNUP API
router.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, username, email, phone, countryCode, city, password, otpAccessToken } = req.body;
    const cleanFirstName = String(firstName || username || "").trim();
    const cleanLastName = String(lastName || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPhone = String(phone || "").trim();
    const cleanCountryCode = String(countryCode || "+91").trim();
    const cleanCity = String(city || "").trim();
    if (!cleanFirstName || !cleanEmail || !password) {
      return res.status(400).json({ error: "First name, email, and password are required" });
    }
    if (!cleanPhone) {
      return res.status(400).json({ error: "Phone number is required" });
    }
    // M13: buyer signup had no minimum at all.
    const signupPasswordProblem = passwordProblem(String(password));
    if (signupPasswordProblem) return res.status(400).json({ error: signupPasswordProblem });
    if (!otpAccessToken) {
      return res.status(400).json({ error: "Please verify your phone number with OTP before creating an account" });
    }
    const otpPayload = await verifySignupOtpToken(otpAccessToken, cleanCountryCode, cleanPhone);
    // Q12 / D23: one buyer account per verified phone. phone_key() (migration
    // 0012) treats "98765 43210" and "+919876543210" as the same number.
    const phoneTaken = await pool.query(
      "SELECT 1 FROM users WHERE verified_phone_key(phone_verified, country_code, phone) = phone_key($1, $2) LIMIT 1",
      [cleanCountryCode, cleanPhone],
    );
    if (phoneTaken.rows.length) {
      return res.status(409).json({ error: "An account with this phone number already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const displayName = [cleanFirstName, cleanLastName].filter(Boolean).join(" ");
    // One transaction: use up the verification token (M17) and create the
    // account. If the insert fails, the token is not used up.
    const client = await pool.connect();
    let result;
    try {
      await client.query("BEGIN");
      if (!(await claimSignupToken(client, otpPayload))) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "This phone verification was already used. Please verify your number again." });
      }
      // The OTP above proved this phone, so it is stored as verified.
      result = await client.query(
        `INSERT INTO users (username, first_name, last_name, email, phone, country_code, city, password, phone_verified)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
        RETURNING id, username, first_name, last_name, email, phone, country_code, city, created_at`,
        [displayName || cleanFirstName, cleanFirstName, cleanLastName, cleanEmail, cleanPhone, cleanCountryCode, cleanCity, hashedPassword],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
    res.json({ message: "Signup successful", user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    sendError(res, err, { message: "Signup failed", log: "Signup failed" });
  }
});

router.get("/auth/google/client-config", (req, res) => {
  res.json({ clientId: googleClientId || "" });
});

async function upsertGoogleBuyer({ name, email, photoURL }) {
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanName = String(name || "Google User").trim() || "Google User";
  if (!cleanEmail) {
    throw new HttpError(400, "Google account did not return an email address");
  }
  const parts = cleanName.split(/\s+/);
  const firstName = parts.shift() || cleanName;
  const lastName = parts.join(" ");
  const existing = await pool.query(
    "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
    [cleanEmail],
  );
  if (existing.rows.length && !isUserActive(existing.rows[0].status)) {
    throw new HttpError(404, USER_NOT_FOUND_ERROR);
  }
  const upsert = await pool.query(
    `INSERT INTO users (username, first_name, last_name, email, password, auth_provider, profile_image_url)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT (email) DO UPDATE SET
      username=EXCLUDED.username,
      first_name=EXCLUDED.first_name,
      last_name=EXCLUDED.last_name,
      auth_provider=EXCLUDED.auth_provider,
      profile_image_url=COALESCE(users.profile_image_url, EXCLUDED.profile_image_url)
    RETURNING id, username, first_name, last_name, email, phone, country_code, city,
      profile_image_url, profile_image_key, profile_image_storage, auth_provider, status`,
    [cleanName, firstName, lastName, cleanEmail, "oauth-provider", "google", photoURL || ""],
  );
  return upsert.rows[0];
}

router.post("/auth/google", async (req, res) => {
  try {
    if (!googleOAuthClient) {
      return res.status(500).json({ error: "Google login is not configured. Add GOOGLE_CLIENT_ID to .env and restart the server." });
    }
    const credential = String((req.body && req.body.credential) || "").trim();
    if (!credential) {
      return res.status(400).json({ error: "Google credential is required" });
    }
    // Checks Google's signature, expiry, issuer and that the token was issued
    // for OUR client ID. A forged or foreign token is a 401, not a 500.
    let payload;
    try {
      const ticket = await googleOAuthClient.verifyIdToken({
        idToken: credential,
        audience: googleClientId,
      });
      payload = ticket.getPayload() || {};
    } catch (verifyErr) {
      console.error("Google ID token rejected:", verifyErr.message);
      return res.status(401).json({ error: "Google sign-in could not be verified" });
    }
    if (!payload.email || payload.email_verified !== true) {
      return res.status(400).json({ error: "Google account email is not verified" });
    }
    const user = await upsertGoogleBuyer({
      name: payload.name || payload.email,
      email: payload.email,
      photoURL: payload.picture || "",
    });
    res.json({
      message: "Login successful",
      user: publicUser(user),
      ...(await startSession(pool, req, res, { role: "buyer", accountId: user.id })),
    });
  } catch (err) {
    sendError(res, err, { message: "Google login failed", log: "Google login failed" });
  }
});

// Q14 / D24: buyers without a phone (Google sign-in) add one before their
// first paid checkout. Saved unverified: it is a contact number for PayU, not
// a login name, and it never replaces a phone that was verified by OTP.
router.put("/profile/phone", requireBuyer, async (req, res) => {
  try {
    const phone = payablePhone(req.body && req.body.phone);
    if (!phone) return res.status(400).json({ error: "Enter a valid 10-digit mobile number" });
    const result = await pool.query(
      `UPDATE users SET phone=$2, country_code='+91', phone_verified=FALSE
       WHERE id=$1 AND verified_phone_key(phone_verified, country_code, phone) IS NULL
       RETURNING id, username, first_name, last_name, email, phone, country_code, city,
         profile_image_url, profile_image_key, profile_image_storage, status`,
      [req.buyer.sub, phone],
    );
    if (!result.rows.length) return res.status(409).json({ error: "Your verified phone number cannot be changed here" });
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error("Saving phone failed:", err);
    res.status(500).json({ error: "Could not save phone number" });
  }
});

// LOGIN API
// L13: buyer login had no limit at all (organizer and admin login did).
// Per IP, and per email/phone so one account can't be guessed from many IPs.
const buyerLoginLimits = [
  rateLimit({ name: "buyer-login-ip", windowSeconds: 600, max: 20, key: (req) => req.ip }),
  rateLimit({
    name: "buyer-login-id",
    windowSeconds: 600,
    max: 10,
    key: (req) => String((req.body && req.body.email) || "").trim().toLowerCase() || null,
    message: "Too many login attempts. Please try again later.",
  }),
];
router.post("/login", ...buyerLoginLimits, async (req, res) => {
  try {
    const { email, password } = req.body;
    const identifier = String(email || "").trim();
    const cleanEmail = identifier.toLowerCase();
    const phoneDigits = identifier.replace(/\D/g, "");
    const cleanPhone = /^[+\d\s()-]+$/.test(identifier) && /^\d{10,12}$/.test(phoneDigits)
      ? phoneDigits
      : "";
    if (!identifier || !password) {
      return res.status(400).json({ error: "Email or phone and password are required" });
    }
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, password, status
      FROM users
      WHERE LOWER(email)=LOWER($1)
        -- Only an OTP-verified phone is a login name (Q14 phones are unverified).
        OR ($2 <> '' AND verified_phone_key(phone_verified, country_code, phone) IS NOT NULL AND (
          REGEXP_REPLACE(COALESCE(country_code,'') || COALESCE(phone,''), '\\D', '', 'g')=$2
          OR REGEXP_REPLACE(COALESCE(phone,''), '\\D', '', 'g')=RIGHT($2,10)
        ))
      ORDER BY created_at DESC`,
      [cleanEmail, cleanPhone],
    );
    // M6: one answer whether the account is unknown or the password is
    // wrong, and the same bcrypt work in both cases, so neither the message
    // nor the timing reveals which emails / phones have accounts.
    let user = null;
    if (!result.rows.length) {
      await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
    }
    for (const candidate of result.rows) {
      if (isBcryptHash(candidate.password) && (await bcrypt.compare(password, candidate.password))) {
        user = candidate;
        break;
      }
    }
    if (!user) {
      return res.status(401).json({ error: "Invalid email/phone or password" });
    }
    if (!isUserActive(user.status)) {
      return res.status(404).json({ error: USER_NOT_FOUND_ERROR });
    }
    res.json({
      message: "Login successful",
      user: publicUser(user),
      ...(await startSession(pool, req, res, { role: "buyer", accountId: user.id })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

module.exports = router;
