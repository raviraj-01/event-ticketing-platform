// Signed tokens (JWT, HS256) via the maintained `jose` library (L4).
//
// Every token has an issuer and an AUDIENCE that says what it is for. A token
// is only accepted where its audience matches, so e.g. a password-reset token
// can never be used as a login session (before, only a `scope` field in the
// payload separated them).
const { SignJWT, jwtVerify } = require("jose");

const ISSUER = "ticketing-app";
const AUDIENCE = {
  session: "session",
  passwordReset: "password-reset",
  signupOtp: "signup-otp",
};

let secretKey = null;

function configureTokens(secret) {
  if (!secret) throw new Error("JWT secret is required");
  secretKey = new TextEncoder().encode(secret);
}

async function signToken(payload, { audience, expiresInSeconds }) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload };
  if (claims.sub !== undefined) claims.sub = String(claims.sub); // JWT "sub" must be a string
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + expiresInSeconds)
    .sign(secretKey);
}

// Throws if the signature, issuer, audience, algorithm or expiry is wrong.
async function verifyToken(token, { audience }) {
  const { payload } = await jwtVerify(String(token || ""), secretKey, {
    issuer: ISSUER,
    audience,
    algorithms: ["HS256"],
  });
  return payload;
}

module.exports = { AUDIENCE, configureTokens, signToken, verifyToken };
