// Browser-facing protections: CORS allowlist (H16) and the CSRF origin check
// for cookie sessions.
const { APP_BASE_URL } = require("../config");
const cors = require("cors");
const { parseCookies } = require("../utils/cookies");

// H16: only these origins may call the API from a browser with credentials.
// Default: the app's own origin + the Cordova WebView origin. Override with
// CORS_ORIGINS="https://a.example,https://b.example".
const allowedOrigins = new Set(
  String(process.env.CORS_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter(Boolean),
);
if (!allowedOrigins.size) {
  allowedOrigins.add(new URL(APP_BASE_URL).origin);
  allowedOrigins.add("https://localhost"); // Cordova Android WebView
}
const corsMiddleware = cors({
  // Requests without an Origin header (same-origin GETs, curl, PayU's
  // server-side posts) are not CORS requests and are allowed through.
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)),
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Client", "X-Session-Role"],
  optionsSuccessStatus: 204,
});

// Lets the Google sign-in popup talk back to this page.
const openerPolicy = (req, res, next) => {
  res.header("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
};

// CSRF defence for cookie sessions (on top of SameSite=Strict): a
// state-changing request that carries our session cookies must come from an
// allowed origin. Bearer-token clients (the app) are not cookie based.
const blockCrossSiteCookieRequests = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || req.headers.authorization) return next();
  const hasSessionCookie = Object.keys(parseCookies(req)).some((name) => /^(at|rt)_/.test(name));
  const origin = req.headers.origin;
  if (hasSessionCookie && origin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: "Cross-site request blocked" });
  }
  next();
};

module.exports = { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests };
