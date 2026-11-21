// L10: load .env before requiring anything else. Some modules read their
// settings (fee %, token lifetimes, ...) at load time.
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const express = require("express");
const bodyParser = require("body-parser");
const QRCode = require("qrcode");
const { runMigrations } = require("./src/db/migrate");
const { pruneRateLimitHits } = require("./src/middleware/rateLimit");
const { expireStaleOrders } = require("./src/services/orders");
const { pool, dbSsl } = require("./src/db/pool");
const { initDb } = require("./src/db/initDb");
const { publicDir, uploadsDir, appHtmlPath } = require("./src/config");
const { hasR2Config, presignR2 } = require("./src/services/storage");
const { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests } = require("./src/middleware/security");

process.on("unhandledRejection", (err) => {
  console.error("Unhandled async error:", err);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught server error:", err);
});

const app = express();
// Number of reverse proxies in front of the app (Render: 1). Needed so req.ip is
// the real client IP for rate limiting; 0 = trust nobody (local development).
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 0));

app.use(corsMiddleware);
app.use(openerPolicy);
app.use(blockCrossSiteCookieRequests);
app.use(bodyParser.json({ limit: "30mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.get("/favicon.ico", (req, res) => {
  res.type("image/svg+xml").sendFile(path.join(publicDir, "assets", "blak-ticket-logo.svg"));
});
// index:false so "/" always goes through the no-cache route below.
app.use(express.static(publicDir, { index: false }));
// nosniff: browsers must use the stored Content-Type and never guess that a
// file is HTML/script.
app.use("/uploads", express.static(uploadsDir, {
  setHeaders: (res) => res.setHeader("X-Content-Type-Options", "nosniff"),
}));












// ─── GOOGLE TOKEN RELAY ────────────────────────────────────────────────────────
// Used by the Android APK to do Google Sign-in via the system browser.
// Flow: app generates a `code`, opens system browser → user signs in → web page
// POSTs the JWT to /google-token/store?code=XYZ → app polls /google-token/fetch?code=XYZ
const googleTokenStore = new Map(); // code → { token, profile, createdAt }

// Clean up tokens older than 5 minutes every minute
setInterval(() => {
  const now = Date.now();
  for (const [code, val] of googleTokenStore) {
    if (now - val.createdAt > 5 * 60 * 1000) googleTokenStore.delete(code);
  }
}, 60 * 1000);

app.post("/google-token/store", (req, res) => {
  const code = String(req.query.code || "").trim();
  if (!code || code.length < 8) return res.status(400).json({ error: "Invalid code" });
  const { token, profile } = req.body || {};
  if (!token || !profile) return res.status(400).json({ error: "token and profile required" });
  googleTokenStore.set(code, { token, profile, createdAt: Date.now() });
  res.json({ ok: true });
});

app.get("/google-token/fetch", (req, res) => {
  const code = String(req.query.code || "").trim();
  if (!code) return res.status(400).json({ error: "Missing code" });
  const entry = googleTokenStore.get(code);
  if (!entry) return res.json({ ready: false });
  googleTokenStore.delete(code); // consume once
  res.json({ ready: true, token: entry.token, profile: entry.profile });
});

// Standalone Google login success page (shown in system browser after OAuth)
app.get("/google-auth-success", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed In - BLAK Tickets</title>
<style>
  body{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;
       background:#0a0a0a;font-family:sans-serif;color:#fff;flex-direction:column;gap:16px}
  .icon{font-size:64px}
  h2{margin:0;font-size:22px}
  p{margin:0;color:#aaa;font-size:14px;text-align:center}
</style></head><body>
<div class="icon">✅</div>
<h2>Signed in successfully!</h2>
<p>You can close this tab and return to BLAK Tickets.</p>
</body></html>`);
});

// OPEN HTML PAGE
app.get("/", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

app.get("/vybera_26.html", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      database: "connected",
      r2: hasR2Config() ? "configured" : "missing",
    });
  } catch (err) {
    res.status(500).json({ ok: false, database: "error", error: err.message });
  }
});

app.get("/qr", async (req, res) => {
  try {
    const text = String((req.query && req.query.text) || "").trim();
    if (!text) return res.status(400).send("Missing QR text");
    const png = await QRCode.toBuffer(text, {
      width: 420,
      margin: 2,
      errorCorrectionLevel: "M",
    });
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(png);
  } catch (err) {
    console.error("QR generation failed:", err);
    res.status(500).send("Could not generate QR");
  }
});

app.use(require("./src/routes/creator"));

app.use(require("./src/routes/staff"));


app.use(require("./src/routes/adminAuth"));

app.use(require("./src/routes/admin"));

// Public media only (event banners, profile photos). Any other key, e.g.
// kyc-documents/..., is a 404 here (H14).
const PUBLIC_MEDIA_PREFIXES = ["event-banners/", "profiles/"];
app.get("/r2/media/*key", (req, res) => {
  try {
    const key = Array.isArray(req.params.key)
      ? req.params.key.join("/")
      : req.params.key;
    if (!key || key.includes("..") || !PUBLIC_MEDIA_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      return res.status(404).send("Not found");
    }
    res.redirect(presignR2({ method: "GET", key, expires: 300 }));
  } catch (err) {
    console.error("R2 media redirect failed:", err);
    res.status(500).send("Media unavailable");
  }
});


app.use(require("./src/routes/orders"));



app.use(require("./src/routes/tickets"));

app.use(require("./src/routes/buyerAuth"));

app.use(require("./src/routes/auth"));

// Startup order: schema migrations → data fix-ups → accept requests.
// Listening only after migrations means no request can hit a missing table.
const PORT = process.env.PORT || 3003;
async function start() {
  await runMigrations({ connectionString: process.env.DATABASE_URL, ssl: dbSsl });
  await initDb();
  // Housekeeping every 5 minutes (correctness never depends on it).
  setInterval(() => {
    expireStaleOrders(pool).catch((err) => console.error("Order expiry failed:", err.message));
    pruneRateLimitHits(pool).catch((err) => console.error("Rate-limit prune failed:", err.message));
  }, 5 * 60 * 1000).unref();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Server startup failed:", err);
  process.exit(1);
});
