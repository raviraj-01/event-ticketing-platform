// Public, non-API routes: the app page, health check, QR image and public media
// (banners/avatars only, H14). The APK Google sign-in relay was removed (M12):
// the app sends the native plugin's Google ID token to POST /auth/google.
const express = require("express");
const { appHtmlPath } = require("../config");
const { pool } = require("../db/pool");
const { hasR2Config, presignR2 } = require("../services/storage");
const QRCode = require("qrcode");
const { rateLimit } = require("../middleware/rateLimit");

const router = express.Router();

// OPEN HTML PAGE
// Bookmarkable admin login: the app opens the sign-in form on the Admin role.
router.get("/admin", (req, res) => res.redirect("/#admin"));

router.get("/", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

router.get("/vybera_26.html", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

router.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      database: "connected",
      r2: hasR2Config() ? "configured" : "missing",
    });
  } catch (err) {
    console.error("Health check failed:", err);
    res.status(500).json({ ok: false, database: "error" });
  }
});

// L1: QR images only for staff share links (the one thing the app draws), so
// this is not a free "QR for any text" service; length-capped and rate limited.
const MAX_QR_TEXT = 512;
function isStaffShareLink(text) {
  if (!text || text.length > MAX_QR_TEXT) return false;
  try {
    const url = new URL(text);
    return (url.protocol === "https:" || url.protocol === "http:") && url.searchParams.has("staff");
  } catch (err) {
    return false;
  }
}

router.get("/qr", rateLimit({ name: "qr-ip", windowSeconds: 600, max: 60, key: (req) => req.ip }), async (req, res) => {
  try {
    const text = String((req.query && req.query.text) || "").trim();
    if (!isStaffShareLink(text)) return res.status(400).send("QR codes are only made for staff share links");
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

// Public media only (event banners, profile photos). Any other key, e.g.
// kyc-documents/..., is a 404 here (H14).
const PUBLIC_MEDIA_PREFIXES = ["event-banners/", "profiles/"];
router.get("/r2/media/*key", (req, res) => {
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

module.exports = router;
