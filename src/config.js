// Settings read once from the environment at startup, plus the folders the
// server serves files from.
const path = require("path");
const fs = require("fs");
const { configureTokens } = require("./utils/tokens");

const APP_BASE_URL = String(process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3003}`).replace(/\/+$/, "");
// Only files inside public/ are reachable from the browser. Never point
// express.static at __dirname: that would publish server.js, CLAUDE.md, etc.
const rootDir = path.join(__dirname, "..");
const publicDir = path.join(rootDir, "public");
const appHtmlPath = path.join(publicDir, "index.html");
const uploadsDir = path.join(rootDir, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

// DEMO_MODE=true: public demo deployment. Shows a "test payments only" banner
// and tells search engines not to index the site (X-Robots-Tag + robots.txt).
const DEMO_MODE = String(process.env.DEMO_MODE || "").trim().toLowerCase() === "true";

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error(
    "JWT_SECRET is missing. Add it to .env before starting the server.",
  );
  process.exit(1);
}
configureTokens(jwtSecret);
// Login sessions live in src/services/sessions.js. Purpose tokens (password
// reset, signup OTP) use signToken/verifyToken with their own audience.

module.exports = { APP_BASE_URL, DEMO_MODE, publicDir, uploadsDir, appHtmlPath };
