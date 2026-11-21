// Builds vybera-cordova/www/ from the single frontend source in public/.
//
// Usage:  CORDOVA_API_BASE=https://your-backend.example.com npm run build:cordova
//         then: cd vybera-cordova && npx cordova build android
//
// What it does:
//   1. Copies public/ (index.html, firebaseconfig.js, assets/) into vybera-cordova/www/.
//   2. In index.html, replaces the CORDOVA_HEAD_INJECT marker with cordova.js and
//      the API base URL (the APK loads from file://, so it must call the backend by URL).
//   3. Enables the app-only <style data-platform="app"> blocks (media="not all" -> "all").
// www/ is generated output: never edit it by hand, edit public/ instead.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const publicDir = path.join(root, "public");
const wwwDir = path.join(root, "vybera-cordova", "www");

const apiBase = String(process.env.CORDOVA_API_BASE || "").trim().replace(/\/+$/, "");
if (!/^https:\/\/[^\s'"<>]+$/.test(apiBase)) {
  console.error("Set CORDOVA_API_BASE to your backend's https URL, e.g. CORDOVA_API_BASE=https://my-app.onrender.com");
  process.exit(1);
}

const MARKER = "<!-- CORDOVA_HEAD_INJECT: replaced by scripts/build-cordova.js -->";
const APP_STYLE_OFF = '<style data-platform="app" media="not all">';
const APP_STYLE_ON = '<style data-platform="app" media="all">';

let html = fs.readFileSync(path.join(publicDir, "index.html"), "utf8");
if (!html.includes(MARKER)) {
  console.error("CORDOVA_HEAD_INJECT marker not found in public/index.html");
  process.exit(1);
}
html = html.replace(
  MARKER,
  `<script src="cordova.js"></script>\n<script>window.VYBERA_API_BASE=${JSON.stringify(apiBase)};</script>`,
);
html = html.split(APP_STYLE_OFF).join(APP_STYLE_ON);

// Replace only the files this script owns; leave anything else in www/ alone.
fs.mkdirSync(wwwDir, { recursive: true });
fs.rmSync(path.join(wwwDir, "assets"), { recursive: true, force: true });
fs.cpSync(path.join(publicDir, "assets"), path.join(wwwDir, "assets"), { recursive: true });
fs.copyFileSync(path.join(publicDir, "firebaseconfig.js"), path.join(wwwDir, "firebaseconfig.js"));
fs.writeFileSync(path.join(wwwDir, "index.html"), html);

console.log(`Built ${path.relative(root, wwwDir)} (API base ${apiBase})`);
