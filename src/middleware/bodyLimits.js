// M11: request bodies are small by default (100 KB). Files arrive base64-
// encoded inside JSON, so the two upload routes need more; they skip the
// default parser here and parse their large body themselves, only AFTER their
// own checks (login for the banner, rate limit for the public application),
// so nobody can make the server read megabytes without passing those first.
const bodyParser = require("body-parser");

const UPLOAD_PATHS = new Set(["/creator/applications", "/creator/events/banner"]);
const smallJson = bodyParser.json({ limit: "100kb" });
const smallForm = bodyParser.urlencoded({ extended: true, limit: "100kb" });

function defaultBodies(req, res, next) {
  if (UPLOAD_PATHS.has(req.path)) return next();
  smallJson(req, res, (err) => (err ? next(err) : smallForm(req, res, next)));
}

// For an upload route, placed after its auth / rate-limit middleware.
const uploadJson = (limit) => bodyParser.json({ limit });

module.exports = { defaultBodies, uploadJson, UPLOAD_PATHS };
