// Builds the Express app: global middleware, static files, then every route
// file. server.js runs migrations and starts listening; this file only wires
// things together.
const path = require("path");
const express = require("express");
const { publicDir, uploadsDir } = require("./config");
const { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests } = require("./middleware/security");
const { sendError } = require("./utils/httpError");
const { defaultBodies } = require("./middleware/bodyLimits");
const { requestId } = require("./middleware/requestId");

const app = express();
// Number of reverse proxies in front of the app (Render: 1). Needed so req.ip is
// the real client IP for rate limiting; 0 = trust nobody (local development).
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 0));

// M5: first, so every response and log line of a request carries its ID.
app.use(requestId);
app.use(corsMiddleware);
app.use(openerPolicy);
app.use(blockCrossSiteCookieRequests);
// M11: 100 KB bodies by default; the two upload routes parse their own (larger) body.
app.use(defaultBodies);
app.get("/favicon.ico", (req, res) => {
  res.type("image/svg+xml").sendFile(path.join(publicDir, "assets", "blak-ticket-logo.svg"));
});
// index:false so "/" always goes through the no-cache "/" route in routes/pages.js.
app.use(express.static(publicDir, { index: false }));
// nosniff: browsers must use the stored Content-Type and never guess that a
// file is HTML/script.
app.use("/uploads", express.static(uploadsDir, {
  setHeaders: (res) => res.setHeader("X-Content-Type-Options", "nosniff"),
}));

// Route files, in the same order the routes had in the old single file
// (Express tries routes in mount order).
app.use(require("./routes/pages"));
app.use(require("./routes/creator"));
app.use(require("./routes/staff"));
app.use(require("./routes/adminAuth"));
app.use(require("./routes/admin"));
app.use(require("./routes/orders"));
app.use(require("./routes/tickets"));
app.use(require("./routes/buyerAuth"));
app.use(require("./routes/auth"));

// M5: last stop for errors no route handled (Express 5 also sends rejected
// async handlers here). Without it Express answers with an HTML stack trace
// whenever NODE_ENV is not "production".
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid request body" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body is too large" });
  sendError(res, err, { log: `Unhandled error on ${req.method} ${req.path}` });
});

module.exports = app;
