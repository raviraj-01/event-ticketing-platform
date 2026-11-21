// Builds the Express app: global middleware, static files, then every route
// file. server.js runs migrations and starts listening; this file only wires
// things together.
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const { publicDir, uploadsDir } = require("./config");
const { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests } = require("./middleware/security");

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

module.exports = app;
