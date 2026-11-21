// Entry point: load .env, run migrations and data fix-ups, then listen.
// The app itself is built in src/app.js.
// L10: load .env before requiring anything else. Some modules read their
// settings (fee %, token lifetimes, ...) at load time.
// H18: the test helper sets SKIP_ENV_FILE so a developer's .env (real
// database, R2, SMTP, Twilio, PayU) can never leak into a test server.
const path = require("path");
if (process.env.SKIP_ENV_FILE !== "true") require("dotenv").config({ path: path.join(__dirname, ".env") });
const { runMigrations } = require("./src/db/migrate");
const { pool, dbSsl } = require("./src/db/pool");
const { initDb } = require("./src/db/initDb");
const { pruneRateLimitHits } = require("./src/middleware/rateLimit");
const { expireStaleOrders } = require("./src/services/orders");
const app = require("./src/app");

// A stray rejected promise is logged; request handlers' own errors go to the
// error handler in src/app.js.
process.on("unhandledRejection", (err) => {
  console.error("Unhandled async error:", err);
});

// M5: after an uncaught exception the process may be in a broken state, so
// log it and exit; the host (Render) starts a fresh one.
process.on("uncaughtException", (err) => {
  console.error("Uncaught server error, exiting:", err);
  process.exit(1);
});

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
