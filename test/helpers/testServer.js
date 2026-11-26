// Starts a throwaway real PostgreSQL (embedded-postgres) and the real
// server.js against it, for integration tests. Nothing here touches .env or
// any real account: all secrets below are test-only values, the inherited
// environment is stripped of real-service variables and the server is told
// not to read .env (H18).
// Every process started here is tracked by processGuard.js, so it is stopped
// however the test process ends (after() hook, crash, Ctrl+C or hard kill).
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Pool } = require("pg");
const guard = require("./processGuard");

const ROOT = path.join(__dirname, "..", "..");
const TEST_JWT_SECRET = "test-only-jwt-secret-for-integration-tests-0123456789";
const TEST_PAYU = { key: "testkey", salt: "testsalt" };

// Signs tokens exactly like the server (same jose module, same test secret).
const tokens = require("../../src/utils/tokens");
tokens.configureTokens(TEST_JWT_SECRET);
// Session tokens carry tv (token_version); new accounts start at 0.
function signTestToken(payload, expiresInSeconds = 3600, audience = tokens.AUDIENCE.session) {
  const claims = audience === tokens.AUDIENCE.session && payload.tv === undefined ? { ...payload, tv: 0 } : payload;
  return tokens.signToken(claims, { audience, expiresInSeconds });
}

const freePort = () => 20000 + Math.floor(Math.random() * 20000);

// H18: anything that could point a test server at a real service. Removed
// from the inherited environment; the server also skips .env (SKIP_ENV_FILE).
const REAL_SERVICE_VARS = /^(DATABASE_URL|JWT_SECRET|APP_BASE_URL|CORS_ORIGINS|PAYU_|TWILIO_|SMTP_|R2_|GOOGLE_|SUPERADMIN_|PGHOST|PGUSER|PGPASSWORD|PGDATABASE|PGPORT)/;

function testEnv(parentEnv, overrides) {
  const base = Object.fromEntries(Object.entries(parentEnv).filter(([name]) => !REAL_SERVICE_VARS.test(name)));
  return { ...base, ...overrides, SKIP_ENV_FILE: "true" };
}

// Start server.js against an existing database (used by startTestServer, and
// by tests that need a second boot on the same database).
async function startApp(databaseUrl, extraEnv = {}) {
  const appPort = freePort();
  const baseUrl = `http://localhost:${appPort}`;
  // The marker lets the watchdog find this server if the test process is hard-killed.
  const marker = `--test-instance=${crypto.randomBytes(8).toString("hex")}`;
  const guardId = guard.track({ marker });
  const child = spawn(process.execPath, ["server.js", marker], {
    cwd: ROOT,
    env: testEnv(process.env, {
      NODE_ENV: "test",
      PORT: String(appPort),
      APP_BASE_URL: baseUrl,
      DATABASE_URL: databaseUrl,
      JWT_SECRET: TEST_JWT_SECRET,
      PAYU_KEY: TEST_PAYU.key,
      PAYU_SALT: TEST_PAYU.salt,
      PAYU_ENV: "test",
      SUPERADMIN_PASSWORD: "",
      TWILIO_ACCOUNT_SID: "",
      SMTP_HOST: "",
      SMTP_SERVICE: "",
      // Admin login code and signup OTP are returned in the response (dev
      // mode, never in production).
      ADMIN_OTP_DEV_MODE: "true",
      OTP_DEV_MODE: "true",
      ...extraEnv,
    }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  guard.trackChild(child);
  const stop = () => {
    child.kill();
    guard.untrack(guardId);
  };
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  try {
    await new Promise((resolve, reject) => {
      const onExit = (code) => {
        clearInterval(check); clearTimeout(timer);
        reject(new Error(`server exited with ${code}:\n${output}`));
      };
      const timer = setTimeout(() => {
        clearInterval(check); child.off("exit", onExit);
        reject(new Error(`server did not start:\n${output}`));
      }, 60000);
      const check = setInterval(() => {
        if (output.includes("Server running on port")) {
          clearInterval(check); clearTimeout(timer); child.off("exit", onExit); resolve();
        }
      }, 100);
      child.on("exit", onExit);
    });
  } catch (err) {
    stop(); // a server that never came up must not keep running
    throw err;
  }
  return { baseUrl, output: () => output, stop };
}

async function startTestServer(extraEnv = {}) {
  const { default: EmbeddedPostgres } = await import("embedded-postgres");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ticketing-test-pg-"));
  // Registered before Postgres starts: its command line carries the data directory.
  const guardId = guard.track({ marker: path.basename(dataDir), dir: dataDir });
  const pgPort = freePort();
  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: "postgres",
    password: "test",
    port: pgPort,
    persistent: false,
    onLog: () => {},
  });
  const databaseUrl = `postgresql://postgres:test@localhost:${pgPort}/ticketing_test`;
  let app = null;
  let db = null;
  const stopAll = async () => {
    if (app) app.stop();
    if (db) await db.end().catch(() => {});
    await pg.stop().catch(() => {});
    fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    guard.untrack(guardId);
  };
  try {
    await pg.initialise();
    await pg.start();
    if (pg.process) guard.trackChild(pg.process);
    await pg.createDatabase("ticketing_test");
    app = await startApp(databaseUrl, extraEnv);
    db = new Pool({ connectionString: databaseUrl, max: 5 });
  } catch (err) {
    await stopAll(); // e.g. the app failed to boot: Postgres must not be left running
    throw err;
  }

  return {
    baseUrl: app.baseUrl,
    databaseUrl,
    dataDir,
    db,
    serverOutput: app.output,
    stop: stopAll,
  };
}

// Small fetch wrapper: returns { status, body, headers }.
async function api(baseUrl, method, urlPath, { token, json, form } = {}) {
  const headers = {};
  let body;
  if (token) headers.Authorization = `Bearer ${token}`;
  if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  if (form !== undefined) { headers["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(form).toString(); }
  const res = await fetch(baseUrl + urlPath, { method, headers, body, redirect: "manual" });
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch (_) { /* not JSON */ }
  return { status: res.status, body: parsed, headers: res.headers };
}

module.exports = { startTestServer, startApp, signTestToken, api, TEST_PAYU, testEnv };
