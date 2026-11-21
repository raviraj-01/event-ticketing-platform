// Starts a throwaway real PostgreSQL (embedded-postgres) and the real
// server.js against it, for integration tests. Nothing here touches .env or
// any real account: all secrets below are test-only values.
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Pool } = require("pg");

const ROOT = path.join(__dirname, "..", "..");
const TEST_JWT_SECRET = "test-only-jwt-secret-for-integration-tests-0123456789";
const TEST_PAYU = { key: "testkey", salt: "testsalt" };

// Signs tokens exactly like the server (same jose module, same test secret).
const tokens = require("../../src/utils/tokens");
tokens.configureTokens(TEST_JWT_SECRET);
function signTestToken(payload, expiresInSeconds = 3600, audience = tokens.AUDIENCE.session) {
  return tokens.signToken(payload, { audience, expiresInSeconds });
}

const freePort = () => 20000 + Math.floor(Math.random() * 20000);

async function startTestServer() {
  const { default: EmbeddedPostgres } = await import("embedded-postgres");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ticketing-test-pg-"));
  const pgPort = freePort();
  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: "postgres",
    password: "test",
    port: pgPort,
    persistent: false,
    onLog: () => {},
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("ticketing_test");
  const databaseUrl = `postgresql://postgres:test@localhost:${pgPort}/ticketing_test`;

  const appPort = freePort();
  const baseUrl = `http://localhost:${appPort}`;
  const child = spawn(process.execPath, ["server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
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
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start:\n${output}`)), 60000);
    const check = setInterval(() => {
      if (output.includes("Server running on port")) {
        clearInterval(check); clearTimeout(timer); resolve();
      }
    }, 100);
    child.on("exit", (code) => {
      clearInterval(check); clearTimeout(timer);
      reject(new Error(`server exited with ${code}:\n${output}`));
    });
  });
  child.removeAllListeners("exit");

  const db = new Pool({ connectionString: databaseUrl, max: 5 });

  return {
    baseUrl,
    db,
    serverOutput: () => output,
    async stop() {
      child.kill();
      await db.end().catch(() => {});
      await pg.stop().catch(() => {});
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
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

module.exports = { startTestServer, signTestToken, api, TEST_PAYU };
