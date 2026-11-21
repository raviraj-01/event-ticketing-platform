// L10: .env must be loaded before any module that reads settings at load time
// (src/services/orders.js ORDER_SETTINGS, src/services/sessions.js
// SESSION_SETTINGS). Checked statically: the test must not create a .env file.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

test("L10: server.js loads .env before requiring any other module", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const requires = [...source.matchAll(/require\("([^"]+)"\)/g)].map((match) => match[1]);
  const dotenvAt = requires.indexOf("dotenv");
  assert.ok(dotenvAt >= 0, "server.js must load dotenv");
  assert.deepEqual(requires.slice(0, dotenvAt), ["path"], "only path may be required before dotenv");
});

// H18: a developer's .env holds real credentials (database, R2, SMTP, Twilio,
// PayU). Test servers must never see them.
const { testEnv } = require("./helpers/testServer");

test("H18: test servers never inherit real-service settings and skip .env", () => {
  const parent = {
    PATH: "/bin", SystemRoot: "C:\Windows",
    DATABASE_URL: "postgres://real", JWT_SECRET: "real", R2_SECRET_ACCESS_KEY: "real", SMTP_PASS: "real",
    TWILIO_AUTH_TOKEN: "real", PAYU_SALT: "real", GOOGLE_CLIENT_ID: "real", SUPERADMIN_PASSWORD: "real",
  };
  const env = testEnv(parent, { DATABASE_URL: "postgres://test" });
  assert.equal(env.SKIP_ENV_FILE, "true");
  assert.equal(env.DATABASE_URL, "postgres://test");
  assert.equal(env.PATH, "/bin");
  for (const name of ["JWT_SECRET", "R2_SECRET_ACCESS_KEY", "SMTP_PASS", "TWILIO_AUTH_TOKEN", "PAYU_SALT", "GOOGLE_CLIENT_ID", "SUPERADMIN_PASSWORD"]) {
    assert.equal(env[name], undefined, name);
  }
});

test("H18: server.js skips .env when SKIP_ENV_FILE=true; scripts imported by tests don't load it", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  assert.match(source, /if \(process\.env\.SKIP_ENV_FILE !== "true"\) require\("dotenv"\)/);
  const report = fs.readFileSync(path.join(__dirname, "..", "scripts", "report-duplicate-phones.js"), "utf8");
  const topLevel = report.slice(0, report.indexOf("async function main"));
  assert.doesNotMatch(topLevel, /dotenv/);
});
