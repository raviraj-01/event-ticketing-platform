// M13: one password rule (8+ characters, at most 72 bytes) wherever a password
// is set; login does not check it, so existing short passwords keep working.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { startTestServer, signTestToken, api } = require("./helpers/testServer");
const tokens = require("../src/utils/tokens");
const { passwordProblem } = require("../src/utils/passwords");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

test("M13: the rule", () => {
  assert.match(passwordProblem("1234567"), /at least 8/);
  assert.equal(passwordProblem("12345678"), null);
  assert.match(passwordProblem("é".repeat(40)), /too long/, "80 bytes: bcrypt would ignore the end");
  assert.match(passwordProblem(undefined), /at least 8/);
});

test("M13: buyer signup refuses a short password (it had no minimum)", async () => {
  const otpAccessToken = await signTestToken({ identifier: "919812345690", jti: crypto.randomUUID() }, 600, tokens.AUDIENCE.signupOtp);
  const res = await api(server.baseUrl, "POST", "/signup", {
    json: { firstName: "Short", email: `short${Date.now()}@test.local`, phone: "9812345690", countryCode: "+91", password: "1234567", otpAccessToken },
  });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /at least 8/);
});

test("M13: an existing account with a short password can still log in", async () => {
  const email = `legacy${Date.now()}@test.local`;
  await server.db.query(
    "INSERT INTO users (username, first_name, email, password) VALUES ('Old', 'Old', $1, $2)",
    [email, await bcrypt.hash("abc123", 4)],
  );
  const res = await api(server.baseUrl, "POST", "/login", { json: { email, password: "abc123" } });
  assert.equal(res.status, 200, JSON.stringify(res.body));
});

test("M6: unknown account and wrong password get the same answer; Google-only accounts are a 401, not an error", async () => {
  const email = `known${Date.now()}@test.local`;
  await server.db.query(
    "INSERT INTO users (username, first_name, email, password) VALUES ('K', 'K', $1, $2)",
    [email, await bcrypt.hash("Right-pass-1", 4)],
  );
  const google = `google${Date.now()}@test.local`;
  await server.db.query(
    "INSERT INTO users (username, first_name, email, password, auth_provider) VALUES ('G', 'G', $1, 'oauth-provider', 'google')",
    [google],
  );
  const login = (id, password) => api(server.baseUrl, "POST", "/login", { json: { email: id, password } });
  const unknown = await login(`nobody${Date.now()}@test.local`, "Whatever-1");
  const wrong = await login(email, "Wrong-pass-1");
  const googleOnly = await login(google, "Whatever-1");
  assert.equal(unknown.status, 401);
  assert.deepEqual([wrong.status, wrong.body], [unknown.status, unknown.body]);
  assert.deepEqual([googleOnly.status, googleOnly.body], [unknown.status, unknown.body]);
});
