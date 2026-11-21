// M5: clients get a clear message for their own mistakes and a generic one
// for server errors; internal details stay in the server log.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { startTestServer, api } = require("./helpers/testServer");
const { HttpError, sendError } = require("../src/utils/httpError");
const { assertProviderSuccess } = require("../src/services/signupOtp");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

function fakeRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

test("M5: sendError shows client errors, hides internal ones", () => {
  const original = console.error;
  console.error = () => {};
  try {
    const shown = sendError(fakeRes(), new HttpError(409, "Not enough tickets", "sold_out"));
    assert.deepEqual([shown.statusCode, shown.body], [409, { error: "Not enough tickets", code: "sold_out" }]);
    const hidden = sendError(fakeRes(), new Error('relation "users" does not exist'), { message: "Could not save" });
    assert.deepEqual([hidden.statusCode, hidden.body], [500, { error: "Could not save" }]);
    const serverSide = sendError(fakeRes(), new HttpError(503, "R2 said no"), { status: 503, message: "Try later", body: { sent: false } });
    assert.deepEqual([serverSide.statusCode, serverSide.body], [503, { sent: false, error: "Try later" }]);
  } finally {
    console.error = original;
  }
});

test("M5: Twilio's own error text never reaches the user", () => {
  const original = console.warn;
  console.warn = () => {};
  try {
    const call = (status, data) => {
      try { assertProviderSuccess({ ok: status < 400, status }, data, "Twilio OTP send failed"); } catch (err) { return err; }
      return null;
    };
    const tooMany = call(429, { message: "Max send attempts reached" });
    assert.equal(tooMany.expose, true);
    assert.equal(tooMany.status, 429);
    const badNumber = call(400, { message: "Invalid parameter `To`: +91..." });
    assert.equal(badNumber.expose, true);
    assert.doesNotMatch(badNumber.message, /Invalid parameter/);
    const ourCredentials = call(401, { message: "Authenticate" });
    assert.notEqual(ourCredentials.expose, true, "a 401 from Twilio is our problem, not the user's");
    assert.equal(ourCredentials.status, 401);
  } finally {
    console.warn = original;
  }
});

test("M5: malformed JSON gets a JSON 400, not an HTML stack trace", async () => {
  const res = await fetch(`${server.baseUrl}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: '{"email": ',
  });
  assert.equal(res.status, 400);
  assert.match(res.headers.get("content-type"), /application\/json/);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), { error: "Invalid request body" });
  assert.doesNotMatch(text, /node_modules|at \w+ \(/);
});

test("M5: an invalid signup verification token is a 400, not a 500", async () => {
  const res = await api(server.baseUrl, "POST", "/signup", {
    json: { firstName: "A", email: `bad-otp-${Date.now()}@test.local`, phone: "9812345699", countryCode: "+91", password: "Buyer-pass-123", otpAccessToken: "not-a-token" },
  });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /verify your number again/);
});

test("M5: no route builds a response from a raw error message", () => {
  const dir = path.join(__dirname, "..", "src");
  const files = [];
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p); else if (p.endsWith(".js")) files.push(p);
  });
  walk(dir);
  const offenders = [];
  for (const file of files) {
    fs.readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      if (/console\.(error|warn|log)/.test(line)) return;
      // The leak patterns M5 removed: "...: ${err.message}" and "err.message || fallback".
      if (/\$\{err\.message\}|err\.message\s*\|\|/.test(line)) offenders.push(`${path.relative(dir, file)}:${i + 1}`);
    });
  }
  assert.deepEqual(offenders, []);
});
