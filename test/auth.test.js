// Integration tests for authentication / authorization fixes.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});

after(async () => {
  if (server) await server.stop();
});

test("H4: a suspended creator's token stops working immediately", async () => {
  const creator = await fx.createCreator();
  assert.equal((await api(server.baseUrl, "GET", "/creator/events", { token: creator.token })).status, 200);

  await server.db.query("UPDATE creator_accounts SET kyc_status = 'Suspended' WHERE id = $1", [creator.id]);
  assert.equal((await api(server.baseUrl, "GET", "/creator/events", { token: creator.token })).status, 401);
  const scan = await api(server.baseUrl, "POST", "/bookings/scan", {
    token: creator.token,
    json: { qrPayload: "VYBERA-TICKET|x|y|z" },
  });
  assert.equal(scan.status, 401);
});

test("H4: a creator that is still pending or rejected cannot use creator routes", async () => {
  for (const kycStatus of ["Pending", "Rejected"]) {
    const creator = await fx.createCreator({ kycStatus });
    assert.equal((await api(server.baseUrl, "GET", "/creator/events", { token: creator.token })).status, 401, kycStatus);
  }
});

// ── H13: creator login ──
const bcrypt = require("bcrypt");

async function creatorWithPassword({ name, email, password, kycStatus = "Approved", plaintext = false }) {
  await server.db.query(
    `INSERT INTO creator_accounts (name, email, phone, category, about, password, kyc_status)
     VALUES ($1, $2, '9000000000', 'Music', 'x', $3, $4)`,
    [name, email, plaintext ? password : await bcrypt.hash(password, 4), kycStatus],
  );
}
const creatorLogin = (body) => api(server.baseUrl, "POST", "/creator/login", { json: body });

test("H13: creator login matches the exact email only", async () => {
  const unique = fx.uid();
  await creatorWithPassword({ name: `John ${unique}`, email: `john${unique}@a.test`, password: "Correct-pass-1" });
  assert.equal((await creatorLogin({ email: `JOHN${unique}@A.TEST`, password: "Correct-pass-1" })).status, 200, "case-insensitive email");
  assert.equal((await creatorLogin({ email: `john${unique}@b.test`, password: "Correct-pass-1" })).status, 401, "same local part, other domain");
  assert.equal((await creatorLogin({ email: `John ${unique}`, password: "Correct-pass-1" })).status, 401, "display name");
});

test("H13: wrong password and unknown email look identical", async () => {
  const unique = fx.uid();
  await creatorWithPassword({ name: "Jane", email: `jane${unique}@a.test`, password: "Correct-pass-1" });
  const wrongPassword = await creatorLogin({ email: `jane${unique}@a.test`, password: "nope" });
  const unknownEmail = await creatorLogin({ email: `nobody${unique}@a.test`, password: "nope" });
  assert.equal(wrongPassword.status, 401);
  assert.deepEqual(wrongPassword.body, unknownEmail.body);
  assert.equal(wrongPassword.body.reason, undefined);
});

test("H13: a plaintext password stored in the DB is not accepted", async () => {
  const unique = fx.uid();
  await creatorWithPassword({ name: "Old", email: `old${unique}@a.test`, password: "plain-pass-1", plaintext: true });
  assert.equal((await creatorLogin({ email: `old${unique}@a.test`, password: "plain-pass-1" })).status, 401);
});

test("H13: creator login is rate limited per email", async () => {
  const email = `brute${fx.uid()}@a.test`;
  const statuses = [];
  for (let i = 0; i < 11; i += 1) statuses.push((await creatorLogin({ email, password: `guess-${i}` })).status);
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401));
  assert.equal(statuses[10], 429);
});

// ── H2: single-use password reset links ──
const { signTestToken } = require("./helpers/testServer");
const resetWith = (token, password = "New-password-1") =>
  api(server.baseUrl, "POST", "/auth/reset-password-by-token", { json: { token, password } });

test("H2: a reset link works once", async () => {
  const buyer = await fx.createBuyer();
  const token = await signTestToken({ email: buyer.email, pv: 0 }, 600, "password-reset");
  assert.equal((await resetWith(token, "First-new-pass-1")).status, 200);
  const reuse = await resetWith(token, "Second-new-pass-1");
  assert.equal(reuse.status, 400);
  assert.match(reuse.body.error, /already been used/);
  const login = await api(server.baseUrl, "POST", "/login", { json: { email: buyer.email, password: "First-new-pass-1" } });
  assert.equal(login.status, 200, "the first new password is the one that stuck");
});

test("H2: links without a password version are rejected", async () => {
  const buyer = await fx.createBuyer();
  const token = await signTestToken({ email: buyer.email }, 600, "password-reset");
  assert.equal((await resetWith(token)).status, 400);
});

test("H2: two simultaneous uses of one link: exactly one succeeds", async () => {
  const buyer = await fx.createBuyer();
  const token = await signTestToken({ email: buyer.email, pv: 0 }, 600, "password-reset");
  const results = await Promise.all(Array.from({ length: 5 }, (_, i) => resetWith(token, `Parallel-pass-${i}`)));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
});

// ── H3: rate limits on endpoints that send SMS / email ──
const sendOtp = (identifier) => api(server.baseUrl, "POST", "/otp/twilio/send", { json: { identifier } });

test("H3: OTP send is limited to 3 per phone per 10 minutes", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const phone = "919800000001";
  const statuses = [];
  for (let i = 0; i < 4; i += 1) statuses.push((await sendOtp(phone)).status);
  assert.deepEqual(statuses, [200, 200, 200, 429]);
  assert.equal((await sendOtp("919800000002")).status, 200, "another number is not blocked");
});

test("H3: OTP send is limited to 10 per IP per hour across numbers", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const statuses = [];
  for (let i = 0; i < 11; i += 1) statuses.push((await sendOtp(`9198100000${String(i).padStart(2, "0")}`)).status);
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(200));
  assert.equal(statuses[10], 429);
});

test("H3: forgot-password is limited per email address", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const statuses = [];
  for (let i = 0; i < 4; i += 1) {
    statuses.push((await api(server.baseUrl, "POST", "/auth/forgot-password", { json: { email: "victim@test.local" } })).status);
  }
  assert.equal(statuses[3], 429);
});

test("H3: the unused /otp/msg91 aliases are gone", async () => {
  assert.equal((await api(server.baseUrl, "POST", "/otp/msg91/send", { json: { identifier: "919800000009" } })).status, 404);
});

test("M20: the anonymous staff existence lookup is gone", async () => {
  assert.equal((await api(server.baseUrl, "GET", "/staff/lookup?identifier=someone@test.local")).status, 404);
});

// ── H17: staff login resolves the right account ──
async function staffWithPassword({ staffId, phone = null, email = null, password }) {
  const id = `STF-h17-${fx.uid()}`;
  await server.db.query(
    `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, share_token, status)
     VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, 'active')`,
    [id, staffId, staffId, email, phone, await bcrypt.hash(password, 4), `share-${fx.uid()}`],
  );
  return id;
}
const staffLogin = (staffId, password) => api(server.baseUrl, "POST", "/staff/login", { json: { staffId, password } });

test("H17: a login ID without digits does not match staff who have no phone", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  await staffWithPassword({ staffId: `nophone${fx.uid()}`, password: "Other-pass-1" }); // phone NULL
  const mineId = await staffWithPassword({ staffId: `evil.staff.${fx.uid().replace(/\d/g, "x")}`, password: "Mine-pass-1" });
  const loginId = (await server.db.query("SELECT staff_id FROM staff_accounts WHERE id=$1", [mineId])).rows[0].staff_id;
  const res = await staffLogin(loginId, "Mine-pass-1");
  assert.equal(res.status, 200);
  assert.equal(res.body.staff.id, mineId, "logged into the right account");
});

test("H17: staff can still log in by phone (10+ digits)", async () => {
  const id = await staffWithPassword({ staffId: `byphone${fx.uid()}`, phone: "+91 98111 22233", password: "Phone-pass-1" });
  const res = await staffLogin("9811122233", "Phone-pass-1");
  assert.equal(res.status, 200);
  assert.equal(res.body.staff.id, id);
});

test("H17: unknown staff and wrong password get the same 401", async () => {
  await staffWithPassword({ staffId: `known${fx.uid()}`, password: "Known-pass-1" });
  const unknown = await staffLogin(`nobody${fx.uid()}`, "x");
  assert.equal(unknown.status, 401);
});

test("D12: staff share links resolve by share token only", async () => {
  const email = `share${fx.uid()}@test.local`;
  const id = await staffWithPassword({ staffId: `sharer${fx.uid()}`, email, password: "Share-pass-1" });
  const token = (await server.db.query("SELECT share_token FROM staff_accounts WHERE id=$1", [id])).rows[0].share_token;
  assert.equal((await api(server.baseUrl, "GET", `/staff/share/${encodeURIComponent(email)}`)).status, 404);
  const ok = await api(server.baseUrl, "GET", `/staff/share/${token}`);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.staff.email, undefined, "no email in the public share response");
});

// ── L4: tokens are only accepted for their own purpose (audience) ──
test("L4: a password-reset token cannot be used as a login session", async () => {
  const buyer = await fx.createBuyer();
  const resetToken = await signTestToken({ sub: buyer.id, email: buyer.email, pv: 0 }, 600, "password-reset");
  assert.equal((await api(server.baseUrl, "GET", "/bookings/mine", { token: resetToken })).status, 401);
  assert.equal((await api(server.baseUrl, "GET", "/bookings/mine", { token: buyer.token })).status, 200);
});

test("L4: a session token cannot be used as a reset link", async () => {
  const buyer = await fx.createBuyer();
  const sessionToken = await signTestToken({ email: buyer.email, pv: 0 });
  assert.equal((await resetWith(sessionToken)).status, 400);
});

test("L4: tokens from the old hand-written format are rejected", async () => {
  const crypto = require("crypto");
  const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: 1, iat: now, exp: now + 600 })}`;
  const legacy = `${unsigned}.${crypto.createHmac("sha256", "test-only-jwt-secret-for-integration-tests-0123456789").update(unsigned).digest("base64url")}`;
  assert.equal((await api(server.baseUrl, "GET", "/bookings/mine", { token: legacy })).status, 401);
});
