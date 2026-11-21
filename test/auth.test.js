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
