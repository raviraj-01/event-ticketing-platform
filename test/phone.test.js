// Q12 / D23: one buyer account per verified phone (step 1: flag, backfill,
// signup check, duplicate report; the unique index comes after the report).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { startTestServer, signTestToken, api } = require("./helpers/testServer");
const tokens = require("../src/utils/tokens");
const { findDuplicatePhones } = require("../scripts/report-duplicate-phones");
const bcrypt = require("bcrypt");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
let n = 0;

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

// Same shape the server issues after a correct OTP (jti = single use, M17).
const otpToken = (identifier) => signTestToken({ identifier, jti: require("crypto").randomUUID() }, 600, tokens.AUDIENCE.signupOtp);

async function signup({ phone, countryCode = "+91", identifier, token, email }) {
  n += 1;
  const otpAccessToken = token || await otpToken(identifier);
  return api(server.baseUrl, "POST", "/signup", {
    json: {
      firstName: "Phone",
      email: email || `phone${n}-${Date.now()}@test.local`,
      phone,
      countryCode,
      password: "Buyer-pass-123",
      otpAccessToken,
    },
  });
}

test("Q12: signup stores the OTP-verified phone as verified", async () => {
  const res = await signup({ phone: "9812345601", identifier: "919812345601" });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const row = await server.db.query("SELECT phone_verified FROM users WHERE id=$1", [res.body.user.id]);
  assert.equal(row.rows[0].phone_verified, true);
});

test("Q12: a second account with the same verified phone is refused (other formatting too)", async () => {
  assert.equal((await signup({ phone: "9812345602", identifier: "919812345602" })).status, 200);
  const spaced = await signup({ phone: "98123 45602", identifier: "919812345602" });
  assert.equal(spaced.status, 409);
  assert.match(spaced.body.error, /phone number already exists/);
});

test("Q12: phone_key normalises formats and ignores empty phones", async () => {
  const keys = await server.db.query(
    `SELECT phone_key('+91', '98123 45603') AS a, phone_key('', '+919812345603') AS b,
            phone_key(NULL, '9812345603') AS c, phone_key('+91', '') AS empty, phone_key('+91', NULL) AS none`,
  );
  const row = keys.rows[0];
  assert.equal(row.a, "919812345603");
  assert.equal(row.b, row.a);
  assert.equal(row.c, row.a);
  assert.equal(row.empty, null);
  assert.equal(row.none, null);
});

test("Q12 + M22: the migration leaves existing rows untouched; their phones still count as verified; the report lists duplicates", async () => {
  const { runner } = await import("node-pg-migrate");
  const migrationsDir = path.join(__dirname, "..", "migrations");
  const laterMigrations = fs.readdirSync(migrationsDir).filter((name) => name >= "0012");
  const migrate = (direction, count) => runner({
    databaseUrl: server.databaseUrl,
    dir: migrationsDir,
    direction,
    count,
    migrationsTable: "pgmigrations",
    log: () => {},
  });

  // Back to the schema before 0012, add old-style rows, then migrate up again.
  await migrate("down", laterMigrations.length);
  const insert = (email, phone, countryCode) => server.db.query(
    `INSERT INTO users (username, first_name, email, password, phone, country_code)
     VALUES ('old', 'Old', $1, 'x', $2, $3) RETURNING id`,
    [email, phone, countryCode],
  ).then((r) => r.rows[0].id);
  const withPhone = await insert(`old-a-${Date.now()}@test.local`, "9812345604", "+91");
  const dupOne = await insert(`old-b-${Date.now()}@test.local`, "98123 45605", "+91");
  const dupTwo = await insert(`old-c-${Date.now()}@test.local`, "+919812345605", null);
  const googleOne = await insert(`old-d-${Date.now()}@test.local`, null, null);
  const googleTwo = await insert(`old-e-${Date.now()}@test.local`, "", "+91");
  const ids = [withPhone, dupOne, dupTwo, googleOne, googleTwo];
  const snapshot = () => server.db.query(
    "SELECT id, username, email, phone, country_code, password FROM users WHERE id = ANY($1::int[]) ORDER BY id",
    [ids],
  ).then((r) => r.rows);
  const before = await snapshot();
  await migrate("up", Infinity);
  assert.deepEqual(await snapshot(), before, "existing values unchanged");

  const rows = await server.db.query(
    "SELECT id, phone_verified, verified_phone_key(phone_verified, country_code, phone) AS key FROM users WHERE id = ANY($1::int[])",
    [ids],
  );
  const byId = Object.fromEntries(rows.rows.map((r) => [r.id, r]));
  for (const id of ids) assert.equal(byId[id].phone_verified, null, "no backfill: the flag stays empty");
  assert.equal(byId[withPhone].key, "919812345604");
  assert.equal(byId[dupOne].key, "919812345605");
  assert.equal(byId[dupTwo].key, "919812345605");
  assert.equal(byId[googleOne].key, null);
  assert.equal(byId[googleTwo].key, null);

  const groups = await findDuplicatePhones(server.db);
  const group = groups.find((g) => g.phone === "919812345605");
  assert.ok(group, JSON.stringify(groups));
  assert.deepEqual(group.accounts.map((a) => a.id).sort(), [dupOne, dupTwo].sort());
  assert.ok(!groups.some((g) => g.phone === "919812345604"));
});

// ── M17: a verification token works for one signup only ──

test("M17: five parallel signups with one verification token create exactly one account", async () => {
  // Sequential reuse is already stopped by the verified-phone check (Q12);
  // the race below is what single-use tokens add: all five can pass that
  // check before any of them has inserted the account.
  const token = await otpToken("919812345610");
  const results = await Promise.all(Array.from({ length: 5 }, () =>
    signup({ phone: "9812345610", identifier: "919812345610", token })));
  const statuses = results.map((r) => r.status).sort();
  assert.equal(statuses.filter((s) => s === 200).length, 1, JSON.stringify(statuses));
  const accounts = await server.db.query("SELECT COUNT(*)::int AS n FROM users WHERE phone='9812345610'");
  assert.equal(accounts.rows[0].n, 1);
});

test("M17: a failed signup does not use up the token; tokens without an id are refused", async () => {
  const taken = await signup({ phone: "9812345611", identifier: "919812345611" });
  assert.equal(taken.status, 200);
  const token = await otpToken("919812345612");
  const duplicateEmail = await signup({ phone: "9812345612", identifier: "919812345612", token, email: taken.body.user.email });
  assert.equal(duplicateEmail.status, 409);
  const retry = await signup({ phone: "9812345612", identifier: "919812345612", token });
  assert.equal(retry.status, 200, "the rolled-back attempt left the token usable");

  const oldStyle = await signTestToken({ identifier: "919812345613" }, 600, tokens.AUDIENCE.signupOtp);
  assert.equal((await signup({ phone: "9812345613", identifier: "919812345613", token: oldStyle })).status, 400);
});

// ── Q14 / D24: phone before the first paid checkout ──

const order = (buyer, eventId, tierName) =>
  api(server.baseUrl, "POST", "/orders", { token: buyer.token, json: { eventId, tierName, qty: 1 } });

test("Q14: a buyer without a phone must add one before a paid order (no hold is created); free tiers don't need it", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({
    creatorId: creator.id,
    tiers: [{ name: "General", price: 500, qty: 10 }, { name: "Free", price: 0, qty: 10 }],
  });
  const buyer = await fx.createBuyer({ phone: null });

  const refused = await order(buyer, eventId, "General");
  assert.equal(refused.status, 400);
  assert.equal(refused.body.code, "phone_required");
  const holds = await server.db.query("SELECT 1 FROM orders WHERE user_id=$1", [buyer.id]);
  assert.equal(holds.rows.length, 0);
  assert.equal((await order(buyer, eventId, "Free")).status, 201);

  const bad = await api(server.baseUrl, "PUT", "/profile/phone", { token: buyer.token, json: { phone: "12345" } });
  assert.equal(bad.status, 400);
  const saved = await api(server.baseUrl, "PUT", "/profile/phone", { token: buyer.token, json: { phone: "+91 98765 43210" } });
  assert.equal(saved.status, 200);
  assert.equal(saved.body.user.phone, "9876543210");
  const row = await server.db.query("SELECT phone_verified FROM users WHERE id=$1", [buyer.id]);
  assert.equal(row.rows[0].phone_verified, false);

  const paid = await order(buyer, eventId, "General");
  assert.equal(paid.status, 201, JSON.stringify(paid.body));
  assert.equal(paid.body.payment.fields.phone, "9876543210");
});

test("Q14: a phone verified by OTP cannot be overwritten through the profile route", async () => {
  const res = await signup({ phone: "9812345606", identifier: "919812345606" });
  assert.equal(res.status, 200);
  const token = await signTestToken({ sub: res.body.user.id, email: res.body.user.email });
  const change = await api(server.baseUrl, "PUT", "/profile/phone", { token, json: { phone: "9876500000" } });
  assert.equal(change.status, 409);
});

test("Q14: only a verified phone works as a login name", async () => {
  const password = "Buyer-pass-123";
  const hash = await bcrypt.hash(password, 4);
  const insert = (email, phone, verified) => server.db.query(
    `INSERT INTO users (username, first_name, email, password, phone, country_code, phone_verified)
     VALUES ('B', 'B', $1, $2, $3, '+91', $4)`,
    [email, hash, phone, verified],
  );
  await insert(`unverified-${Date.now()}@test.local`, "9812345607", false);
  await insert(`verified-${Date.now()}@test.local`, "9812345608", true);
  const login = (id) => api(server.baseUrl, "POST", "/login", { json: { email: id, password } });
  assert.notEqual((await login("9812345607")).status, 200);
  assert.equal((await login("9812345608")).status, 200);
});
