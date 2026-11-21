// Q12 / D23: one buyer account per verified phone (step 1: flag, backfill,
// signup check, duplicate report; the unique index comes after the report).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { startTestServer, signTestToken, api } = require("./helpers/testServer");
const tokens = require("../src/utils/tokens");
const { findDuplicatePhones } = require("../scripts/report-duplicate-phones");

let server;
let n = 0;

before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

const otpToken = (identifier) => signTestToken({ identifier }, 600, tokens.AUDIENCE.signupOtp);

async function signup({ phone, countryCode = "+91", identifier }) {
  n += 1;
  const otpAccessToken = await otpToken(identifier);
  return api(server.baseUrl, "POST", "/signup", {
    json: {
      firstName: "Phone",
      email: `phone${n}-${Date.now()}@test.local`,
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

test("Q12: migration backfills phone_verified and the report lists duplicates (phoneless accounts never collide)", async () => {
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
  await migrate("up", Infinity);

  const flags = await server.db.query(
    "SELECT id, phone_verified FROM users WHERE id = ANY($1::int[])",
    [[withPhone, dupOne, dupTwo, googleOne, googleTwo]],
  );
  const verified = Object.fromEntries(flags.rows.map((r) => [r.id, r.phone_verified]));
  assert.equal(verified[withPhone], true);
  assert.equal(verified[dupOne], true);
  assert.equal(verified[dupTwo], true);
  assert.equal(verified[googleOne], false);
  assert.equal(verified[googleTwo], false);

  const groups = await findDuplicatePhones(server.db);
  const group = groups.find((g) => g.phone === "919812345605");
  assert.ok(group, JSON.stringify(groups));
  assert.deepEqual(group.accounts.map((a) => a.id).sort(), [dupOne, dupTwo].sort());
  assert.ok(!groups.some((g) => g.phone === "919812345604"));
});
