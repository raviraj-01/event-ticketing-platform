// M16: the finance PIN is set explicitly (with the account password), never by
// a first unlock; 5 wrong PINs in a row lock unlock for 15 minutes.
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcrypt");
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
beforeEach(() => server.db.query("DELETE FROM rate_limit_hits"));

const PASSWORD = "Creator-pass-1";
async function creatorWithPassword() {
  const creator = await fx.createCreator();
  await server.db.query("UPDATE creator_accounts SET password=$2 WHERE id=$1", [creator.id, await bcrypt.hash(PASSWORD, 4)]);
  return creator;
}
const setPin = (creator, pin, password = PASSWORD) =>
  api(server.baseUrl, "POST", "/creator/finance/pin", { token: creator.token, json: { pin, password } });
const unlock = (creator, pin) =>
  api(server.baseUrl, "POST", "/creator/finance/unlock", { token: creator.token, json: { pin } });

test("M16: unlock never sets a PIN; setting one needs the account password", async () => {
  const creator = await creatorWithPassword();
  const first = await unlock(creator, "1234");
  assert.equal(first.status, 409);
  assert.equal(first.body.code, "pin_not_set");
  const stored = await server.db.query("SELECT finance_pin FROM creator_accounts WHERE id=$1", [creator.id]);
  assert.equal(stored.rows[0].finance_pin, null, "the guess was not saved as the PIN");

  assert.equal((await setPin(creator, "1234", "wrong-password")).status, 401);
  assert.equal((await setPin(creator, "12a4")).status, 400);
  assert.equal((await setPin(creator, "1234")).status, 200);
  assert.equal((await unlock(creator, "1234")).status, 200);
});

test("M16: five wrong PINs lock unlock, even for the right PIN; parallel guesses are counted", async () => {
  const creator = await creatorWithPassword();
  await setPin(creator, "4321");
  const guesses = await Promise.all(["0000", "0001", "0002", "0003", "0004", "0005", "0006", "0007"].map((p) => unlock(creator, p)));
  const statuses = guesses.map((g) => g.status);
  assert.equal(statuses.filter((s) => s === 401).length, 4, JSON.stringify(statuses));
  assert.equal(statuses.filter((s) => s === 429).length, 4, JSON.stringify(statuses));
  const right = await unlock(creator, "4321");
  assert.equal(right.status, 429);
  assert.equal(right.body.code, "pin_locked");

  // After the lock expires, the right PIN works and the count starts again.
  await server.db.query("UPDATE creator_accounts SET finance_pin_locked_until = NOW() - INTERVAL '1 second' WHERE id=$1", [creator.id]);
  assert.equal((await unlock(creator, "4321")).status, 200);
});
