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
