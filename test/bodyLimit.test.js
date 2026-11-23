// M11: 100 KB request bodies by default; only the two upload routes accept
// more, and only after their own login / rate-limit checks.
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer } = require("./helpers/testServer");
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

const bigString = (bytes) => "a".repeat(bytes);
async function postJson(path, body, token) {
  const res = await fetch(server.baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

test("M11: an ordinary route refuses a body over 100 KB with a JSON 413", async () => {
  const res = await postJson("/login", { email: "x@test.local", password: bigString(200 * 1024) });
  assert.equal(res.status, 413);
  assert.deepEqual(res.body, { error: "Request body is too large" });
});

test("M11: the banner upload checks the login before reading a large body", async () => {
  const payload = { fileName: "b.png", dataUrl: `data:image/png;base64,${bigString(1024 * 1024)}` };
  assert.equal((await postJson("/creator/events/banner", payload)).status, 401);
  const creator = await fx.createCreator();
  const signedIn = await postJson("/creator/events/banner", payload, creator.token);
  assert.notEqual(signedIn.status, 413, "a 1 MB banner is within the upload limit");
  assert.notEqual(signedIn.status, 401);
});

test("M11: the public application form takes large KYC files but is rate limited per IP", async () => {
  const body = { name: "A", email: `apply${fx.uid()}@test.local`, documents: [{ documentType: "pan", fileName: "p.pdf", dataUrl: bigString(2 * 1024 * 1024) }] };
  const statuses = [];
  for (let i = 0; i < 6; i += 1) statuses.push((await postJson("/creator/applications", body)).status);
  assert.ok(statuses.slice(0, 5).every((s) => s !== 413 && s !== 429), JSON.stringify(statuses));
  assert.equal(statuses[5], 429);
});
