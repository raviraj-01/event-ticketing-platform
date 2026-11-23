// M5: request IDs link what the user sees to the server log.
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

test("M5: every response has an X-Request-Id", async () => {
  const a = await api(server.baseUrl, "GET", "/health");
  const b = await api(server.baseUrl, "GET", "/events");
  assert.match(a.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);
  assert.notEqual(a.headers.get("x-request-id"), b.headers.get("x-request-id"));
  assert.equal(b.body.requestId, undefined, "only error responses carry it in the body");
});

test("M5: a server error shows the request ID to the user and in the server log", async () => {
  const admin = await fx.createAdmin();
  await server.db.query("UPDATE admin_accounts SET reauth_until = NOW() + INTERVAL '1 hour' WHERE id=$1", [admin.id]);
  // Passes the integer check but overflows Postgres "integer": a real 500.
  const res = await api(server.baseUrl, "PATCH", "/admin/users/USR-99999999999/status", {
    token: admin.token,
    json: { status: "Suspended" },
  });
  assert.equal(res.status, 500);
  const id = res.headers.get("x-request-id");
  assert.equal(res.body.requestId, id);
  assert.doesNotMatch(JSON.stringify(res.body), /out of range|integer/, "no database details");
  await new Promise((resolve) => setTimeout(resolve, 200));
  // The tagged log entry and the error details that follow it (stack traces
  // span several lines).
  const output = server.serverOutput();
  const at = output.indexOf(`[req ${id}]`);
  assert.ok(at >= 0, "the server log carries the same id");
  assert.match(output.slice(at, at + 2000), /out of range|integer/, "the real error is in the log");
});
