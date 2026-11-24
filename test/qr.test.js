// L1: /qr draws only staff share links, length-capped and rate limited.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer } = require("./helpers/testServer");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

const qr = (text) => fetch(`${server.baseUrl}/qr?text=${encodeURIComponent(text)}`);

test("L1: a staff share link gets a PNG; anything else is refused", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const ok = await qr("https://tickets.example/?staff=abc123&event=EVT-1");
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("content-type"), "image/png");
  for (const text of ["hello world", "javascript:alert(1)", "https://evil.example/no-token", `https://x.example/?staff=${"a".repeat(600)}`]) {
    assert.equal((await qr(text)).status, 400, text.slice(0, 40));
  }
});

test("L1: rate limited per IP", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  let last;
  for (let i = 0; i < 61; i += 1) last = await qr(`https://tickets.example/?staff=t${i}`);
  assert.equal(last.status, 429);
  await server.db.query("DELETE FROM rate_limit_hits");
});

test("L14: /admin is a bookmarkable address for the admin login (redirects to /#admin)", async () => {
  const res = await fetch(`${server.baseUrl}/admin`, { redirect: "manual" });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "/#admin");
  // API routes under /admin/ are not affected.
  const api = await fetch(`${server.baseUrl}/admin/session`);
  assert.equal(api.status, 401);
});
