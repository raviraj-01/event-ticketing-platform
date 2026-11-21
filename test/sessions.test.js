// Integration tests for H5 (sessions) and H16 (CORS / CSRF).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcrypt");
const { startTestServer } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
const PASSWORD = "Session-pass-1";

before(async () => {
  // Short access tokens so expiry can be tested; no grace for refresh reuse.
  server = await startTestServer({ ACCESS_TOKEN_TTL_SECONDS: "2", REFRESH_REUSE_GRACE_SECONDS: "0" });
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function buyerAccount() {
  const email = `session${fx.uid()}@test.local`;
  const result = await server.db.query(
    "INSERT INTO users (username, first_name, email, password) VALUES ('S','S',$1,$2) RETURNING id",
    [email, await bcrypt.hash(PASSWORD, 4)],
  );
  return { id: result.rows[0].id, email };
}

async function call(method, path, { headers = {}, json } = {}) {
  const res = await fetch(server.baseUrl + path, {
    method,
    headers: { ...(json ? { "Content-Type": "application/json" } : {}), ...headers },
    body: json ? JSON.stringify(json) : undefined,
    redirect: "manual",
  });
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch (_) {}
  return { status: res.status, body, headers: res.headers, cookies: res.headers.getSetCookie() };
}

// "name=value" pairs from Set-Cookie headers, ready for a Cookie header.
const cookieJar = (setCookies) => setCookies.map((c) => c.split(";")[0]).join("; ");
const cookieNamed = (setCookies, name) => setCookies.find((c) => c.startsWith(`${name}=`));

const loginWeb = (email) => call("POST", "/login", { json: { email, password: PASSWORD } });
const loginApp = (email) => call("POST", "/login", { json: { email, password: PASSWORD }, headers: { "X-Client": "app" } });

test("web login: httpOnly SameSite=Strict cookies, no tokens in the body", async () => {
  const buyer = await buyerAccount();
  const res = await loginWeb(buyer.email);
  assert.equal(res.status, 200);
  assert.equal(res.body.token, undefined);
  assert.equal(res.body.accessToken, undefined);
  const access = cookieNamed(res.cookies, "at_buyer");
  const refresh = cookieNamed(res.cookies, "rt_buyer");
  assert.match(access, /HttpOnly/i);
  assert.match(access, /SameSite=Strict/i);
  assert.match(refresh, /HttpOnly/i);
  assert.match(refresh, /Path=\/auth/i, "refresh cookie is only sent to /auth");
  const session = await call("GET", "/session", { headers: { Cookie: cookieJar(res.cookies) } });
  assert.equal(session.status, 200);
  assert.equal(session.body.user.email, buyer.email);
});

test("app login: tokens in the body, no cookies; Bearer works", async () => {
  const buyer = await buyerAccount();
  const res = await loginApp(buyer.email);
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken && res.body.refreshToken);
  assert.equal(res.cookies.length, 0);
  const session = await call("GET", "/session", { headers: { Authorization: `Bearer ${res.body.accessToken}` } });
  assert.equal(session.status, 200);
});

test("access tokens expire; a refresh gives a working new one", async () => {
  const buyer = await buyerAccount();
  const login = await loginApp(buyer.email);
  await wait(2500);
  const expired = await call("GET", "/session", { headers: { Authorization: `Bearer ${login.body.accessToken}` } });
  assert.equal(expired.status, 401);
  const refreshed = await call("POST", "/auth/refresh", {
    json: { role: "buyer", refreshToken: login.body.refreshToken },
    headers: { "X-Client": "app" },
  });
  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.body.refreshToken, login.body.refreshToken, "refresh token rotates");
  const ok = await call("GET", "/session", { headers: { Authorization: `Bearer ${refreshed.body.accessToken}` } });
  assert.equal(ok.status, 200);
});

test("web refresh works from the refresh cookie", async () => {
  const buyer = await buyerAccount();
  const login = await loginWeb(buyer.email);
  const refreshed = await call("POST", "/auth/refresh", {
    json: { role: "buyer" },
    headers: { Cookie: cookieJar(login.cookies) },
  });
  assert.equal(refreshed.status, 200);
  assert.ok(cookieNamed(refreshed.cookies, "at_buyer"));
  assert.ok(cookieNamed(refreshed.cookies, "rt_buyer"));
});

test("reusing a rotated refresh token revokes the whole login (theft detection)", async () => {
  const buyer = await buyerAccount();
  const login = await loginApp(buyer.email);
  const refresh = (token) => call("POST", "/auth/refresh", { json: { role: "buyer", refreshToken: token }, headers: { "X-Client": "app" } });
  const first = await refresh(login.body.refreshToken);
  assert.equal(first.status, 200);
  assert.equal((await refresh(login.body.refreshToken)).status, 401, "old token reused");
  assert.equal((await refresh(first.body.refreshToken)).status, 401, "the newer token of the same family is revoked too");
});

test("logout revokes the refresh token", async () => {
  const buyer = await buyerAccount();
  const login = await loginApp(buyer.email);
  const headers = { "X-Client": "app" };
  assert.equal((await call("POST", "/auth/logout", { json: { role: "buyer", refreshToken: login.body.refreshToken }, headers })).status, 200);
  assert.equal((await call("POST", "/auth/refresh", { json: { role: "buyer", refreshToken: login.body.refreshToken }, headers })).status, 401);
});

test("logout everywhere kills existing access tokens immediately (token_version)", async () => {
  const buyer = await buyerAccount();
  const phone = await loginApp(buyer.email);
  const laptop = await loginApp(buyer.email);
  const auth = (t) => ({ Authorization: `Bearer ${t}` });
  assert.equal((await call("POST", "/auth/logout-all", { json: { role: "buyer" }, headers: auth(laptop.body.accessToken) })).status, 200);
  assert.equal((await call("GET", "/session", { headers: auth(phone.body.accessToken) })).status, 401);
  assert.equal((await call("POST", "/auth/refresh", { json: { role: "buyer", refreshToken: phone.body.refreshToken }, headers: { "X-Client": "app" } })).status, 401);
});

test("a suspended account cannot refresh", async () => {
  const buyer = await buyerAccount();
  const login = await loginApp(buyer.email);
  await server.db.query("UPDATE users SET status='Suspended' WHERE id=$1", [buyer.id]);
  assert.equal((await call("POST", "/auth/refresh", { json: { role: "buyer", refreshToken: login.body.refreshToken }, headers: { "X-Client": "app" } })).status, 401);
});

test("H16: CORS allows only listed origins", async () => {
  const allowed = new URL(server.baseUrl).origin;
  const good = await call("GET", "/events", { headers: { Origin: allowed } });
  assert.equal(good.headers.get("access-control-allow-origin"), allowed);
  assert.equal(good.headers.get("access-control-allow-credentials"), "true");
  const bad = await call("GET", "/events", { headers: { Origin: "https://evil.test" } });
  assert.equal(bad.headers.get("access-control-allow-origin"), null);
  const cordova = await call("GET", "/events", { headers: { Origin: "https://localhost" } });
  assert.equal(cordova.headers.get("access-control-allow-origin"), "https://localhost");
});

test("H16: cookie-authenticated POST from another origin is blocked (CSRF)", async () => {
  const buyer = await buyerAccount();
  const login = await loginWeb(buyer.email);
  const cookie = cookieJar(login.cookies);
  const evil = await call("POST", "/auth/logout-all", { json: { role: "buyer" }, headers: { Cookie: cookie, Origin: "https://evil.test" } });
  assert.equal(evil.status, 403);
  const same = await call("POST", "/auth/logout-all", { json: { role: "buyer" }, headers: { Cookie: cookie, Origin: new URL(server.baseUrl).origin } });
  assert.equal(same.status, 200);
});

test("H12: /session only accepts buyer sessions", async () => {
  const creator = await fx.createCreator();
  assert.equal((await call("GET", "/session", { headers: { Authorization: `Bearer ${creator.token}` } })).status, 401);
});
