// Integration tests for H6 (admin hardening).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcrypt");
const { startTestServer, api, signTestToken } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
const PASSWORD = "Admin-pass-123";

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

async function makeAdmin({ superAdmin = false } = {}) {
  const email = `${superAdmin ? "super" : "admin"}${fx.uid()}@test.local`;
  const table = superAdmin ? "super_admin_accounts" : "admin_accounts";
  const result = await server.db.query(
    `INSERT INTO ${table} (name, email, password, status) VALUES ('Admin', $1, $2, 'Active') RETURNING id`,
    [email, await bcrypt.hash(PASSWORD, 4)],
  );
  const id = result.rows[0].id;
  const adminType = superAdmin ? "super" : "admin";
  return { id, email, adminType, token: await signTestToken({ sub: id, email, scope: "admin", adminType }) };
}

const auditRows = async (where, params) =>
  (await server.db.query(`SELECT * FROM admin_audit_log WHERE ${where} ORDER BY id`, params)).rows;

test("H6 audit: admin logins are logged, success and failure", async () => {
  const admin = await makeAdmin();
  await api(server.baseUrl, "POST", "/admin/login", { json: { email: admin.email, password: "wrong" } });
  await api(server.baseUrl, "POST", "/admin/login", { json: { email: admin.email, password: PASSWORD } });
  const rows = await auditRows("admin_email = $1", [admin.email]);
  assert.deepEqual(rows.map((r) => r.action), ["login.failed", "login.success"]);
  assert.ok(rows[0].ip, "IP recorded");
});

test("H6 audit: successful admin changes are logged with target and new status; failures are not", async () => {
  const superAdmin = await makeAdmin({ superAdmin: true });
  const creator = await fx.createCreator({ kycStatus: "Pending" });
  const ok = await api(server.baseUrl, "PATCH", `/admin/creators/${creator.id}/status`, { token: superAdmin.token, json: { status: "Rejected" } });
  assert.equal(ok.status, 200);
  const missing = await api(server.baseUrl, "PATCH", "/admin/creators/999999/status", { token: superAdmin.token, json: { status: "Rejected" } });
  assert.equal(missing.status, 404);
  await new Promise((r) => setTimeout(r, 200)); // log is written after the response finishes
  const rows = await auditRows("admin_id = $1 AND action = 'creator.status'", [String(superAdmin.id)]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].target_id, String(creator.id));
  assert.equal(rows[0].details.status, "Rejected");
});

test("H6 audit: only super admins can read the audit log", async () => {
  const superAdmin = await makeAdmin({ superAdmin: true });
  const admin = await makeAdmin();
  const asSuper = await api(server.baseUrl, "GET", "/admin/audit-log?limit=5", { token: superAdmin.token });
  assert.equal(asSuper.status, 200);
  assert.ok(Array.isArray(asSuper.body.entries));
  const asAdmin = await api(server.baseUrl, "GET", "/admin/audit-log", { token: admin.token });
  assert.equal(asAdmin.status, 403);
});

// ── H6 part 2: rate limit + lockout ──
const adminLogin = (email, password) => api(server.baseUrl, "POST", "/admin/login", { json: { email, password } });

test("H6 lockout: 5 wrong passwords lock the account, even the right password is refused", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const admin = await makeAdmin();
  for (let i = 0; i < 5; i += 1) assert.equal((await adminLogin(admin.email, `wrong-${i}`)).status, 401);
  const locked = await adminLogin(admin.email, PASSWORD);
  assert.equal(locked.status, 429);
  assert.match(locked.body.error, /Too many attempts/);
  const actions = (await auditRows("admin_email = $1", [admin.email])).map((r) => r.action);
  assert.ok(actions.includes("login.locked"));
  // After the lock expires the right password works and the counter resets.
  await server.db.query("UPDATE admin_accounts SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1", [admin.id]);
  assert.equal((await adminLogin(admin.email, PASSWORD)).status, 200);
  const row = (await server.db.query("SELECT failed_login_count, locked_until FROM admin_accounts WHERE id=$1", [admin.id])).rows[0];
  assert.equal(row.failed_login_count, 0);
  assert.equal(row.locked_until, null);
});

test("H6 lockout: a correct password resets the failure count", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const admin = await makeAdmin({ superAdmin: true });
  for (let i = 0; i < 4; i += 1) await adminLogin(admin.email, "wrong");
  assert.equal((await adminLogin(admin.email, PASSWORD)).status, 200);
  for (let i = 0; i < 4; i += 1) await adminLogin(admin.email, "wrong");
  assert.equal((await adminLogin(admin.email, PASSWORD)).status, 200, "still not locked: count was reset");
});

test("H6 rate limit: unknown emails are limited too, with the same message", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const email = `nobody${fx.uid()}@test.local`;
  const statuses = [];
  for (let i = 0; i < 11; i += 1) statuses.push((await adminLogin(email, "x")).status);
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401));
  assert.equal(statuses[10], 429);
});
