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
