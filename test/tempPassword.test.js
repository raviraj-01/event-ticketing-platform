// Q4: resets by someone else -> temporary password -> forced change.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcrypt");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
const ADMIN_PASSWORD = "Admin-pass-123";

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

const clearLimits = () => server.db.query("DELETE FROM rate_limit_hits");

// Staff login returns cookies on the web; for API tests use the app mode (Bearer).
async function staffAppLogin(staffId, password) {
  const res = await fetch(`${server.baseUrl}/staff/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client": "app" },
    body: JSON.stringify({ staffId, password }),
  });
  return { status: res.status, body: await res.json() };
}
const bearer = (token) => ({ Authorization: `Bearer ${token}` });
async function call(method, path, headers, json) {
  const res = await fetch(server.baseUrl + path, {
    method,
    headers: { ...(json ? { "Content-Type": "application/json" } : {}), ...headers },
    body: json ? JSON.stringify(json) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function adminWithPassword({ superAdmin = false } = {}) {
  const admin = await fx.createAdmin({ superAdmin });
  const table = superAdmin ? "super_admin_accounts" : "admin_accounts";
  await server.db.query(`UPDATE ${table} SET password=$1 WHERE id=$2`, [await bcrypt.hash(ADMIN_PASSWORD, 4), admin.id]);
  return admin;
}
const reauth = (admin) => api(server.baseUrl, "POST", "/admin/reauth", { token: admin.token, json: { password: ADMIN_PASSWORD } });

test("Q4: organizer resets a staff password; staff must change it before doing anything", async () => {
  await clearLimits();
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const staff = await fx.createStaff({ creatorId: creator.id, eventId });
  const loginId = (await server.db.query("SELECT staff_id FROM staff_accounts WHERE id=$1", [staff.id])).rows[0].staff_id;

  const reset = await api(server.baseUrl, "POST", `/creator/staff/${staff.id}/reset-password`, { token: creator.token });
  assert.equal(reset.status, 200);
  const temp = reset.body.temporaryPassword;
  assert.match(temp, /^[A-Za-z0-9]{12}$/);
  assert.equal((await api(server.baseUrl, "GET", "/staff/dashboard", { token: staff.token })).status, 401, "old sessions ended");

  const login = await staffAppLogin(loginId, temp);
  assert.equal(login.status, 200);
  assert.equal(login.body.mustChangePassword, true, "login response tells the app to ask for a new password");
  const blocked = await call("GET", "/staff/dashboard", bearer(login.body.accessToken));
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.passwordChangeRequired, true);

  assert.equal((await call("POST", "/auth/change-password", bearer(login.body.accessToken), { currentPassword: "wrong", newPassword: "My-own-pass-1" })).status, 401);
  assert.equal((await call("POST", "/auth/change-password", bearer(login.body.accessToken), { currentPassword: temp, newPassword: "short" })).status, 400);
  const changed = await call("POST", "/auth/change-password", { ...bearer(login.body.accessToken), "X-Client": "app" }, { currentPassword: temp, newPassword: "My-own-pass-1" });
  assert.equal(changed.status, 200);
  assert.equal((await call("GET", "/staff/dashboard", bearer(changed.body.accessToken))).status, 200, "fresh session works");
  assert.equal((await staffAppLogin(loginId, temp)).status, 401, "temporary password no longer works");
});

test("Q4: an organizer cannot reset another organizer's staff", async () => {
  const owner = await fx.createCreator();
  const other = await fx.createCreator();
  const staff = await fx.createStaff({ creatorId: owner.id, eventId: await fx.createEvent({ creatorId: owner.id }) });
  assert.equal((await api(server.baseUrl, "POST", `/creator/staff/${staff.id}/reset-password`, { token: other.token })).status, 404);
});

test("Q4: an admin resets a staff password only after re-confirming, and it is audited", async () => {
  await clearLimits();
  const admin = await adminWithPassword();
  const creator = await fx.createCreator();
  const staff = await fx.createStaff({ creatorId: creator.id, eventId: await fx.createEvent({ creatorId: creator.id }) });
  const path = `/admin/staff/${staff.id}/reset-password`;
  assert.equal((await api(server.baseUrl, "POST", path, { token: admin.token })).status, 403);
  await reauth(admin);
  const ok = await api(server.baseUrl, "POST", path, { token: admin.token });
  assert.equal(ok.status, 200);
  await new Promise((r) => setTimeout(r, 200));
  const rows = await server.db.query("SELECT 1 FROM admin_audit_log WHERE action='staff.password_reset' AND target_id=$1", [staff.id]);
  assert.equal(rows.rows.length, 1);
});

test("Q4: only a super admin resets an admin; the admin still needs the emailed code, then a forced change", async () => {
  await clearLimits();
  const target = await adminWithPassword();
  const normalAdmin = await adminWithPassword();
  await reauth(normalAdmin);
  assert.equal((await api(server.baseUrl, "POST", `/admin/accounts/${target.id}/reset-password`, { token: normalAdmin.token })).status, 403);

  const superAdmin = await adminWithPassword({ superAdmin: true });
  await reauth(superAdmin);
  const reset = await api(server.baseUrl, "POST", `/admin/accounts/${target.id}/reset-password`, { token: superAdmin.token });
  assert.equal(reset.status, 200);

  const step1 = await api(server.baseUrl, "POST", "/admin/login", { json: { email: target.email, password: reset.body.temporaryPassword } });
  assert.equal(step1.body.otpRequired, true, "temporary password still needs the second factor");
  const step2 = await fetch(`${server.baseUrl}/admin/login/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client": "app" },
    body: JSON.stringify({ challengeId: step1.body.challengeId, code: step1.body.devCode }),
  }).then((r) => r.json());
  const blocked = await call("GET", "/admin/snapshot", bearer(step2.accessToken));
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.passwordChangeRequired, true);
});

// ── Q4: super admin recovery via CLI; bootstrap never overwrites (M1) ──
const { execFileSync } = require("child_process");
const path = require("path");
const { startApp } = require("./helpers/testServer");

test("Q4: the CLI gives a super admin a temporary password; login still needs the code, then a forced change", async () => {
  await clearLimits();
  const superAdmin = await adminWithPassword({ superAdmin: true });
  const output = execFileSync(process.execPath, [path.join(__dirname, "..", "scripts", "reset-super-admin.js"), superAdmin.email], {
    env: { ...process.env, DATABASE_URL: server.databaseUrl },
  }).toString();
  const temp = (output.match(/Temporary password for \S+: (\S+)/) || [])[1];
  assert.ok(temp, output);
  assert.equal((await api(server.baseUrl, "GET", "/admin/snapshot", { token: superAdmin.token })).status, 401, "old sessions ended");
  const step1 = await api(server.baseUrl, "POST", "/admin/login", { json: { email: superAdmin.email, password: temp } });
  assert.equal(step1.body.otpRequired, true);
  const audit = await server.db.query("SELECT 1 FROM admin_audit_log WHERE action='super_admin.cli_reset' AND admin_email=$1", [superAdmin.email]);
  assert.equal(audit.rows.length, 1);
});

test("M1: restarting with SUPERADMIN_PASSWORD set never overwrites an existing super admin password", async () => {
  const superAdmin = await adminWithPassword({ superAdmin: true });
  const before = (await server.db.query("SELECT password FROM super_admin_accounts WHERE id=$1", [superAdmin.id])).rows[0].password;
  const second = await startApp(server.databaseUrl, { SUPERADMIN_EMAIL: superAdmin.email, SUPERADMIN_PASSWORD: "Env-password-from-env-1" });
  second.stop();
  const after = (await server.db.query("SELECT password FROM super_admin_accounts WHERE id=$1", [superAdmin.id])).rows[0].password;
  assert.equal(after, before);
});
