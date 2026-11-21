// M22: starting the app (and running its migrations) never changes or deletes
// rows that already exist. One-off repairs are a manual, dry-run-first script.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { execFile } = require("child_process");
const { startTestServer, startApp, signTestToken, api, testEnv } = require("./helpers/testServer");
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

async function legacyData() {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  await fx.createBooking({ eventId }); // one ₹500 ticket
  // A wrong denormalised counter (test data only), for the fix-up script to repair.
  await server.db.query("UPDATE creator_events SET booking_count=99, revenue=12345 WHERE id=$1", [eventId]);
  const email = `legacy-super-${fx.uid()}@test.local`;
  const admin = await server.db.query(
    "INSERT INTO admin_accounts (name, email, password, role, status) VALUES ('Old Super', $1, 'x', 'Super Admin', 'Active') RETURNING id",
    [email],
  );
  return { eventId, adminId: admin.rows[0].id, email };
}

const rowsOf = async ({ eventId, adminId }) => ({
  event: (await server.db.query("SELECT booking_count, revenue FROM creator_events WHERE id=$1", [eventId])).rows[0],
  admin: (await server.db.query("SELECT id, email, role, status FROM admin_accounts WHERE id=$1", [adminId])).rows[0],
  copied: (await server.db.query("SELECT COUNT(*)::int AS n FROM super_admin_accounts WHERE email LIKE 'legacy-super-%'")).rows[0].n,
});

test("M22: restarting the app leaves existing rows exactly as they were", async () => {
  const data = await legacyData();
  const beforeRows = await rowsOf(data);
  const second = await startApp(server.databaseUrl, { SUPERADMIN_EMAIL: "", SUPERADMIN_PASSWORD: "" });
  try {
    const health = await api(second.baseUrl, "GET", "/health");
    assert.equal(health.status, 200);
  } finally {
    second.stop();
  }
  assert.deepEqual(await rowsOf(data), beforeRows);
  assert.equal(beforeRows.event.booking_count, 99, "wrong counter left alone (fix-ups are manual now)");
});

test("M22: a legacy super admin keeps super-admin access, and the row is not moved or deleted", async () => {
  const data = await legacyData();
  const token = await signTestToken({ sub: data.adminId, email: data.email, scope: "admin", adminType: "admin" });
  const res = await api(server.baseUrl, "GET", "/admin/audit-log", { token });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const after = await rowsOf(data);
  assert.equal(after.admin.role, "Super Admin");
  assert.equal(after.copied, 0);
});

function runFixups(args) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [path.join(__dirname, "..", "scripts", "db-fixups.js"), ...args], {
      env: testEnv(process.env, { DATABASE_URL: server.databaseUrl }),
    }, (err, stdout, stderr) => (err ? reject(new Error(stderr || err.message)) : resolve(stdout)));
  });
}

test("M22: db-fixups changes nothing without --apply, and repairs with it", async () => {
  await server.db.query("DELETE FROM admin_accounts WHERE role='Super Admin'"); // test DB only: start clean
  const data = await legacyData();
  const dry = await runFixups([]);
  assert.match(dry, /Dry run: nothing was changed/);
  assert.match(dry, /Legacy super admins to copy: 1/);
  assert.equal((await rowsOf(data)).event.booking_count, 99);
  assert.ok((await rowsOf(data)).admin, "legacy row still there after the dry run");

  const applied = await runFixups(["--apply"]);
  assert.match(applied, /Applied/);
  const after = await rowsOf(data);
  assert.equal(after.event.booking_count, 1);
  assert.equal(Number(after.event.revenue), 500);
  assert.equal(after.admin, undefined);
  assert.equal(after.copied, 1);
});
