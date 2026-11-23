// M19 / D27: admin powers over staff accounts.
//   suspend: any admin, any staff
//   activate / pending, delete: normal admins only staff they created; super admins any
//   organizer staff are never deleted from the admin panel
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
let adminA;
let adminB;
let superAdmin;
before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
  adminA = await fx.createAdmin();
  adminB = await fx.createAdmin();
  superAdmin = await fx.createAdmin({ superAdmin: true });
  // Status changes and deletes need a recent password confirmation (H6).
  await server.db.query("UPDATE admin_accounts SET reauth_until = NOW() + INTERVAL '1 hour'");
  await server.db.query("UPDATE super_admin_accounts SET reauth_until = NOW() + INTERVAL '1 hour'");
});
after(async () => {
  if (server) await server.stop();
});

async function adminCreatedStaff(createdBy) {
  const id = `STF-m19-${fx.uid()}`;
  await server.db.query(
    `INSERT INTO staff_accounts (id, creator_id, name, staff_id, password, share_token, status, created_by_admin_email)
     VALUES ($1, NULL, 'S', $2, 'x', $3, 'active', $4)`,
    [id, `m19${fx.uid()}`, `share-${fx.uid()}`, createdBy],
  );
  return id;
}
const del = (who, id) => api(server.baseUrl, "DELETE", `/admin/staff/${id}`, { token: who.token });
const setStatus = (who, id, status) => api(server.baseUrl, "PATCH", `/admin/staff/${id}/status`, { token: who.token, json: { status } });
const exists = async (id) => (await server.db.query("SELECT 1 FROM staff_accounts WHERE id=$1", [id])).rows.length === 1;

test("M19: a normal admin deletes only staff they created; super admin any admin-created staff", async () => {
  const mine = await adminCreatedStaff(adminA.email);
  const legacy = await adminCreatedStaff(null);
  assert.equal((await del(adminB, mine)).status, 403);
  assert.equal((await del(adminB, legacy)).status, 403, "no recorded creator no longer means anyone may delete");
  assert.ok(await exists(mine) && await exists(legacy));
  assert.equal((await del(adminA, mine)).status, 200);
  assert.equal((await del(superAdmin, legacy)).status, 200);
  assert.ok(!(await exists(mine)) && !(await exists(legacy)));
});

test("M19: organizer staff can be suspended by any admin, re-activated only by a super admin, never deleted here", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const staff = await fx.createStaff({ creatorId: creator.id, eventId });
  const id = staff.id;
  assert.equal((await setStatus(adminB, id, "suspended")).status, 200);
  assert.equal((await setStatus(adminB, id, "active")).status, 403);
  assert.equal((await setStatus(superAdmin, id, "active")).status, 200);
  assert.equal((await del(superAdmin, id)).status, 403);
  assert.ok(await exists(id));
});
