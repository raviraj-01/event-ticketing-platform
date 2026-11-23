// D22 / M18: no global scanner. Staff can scan only events they are assigned
// to (assignment or primary event), admin-created staff included.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, signTestToken, api } = require("./helpers/testServer");
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

async function adminStaff(primaryEventId) {
  const id = `STF-adm-${fx.uid()}`;
  await server.db.query(
    `INSERT INTO staff_accounts (id, creator_id, name, staff_id, password, share_token, status, primary_event_id)
     VALUES ($1, NULL, 'Gate', $2, 'x', $3, 'active', $4)`,
    [id, `gate${fx.uid()}`, `share-${fx.uid()}`, primaryEventId],
  );
  return { id, token: await signTestToken({ sub: id, scope: "staff", creatorId: null }) };
}

async function ticketPayload(eventId) {
  const bookingId = await fx.createBooking({ eventId });
  const row = await server.db.query("SELECT qr_token FROM bookings WHERE id=$1", [bookingId]);
  return `VYBERA-TICKET|${bookingId}|${eventId}|${row.rows[0].qr_token}`;
}

const scan = (token, qrPayload) => api(server.baseUrl, "POST", "/bookings/scan", { token, json: { qrPayload } });

test("M18: admin-created staff with no event cannot scan any event", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const unassigned = await adminStaff(null);
  const res = await scan(unassigned.token, await ticketPayload(eventId));
  assert.equal(res.status, 403);
});

test("M18: admin-created staff can scan their primary event only", async () => {
  const creator = await fx.createCreator();
  const mine = await fx.createEvent({ creatorId: creator.id });
  const other = await fx.createEvent({ creatorId: creator.id });
  const gate = await adminStaff(mine);
  assert.equal((await scan(gate.token, await ticketPayload(mine))).status, 200);
  assert.equal((await scan(gate.token, await ticketPayload(other))).status, 403);
});
