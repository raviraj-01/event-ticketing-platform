// Integration tests for C6: who may see a ticket and its QR payload.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;
let world;

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
  const creator = await fx.createCreator();
  const otherCreator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const otherEventId = await fx.createEvent({ creatorId: otherCreator.id });
  const owner = await fx.createBuyer();
  const stranger = await fx.createBuyer();
  world = {
    creator,
    otherCreator,
    eventId,
    owner,
    stranger,
    assignedStaff: await fx.createStaff({ creatorId: creator.id, eventId }),
    otherStaff: await fx.createStaff({ creatorId: otherCreator.id, eventId: otherEventId }),
    ownedBooking: await fx.createBooking({ eventId, userId: owner.id, buyerEmail: owner.email }),
    // Old guest booking with the stranger's email but no owner.
    guestBooking: await fx.createBooking({ eventId, userId: null, buyerEmail: stranger.email }),
  };
});

after(async () => {
  if (server) await server.stop();
});

const getTicket = (bookingId, token) =>
  api(server.baseUrl, "GET", `/bookings/${encodeURIComponent(bookingId)}/ticket`, { token });

test("no login → 401", async () => {
  assert.equal((await getTicket(world.ownedBooking)).status, 401);
});

test("owning buyer sees the ticket with its QR payload", async () => {
  const res = await getTicket(world.ownedBooking, world.owner.token);
  assert.equal(res.status, 200);
  assert.match(res.body.booking.qrPayload, /^VYBERA-TICKET\|/);
});

test("another buyer gets 404, the same as a missing ticket", async () => {
  const other = await getTicket(world.ownedBooking, world.stranger.token);
  const missing = await getTicket("BKG-does-not-exist", world.stranger.token);
  assert.equal(other.status, 404);
  assert.equal(missing.status, 404);
  assert.deepEqual(other.body, missing.body, "no way to tell 'exists' from 'missing'");
});

test("the event's creator sees it; another creator gets 404", async () => {
  assert.equal((await getTicket(world.ownedBooking, world.creator.token)).status, 200);
  assert.equal((await getTicket(world.ownedBooking, world.otherCreator.token)).status, 404);
});

test("staff assigned to the event see it; other staff get 404", async () => {
  assert.equal((await getTicket(world.ownedBooking, world.assignedStaff.token)).status, 200);
  assert.equal((await getTicket(world.ownedBooking, world.otherStaff.token)).status, 404);
});

test("a suspended creator loses access", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const bookingId = await fx.createBooking({ eventId, userId: world.owner.id });
  assert.equal((await getTicket(bookingId, creator.token)).status, 200);
  await server.db.query("UPDATE creator_accounts SET kyc_status = 'Suspended' WHERE id = $1", [creator.id]);
  assert.equal((await getTicket(bookingId, creator.token)).status, 401);
});

test("guest bookings are not reachable by a buyer with the matching email", async () => {
  assert.equal((await getTicket(world.guestBooking, world.stranger.token)).status, 404);
  for (const path of ["/bookings/mine", "/profile/tickets"]) {
    const res = await api(server.baseUrl, "GET", path, { token: world.stranger.token });
    assert.equal(res.status, 200);
    assert.equal(res.body.bookings.some((b) => b.id === world.guestBooking), false, path);
  }
});

test("buyer ticket lists contain only the buyer's own tickets and need a buyer token", async () => {
  const buyer = await fx.createBuyer();
  const bookingId = await fx.createBooking({ eventId: world.eventId, userId: buyer.id });
  const mine = await api(server.baseUrl, "GET", "/profile/tickets", { token: buyer.token });
  assert.deepEqual(mine.body.bookings.map((b) => b.id), [bookingId]);
  const asCreator = await api(server.baseUrl, "GET", "/profile/tickets", { token: world.creator.token });
  assert.equal(asCreator.status, 401);
});
