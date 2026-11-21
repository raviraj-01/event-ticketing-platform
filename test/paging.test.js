// M4: paged list endpoints (?limit=&offset=, at most 100 per page).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");
const { readPage, pageOf } = require("../src/utils/paging");

let server;
let fx;
before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

test("M4: readPage applies defaults, the cap and ignores junk", () => {
  assert.deepEqual(readPage({}, { defaultLimit: 50, maxLimit: 100 }), { limit: 50, offset: 0 });
  assert.deepEqual(readPage({ limit: "1000", offset: "20" }, { maxLimit: 100 }), { limit: 100, offset: 20 });
  assert.deepEqual(readPage({ limit: "-5", offset: "abc" }, { defaultLimit: 50 }), { limit: 50, offset: 0 });
  assert.deepEqual(pageOf([1, 2, 3], { limit: 2, offset: 4 }), { rows: [1, 2], paging: { limit: 2, offset: 4, nextOffset: 6 } });
  assert.deepEqual(pageOf([1], { limit: 2, offset: 0 }).paging.nextOffset, null);
});

test("M4: a buyer's tickets come in pages", async () => {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const buyer = await fx.createBuyer();
  const ids = [];
  for (let i = 0; i < 3; i += 1) ids.push(await fx.createBooking({ eventId, userId: buyer.id }));

  const first = await api(server.baseUrl, "GET", "/bookings/mine?limit=2", { token: buyer.token });
  assert.equal(first.status, 200);
  assert.equal(first.body.bookings.length, 2);
  assert.deepEqual(first.body.paging, { limit: 2, offset: 0, nextOffset: 2 });
  const second = await api(server.baseUrl, "GET", "/profile/tickets?limit=2&offset=2", { token: buyer.token });
  assert.equal(second.body.bookings.length, 1);
  assert.equal(second.body.paging.nextOffset, null);
  const seen = [...first.body.bookings, ...second.body.bookings].map((b) => b.id).sort();
  assert.deepEqual(seen, ids.sort());

  const all = await api(server.baseUrl, "GET", "/bookings/mine", { token: buyer.token });
  assert.equal(all.body.bookings.length, 3);
  assert.equal(all.body.paging.limit, 100);
});

test("M4: the public event list comes in pages", async () => {
  const creator = await fx.createCreator();
  for (let i = 0; i < 3; i += 1) await fx.createEvent({ creatorId: creator.id });
  const first = await api(server.baseUrl, "GET", "/events?limit=2");
  assert.equal(first.status, 200);
  assert.equal(first.body.events.length, 2);
  assert.equal(first.body.paging.nextOffset, 2);
  const rest = await api(server.baseUrl, "GET", `/events?limit=100&offset=2`);
  const ids = new Set([...first.body.events, ...rest.body.events].map((e) => e.id));
  assert.equal(ids.size, first.body.events.length + rest.body.events.length, "no event appears twice");
  assert.equal((await api(server.baseUrl, "GET", "/events?limit=500")).body.paging.limit, 100);
});
