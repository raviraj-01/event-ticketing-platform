// L5: event input checks (pure function) and one end-to-end refusal.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { eventInputProblem } = require("../src/utils/events");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

const NOW = new Date("2026-11-23T06:00:00Z");
const valid = (over = {}) => ({
  name: "Show", category: "Music", description: "d", date: "2026-12-31", time: "07:30 PM", endTime: "",
  venue: "Hall", city: "Pune", capacity: 100, latitude: "18.52", longitude: "73.85", visibility: "Public",
  banner: "/r2/media/event-banners/creator-7/b.png", bannerKey: "event-banners/creator-7/b.png",
  tickets: [{ name: "General", price: 500, qty: 80 }, { name: "VIP", price: 0, qty: 20 }],
  ...over,
});
const problem = (over) => eventInputProblem(valid(over), { creatorId: 7, now: NOW });

test("L5: a normal event passes (12h and 24h times)", () => {
  assert.equal(problem(), null);
  assert.equal(problem({ time: "19:00", endTime: "23:30" }), null);
});

test("L5: bad dates, times, capacity and coordinates are refused", () => {
  assert.match(problem({ date: "31/12/2026" }), /valid event date/);
  assert.match(problem({ date: "2026-02-30" }), /valid event date/);
  assert.match(problem({ date: "2026-11-22" }), /in the past/);
  assert.match(problem({ time: "7pm-ish" }), /start time/);
  assert.match(problem({ endTime: "25:00" }), /end time/);
  assert.match(problem({ capacity: 0 }), /Capacity/);
  assert.match(problem({ capacity: 1.5 }), /Capacity/);
  assert.match(problem({ latitude: "95" }), /latitude/);
  assert.match(problem({ visibility: "Everyone" }), /Visibility/);
});

test("L5: the banner must be this organizer's own upload", () => {
  assert.match(problem({ bannerKey: "event-banners/creator-8/b.png" }), /banner/);
  assert.match(problem({ banner: "https://evil.example/b.png" }), /banner/);
  assert.match(problem({ banner: "javascript:alert(1)" }), /banner/);
});

test("L5: tiers: unique names, valid prices and quantities, total within capacity", () => {
  assert.match(problem({ tickets: [{ name: "A", price: 1, qty: 1 }, { name: "a", price: 1, qty: 1 }] }), /both called/);
  assert.match(problem({ tickets: [{ name: "A", price: -5, qty: 1 }] }), /price/);
  assert.match(problem({ tickets: [{ name: "A", price: 5, qty: 2.5 }] }), /quantity/);
  assert.match(problem({ tickets: [{ name: "A", price: 5, qty: 101 }] }), /more than the capacity/);
});

let server;
let fx;
before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

test("L5: the API refuses an invalid event with a clear 400", async () => {
  const creator = await fx.createCreator();
  const body = valid({
    date: "2099-12-31",
    banner: `/r2/media/event-banners/creator-${creator.id}/b.png`,
    bannerKey: `event-banners/creator-${creator.id}/b.png`,
    tickets: [{ name: "General", price: 500, qty: 500 }],
  });
  const res = await api(server.baseUrl, "POST", "/creator/events", { token: creator.token, json: body });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /more than the capacity/);
});
