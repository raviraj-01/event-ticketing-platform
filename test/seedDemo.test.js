// scripts/seed-demo.js: the demo accounts and events work through the real
// app, and a second run inserts nothing and changes nothing.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, signTestToken, api } = require("./helpers/testServer");
const { seedDemo, adminEmailFrom, DEMO } = require("../scripts/seed-demo");

let server;
let first;
const ADMIN_EMAIL = "demo-admin@test.local";
const passwordOf = (label) => first.credentials.find((line) => line.startsWith(label)).split(/\s+/)[2];

before(async () => {
  server = await startTestServer();
  first = await seedDemo(server.db, { adminEmail: ADMIN_EMAIL });
});
after(async () => {
  if (server) await server.stop();
});

test("seed-demo creates one of each account and both events", () => {
  assert.equal(first.kept.length, 0);
  assert.equal(first.credentials.length, 4); // admin, organizer, staff, buyer
  for (const item of [`admin ${ADMIN_EMAIL}`, `organizer ${DEMO.organizer.email}`, `staff ${DEMO.staff.loginId}`, `buyer ${DEMO.buyer.email}`]) {
    assert.ok(first.created.includes(item), item);
  }
  assert.ok(first.created.some((item) => item.startsWith(`event ${DEMO.freeEvent.id}`)));
  assert.ok(first.created.some((item) => item.startsWith(`event ${DEMO.paidEvent.id}`)));
  assert.ok(first.created.some((item) => item.startsWith(`event ${DEMO.paidEvent2.id}`)));
});

test("seed-demo accounts can log in through the real routes", async () => {
  const admin = await api(server.baseUrl, "POST", "/admin/login", { json: { email: ADMIN_EMAIL, password: passwordOf("admin") } });
  assert.equal(admin.status, 200, JSON.stringify(admin.body));
  const verified = await api(server.baseUrl, "POST", "/admin/login/verify", { json: { challengeId: admin.body.challengeId, code: admin.body.devCode } });
  assert.equal(verified.status, 200, JSON.stringify(verified.body));

  const organizer = await api(server.baseUrl, "POST", "/creator/login", { json: { email: DEMO.organizer.email, password: passwordOf("organizer") } });
  assert.equal(organizer.status, 200, JSON.stringify(organizer.body));
  const staff = await api(server.baseUrl, "POST", "/staff/login", { json: { staffId: DEMO.staff.loginId, password: passwordOf("staff") } });
  assert.equal(staff.status, 200, JSON.stringify(staff.body));
  const buyer = await api(server.baseUrl, "POST", "/login", { json: { email: DEMO.buyer.email, password: passwordOf("buyer") } });
  assert.equal(buyer.status, 200, JSON.stringify(buyer.body));
});

test("seed-demo events are public, the staff allocation came out of the paid event's inventory", async () => {
  const events = await api(server.baseUrl, "GET", "/events");
  const ids = events.body.events.map((event) => event.id);
  assert.ok(ids.includes(DEMO.freeEvent.id) && ids.includes(DEMO.paidEvent.id));

  const paid = await server.db.query("SELECT tickets FROM creator_events WHERE id = $1", [DEMO.paidEvent.id]);
  const tiers = Object.fromEntries(paid.rows[0].tickets.map((tier) => [tier.name, tier.qty]));
  assert.deepEqual(tiers, { General: 2, "Staff Desk": 0 });
  const assignment = await server.db.query("SELECT qty, tier_name, commission_rate FROM staff_assignments WHERE staff_id = $1", [DEMO.staff.id]);
  assert.equal(assignment.rows.length, 1);
  assert.equal(assignment.rows[0].qty, DEMO.staff.qty);
});

test("the demo buyer can get a free ticket and start a PayU checkout (has a verified phone)", async () => {
  const id = (await server.db.query("SELECT id FROM users WHERE email = $1", [DEMO.buyer.email])).rows[0].id;
  const token = await signTestToken({ sub: id, email: DEMO.buyer.email });
  const free = await api(server.baseUrl, "POST", "/orders", { token, json: { eventId: DEMO.freeEvent.id, tierName: "Free Entry", qty: 1 } });
  assert.equal(free.status, 201, JSON.stringify(free.body));
  assert.ok(free.body.booking);
  const paid = await api(server.baseUrl, "POST", "/orders", { token, json: { eventId: DEMO.paidEvent.id, tierName: "General", qty: 1 } });
  assert.equal(paid.status, 201, JSON.stringify(paid.body));
  assert.equal(paid.body.payment.fields.amount, "109.44");
});

test("running seed-demo again inserts nothing and changes no row", async () => {
  const snapshot = async () => {
    const tables = ["admin_accounts", "creator_accounts", "creator_events", "staff_accounts", "staff_assignments", "users"];
    const out = {};
    for (const table of tables) out[table] = (await server.db.query(`SELECT * FROM ${table} ORDER BY 1`)).rows;
    return JSON.stringify(out);
  };
  const before = await snapshot();
  const second = await seedDemo(server.db, { adminEmail: ADMIN_EMAIL });
  assert.deepEqual(second.created, []);
  assert.deepEqual(second.credentials, []);
  assert.equal(second.kept.length, 7);
  assert.equal(await snapshot(), before);
});

test("admin email: argument first, else a plus-address of the SMTP login", () => {
  assert.equal(adminEmailFrom(["--admin-email=Me@Example.com"], {}), "me@example.com");
  assert.equal(adminEmailFrom([], { SMTP_USER: "dev@gmail.com" }), "dev+demo-admin@gmail.com");
  assert.equal(adminEmailFrom([], { SMTP_USER: "apikey" }), DEMO.admin.email);
});
