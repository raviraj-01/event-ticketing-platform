// Integration tests for H10 (withdrawal double-spend) and D4 (cash owed).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;

before(async () => {
  server = await startTestServer();
  fx = makeFixtures(server.db);
  // Warm the server's DB pool so parallel requests really overlap.
  await Promise.all(Array.from({ length: 10 }, () => api(server.baseUrl, "GET", "/events")));
});
after(async () => {
  if (server) await server.stop();
});

// A creator with one event and one staff member who has made sales.
async function staffWithSales(sales) {
  const creator = await fx.createCreator();
  const eventId = await fx.createEvent({ creatorId: creator.id });
  const staff = await fx.createStaff({ creatorId: creator.id, eventId });
  for (const sale of sales) {
    await server.db.query(
      `INSERT INTO staff_sales (id, creator_id, staff_id, event_id, event_name, tier_name, qty, price, total,
         payment_mode, commission, revenue_owner, allocation_mode, status)
       VALUES ($1,$2,$3,$4,'Test Event','General',1,$5,$5,$6,$7,$8,$9,'active')`,
      [`SLS-w-${fx.uid()}`, creator.id, staff.id, eventId, sale.total, sale.mode, sale.commission,
        sale.owner || "creator", sale.owner === "staff" ? "staff_owned" : "creator_quota"],
    );
  }
  return { creator, staff };
}

const wallet = async (staff) => (await api(server.baseUrl, "GET", "/staff/dashboard", { token: staff.token })).body.wallet;
const withdraw = (staff, amount) =>
  api(server.baseUrl, "POST", "/staff/withdrawals", { token: staff.token, json: { amount, method: "upi", upiId: "staff@upi" } });

test("D4: cash collected is owed to the organizer; only commission is withdrawable", async () => {
  const { staff } = await staffWithSales([
    { total: 1000, mode: "cash", commission: 100 },
    { total: 500, mode: "online", commission: 50 },
    { total: 800, mode: "cash", commission: 0, owner: "staff" }, // staff-owned resale: theirs, not owed
  ]);
  const w = await wallet(staff);
  assert.equal(w.commissionEarned, 150);
  assert.equal(w.availableBalance, 150);
  assert.equal(w.cashCollected, 1000);
  assert.equal(w.cashOwed, 1000);
  const tooMuch = await withdraw(staff, 500); // the old wallet allowed this (cash counted as balance)
  assert.equal(tooMuch.status, 400);
  assert.equal((await withdraw(staff, 150)).status, 201);
  assert.equal((await wallet(staff)).availableBalance, 0);
});

test("H10: parallel withdrawals cannot spend the same balance twice", async () => {
  const { staff } = await staffWithSales([{ total: 1000, mode: "cash", commission: 100 }]);
  const results = await Promise.all(Array.from({ length: 8 }, () => withdraw(staff, 60)));
  assert.equal(results.filter((r) => r.status === 201).length, 1);
  const total = await server.db.query("SELECT COALESCE(SUM(amount),0)::NUMERIC AS s FROM staff_withdrawals WHERE staff_id=$1", [staff.id]);
  assert.equal(Number(total.rows[0].s), 60);
});

test("H10: zero, negative or junk amounts are rejected", async () => {
  const { staff } = await staffWithSales([{ total: 1000, mode: "cash", commission: 100 }]);
  for (const amount of [0, -5, "abc"]) assert.equal((await withdraw(staff, amount)).status, 400, String(amount));
});

test("D4: the organizer records cash received, which lowers cash owed", async () => {
  const { creator, staff } = await staffWithSales([{ total: 1000, mode: "cash", commission: 100 }]);
  const settle = (who, amount) =>
    api(server.baseUrl, "POST", `/creator/staff/${encodeURIComponent(staff.id)}/cash-settlements`, { token: who.token, json: { amount } });
  const ok = await settle(creator, 400);
  assert.equal(ok.status, 201);
  assert.equal(ok.body.wallet.cashOwed, 600);
  assert.equal((await settle(creator, 700)).status, 400, "more than owed");
  const other = await fx.createCreator();
  assert.equal((await settle(other, 100)).status, 404, "another creator's staff");
  const list = await api(server.baseUrl, "GET", "/creator/staff", { token: creator.token });
  assert.equal(list.body.staff.find((m) => m.id === staff.id).cashOwed, 600);
});
