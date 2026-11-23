// Test data factories. Rows are inserted directly so each test controls
// exactly the state it needs.
const crypto = require("crypto");
const { signTestToken } = require("./testServer");

function makeFixtures(db) {
  let seq = 0;
  const uid = () => `${Date.now()}${++seq}${crypto.randomBytes(2).toString("hex")}`;
  const uniquePhone = () => `9${String(Date.now() % 100000).padStart(5, "0")}${String(++seq % 10000).padStart(4, "0")}`;

  async function createCreator({ kycStatus = "Approved" } = {}) {
    const result = await db.query(
      `INSERT INTO creator_accounts (name, email, phone, category, about, password, kyc_status)
       VALUES ('Creator', $1, '9000000000', 'Music', 'x', 'x', $2) RETURNING id, email`,
      [`creator${uid()}@test.local`, kycStatus],
    );
    const creator = result.rows[0];
    return { ...creator, token: await signTestToken({ sub: creator.id, email: creator.email, scope: "creator" }) };
  }

  async function createBuyer({ email, phone } = {}) {
    const result = await db.query(
      `INSERT INTO users (username, first_name, email, password, phone)
       VALUES ('Buyer', 'Buyer', $1, 'x', $2) RETURNING id, email`,
      // Paid checkout needs a phone (Q14); pass phone: null for a phoneless buyer.
      // Unique per buyer: verified phones are unique (migration 0019).
      [email || `buyer${uid()}@test.local`, phone === undefined ? uniquePhone() : phone],
    );
    const user = result.rows[0];
    return { ...user, token: await signTestToken({ sub: user.id, email: user.email }) };
  }

  async function createEvent({ creatorId, capacity = 100, tiers = [{ name: "General", price: 500, qty: 100 }] } = {}) {
    const id = `EVT-test-${uid()}`;
    await db.query(
      `INSERT INTO creator_events (id, creator_id, creator_name, name, category, description, event_date,
         start_time, venue, city, capacity, banner_url, banner_key, status, tickets)
       VALUES ($1, $2, 'Creator', 'Test Event', 'Music', 'd', '2099-12-31', '19:00', 'Hall', 'City', $3,
         '/b.png', 'b', 'live', $4)`,
      [id, creatorId, capacity, JSON.stringify(tiers)],
    );
    return id;
  }

  async function createStaff({ creatorId, eventId, email = null, phone = null, assignedTier = "General" }) {
    const id = `STF-test-${uid()}`;
    const shareToken = `share-${crypto.randomBytes(6).toString("hex")}`;
    await db.query(
      `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, share_token, status)
       VALUES ($1, $2, 'Staff', $3, $4, $5, 'x', $6, 'active')`,
      [id, creatorId, `login${uid()}`, email, phone, shareToken],
    );
    if (assignedTier && eventId) {
      await db.query(
        `INSERT INTO staff_assignments (id, creator_id, staff_id, event_id, event_name, tier_name, qty, price, commission_rate)
         VALUES ($1, $2, $3, $4, 'Test Event', $5, 10, 500, 10)`,
        [`ASN-test-${uid()}`, creatorId, id, eventId, assignedTier],
      );
    }
    return { id, shareToken, token: await signTestToken({ sub: id, scope: "staff", creatorId }) };
  }

  // A booking row as old code (or a staff walk-in sale) would have left it.
  async function createBooking({ eventId, userId = null, buyerEmail = null }) {
    const id = `BKG-test-${uid()}`;
    await db.query(
      `INSERT INTO bookings (id, user_id, buyer_email, event_id, event_name, ticket_type, price, qty, total, status, qr_token)
       VALUES ($1, $2, $3, $4, 'Test Event', 'General', 500, 1, 500, 'upcoming', $5)`,
      [id, userId, buyerEmail, eventId, crypto.randomBytes(18).toString("hex")],
    );
    return id;
  }

  async function createAdmin({ superAdmin = false } = {}) {
    const email = `${superAdmin ? "super" : "admin"}${uid()}@test.local`;
    const table = superAdmin ? "super_admin_accounts" : "admin_accounts";
    const result = await db.query(
      `INSERT INTO ${table} (name, email, password, status) VALUES ('Admin', $1, 'x', 'Active') RETURNING id`,
      [email],
    );
    const id = result.rows[0].id;
    const adminType = superAdmin ? "super" : "admin";
    return { id, email, adminType, token: await signTestToken({ sub: id, email, scope: "admin", adminType }) };
  }

  return { uid, createCreator, createBuyer, createEvent, createStaff, createBooking, createAdmin };
}

module.exports = { makeFixtures };
