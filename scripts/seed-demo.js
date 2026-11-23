// Demo data for a fresh development database:
//
//   npm run migrate
//   npm run seed-demo                       (or: npm run seed-demo -- --admin-email=you+admin@gmail.com)
//
// Creates, if they are not there yet:
//   - one admin            (admin login needs the emailed code, so use an address you can read)
//   - one approved organizer
//   - one free event and one paid event, both live (approved)
//   - one staff member of that organizer, assigned 10 tickets of the paid event
//   - one buyer with a verified phone (paid checkout needs a phone, Q14)
//
// Insert-only: a row that already exists (same email / login ID / event ID) is
// left exactly as it is and reported as "kept". Nothing is updated or deleted,
// so running it twice is safe. New passwords are random and written to
// demo-credentials.local.txt (git-ignored), never printed.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const { createStaffAssignment } = require("../src/services/staffAssignments");
const { todayInIndia } = require("../src/utils/events");

const CREDENTIALS_FILE = path.join(__dirname, "..", "demo-credentials.local.txt");

const DEMO = {
  admin: { name: "Demo Admin", email: "admin@demo.local" },
  organizer: { name: "Demo Organizer", email: "organizer@demo.local", phone: "9000000001", category: "Music" },
  freeEvent: { id: "EVT-DEMO-FREE", name: "Demo Open Mic (free)", capacity: 50, tickets: [{ name: "Free Entry", price: 0, qty: 50, perks: "" }] },
  // General: 2 seats online, for the sold-out case in docs/PAYU-TEST.md.
  // Staff Desk: all 10 allocated to the demo staff member below.
  paidEvent: {
    id: "EVT-DEMO-PAID",
    name: "Demo Live Night (paid)",
    capacity: 12,
    tickets: [
      { name: "General", price: 100, qty: 2, perks: "" },
      { name: "Staff Desk", price: 100, qty: 10, perks: "" },
    ],
  },
  staff: { id: "STF-DEMO-1", name: "Demo Staff", loginId: "demo.staff", tier: "Staff Desk", qty: 10, commissionRate: 10 },
  buyer: { firstName: "Demo", lastName: "Buyer", email: "buyer@demo.local", countryCode: "+91", phone: "9000000002" },
};

const newPassword = () => `Demo-${crypto.randomBytes(9).toString("base64url")}`;

// An address that reaches the developer's inbox: the --admin-email argument,
// else a plus-address of the SMTP login (you@gmail.com -> you+demo-admin@gmail.com).
function adminEmailFrom(argv, env) {
  const arg = argv.find((a) => a.startsWith("--admin-email="));
  if (arg) return arg.slice("--admin-email=".length).trim().toLowerCase();
  const smtpUser = String(env.SMTP_USER || "").trim().toLowerCase();
  const match = smtpUser.match(/^([^@+\s]+)@([^@\s]+\.[^@\s]+)$/);
  return match ? `${match[1]}+demo-admin@${match[2]}` : DEMO.admin.email;
}

function addDays(isoDate, days) {
  const date = new Date(`${isoDate}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

async function seedDemo(pool, { adminEmail = DEMO.admin.email, now = new Date() } = {}) {
  const created = [];
  const kept = [];
  const credentials = [];
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Admin (a normal admin; the super admin comes from SUPERADMIN_EMAIL at startup).
    const admin = await client.query("SELECT id FROM admin_accounts WHERE LOWER(email) = $1", [adminEmail]);
    if (admin.rows.length) kept.push(`admin ${adminEmail}`);
    else {
      const password = newPassword();
      await client.query(
        "INSERT INTO admin_accounts (name, email, password, role, status) VALUES ($1, $2, $3, 'Admin', 'Active')",
        [DEMO.admin.name, adminEmail, await bcrypt.hash(password, 10)],
      );
      created.push(`admin ${adminEmail}`);
      credentials.push(`admin      ${adminEmail}  ${password}   (Admin login; the 6-digit code is emailed)`);
    }

    // Organizer, already approved (KYC review is skipped for demo data).
    let organizer = await client.query("SELECT id, name FROM creator_accounts WHERE LOWER(email) = $1", [DEMO.organizer.email]);
    if (organizer.rows.length) kept.push(`organizer ${DEMO.organizer.email}`);
    else {
      const password = newPassword();
      organizer = await client.query(
        `INSERT INTO creator_accounts (name, email, phone, category, about, password, kyc_status)
         VALUES ($1, $2, $3, $4, 'Demo organizer created by npm run seed-demo', $5, 'Approved') RETURNING id, name`,
        [DEMO.organizer.name, DEMO.organizer.email, DEMO.organizer.phone, DEMO.organizer.category, await bcrypt.hash(password, 10)],
      );
      created.push(`organizer ${DEMO.organizer.email}`);
      credentials.push(`organizer  ${DEMO.organizer.email}  ${password}   (Organizer login)`);
    }
    const { id: organizerId, name: organizerName } = organizer.rows[0];

    // Events: live (approved), 30 days from today in India.
    const eventDate = addDays(todayInIndia(now), 30);
    const newEvents = new Set();
    for (const event of [DEMO.freeEvent, DEMO.paidEvent]) {
      const exists = await client.query("SELECT 1 FROM creator_events WHERE id = $1", [event.id]);
      if (exists.rows.length) { kept.push(`event ${event.id}`); continue; }
      await client.query(
        `INSERT INTO creator_events (id, creator_id, creator_name, name, category, description, event_date, start_time,
           end_time, venue, city, capacity, banner_url, banner_key, visibility, status, tickets)
         VALUES ($1, $2, $3, $4, 'Music', 'Demo event created by npm run seed-demo.', $5, '19:00', '22:00',
           'Demo Hall', 'Hyderabad', $6, '/assets/blak-ticket-logo.svg', '', 'Public', 'live', $7)`,
        [event.id, organizerId, organizerName, event.name, eventDate, event.capacity, JSON.stringify(event.tickets)],
      );
      newEvents.add(event.id);
      created.push(`event ${event.id} (${eventDate})`);
    }

    // Staff member of the organizer, assigned through the app's own service
    // (moves the tier's inventory to the staff member, like the organizer screen does).
    const staff = await client.query("SELECT id FROM staff_accounts WHERE id = $1 OR staff_id = $2", [DEMO.staff.id, DEMO.staff.loginId]);
    if (staff.rows.length) kept.push(`staff ${DEMO.staff.loginId}`);
    else {
      const password = newPassword();
      await client.query(
        `INSERT INTO staff_accounts (id, creator_id, name, staff_id, password, role, status, share_token)
         VALUES ($1, $2, $3, $4, $5, 'Ticket Seller', 'active', $6)`,
        [DEMO.staff.id, organizerId, DEMO.staff.name, DEMO.staff.loginId, await bcrypt.hash(password, 10),
          `demo-staff-${crypto.randomBytes(4).toString("hex")}`],
      );
      created.push(`staff ${DEMO.staff.loginId}`);
      credentials.push(`staff      ${DEMO.staff.loginId}  ${password}   (Staff login, login ID)`);
      // Only allocate from an event this run created, so an existing event's inventory is never touched.
      if (newEvents.has(DEMO.paidEvent.id)) {
        await createStaffAssignment(client, {
          creatorId: organizerId,
          staffId: DEMO.staff.id,
          eventId: DEMO.paidEvent.id,
          tierName: DEMO.staff.tier,
          qty: DEMO.staff.qty,
          commissionRate: DEMO.staff.commissionRate,
        });
        created.push(`assignment ${DEMO.staff.qty} x ${DEMO.staff.tier} -> ${DEMO.staff.loginId}`);
      }
    }

    // Buyer with a verified phone.
    const buyer = await client.query("SELECT id FROM users WHERE LOWER(email) = $1", [DEMO.buyer.email]);
    if (buyer.rows.length) kept.push(`buyer ${DEMO.buyer.email}`);
    else {
      const password = newPassword();
      await client.query(
        `INSERT INTO users (username, first_name, last_name, email, password, country_code, phone, phone_verified, auth_provider)
         VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, 'email')`,
        [`${DEMO.buyer.firstName} ${DEMO.buyer.lastName}`, DEMO.buyer.firstName, DEMO.buyer.lastName, DEMO.buyer.email,
          await bcrypt.hash(password, 10), DEMO.buyer.countryCode, DEMO.buyer.phone],
      );
      created.push(`buyer ${DEMO.buyer.email}`);
      credentials.push(`buyer      ${DEMO.buyer.email}  ${password}   (Buyer login)`);
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return { created, kept, credentials };
}

async function main() {
  // Only when run as a script: tests import seedDemo() and must never read .env (H18).
  if (process.env.SKIP_ENV_FILE !== "true") require("dotenv").config({ path: path.join(__dirname, "..", ".env"), quiet: true });
  if (process.env.NODE_ENV === "production") {
    console.error("Refusing to seed demo accounts with NODE_ENV=production.");
    process.exit(1);
  }
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  const pool = new Pool({
    connectionString,
    ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
  });
  try {
    const result = await seedDemo(pool, { adminEmail: adminEmailFrom(process.argv.slice(2), process.env) });
    for (const item of result.created) console.log(`created  ${item}`);
    for (const item of result.kept) console.log(`kept     ${item} (already there, not changed)`);
    if (result.credentials.length) {
      const stamp = new Date().toISOString();
      fs.appendFileSync(CREDENTIALS_FILE, `# npm run seed-demo, ${stamp}\n${result.credentials.join("\n")}\n\n`, { mode: 0o600 });
      console.log(`Passwords for the new accounts: ${path.basename(CREDENTIALS_FILE)} (git-ignored).`);
    }
  } finally {
    await pool.end();
  }
}

module.exports = { seedDemo, adminEmailFrom, DEMO };

if (require.main === module) {
  main().catch((err) => {
    console.error("Seeding failed:", err.message);
    process.exit(1);
  });
}
