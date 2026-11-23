// Run BEFORE adding unique indexes (Q12 / D23, M3):
//
//   npm run report-duplicates        (same as npm run report-duplicate-phones)
//
// Lists, read-only:
//   - verified buyer phones used by more than one account (same phone key)
//   - emails used twice when case is ignored (A@x.com vs a@x.com), per account table
//     (buyers, organizers, admins, super admins)
// Each group has to be resolved by hand before the matching unique index can
// be added. It runs inside a READ ONLY transaction, so it cannot change data,
// and it does not need the app's migrations to have run.
const path = require("path");
const { Pool } = require("pg");

// The same rule as phone_key() / verified_phone_key() (migrations 0012, 0015),
// inlined so the report also works on a database the app has not migrated.
const PHONE_KEY = (cc, phone) => `CASE
    WHEN COALESCE(REGEXP_REPLACE(${phone}, '\\D', '', 'g'), '') = '' THEN NULL
    ELSE COALESCE(NULLIF(REGEXP_REPLACE(COALESCE(${cc}, ''), '\\D', '', 'g'), ''), '91')
      || RIGHT(REGEXP_REPLACE(${phone}, '\\D', '', 'g'), 10)
  END`;

async function hasColumn(db, table, column) {
  const result = await db.query(
    "SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2",
    [table, column],
  );
  return result.rows.length > 0;
}

async function findDuplicatePhones(db) {
  // NULL / missing flag = account from before the flag: its phone counts as verified.
  const verified = (await hasColumn(db, "users", "phone_verified")) ? "COALESCE(phone_verified, TRUE)" : "TRUE";
  const key = `CASE WHEN ${verified} THEN ${PHONE_KEY("country_code", "phone")} END`;
  const result = await db.query(`
    SELECT ${key} AS phone,
           json_agg(json_build_object('id', id, 'email', email, 'createdAt', created_at, 'status', status)
             ORDER BY created_at, id) AS accounts
    FROM users
    WHERE ${key} IS NOT NULL
    GROUP BY 1 HAVING COUNT(*) > 1 ORDER BY 1`);
  return result.rows;
}

// Tables that get a unique LOWER(email) index (migration 0019). Not
// staff_accounts: staff may share an email on purpose (D18).
const EMAIL_TABLES = ["users", "creator_accounts", "admin_accounts", "super_admin_accounts"];

async function findDuplicateEmails(db) {
  const groups = [];
  for (const table of EMAIL_TABLES) {
    const result = await db.query(`
      SELECT LOWER(email) AS email, json_agg(json_build_object('id', id, 'email', email) ORDER BY id) AS accounts
      FROM ${table}
      WHERE COALESCE(email, '') <> ''
      GROUP BY 1 HAVING COUNT(*) > 1 ORDER BY 1`);
    for (const row of result.rows) groups.push({ table, ...row });
  }
  return groups;
}

async function main() {
  // Only when run as a script: tests import the functions and must never pick
  // up the developer's .env (H18).
  if (process.env.SKIP_ENV_FILE !== "true") require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  const pool = new Pool({
    connectionString,
    ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
  });
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const phones = await findDuplicatePhones(client);
    const emails = await findDuplicateEmails(client);
    await client.query("ROLLBACK");

    if (!phones.length) console.log("Phones: no duplicate verified phones.");
    else {
      console.log(`Phones: ${phones.length} verified phone(s) used by more than one buyer account:`);
      for (const group of phones) {
        console.log(`  +${group.phone}`);
        for (const a of group.accounts) console.log(`    user ${a.id}  ${a.email}  created ${a.createdAt}  ${a.status || "Active"}`);
      }
    }
    if (!emails.length) console.log("Emails: no duplicates when case is ignored.");
    else {
      console.log(`Emails: ${emails.length} address(es) used twice when case is ignored:`);
      for (const group of emails) {
        console.log(`  ${group.table}: ${group.email}`);
        for (const a of group.accounts) console.log(`    id ${a.id}  ${a.email}`);
      }
    }
    if (phones.length || emails.length) process.exitCode = 2;
    else console.log("No duplicates: the unique indexes can be added.");
  } finally {
    client.release();
    await pool.end();
  }
}

module.exports = { findDuplicatePhones, findDuplicateEmails };

if (require.main === module) {
  main().catch((err) => {
    console.error("Report failed:", err.message);
    process.exit(1);
  });
}
