// Q12 / D23: run BEFORE the unique-phone index is added.
//
//   npm run report-duplicate-phones
//
// Lists every verified phone that more than one buyer account uses (same
// phone_key, see migrations/0012). Read-only: it changes nothing. Each group
// has to be resolved by hand (e.g. mark the extra accounts unverified) before
// the partial unique index can be created.
const path = require("path");
const { Pool } = require("pg");

const DUPLICATES_SQL = `
  SELECT phone_key(country_code, phone) AS phone,
         json_agg(json_build_object(
           'id', id, 'email', email, 'createdAt', created_at, 'status', status
         ) ORDER BY created_at, id) AS accounts
  FROM users
  WHERE phone_verified AND phone_key(country_code, phone) IS NOT NULL
  GROUP BY 1
  HAVING COUNT(*) > 1
  ORDER BY 1`;

async function findDuplicatePhones(pool) {
  const result = await pool.query(DUPLICATES_SQL);
  return result.rows;
}

async function main() {
  // Only when run as a script: tests import findDuplicatePhones and must
  // never pick up the developer's .env (H18).
  require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
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
    const groups = await findDuplicatePhones(pool);
    if (!groups.length) {
      console.log("No duplicate verified phones. The unique index can be added.");
      return;
    }
    console.log(`${groups.length} verified phone(s) used by more than one account:\n`);
    for (const group of groups) {
      console.log(`+${group.phone}`);
      for (const account of group.accounts) {
        console.log(`  user ${account.id}  ${account.email}  created ${account.createdAt}  ${account.status || "Active"}`);
      }
    }
    process.exitCode = 2;
  } finally {
    await pool.end();
  }
}

module.exports = { findDuplicatePhones };

if (require.main === module) {
  main().catch((err) => {
    console.error("Report failed:", err.message);
    process.exit(1);
  });
}
