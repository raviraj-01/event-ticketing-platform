// Runs pending SQL migrations from /migrations (node-pg-migrate).
// Used by server.js at startup (before it accepts requests) and by
// `npm run migrate`. Each file in /migrations runs once, in name order, and is
// recorded in the pgmigrations table.
const path = require("path");

const migrationsDir = path.join(__dirname, "..", "..", "migrations");

async function runMigrations({ connectionString, ssl }) {
  // node-pg-migrate is an ES module, so it is loaded with import().
  const { runner } = await import("node-pg-migrate");
  return runner({
    databaseUrl: { connectionString, ssl },
    dir: migrationsDir,
    direction: "up",
    migrationsTable: "pgmigrations",
    count: Infinity,
    log: (message) => console.log(`[migrate] ${message}`),
  });
}

module.exports = { runMigrations };

if (require.main === module) {
  require("dotenv").config({ path: path.join(__dirname, "..", "..", ".env") });
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  runMigrations({
    connectionString,
    ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false },
  })
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("Migration failed:", err);
      process.exit(1);
    });
}
