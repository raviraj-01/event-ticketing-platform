// The one shared Postgres connection pool. Every module that talks to the
// database requires it from here.
const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  console.error(
    "DATABASE_URL is missing. Add it to .env before starting the server.",
  );
  process.exit(1);
}

const dbSsl = process.env.DATABASE_URL.includes("localhost")
  ? false
  : { rejectUnauthorized: false };
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: dbSsl,
});

module.exports = { pool, dbSsl };
