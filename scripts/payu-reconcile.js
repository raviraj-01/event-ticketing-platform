// H19: ask PayU now about PayU orders that are pending or expired but may have
// been paid (the server also does this every 5 minutes):
//
//   npm run payu:reconcile                      (all recent candidates)
//   npm run payu:reconcile -- TXN123 TXN456     (only these txnids)
//
// Paid at PayU → ticket if seats remain, otherwise `paid_needs_refund` (Admin →
// Payments → Refunds). Nothing else is changed.
const path = require("path");
const { Pool } = require("pg");

async function main() {
  if (process.env.SKIP_ENV_FILE !== "true") require("dotenv").config({ path: path.join(__dirname, "..", ".env"), quiet: true });
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
  }
  // Loaded after .env so it sees PAYU_KEY / PAYU_SALT / PAYU_ENV.
  const { reconcilePayuOrders } = require("../src/services/payuReconcile");
  const pool = new Pool({ connectionString, ssl: connectionString.includes("localhost") ? false : { rejectUnauthorized: false } });
  try {
    const txnids = process.argv.slice(2).filter(Boolean);
    const results = await reconcilePayuOrders(pool, txnids.length ? { txnids } : {});
    if (!results.length) console.log("Nothing to check (no matching pending/expired PayU order).");
    for (const r of results) console.log(`${r.orderId}  ${r.txnid}  PayU: ${r.gatewayStatus}  ->  ${r.outcome}`);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Reconciliation failed:", err.message);
  process.exit(1);
});
