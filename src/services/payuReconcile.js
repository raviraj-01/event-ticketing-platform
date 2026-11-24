// H19: a paid order must not depend on the buyer's browser coming back.
//
// PayU captures the money first and only then sends the browser back to
// /payments/payu/success. If that last hop never happens (tab closed, network
// lost, an embedded browser that cannot open localhost), the order used to stay
// `pending` and later turn `expired`: buyer charged, no ticket.
//
// Here we ask PayU directly, server to server, with PayU's verify_payment API
// (authenticated with our salt). Two triggers use it:
//   - a poll every 5 minutes (server.js) over recent PayU orders that are still
//     pending, or that expired before PayU settled them;
//   - PayU's webhook (POST /payments/payu/webhook), which only tells us WHICH
//     txnid to check. Its posted status is never trusted.
// A success goes through the same applyPayuResult() as the browser callback,
// so it is idempotent (one ticket at most) and re-checks seats for a late
// payment: ticket if seats remain, otherwise `paid_needs_refund` for an admin.
const { getPayuConfig, makeApiHash } = require("./payu");
const { applyPayuResult, recordPaymentResult } = require("./orders");

const RECONCILE = {
  minAgeMinutes: 1,     // give the browser callback a moment first
  lookbackHours: 72,    // older unsettled orders are left to an admin
  recheckMinutes: 5,    // ask PayU about the same order at most this often
  batchSize: 25,        // txnids per verify_payment call
};

// What PayU's `unmappedstatus` (or `status`) says, and what we do with it:
//   captured / success      → paid at PayU: confirm (settled, not asked again)
//   usercancelled / dropped → the buyer left PayU's page: release the seat hold now
//   / bounced
//   failed / failure        → this attempt failed, but PayU lets the buyer retry
//                             on the same checkout, so keep asking for a while
const SETTLED_AT_PAYU = ["captured", "success"];
const BUYER_GAVE_UP = ["usercancelled", "dropped", "bounced"];
const NOT_PAID = ["failed", "failure", ...BUYER_GAVE_UP];
const FAILURE_FINAL_AFTER_HOURS = 2;   // a retry on PayU's page is over by then

const normalStatus = (value) => String(value || "").trim().toLowerCase().replace(/\s+/g, "_") || "unknown";

// Ask PayU about up to RECONCILE.batchSize txnids at once.
// Returns { [txnid]: details } as PayU sends them (status, amt, mihpayid, udf1, ...).
async function fetchPayuStatuses(txnids, { payu = getPayuConfig(), fetchImpl = fetch } = {}) {
  if (!payu.key || !payu.salt || !txnids.length) return {};
  const command = "verify_payment";
  const var1 = txnids.join("|");
  const resp = await fetchImpl(payu.verifyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({ key: payu.key, command, var1, hash: makeApiHash(payu.key, command, var1, payu.salt) }).toString(),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) throw new Error(`PayU verify_payment answered HTTP ${resp.status}`);
  const data = await resp.json();
  const details = data && data.transaction_details;
  return details && typeof details === "object" ? details : {};
}

// Orders worth asking PayU about. With `txnids` (webhook, CLI): only those.
async function findCandidates(pool, txnids) {
  if (txnids) {
    const result = await pool.query(
      `SELECT id, txnid, amount FROM orders
       WHERE payment_method = 'payu' AND status IN ('pending', 'expired') AND txnid = ANY($1::text[])`,
      [txnids],
    );
    return result.rows;
  }
  const result = await pool.query(
    `SELECT id, txnid, amount FROM orders
     WHERE payment_method = 'payu' AND status IN ('pending', 'expired')
       AND created_at > NOW() - make_interval(hours => $1)
       AND created_at < NOW() - make_interval(mins => $2)
       AND (gateway_status IS NULL OR gateway_status <> ALL($3::text[]))
       AND NOT (COALESCE(gateway_status, '') = ANY($6::text[]) AND created_at < NOW() - make_interval(hours => $7))
       AND (gateway_checked_at IS NULL OR gateway_checked_at < NOW() - make_interval(mins => $4))
     ORDER BY gateway_checked_at NULLS FIRST, created_at
     LIMIT $5`,
    [RECONCILE.lookbackHours, RECONCILE.minAgeMinutes, SETTLED_AT_PAYU, RECONCILE.recheckMinutes, RECONCILE.batchSize,
      NOT_PAID, FAILURE_FINAL_AFTER_HOURS],
  );
  return result.rows;
}

// Returns one entry per order checked: { orderId, txnid, gatewayStatus, outcome }.
// outcome: 'paid' | 'paid_needs_refund' | 'already_paid' | 'amount_mismatch' | 'mismatch'
//        | 'released' (buyer cancelled at PayU, seat hold ended) | 'unchanged'
async function reconcilePayuOrders(pool, { txnids, payu = getPayuConfig(), fetchImpl } = {}) {
  if (!payu.key || !payu.salt) return [];
  const orders = await findCandidates(pool, txnids ? txnids.map(String).slice(0, RECONCILE.batchSize) : null);
  if (!orders.length) return [];
  const statuses = await fetchPayuStatuses(orders.map((order) => order.txnid), { payu, fetchImpl });

  const results = [];
  for (const order of orders) {
    const details = statuses[order.txnid] || null;
    const paidAtPayu = Boolean(details) && normalStatus(details.status) === "success";
    const gatewayStatus = details ? normalStatus(details.unmappedstatus || details.status) : "no_answer";
    let outcome = "unchanged";
    if (!paidAtPayu && BUYER_GAVE_UP.includes(gatewayStatus)) {
      const released = await pool.query(
        "UPDATE orders SET status = 'expired' WHERE id = $1 AND status = 'pending' RETURNING id",
        [order.id],
      );
      if (released.rows.length) outcome = "released";
    }
    if (paidAtPayu) {
      // PayU's answer must be about this order (same txnid, our order ID in udf1).
      const sameOrder = String(details.txnid || order.txnid) === order.txnid && (!details.udf1 || details.udf1 === order.id);
      if (!sameOrder) {
        outcome = "mismatch";
      } else {
        const payment = {
          txnid: order.txnid,
          amount: details.transaction_amount || details.amt,
          mihpayid: details.mihpayid,
          email: details.email,
          error_Message: details.error_Message,
        };
        ({ outcome } = await applyPayuResult(pool, payment, { success: true }));
        if (outcome !== "unknown_order") {
          await recordPaymentResult(pool, payment, order.id, outcome).catch((err) =>
            console.error("Payment audit write failed:", err.message),
          );
        }
      }
      if (outcome === "amount_mismatch" || outcome === "mismatch") {
        console.error("PayU reconciliation not applied:", outcome, order.id);
      }
    }
    await pool.query(
      "UPDATE orders SET gateway_status = $1, gateway_checked_at = NOW() WHERE id = $2",
      [gatewayStatus, order.id],
    );
    results.push({ orderId: order.id, txnid: order.txnid, gatewayStatus, outcome });
  }
  return results;
}

// One readable log line per result that changed something.
const OUTCOME_TEXT = {
  paid: "paid at PayU but not confirmed by the browser: ticket issued",
  paid_needs_refund: "paid at PayU after the seats were gone: no ticket, listed for refund",
  released: "buyer cancelled at PayU: seat hold released",
  amount_mismatch: "PayU amount differs from the order: NOT applied, check by hand",
  mismatch: "PayU answer is for another order: NOT applied, check by hand",
};
const describeResult = (r) => OUTCOME_TEXT[r.outcome]
  ? `PayU check: order ${r.orderId} (txn ${r.txnid}) ${OUTCOME_TEXT[r.outcome]}`
  : null;

module.exports = { reconcilePayuOrders, fetchPayuStatuses, describeResult, RECONCILE, SETTLED_AT_PAYU, BUYER_GAVE_UP };
