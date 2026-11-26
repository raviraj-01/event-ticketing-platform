// Orders & payments (C4).
// The browser never sends a price, booking ID or "paid" flag. It asks for
// (event, tier, qty); the server prices it from the DB, reserves seats and
// either confirms a free order or returns a PayU checkout form. Tickets are
// issued only by the verified PayU callback (see src/services/orders.js).
const express = require("express");
const { pool } = require("../db/pool");
const {
  ORDER_SETTINGS,
  createOrder,
  OrderError,
  applyPayuResult,
  recordPaymentResult,
  getOrderForBuyer,
  payablePhone,
} = require("../services/orders");
const { rateLimit, consumeRateLimit } = require("../middleware/rateLimit");
const { requireBuyer } = require("../middleware/auth");
const { publicOrder } = require("../utils/serializers");
const { ticketResponse } = require("../services/tickets");
const {
  getPayuConfig,
  formatPayuAmount,
  cleanPayuText,
  makeRequestHash,
  isValidResponseHash,
} = require("../services/payu");
const { APP_BASE_URL, DEMO_MODE } = require("../config");
const { reconcilePayuOrders, describeResult } = require("../services/payuReconcile");

const router = express.Router();

router.get("/config/public", (req, res) => {
  res.json({
    platformFeePercent: ORDER_SETTINGS.platformFeePercent,
    gstPercent: ORDER_SETTINGS.gstPercent,
    maxTicketsPerOrder: ORDER_SETTINGS.maxTicketsPerOrder,
    freeTicketsPerUserPerEvent: ORDER_SETTINGS.freeTicketsPerUserPerEvent,
    demoMode: DEMO_MODE,
  });
});

const orderRateLimits = [
  rateLimit({ name: "orders-user", windowSeconds: 600, max: 10, key: (req) => req.buyer && String(req.buyer.sub) }),
  rateLimit({ name: "orders-ip", windowSeconds: 600, max: 30, key: (req) => req.ip }),
];

router.post("/orders", requireBuyer, ...orderRateLimits, async (req, res) => {
  try {
    const { eventId, tierName, qty, shareToken } = req.body || {};
    const result = await createOrder(pool, { userId: req.buyer.sub, eventId, tierName, qty, shareToken });
    if (result.booking) {
      return res.status(201).json({ order: publicOrder(result.order), booking: await ticketResponse(result.booking) });
    }
    const { order, buyer, event } = result;
    const payu = getPayuConfig();
    if (!payu.key || !payu.salt) {
      await pool.query("UPDATE orders SET status = 'expired' WHERE id = $1", [order.id]);
      return res.status(503).json({ error: "Online payments are not configured" });
    }
    const fields = {
      key: payu.key,
      txnid: order.txnid,
      amount: formatPayuAmount(order.amount),
      productinfo: cleanPayuText(`Tickets ${event.name}`, 100) || "Event tickets",
      firstname: cleanPayuText(buyer.first_name || buyer.username || "Buyer", 60) || "Buyer",
      email: buyer.email,
      // Q14: createOrder refuses paid orders without a usable phone, so this is real.
      phone: payablePhone(buyer.phone),
      surl: `${APP_BASE_URL}/payments/payu/success`,
      furl: `${APP_BASE_URL}/payments/payu/failure`,
      udf1: order.id,
    };
    fields.hash = makeRequestHash(fields, payu.salt);
    res.status(201).json({ order: publicOrder(order), payment: { action: payu.action, fields } });
  } catch (err) {
    if (err instanceof OrderError) return res.status(err.status).json({ error: err.message, code: err.code });
    console.error("Order creation failed:", err);
    res.status(500).json({ error: "Could not create order" });
  }
});

// PayU posts the result here from the buyer's browser. We verify the hash,
// update the order, then redirect (303) to the app with only our order ID in
// the URL. No posted value is ever written into a page (fixes H8).
const handlePayuCallback = (isSuccessUrl) => async (req, res) => {
  const body = req.body || {};
  const payu = getPayuConfig();
  let target = `${APP_BASE_URL}/?payment=payu&status=failed`;
  try {
    if (!payu.key || body.key !== payu.key || !isValidResponseHash(body, payu.salt)) {
      console.error("PayU callback rejected: bad key or hash", { txnid: String(body.txnid || "").slice(0, 40) });
    } else {
      const paid = isSuccessUrl && String(body.status || "").toLowerCase() === "success";
      const { orderId, outcome } = await applyPayuResult(pool, body, { success: paid });
      if (outcome === "unknown_order" || outcome === "amount_mismatch") {
        console.error("PayU callback not applied:", outcome, String(body.txnid || "").slice(0, 40));
      }
      if (orderId) {
        await recordPaymentResult(pool, body, orderId, outcome).catch((err) =>
          console.error("Payment audit write failed:", err.message),
        );
        target = `${APP_BASE_URL}/?payment=payu&order=${encodeURIComponent(orderId)}`;
      }
    }
  } catch (err) {
    console.error("PayU callback failed:", err);
  }
  res.redirect(303, target);
};
router.post("/payments/payu/success", handlePayuCallback(true));
router.post("/payments/payu/failure", handlePayuCallback(false));

// H19: PayU's server-to-server webhook (PayU dashboard → Webhooks, URL
// <APP_BASE_URL>/payments/payu/webhook). The payload is only a hint about
// WHICH txnid changed: its status and hash are not trusted. We ask PayU's
// verify API ourselves and apply that answer, so a forged webhook can at most
// make us check an order. Always 200, so it reveals nothing about our orders.
const webhookLimit = rateLimit({ name: "payu-webhook", windowSeconds: 600, max: 300, key: (req) => req.ip });
router.post("/payments/payu/webhook", webhookLimit, async (req, res) => {
  const txnid = String((req.body && req.body.txnid) || "").trim().slice(0, 64);
  if (txnid) {
    try {
      const results = await reconcilePayuOrders(pool, { txnids: [txnid] });
      for (const line of results.map(describeResult).filter(Boolean)) console.log(`(webhook) ${line}`);
    } catch (err) {
      console.error("PayU webhook check failed:", err.message);
    }
  }
  res.json({ received: true });
});

// H19 (instant check): the buyer's payment in progress for an event, if any
// (PayU checkout started, seat hold still active). The booking page shows it
// instead of letting the buyer start a second checkout blindly.
router.get("/orders/pending", requireBuyer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM orders
       WHERE user_id = $1 AND event_id = $2 AND payment_method = 'payu'
         AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [req.buyer.sub, String(req.query.eventId || "")],
    );
    res.json({ order: result.rows[0] ? publicOrder(result.rows[0]) : null });
  } catch (err) {
    console.error("Pending order lookup failed:", err);
    res.status(500).json({ error: "Could not load your payment" });
  }
});

// H19 (instant check): the buyer is back on the site, or is waiting while the
// PayU window is open, with a checkout that is not confirmed yet. Returns the
// order (and ticket) and, at most once per 15 seconds per order and 45 times
// per 10 minutes per buyer, first asks PayU about it through the same path as
// the webhook and the poll. Calls in between only read our database, so the
// page can poll this every few seconds (a browser callback shows up at once)
// without hammering PayU. Owner only: 404 otherwise, so IDs cannot be probed.
const PAYU_CHECK = { perOrderSeconds: 15, perBuyerMax: 45, perBuyerWindowSeconds: 600 };
const orderCheckLimit = rateLimit({ name: "order-check-user", windowSeconds: 600, max: 300,
  key: (req) => req.buyer && String(req.buyer.sub), message: "Too many checks. Please wait a minute." });
router.post("/orders/:orderId/check", requireBuyer, orderCheckLimit, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "");
    const current = await getOrderForBuyer(pool, orderId, req.buyer.sub);
    if (!current) return res.status(404).json({ error: "Order not found" });
    const { order } = current;
    let checkedWithPayu = false;
    if (order.payment_method === "payu" && ["pending", "expired"].includes(order.status)) {
      const orderAllowed = await consumeRateLimit(pool, { name: "payu-check-order", windowSeconds: PAYU_CHECK.perOrderSeconds, max: 1, id: orderId });
      const buyerAllowed = orderAllowed && await consumeRateLimit(pool, {
        name: "payu-check-user", windowSeconds: PAYU_CHECK.perBuyerWindowSeconds, max: PAYU_CHECK.perBuyerMax, id: String(req.buyer.sub),
      });
      if (orderAllowed && buyerAllowed) {
        const results = await reconcilePayuOrders(pool, { txnids: [order.txnid] });
        for (const line of results.map(describeResult).filter(Boolean)) console.log(`(buyer check) ${line}`);
        checkedWithPayu = true;
      }
    }
    const result = checkedWithPayu ? await getOrderForBuyer(pool, orderId, req.buyer.sub) : current;
    res.json({
      order: publicOrder(result.order),
      booking: result.booking ? await ticketResponse(result.booking) : null,
      checkedWithPayu,
    });
  } catch (err) {
    console.error("Order check failed:", err);
    res.status(500).json({ error: "Could not check your payment" });
  }
});

// The buyer's own order and ticket. Someone else's order → 404, so order IDs
// cannot be probed.
router.get("/orders/:orderId", requireBuyer, async (req, res) => {
  try {
    const result = await getOrderForBuyer(pool, String(req.params.orderId || ""), req.buyer.sub);
    if (!result) return res.status(404).json({ error: "Order not found" });
    res.json({
      order: publicOrder(result.order),
      booking: result.booking ? await ticketResponse(result.booking) : null,
    });
  } catch (err) {
    console.error("Order load failed:", err);
    res.status(500).json({ error: "Could not load order" });
  }
});

module.exports = router;
