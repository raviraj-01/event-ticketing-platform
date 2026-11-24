// Orders: the only way a buyer gets a ticket (C4).
//
// Rules (agreed with Ravi, see CLAUDE.md "Key design decisions"):
//  - Price, quantity limits and inventory are decided here from the database,
//    never from the request.
//  - Inventory is reserved atomically: the event row is locked (SELECT … FOR
//    UPDATE) while we count seats, so two buyers cannot both get the last seat.
//  - Paid tiers: a 'pending' order holds seats for 15 minutes; the ticket is
//    issued only when the verified PayU callback marks the order 'paid'.
//  - Free tiers: confirmed immediately, same inventory check, per-user limit.
//  - Lock order is always event → order, so two transactions never deadlock.
const crypto = require("crypto");
const { isEventBookable, eventSalesClosed } = require("../utils/events");

const intFromEnv = (name, fallback) => {
  const value = Number(process.env[name]);
  return Number.isInteger(value) && value > 0 ? value : fallback;
};
const percentFromEnv = (name, fallback) => {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value >= 0 && value <= 100 ? value : fallback;
};

const ORDER_SETTINGS = {
  platformFeePercent: percentFromEnv("PLATFORM_FEE_PERCENT", 8),
  gstPercent: percentFromEnv("GST_PERCENT", 18),
  maxTicketsPerOrder: intFromEnv("MAX_TICKETS_PER_ORDER", 10),
  freeTicketsPerUserPerEvent: intFromEnv("FREE_TICKETS_PER_USER_PER_EVENT", 2),
  holdMinutes: 15,
};

class OrderError extends Error {
  // code: optional machine-readable reason the client can act on.
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// PayU needs a real mobile number. 10 digits after removing spaces, +91 etc.
const payablePhone = (phone) => {
  const digits = String(phone || "").replace(/\D/g, "").slice(-10);
  return /^[6-9]\d{9}$/.test(digits) ? digits : null;
};

const roundMoney = (value) => Math.round(value * 100) / 100;
const randomId = (prefix, bytes) => `${prefix}${crypto.randomBytes(bytes).toString("hex")}`;

// The organizer's side of their ticket sales: the ONE formula used by
// analytics, finance and the admin panel (M8).
// Q16 (decided 2026-11-22): the platform fee + GST is charged to the BUYER on
// top of the ticket price at checkout (priceOrder). gross = ticket subtotals
// (bookings.total), so the organizer is charged nothing: fee 0, net = gross.
// buyerFeePercent is only for display ("buyers pay X% on top").
function organizerEarnings(gross) {
  const cleanGross = roundMoney(Number(gross) || 0);
  return { gross: cleanGross, fee: 0, net: cleanGross, buyerFeePercent: ORDER_SETTINGS.platformFeePercent };
}

// Same formula the checkout page shows: tickets + platform fee + GST on the fee.
function priceOrder(unitPrice, qty) {
  const subtotal = roundMoney(unitPrice * qty);
  const platformFee = subtotal > 0 ? roundMoney((subtotal * ORDER_SETTINGS.platformFeePercent) / 100) : 0;
  const gst = platformFee > 0 ? roundMoney((platformFee * ORDER_SETTINGS.gstPercent) / 100) : 0;
  return { subtotal, platformFee, gst, amount: roundMoney(subtotal + platformFee + gst) };
}

// Seats in use. Must be called while the event row is locked.
//   eventUsed: every issued ticket (online + staff sales) + live online holds
//   tierUsed : online orders for this tier that are paid or still on hold
//              (staff quota was already removed from the tier's qty at assignment)
async function seatUsage(client, eventId, tierName, excludeOrderId = "") {
  const result = await client.query(
    `SELECT
       (SELECT COALESCE(SUM(qty), 0) FROM bookings
         WHERE event_id = $1 AND COALESCE(status, '') <> 'refunded')::INTEGER AS booked,
       (SELECT COALESCE(SUM(qty), 0) FROM orders
         WHERE event_id = $1 AND id <> $3 AND status = 'pending' AND expires_at > NOW())::INTEGER AS held,
       (SELECT COALESCE(SUM(qty), 0) FROM orders
         WHERE event_id = $1 AND tier_name = $2 AND id <> $3
           AND (status = 'paid' OR (status = 'pending' AND expires_at > NOW())))::INTEGER AS tier_used`,
    [eventId, tierName, excludeOrderId],
  );
  const row = result.rows[0];
  return { eventUsed: row.booked + row.held, tierUsed: row.tier_used };
}

function hasRoom(event, tier, usage, qty) {
  return (
    usage.eventUsed + qty <= Number(event.capacity || 0) &&
    usage.tierUsed + qty <= Number(tier.qty || 0)
  );
}

async function lockEvent(client, eventId) {
  const result = await client.query("SELECT * FROM creator_events WHERE id = $1 FOR UPDATE", [eventId]);
  return result.rows[0] || null;
}

const findTier = (event, tierName) =>
  (Array.isArray(event.tickets) ? event.tickets : []).find((tier) => tier.name === tierName) || null;

const digitsTail = (value) => String(value || "").replace(/\D/g, "").slice(-10);

// Staff referral: only the secret share_token counts, and only for an active
// staff member assigned to this event + tier. Self-referral earns nothing.
async function resolveReferral(client, shareToken, event, tierName, user) {
  const token = String(shareToken || "").trim();
  if (!token) return null;
  const result = await client.query(
    `SELECT s.id, s.email, s.phone, a.id AS assignment_id, a.commission_rate
     FROM staff_accounts s
     JOIN staff_assignments a ON a.staff_id = s.id AND a.event_id = $2 AND a.tier_name = $3
     WHERE s.share_token = $1 AND s.status = 'active'
     ORDER BY a.created_at DESC
     LIMIT 1`,
    [token, event.id, tierName],
  );
  const staff = result.rows[0];
  if (!staff) return null;
  const sameEmail = staff.email && user.email && staff.email.trim().toLowerCase() === user.email.trim().toLowerCase();
  const samePhone = digitsTail(staff.phone).length === 10 && digitsTail(staff.phone) === digitsTail(user.phone);
  if (sameEmail || samePhone) return null;
  return staff;
}

// Issue the ticket for a paid order. The unique index on bookings.order_id
// guarantees at most one ticket per order.
async function issueBooking(client, order, event, user) {
  const result = await client.query(
    `INSERT INTO bookings (
       id, user_id, buyer_name, buyer_email, event_id, event_name, event_date, event_venue,
       event_banner, ticket_type, price, qty, total, status, qr_token, order_id, booked_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'upcoming',$14,$15,NOW())
     RETURNING *`,
    [
      randomId("BKG-", 12),
      user.id,
      user.username || [user.first_name, user.last_name].filter(Boolean).join(" ") || user.email,
      user.email,
      event.id,
      event.name,
      event.event_date,
      event.venue,
      event.banner_url,
      order.tier_name,
      order.unit_price,
      order.qty,
      order.subtotal,
      crypto.randomBytes(18).toString("hex"),
      order.id,
    ],
  );
  return result.rows[0];
}

// Commission = ticket subtotal × the staff assignment's commission rate.
// Written only when the order becomes paid; free orders never get here.
async function recordReferralCommission(client, order, event, booking, user) {
  const staff = await client.query(
    `SELECT a.id AS assignment_id, a.commission_rate
     FROM staff_accounts s
     JOIN staff_assignments a ON a.staff_id = s.id AND a.event_id = $2 AND a.tier_name = $3
     WHERE s.id = $1 AND s.status = 'active'
     ORDER BY a.created_at DESC LIMIT 1`,
    [order.referral_staff_id, event.id, order.tier_name],
  );
  const assignment = staff.rows[0];
  if (!assignment) return null; // staff deactivated or unassigned since the order was created
  const commission = roundMoney((Number(order.subtotal) * Number(assignment.commission_rate || 0)) / 100);
  await client.query(
    `INSERT INTO staff_sales (
       id, creator_id, staff_id, assignment_id, event_id, event_name, tier_name,
       buyer_name, buyer_phone, buyer_email, qty, price, total, payment_mode, booking_id,
       commission, revenue_owner, allocation_mode, status, order_id
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'online',$14,$15,'creator','online_referral','active',$16)`,
    [
      randomId("SLS-", 8),
      event.creator_id,
      order.referral_staff_id,
      assignment.assignment_id,
      event.id,
      event.name,
      order.tier_name,
      booking.buyer_name,
      user.phone || null,
      user.email,
      order.qty,
      order.unit_price,
      order.subtotal,
      booking.id,
      commission,
      order.id,
    ],
  );
  await client.query(
    "UPDATE staff_accounts SET sold_tickets = sold_tickets + $1, earnings = earnings + $2 WHERE id = $3",
    [order.qty, commission, order.referral_staff_id],
  );
  return commission;
}

// Keep the denormalised counters on creator_events in sync with bookings.
async function refreshEventCounters(client, eventId) {
  await client.query(
    `UPDATE creator_events e SET
       booking_count = COALESCE(s.tickets, 0),
       revenue = COALESCE(s.revenue, 0)
     FROM (
       SELECT event_id,
         COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END), 0)::INTEGER AS tickets,
         COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END), 0)::NUMERIC AS revenue
       FROM bookings WHERE event_id = $1 GROUP BY event_id
     ) s
     WHERE e.id = s.event_id`,
    [eventId],
  );
}

async function loadBuyer(client, userId) {
  const result = await client.query(
    "SELECT id, username, first_name, last_name, email, phone, status FROM users WHERE id = $1",
    [userId],
  );
  return result.rows[0] || null;
}

// Create an order for a logged-in buyer.
// Returns { order, booking } for free tiers, { order, buyer, event } for paid tiers.
async function createOrder(pool, { userId, eventId, tierName, qty, shareToken }) {
  const cleanQty = Number(qty);
  if (!Number.isInteger(cleanQty) || cleanQty < 1 || cleanQty > ORDER_SETTINGS.maxTicketsPerOrder) {
    throw new OrderError(400, `Choose between 1 and ${ORDER_SETTINGS.maxTicketsPerOrder} tickets`);
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const event = await lockEvent(client, String(eventId || ""));
    if (!event || !isEventBookable(event.status)) throw new OrderError(404, "Event does not exist");
    if (eventSalesClosed(event)) throw new OrderError(409, "Ticket sales for this event have closed");
    const tier = findTier(event, String(tierName || ""));
    if (!tier) throw new OrderError(404, "Ticket type not found");
    const unitPrice = Number(tier.price);
    if (!Number.isFinite(unitPrice) || unitPrice < 0) throw new OrderError(409, "Ticket type is not on sale");

    const buyer = await loadBuyer(client, userId);
    if (!buyer) throw new OrderError(401, "Buyer login required");
    // Q14 / D24: paid checkout needs the buyer's phone (asked once, then saved
    // to the profile). Checked before any hold is released or created.
    if (unitPrice > 0 && !payablePhone(buyer.phone)) {
      throw new OrderError(400, "Add your phone number to pay", "phone_required");
    }

    // Starting a new checkout releases this buyer's earlier hold for the same
    // event, so one person cannot block the event with many open checkouts.
    await client.query(
      "UPDATE orders SET status = 'expired' WHERE user_id = $1 AND event_id = $2 AND status = 'pending'",
      [buyer.id, event.id],
    );

    const usage = await seatUsage(client, event.id, tier.name);
    if (!hasRoom(event, tier, usage, cleanQty)) throw new OrderError(409, "Not enough tickets left for this ticket type");

    const isFree = unitPrice === 0;
    if (isFree) {
      const owned = await client.query(
        `SELECT COALESCE(SUM(qty), 0)::INTEGER AS qty FROM orders
         WHERE user_id = $1 AND event_id = $2 AND payment_method = 'free' AND status = 'paid'`,
        [buyer.id, event.id],
      );
      if (owned.rows[0].qty + cleanQty > ORDER_SETTINGS.freeTicketsPerUserPerEvent) {
        throw new OrderError(409, `You can get at most ${ORDER_SETTINGS.freeTicketsPerUserPerEvent} free tickets for this event`);
      }
    }

    const referral = isFree ? null : await resolveReferral(client, shareToken, event, tier.name, buyer);
    const price = priceOrder(unitPrice, cleanQty);
    const orderId = randomId("ORD-", 12);
    const inserted = await client.query(
      `INSERT INTO orders (
         id, user_id, event_id, tier_name, qty, unit_price, subtotal, platform_fee, gst, amount,
         status, payment_method, txnid, referral_staff_id, expires_at, paid_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
         CASE WHEN $12 = 'payu' THEN NOW() + make_interval(mins => $15) END,
         CASE WHEN $12 = 'free' THEN NOW() END)
       RETURNING *`,
      [
        orderId, buyer.id, event.id, tier.name, cleanQty, unitPrice,
        price.subtotal, price.platformFee, price.gst, price.amount,
        isFree ? "paid" : "pending",
        isFree ? "free" : "payu",
        isFree ? null : randomId("TXN", 10),
        referral ? referral.id : null,
        ORDER_SETTINGS.holdMinutes,
      ],
    );
    const order = inserted.rows[0];

    if (isFree) {
      const booking = await issueBooking(client, order, event, buyer);
      await refreshEventCounters(client, event.id);
      await client.query("COMMIT");
      return { order, booking };
    }
    await client.query("COMMIT");
    return { order, buyer, event };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Apply a PayU callback whose hash was already verified by the caller.
// Returns { orderId, outcome } where outcome is one of:
//   'paid' | 'already_paid' | 'paid_needs_refund' | 'failed' | 'amount_mismatch' | 'unknown_order'
async function applyPayuResult(pool, body, { success }) {
  const txnid = String(body.txnid || "");
  const found = await pool.query("SELECT id, event_id FROM orders WHERE txnid = $1", [txnid]);
  if (!found.rows.length) return { orderId: null, outcome: "unknown_order" };
  const { id: orderId, event_id: eventId } = found.rows[0];

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const event = await lockEvent(client, eventId);
    const order = (await client.query("SELECT * FROM orders WHERE id = $1 FOR UPDATE", [orderId])).rows[0];

    // Gateways retry callbacks: a second success must not issue a second ticket.
    if (order.status === "paid" || order.status === "paid_needs_refund") {
      await client.query("COMMIT");
      return { orderId, outcome: order.status === "paid" ? "already_paid" : "paid_needs_refund" };
    }
    if (Number(body.amount).toFixed(2) !== Number(order.amount).toFixed(2)) {
      await client.query("ROLLBACK");
      return { orderId, outcome: "amount_mismatch" };
    }
    if (!success) {
      await client.query("UPDATE orders SET status = 'expired' WHERE id = $1", [orderId]);
      await client.query("COMMIT");
      return { orderId, outcome: "failed" };
    }

    // Paid inside the hold → seats are ours. Paid late → re-check seats now.
    const holdActive = order.status === "pending" && new Date(order.expires_at) > new Date();
    let canIssue = holdActive;
    if (!holdActive) {
      const tier = event ? findTier(event, order.tier_name) : null;
      const usage = tier ? await seatUsage(client, event.id, order.tier_name, order.id) : null;
      canIssue = Boolean(tier && hasRoom(event, tier, usage, order.qty));
    }
    const newStatus = canIssue ? "paid" : "paid_needs_refund";
    await client.query(
      "UPDATE orders SET status = $1, paid_at = NOW(), gateway_payment_id = $2 WHERE id = $3",
      [newStatus, String(body.mihpayid || "") || null, orderId],
    );
    if (canIssue) {
      const buyer = await loadBuyer(client, order.user_id);
      const booking = await issueBooking(client, order, event, buyer);
      if (order.referral_staff_id) await recordReferralCommission(client, order, event, booking, buyer);
      await refreshEventCounters(client, event.id);
    }
    await client.query("COMMIT");
    return { orderId, outcome: newStatus };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Audit trail for the admin "payments" view. Written only for results that
// were verified (callback hash, or PayU's verify API), so nobody can overwrite
// a payment record by posting fake data (H9). `result` has txnid, email,
// mihpayid and error_Message, as PayU names them.
const PAYMENT_STATUS_LABELS = {
  paid: "Success",
  already_paid: "Success",
  paid_needs_refund: "Paid - needs refund",
  failed: "Failed",
  amount_mismatch: "Amount mismatch",
};
async function recordPaymentResult(pool, result, orderId, outcome) {
  await pool.query(
    `INSERT INTO payment_transactions (
       txnid, booking_id, event_id, ticket_type, qty, buyer_email, amount,
       gateway_payment_id, status, verified, error, updated_at
     )
     SELECT $1, o.id, o.event_id, o.tier_name, o.qty, $2, o.amount, $3, $4, TRUE, $5, NOW()
     FROM orders o WHERE o.id = $6
     ON CONFLICT (txnid) DO UPDATE SET
       gateway_payment_id = COALESCE(EXCLUDED.gateway_payment_id, payment_transactions.gateway_payment_id),
       status = EXCLUDED.status,
       verified = TRUE,
       error = EXCLUDED.error,
       updated_at = NOW()`,
    [
      String(result.txnid || ""),
      String(result.email || "") || null,
      String(result.mihpayid || "") || null,
      PAYMENT_STATUS_LABELS[outcome] || outcome,
      outcome === "paid" || outcome === "already_paid" ? null : String(result.error_Message || outcome).slice(0, 200),
      orderId,
    ],
  );
}

// Order + its ticket, only for the buyer who owns it (null otherwise → caller sends 404).
async function getOrderForBuyer(pool, orderId, userId) {
  const order = await pool.query("SELECT * FROM orders WHERE id = $1 AND user_id = $2", [orderId, userId]);
  if (!order.rows.length) return null;
  const booking = await pool.query("SELECT * FROM bookings WHERE order_id = $1", [orderId]);
  return { order: order.rows[0], booking: booking.rows[0] || null };
}

// Adds `available` to each tier of public events, using the same counting
// rules as checkout (so the page shows what the server will actually allow).
async function withAvailability(pool, events) {
  if (!events.length) return events;
  const ids = events.map((event) => event.id);
  const usage = await pool.query(
    `SELECT e.id,
       (SELECT COALESCE(SUM(qty), 0) FROM bookings b
         WHERE b.event_id = e.id AND COALESCE(b.status, '') <> 'refunded')
       + (SELECT COALESCE(SUM(qty), 0) FROM orders o
         WHERE o.event_id = e.id AND o.status = 'pending' AND o.expires_at > NOW()) AS event_used,
       COALESCE((SELECT json_object_agg(t.tier_name, t.used) FROM (
         SELECT tier_name, SUM(qty)::INTEGER AS used FROM orders o
         WHERE o.event_id = e.id AND (o.status = 'paid' OR (o.status = 'pending' AND o.expires_at > NOW()))
         GROUP BY tier_name) t), '{}') AS tier_used
     FROM creator_events e WHERE e.id = ANY($1)`,
    [ids],
  );
  const byId = new Map(usage.rows.map((row) => [row.id, row]));
  return events.map((event) => {
    const row = byId.get(event.id) || { event_used: 0, tier_used: {} };
    const eventLeft = Math.max(0, Number(event.capacity || 0) - Number(row.event_used || 0));
    const tickets = (event.tickets || []).map((tier) => ({
      ...tier,
      available: Math.max(0, Math.min(Number(tier.qty || 0) - Number(row.tier_used[tier.name] || 0), eventLeft)),
    }));
    return { ...event, tickets };
  });
}

// Pending orders past their hold no longer count anyway; this just tidies status.
async function expireStaleOrders(pool) {
  await pool.query("UPDATE orders SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()");
}

module.exports = {
  ORDER_SETTINGS,
  OrderError,
  priceOrder,
  createOrder,
  applyPayuResult,
  recordPaymentResult,
  getOrderForBuyer,
  withAvailability,
  expireStaleOrders,
  payablePhone,
  organizerEarnings,
};
