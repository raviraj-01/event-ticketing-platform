// Admin panel data (M4, M8). Totals and chart data are computed in SQL over
// ALL rows; lists are sent one page at a time. Before this, the snapshot sent
// every user, booking and payment and the browser added them up, so paging the
// lists would have silently changed the totals.
// Revenue never counts refunded bookings (M8).
const { readPage, pageOf } = require("../utils/paging");
const { normalizeUserStatus } = require("../utils/accounts");
const { publicCreatorEvent } = require("../utils/serializers");

const NOT_REFUNDED = "status <> 'refunded'";
// Charts bucket by Indian time, like the browser did before.
const LOCAL_TIME = "AT TIME ZONE 'Asia/Kolkata'";

async function adminStats(pool) {
  const [totals, monthly, daily, categories, topEvents, cities, leaderboard] = await Promise.all([
    pool.query(`SELECT
      (SELECT COALESCE(SUM(total),0) FROM bookings WHERE ${NOT_REFUNDED})::NUMERIC AS gmv,
      (SELECT COALESCE(SUM(qty),0) FROM bookings WHERE ${NOT_REFUNDED})::INTEGER AS tickets,
      (SELECT COUNT(*) FROM bookings)::INTEGER AS booking_count,
      (SELECT COALESCE(SUM(platform_fee),0) FROM orders WHERE status = 'paid')::NUMERIC AS platform_fees,
      (SELECT COUNT(*) FROM payment_transactions)::INTEGER AS payment_records,
      (SELECT COUNT(*) FROM payment_transactions WHERE status = 'Success')::INTEGER AS successful_payments,
      (SELECT COUNT(*) FROM creator_events)::INTEGER AS events,
      (SELECT COUNT(*) FROM creator_events WHERE status = 'live')::INTEGER AS live_events,
      (SELECT COUNT(*) FROM creator_events WHERE status = 'pending')::INTEGER AS pending_events,
      (SELECT COUNT(*) FROM creator_accounts)::INTEGER AS creators,
      (SELECT COUNT(*) FROM users)::INTEGER AS buyers,
      (SELECT COUNT(*) FROM staff_accounts)::INTEGER AS staff,
      (SELECT COALESCE(SUM(sold_tickets),0) FROM staff_accounts)::INTEGER AS staff_sold,
      (SELECT COALESCE(SUM(earnings),0) FROM staff_accounts)::NUMERIC AS staff_earnings,
      -- Same definition the payments page used: revenue of creators still pending review.
      (SELECT COALESCE(SUM(b.total),0) FROM bookings b JOIN creator_events e ON e.id = b.event_id
         JOIN creator_accounts c ON c.id = e.creator_id
         WHERE c.kyc_status = 'Pending' AND b.${NOT_REFUNDED})::NUMERIC AS pending_payouts`),
    pool.query(`SELECT to_char(date_trunc('month', booked_at ${LOCAL_TIME}), 'YYYY-MM') AS month,
        COALESCE(SUM(total),0)::NUMERIC AS revenue, COALESCE(SUM(qty),0)::INTEGER AS tickets
      FROM bookings
      WHERE ${NOT_REFUNDED}
        AND booked_at ${LOCAL_TIME} >= date_trunc('month', NOW() ${LOCAL_TIME}) - INTERVAL '11 months'
      GROUP BY 1 ORDER BY 1`),
    pool.query(`SELECT to_char(booked_at ${LOCAL_TIME}, 'YYYY-MM-DD') AS day, COALESCE(SUM(total),0)::NUMERIC AS revenue
      FROM bookings
      WHERE ${NOT_REFUNDED} AND booked_at ${LOCAL_TIME} >= date_trunc('day', NOW() ${LOCAL_TIME}) - INTERVAL '13 days'
      GROUP BY 1 ORDER BY 1`),
    pool.query(`SELECT COALESCE(NULLIF(TRIM(category), ''), 'Other') AS label, COUNT(*)::INTEGER AS count
      FROM creator_events GROUP BY 1 ORDER BY 2 DESC, 1`),
    pool.query(`SELECT e.id, e.name, COALESCE(SUM(b.total) FILTER (WHERE b.${NOT_REFUNDED}), 0)::NUMERIC AS revenue
      FROM creator_events e LEFT JOIN bookings b ON b.event_id = e.id
      GROUP BY e.id ORDER BY revenue DESC, e.created_at DESC LIMIT 5`),
    pool.query(`SELECT COALESCE(NULLIF(TRIM(e.city), ''), 'Unknown') AS city, COALESCE(SUM(b.qty),0)::INTEGER AS tickets
      FROM bookings b LEFT JOIN creator_events e ON e.id = b.event_id
      WHERE b.${NOT_REFUNDED} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5`),
    pool.query(`SELECT COALESCE(MAX(e.creator_name), 'Unknown') AS name, COUNT(DISTINCT e.id)::INTEGER AS events,
        COALESCE(SUM(b.total) FILTER (WHERE b.${NOT_REFUNDED}), 0)::NUMERIC AS revenue
      FROM creator_events e LEFT JOIN bookings b ON b.event_id = e.id
      GROUP BY e.creator_id ORDER BY revenue DESC, events DESC LIMIT 5`),
  ]);
  const t = totals.rows[0];
  const num = (v) => Number(v || 0);
  return {
    gmv: num(t.gmv),
    tickets: t.tickets,
    bookingCount: t.booking_count,
    platformFees: num(t.platform_fees),
    averageOrderValue: t.booking_count ? Math.round(num(t.gmv) / t.booking_count) : 0,
    paymentRecords: t.payment_records,
    successfulPayments: t.successful_payments,
    events: t.events,
    liveEvents: t.live_events,
    pendingEvents: t.pending_events,
    creators: t.creators,
    buyers: t.buyers,
    staff: t.staff,
    staffSold: t.staff_sold,
    staffEarnings: num(t.staff_earnings),
    pendingPayouts: num(t.pending_payouts),
    monthly: monthly.rows.map((r) => ({ month: r.month, revenue: num(r.revenue), tickets: r.tickets })),
    daily: daily.rows.map((r) => ({ day: r.day, revenue: num(r.revenue) })),
    categories: categories.rows,
    topEvents: topEvents.rows.map((r) => ({ id: r.id, name: r.name, revenue: num(r.revenue) })),
    cities: cities.rows,
    creatorLeaderboard: leaderboard.rows.map((r) => ({ name: r.name, events: r.events, revenue: num(r.revenue) })),
  };
}

// ── Lists. Each takes { limit, offset } and returns { items, paging }. ──

const buyerView = (buyer) => ({
  id: `USR-${buyer.id}`,
  name: buyer.username || [buyer.first_name, buyer.last_name].filter(Boolean).join(" ") || buyer.email,
  email: buyer.email,
  city: buyer.city || "",
  bookings: Number(buyer.bookings || 0),
  status: normalizeUserStatus(buyer.status),
  createdAt: buyer.created_at,
});

const ledgerView = (row) => ({
  id: row.id,
  orderId: row.order_id,
  userId: row.user_id,
  buyerEmail: row.buyer_email,
  buyer: row.buyer_email || "Buyer",
  eventId: row.event_id,
  eventName: row.event_name,
  ticketType: row.ticket_type,
  price: Number(row.price || 0),
  qty: Number(row.qty || 0),
  // Ticket subtotal, and what the order actually charged (fee + GST on top);
  // null where unknown (legacy bookings without an order, payment-only rows).
  subtotal: row.subtotal == null ? null : Number(row.subtotal),
  fee: row.fee == null ? null : Number(row.fee),
  gst: row.gst == null ? null : Number(row.gst),
  total: row.amount == null ? null : Number(row.amount),
  status: row.booking_status,
  // Payment status for the ledger (Refunded for refunded bookings).
  paymentStatus: row.payment_status,
  bookedAt: row.at,
  _paymentOnly: row.payment_only,
  payment: row.txnid ? {
    gateway: String(row.txnid).startsWith("LEGACY-") ? "Legacy Imported" : "PayU",
    status: row.payment_status,
    txnid: row.txnid,
    verified: row.verified,
  } : null,
});

const staffView = (member) => ({
  id: member.id,
  creatorId: member.creator_id,
  name: member.name,
  staffId: member.staff_id,
  email: member.email,
  phone: member.phone,
  status: member.status,
  assignedTickets: Number(member.assigned_tickets || 0),
  soldTickets: Number(member.sold_tickets || 0),
  earnings: Number(member.earnings || 0),
  createdAt: member.created_at,
});

const LISTS = {
  buyers: {
    sql: `SELECT u.id, u.username, u.first_name, u.last_name, u.email, u.city, u.status, u.created_at,
        (SELECT COUNT(*) FROM bookings b
          WHERE b.user_id = u.id OR (b.user_id IS NULL AND LOWER(b.buyer_email) = LOWER(u.email)))::INTEGER AS bookings
      FROM users u ORDER BY u.created_at DESC, u.id DESC LIMIT $1 OFFSET $2`,
    view: buyerView,
  },
  creators: {
    sql: `SELECT c.id, c.name, c.email, c.phone, c.category, c.kyc_status, c.created_at,
        (SELECT COUNT(*) FROM creator_events e WHERE e.creator_id = c.id)::INTEGER AS events,
        (SELECT COALESCE(SUM(b.total),0) FROM creator_events e JOIN bookings b ON b.event_id = e.id
          WHERE e.creator_id = c.id AND b.${NOT_REFUNDED})::NUMERIC AS revenue,
        (SELECT COALESCE(json_agg(d ORDER BY d.created_at DESC), '[]') FROM creator_kyc_documents d
          WHERE d.creator_id = c.id) AS documents
      FROM creator_accounts c ORDER BY c.created_at DESC, c.id DESC LIMIT $1 OFFSET $2`,
    view: (row) => row, // shaped by the route (KYC documents for super admins only)
  },
  events: {
    // $3: optional status filter (the Pending / Blocked tabs).
    sql: `SELECT e.*,
        COALESCE(SUM(b.qty) FILTER (WHERE b.${NOT_REFUNDED}), 0)::INTEGER AS booking_count,
        COALESCE(SUM(b.total) FILTER (WHERE b.${NOT_REFUNDED}), 0)::NUMERIC AS revenue
      FROM creator_events e LEFT JOIN bookings b ON b.event_id = e.id
      WHERE ($3::text IS NULL OR e.status = $3)
      GROUP BY e.id ORDER BY e.created_at DESC, e.id DESC LIMIT $1 OFFSET $2`,
    view: publicCreatorEvent,
    filtered: true,
  },
  // Payments ledger: every booking with its payment record (joined by order id,
  // or booking id for legacy rows), plus payment records that have no booking
  // (failed, cancelled, refund needed). $3: optional payment status filter.
  ledger: {
    sql: `SELECT * FROM (
        SELECT b.id, b.order_id, b.user_id, b.buyer_email, b.event_id, b.event_name, b.ticket_type,
          b.price, b.qty, b.total AS subtotal, o.platform_fee AS fee, o.gst, o.amount,
          b.status AS booking_status, b.booked_at AS at, FALSE AS payment_only,
          pt.txnid,
          -- A refunded booking shows as Refunded whatever its payment record says.
          CASE WHEN b.status = 'refunded' THEN 'Refunded' ELSE COALESCE(pt.status, 'Success') END AS payment_status,
          pt.verified
        FROM bookings b
        LEFT JOIN orders o ON o.id = b.order_id
        LEFT JOIN payment_transactions pt ON pt.booking_id = COALESCE(b.order_id, b.id)
        UNION ALL
        SELECT COALESCE(pt.booking_id, pt.txnid), pt.booking_id, NULL, pt.buyer_email, pt.event_id, pt.event_id,
          pt.ticket_type, NULL, pt.qty, NULL, NULL, NULL, pt.amount, NULL, pt.updated_at, TRUE,
          pt.txnid, pt.status, pt.verified
        FROM payment_transactions pt
        WHERE NOT EXISTS (SELECT 1 FROM bookings b WHERE COALESCE(b.order_id, b.id) = pt.booking_id)
      ) ledger
      WHERE ($3::text IS NULL OR payment_status = $3)
      ORDER BY at DESC NULLS LAST, id DESC LIMIT $1 OFFSET $2`,
    view: ledgerView,
    filtered: true,
  },
  // Buyers and creators together (the "All users" tab).
  users: {
    sql: `SELECT * FROM (
        SELECT 'USR-' || id AS id, COALESCE(NULLIF(username, ''), email) AS name, email, status, created_at, 'buyer' AS source FROM users
        UNION ALL
        SELECT 'CRT-' || id, name, email, kyc_status, created_at, 'creator' FROM creator_accounts
      ) u ORDER BY created_at DESC NULLS LAST, id DESC LIMIT $1 OFFSET $2`,
    view: (row) => ({ id: row.id, name: row.name, email: row.email, status: row.status, createdAt: row.created_at, source: row.source }),
  },
  staff: {
    sql: "SELECT * FROM staff_accounts ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
    view: staffView,
  },
};

async function adminList(pool, kind, query = {}) {
  const list = LISTS[kind];
  if (!list) return null;
  const page = readPage(query, { defaultLimit: 100, maxLimit: 100 });
  const params = [page.limit + 1, page.offset];
  if (list.filtered) params.push(query.status ? String(query.status) : null);
  const result = await pool.query(list.sql, params);
  const { rows, paging } = pageOf(result.rows, page);
  return { items: rows.map(list.view), paging };
}

module.exports = { adminStats, adminList, ADMIN_LIST_KINDS: Object.keys(LISTS) };
