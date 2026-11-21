// Staff routes: login, public share link lookup, dashboard, offline sales,
// withdrawals (H10).
const express = require("express");
const { pool } = require("../db/pool");
const bcrypt = require("bcrypt");
const { creatorEventSalesQuery } = require("../db/queries");
const { staffWallet, requestWithdrawal, WalletError } = require("../services/staffWallet");
const {
  publicStaff,
  publicStaffShareUrl,
  publicStaffAssignment,
  publicCreatorEvent,
  publicStaffSale,
  publicStaffWithdrawal,
  EVENT_NOT_FOUND_ERROR,
} = require("../utils/serializers");
const { startSession } = require("../services/sessions");
const { requireStaff } = require("../middleware/auth");
const { eventSalesClosed, isEventBookable } = require("../utils/events");
const crypto = require("crypto");
const { ticketResponse } = require("../services/tickets");

const router = express.Router();

router.post("/staff/login", async (req, res) => {
  try {
    const staffId = String((req.body && req.body.staffId) || "").trim();
    const cleanStaffId = staffId.toLowerCase();
    const digits = staffId.replace(/\D/g, "");
    const password = String((req.body && req.body.password) || "");
    if (!staffId || !password) {
      return res
        .status(400)
        .json({ error: "Staff login ID and password are required" });
    }
    // H17: only treat the input as a phone number when it has at least 10
    // digits; otherwise "evil.staff" (no digits) matched every staff member
    // without a phone. Exact login ID wins over email, email over phone.
    const phoneDigits = digits.length >= 10 ? digits.slice(-10) : null;
    const result = await pool.query(
      `SELECT *
       FROM staff_accounts
       WHERE status='active'
         AND (
           LOWER(staff_id)=$1
           OR LOWER(COALESCE(email,''))=$1
           OR ($2::text IS NOT NULL AND RIGHT(regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g'), 10)=$2)
         )
       ORDER BY CASE WHEN LOWER(staff_id)=$1 THEN 0 WHEN LOWER(COALESCE(email,''))=$1 THEN 1 ELSE 2 END
       LIMIT 1`,
      [cleanStaffId, phoneDigits],
    );
    // Same answer for "no such staff" and "wrong password" (no account enumeration).
    if (!result.rows.length || !result.rows[0].password) {
      return res.status(401).json({ error: "Invalid staff login ID or password" });
    }
    const member = result.rows[0];
    const ok = await bcrypt.compare(password, member.password);
    if (!ok)
      return res
        .status(401)
        .json({ error: "Invalid staff login ID or password" });
    const [assignments, events, sales, withdrawals, wallet] = await Promise.all(
      [
        pool.query(
          "SELECT * FROM staff_assignments WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        pool.query(
          `${creatorEventSalesQuery}
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
          [member.creator_id],
        ),
        pool.query(
          "SELECT * FROM staff_sales WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        pool.query(
          "SELECT * FROM staff_withdrawals WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        staffWallet(pool, member.id),
      ],
    );
    res.json({
      message: "Staff login successful",
      staff: publicStaff({
        ...member,
        share_url: publicStaffShareUrl(req, member),
      }),
      assignments: assignments.rows.map(publicStaffAssignment),
      events: events.rows.map(publicCreatorEvent),
      sales: sales.rows.map(publicStaffSale),
      withdrawals: withdrawals.rows.map(publicStaffWithdrawal),
      wallet,
      ...(await startSession(pool, req, res, { role: "staff", accountId: member.id })),
    });
  } catch (err) {
    console.error("Staff login failed:", err);
    res.status(500).json({ error: "Staff login failed" });
  }
});

router.get("/staff/share/:token", async (req, res) => {
  try {
    const token = decodeURIComponent(String(req.params.token || ""))
      .trim()
      .replace(/[.)\]\s]+$/g, "");
    // Share links resolve by the secret share token only (D12); looking up
    // staff by email/phone/login ID let anyone probe staff details.
    const result = await pool.query(
      `SELECT s.id, s.name, s.staff_id, s.share_token, s.primary_event_id, e.name AS event_name
       FROM staff_accounts s
       LEFT JOIN creator_events e ON e.id=s.primary_event_id
       WHERE s.status='active' AND s.share_token=$1`,
      [token],
    );
    if (!result.rows.length)
      return res.status(404).json({ error: "Staff share link not found" });
    const row = result.rows[0];
    res.json({
      staff: {
        id: row.id,
        name: row.name,
        staffId: row.staff_id,
        shareToken: row.share_token,
        primaryEventId: row.primary_event_id,
        eventName: row.event_name,
      },
    });
  } catch (err) {
    console.error("Staff share lookup failed:", err);
    res.status(500).json({ error: "Could not load staff share link" });
  }
});

router.get("/staff/dashboard", requireStaff, async (req, res) => {
  try {
    const staff = await pool.query(
      "SELECT * FROM staff_accounts WHERE id=$1 AND status='active'",
      [req.staff.sub],
    );
    if (!staff.rows.length)
      return res.status(404).json({ error: "Staff account not found" });
    const member = staff.rows[0];
    const [assignments, events, sales, withdrawals, wallet] = await Promise.all(
      [
        pool.query(
          "SELECT * FROM staff_assignments WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        pool.query(
          `${creatorEventSalesQuery}
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
          [member.creator_id],
        ),
        pool.query(
          "SELECT * FROM staff_sales WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        pool.query(
          "SELECT * FROM staff_withdrawals WHERE staff_id=$1 ORDER BY created_at DESC",
          [member.id],
        ),
        staffWallet(pool, member.id),
      ],
    );
    res.json({
      staff: publicStaff({
        ...member,
        share_url: publicStaffShareUrl(req, member),
      }),
      assignments: assignments.rows.map(publicStaffAssignment),
      events: events.rows.map(publicCreatorEvent),
      sales: sales.rows.map(publicStaffSale),
      withdrawals: withdrawals.rows.map(publicStaffWithdrawal),
      wallet,
    });
  } catch (err) {
    console.error("Staff dashboard failed:", err);
    res.status(500).json({ error: "Could not load staff dashboard" });
  }
});

router.post("/staff/sales", requireStaff, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      assignmentId,
      buyerName,
      buyerPhone,
      buyerEmail,
      qty,
      paymentMode,
    } = req.body || {};
    const cleanQty = Number(qty || 1);
    if (!assignmentId)
      return res.status(400).json({ error: "Select assigned tickets to sell" });
    if (!Number.isInteger(cleanQty) || cleanQty < 1)
      return res.status(400).json({ error: "Enter a valid ticket quantity" });
    const mode =
      String(paymentMode || "cash")
        .trim()
        .toLowerCase() === "online"
        ? "online"
        : "cash";
    await client.query("BEGIN");
    const staff = await client.query(
      "SELECT * FROM staff_accounts WHERE id=$1 AND status='active' FOR UPDATE",
      [req.staff.sub],
    );
    if (!staff.rows.length) throw new Error("Staff account not found");
    const assignment = await client.query(
      `SELECT a.*, e.event_date, e.venue, e.banner_url, e.status AS event_status
       FROM staff_assignments a
       JOIN creator_events e ON e.id=a.event_id
       WHERE a.id=$1 AND a.staff_id=$2
       FOR UPDATE OF a`,
      [assignmentId, req.staff.sub],
    );
    if (!assignment.rows.length) throw new Error("Assigned tickets not found");
    const assigned = assignment.rows[0];
    if (eventSalesClosed(assigned) || !isEventBookable(assigned.event_status)) {
      throw new Error(EVENT_NOT_FOUND_ERROR);
    }
    const remaining =
      Number(assigned.qty || 0) - Number(assigned.sold_count || 0);
    if (cleanQty > remaining)
      throw new Error(
        `Only ${remaining} tickets are available in this assignment`,
      );
    const id = `SLS-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const bookingId = `STF-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const assignmentMode =
      String(assigned.allocation_mode || "creator_quota") === "staff_owned"
        ? "staff_owned"
        : "creator_quota";
    // Q5b: older resale assignments cannot be sold from while resale is disabled.
    if (assignmentMode === "staff_owned") throw new Error("Staff resale is not available yet");
    const salePrice =
      assignmentMode === "staff_owned"
        ? Number(assigned.resale_price || assigned.price || 0)
        : Number(assigned.price || 0);
    const total = salePrice * cleanQty;
    const commission =
      assignmentMode === "creator_quota"
        ? Math.round((total * Number(assigned.commission_rate || 0)) / 100)
        : 0;
    const revenueOwner = assignmentMode === "staff_owned" ? "staff" : "creator";
    const qrToken = crypto.randomBytes(18).toString("hex");
    const savedBooking = await client.query(
      `INSERT INTO bookings (
        id, buyer_name, buyer_email, event_id, event_name, event_date, event_venue,
        event_banner, ticket_type, price, qty, total, status, qr_token, booked_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'upcoming',$13,NOW())
      RETURNING *`,
      [
        bookingId,
        String(buyerName || "Walk-in Customer").trim(),
        String(buyerEmail || "").trim() || null,
        assigned.event_id,
        assigned.event_name,
        assigned.event_date,
        assigned.venue,
        assigned.banner_url,
        assigned.tier_name,
        salePrice,
        cleanQty,
        total,
        qrToken,
      ],
    );
    const sale = await client.query(
      `INSERT INTO staff_sales (
        id, creator_id, staff_id, assignment_id, event_id, event_name, tier_name,
        buyer_name, buyer_phone, buyer_email, qty, price, total, payment_mode, booking_id,
        commission, revenue_owner, allocation_mode
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING *`,
      [
        id,
        staff.rows[0].creator_id,
        staff.rows[0].id,
        assigned.id,
        assigned.event_id,
        assigned.event_name,
        assigned.tier_name,
        String(buyerName || "Walk-in Customer").trim(),
        String(buyerPhone || "").trim() || null,
        String(buyerEmail || "").trim() || null,
        cleanQty,
        salePrice,
        total,
        mode,
        bookingId,
        commission,
        revenueOwner,
        assignmentMode,
      ],
    );
    await client.query(
      "UPDATE staff_assignments SET sold_count=sold_count+$1 WHERE id=$2",
      [cleanQty, assigned.id],
    );
    await client.query(
      "UPDATE staff_accounts SET sold_tickets=sold_tickets+$1, earnings=earnings+$2 WHERE id=$3",
      [
        cleanQty,
        revenueOwner === "staff" ? total : commission,
        staff.rows[0].id,
      ],
    );
    await client.query(
      `UPDATE creator_events e SET
         booking_count=COALESCE(s.tickets,0),
         revenue=COALESCE(s.revenue,0)
       FROM (
         SELECT event_id,
           COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
           COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
         FROM bookings
         WHERE event_id=$1
         GROUP BY event_id
       ) s
       WHERE e.id=s.event_id`,
      [assigned.event_id],
    );
    await client.query("COMMIT");
    const wallet = await staffWallet(pool, staff.rows[0].id);
    res.status(201).json({
      message: "Ticket sold successfully",
      sale: publicStaffSale(sale.rows[0]),
      booking: await ticketResponse(savedBooking.rows[0]),
      wallet,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Staff sale failed:", err);
    res.status(400).json({ error: err.message || "Could not sell ticket" });
  } finally {
    client.release();
  }
});

router.post("/staff/withdrawals", requireStaff, async (req, res) => {
  try {
    const body = req.body || {};
    const method = String(body.method || "upi").trim().toLowerCase() === "bank" ? "bank" : "upi";
    const bankAccountName = String(body.bankAccountName || "").trim();
    const bankAccountNumber = String(body.bankAccountNumber || "").trim();
    const bankIfsc = String(body.bankIfsc || "").trim().toUpperCase();
    const upiId = String(body.upiId || "").trim();
    if (method === "bank" && (!bankAccountName || !bankAccountNumber || !bankIfsc)) {
      return res.status(400).json({ error: "Add bank account name, account number, and IFSC before withdrawal" });
    }
    if (method === "upi" && !upiId) {
      return res.status(400).json({ error: "Add a UPI ID before withdrawal" });
    }
    const result = await requestWithdrawal(pool, req.staff.sub, {
      amount: body.amount, method, bankAccountName, bankAccountNumber, bankIfsc, upiId,
    });
    res.status(201).json({
      message: "Withdrawal requested successfully",
      withdrawal: publicStaffWithdrawal(result.withdrawal),
      wallet: result.wallet,
    });
  } catch (err) {
    if (err instanceof WalletError) return res.status(err.status).json({ error: err.message });
    console.error("Staff withdrawal failed:", err);
    res.status(500).json({ error: "Could not request withdrawal" });
  }
});

module.exports = router;
