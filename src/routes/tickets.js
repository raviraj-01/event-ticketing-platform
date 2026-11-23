// Ticket routes: a buyer's tickets, one ticket (owner / creator / assigned
// staff only, C6) and the gate scan (row lock, see the Study guide).
const express = require("express");
const { pool } = require("../db/pool");
const { ticketResponse } = require("../services/tickets");
const { requireBuyer, requireTicketViewer, requireScanIdentity } = require("../middleware/auth");
const crypto = require("crypto");
const { readPage, pageOf } = require("../utils/paging");

const router = express.Router();

// A buyer's tickets = bookings whose user_id is the buyer's own id.
// No matching by email: guest bookings (user_id NULL) and staff walk-in sales
// stay unreachable here, so registering with someone's email reveals nothing (C6).
// Paged (M4): every ticket renders a QR image, so a long history is costly.
const listBuyerTickets = async (userId, query) => {
  const page = readPage(query, { defaultLimit: 100, maxLimit: 100 });
  const result = await pool.query(
    "SELECT * FROM bookings WHERE user_id=$1 ORDER BY booked_at DESC, id LIMIT $2 OFFSET $3",
    [userId, page.limit + 1, page.offset],
  );
  const { rows, paging } = pageOf(result.rows, page);
  return { bookings: await Promise.all(rows.map(ticketResponse)), paging };
};

router.get("/bookings/mine", requireBuyer, async (req, res) => {
  try {
    res.json(await listBuyerTickets(req.buyer.sub, req.query));
  } catch (err) {
    console.error("Buyer booking history failed:", err);
    res.status(500).json({ error: "Could not load booking history" });
  }
});

// Same list; kept because the profile page calls this path.
router.get("/profile/tickets", requireBuyer, async (req, res) => {
  try {
    res.json(await listBuyerTickets(req.buyer.sub, req.query));
  } catch (err) {
    console.error("Profile tickets failed:", err);
    res.status(500).json({ error: "Could not load profile tickets" });
  }
});


router.get("/bookings/:bookingId/ticket", requireTicketViewer, async (req, res) => {
  try {
    const bookingId = String(req.params.bookingId || "").trim();
    const viewer = req.ticketViewer;
    // One query decides access: the row comes back only if this viewer may see it.
    let result = await pool.query(
      `SELECT b.* FROM bookings b
       LEFT JOIN creator_events e ON e.id = b.event_id
       WHERE b.id = $1
         AND (
           ($2 = 'buyer' AND b.user_id::text = $3)
           OR ($2 = 'creator' AND e.creator_id::text = $3)
           OR ($2 = 'staff' AND EXISTS (
                 SELECT 1 FROM staff_assignments sa
                 WHERE sa.staff_id = $3 AND sa.event_id = b.event_id
               ))
         )`,
      [bookingId, viewer.type, String(viewer.id)],
    );
    if (!result.rows.length) return res.status(404).json({ error: "Ticket not found" });
    if (!result.rows[0].qr_token) {
      result = await pool.query(
        "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
        [crypto.randomBytes(18).toString("hex"), bookingId],
      );
    }
    res.json({ booking: await ticketResponse(result.rows[0]) });
  } catch (err) {
    console.error("Ticket load failed:", err);
    res.status(500).json({ error: "Could not load ticket" });
  }
});

router.post("/bookings/scan", requireScanIdentity, async (req, res) => {
  const client = await pool.connect();
  try {
    const payload = String((req.body && req.body.qrPayload) || "").trim();
    const parts = payload.split("|");
    if ((parts.length !== 3 && parts.length !== 4) || parts[0] !== "VYBERA-TICKET") {
      return res.status(400).json({ result: "invalid", error: "Invalid BLAK Tickets ticket QR" });
    }
    const bookingId = parts[1];
    const qrEventId = parts.length === 4 && parts[2] !== "NOEVENT" ? parts[2] : null;
    const qrToken = parts.length === 4 ? parts[3] : parts[2];
    await client.query("BEGIN");
    const scanIdentity = req.scanIdentity || {};
    let result;
    if (scanIdentity.type === "creator") {
      result = await client.query(
        `SELECT b.* FROM bookings b
         JOIN creator_events e ON e.id=b.event_id
         WHERE b.id=$1
           AND b.qr_token=$2
           AND ($4::text IS NULL OR b.event_id=$4)
           AND e.creator_id=$3
         FOR UPDATE OF b`,
        [bookingId, qrToken, scanIdentity.payload.sub, qrEventId],
      );
    } else {
      result = await client.query(
        `SELECT b.* FROM bookings b
         JOIN creator_events e ON e.id=b.event_id
         LEFT JOIN staff_assignments sa
           ON sa.event_id=b.event_id AND sa.staff_id=$3
         LEFT JOIN staff_accounts st
           ON st.id=$3 AND st.status='active'
         WHERE b.id=$1
           AND b.qr_token=$2
           AND ($4::text IS NULL OR b.event_id=$4)
           AND st.id IS NOT NULL
           -- D22 / M18: staff scan only events they are assigned to (an
           -- assignment or their primary event). Admin-created staff with no
           -- event used to be able to scan every event.
           AND (
             sa.id IS NOT NULL
             OR st.primary_event_id=b.event_id
           )
         FOR UPDATE OF b`,
        [bookingId, qrToken, scanIdentity.payload.sub, qrEventId],
      );
    }
    if (!result.rows.length) {
      const ticketCheck = await client.query(
        "SELECT id, event_id FROM bookings WHERE id=$1 AND qr_token=$2 AND ($3::text IS NULL OR event_id=$3) LIMIT 1",
        [bookingId, qrToken, qrEventId],
      );
      await client.query("ROLLBACK");
      if (ticketCheck.rows.length && scanIdentity.type === "staff") {
        return res.status(403).json({
          result: "invalid",
          error: "This staff account is not assigned to this event",
        });
      }
      return res.status(404).json({ result: "invalid", error: "Ticket not found" });
    }
    const booking = result.rows[0];
    if (booking.status === "refunded") {
      await client.query("ROLLBACK");
      return res.status(409).json({ result: "invalid", error: "Ticket was refunded" });
    }
    if (booking.scanned_at) {
      await client.query("ROLLBACK");
      return res.status(409).json({ result: "duplicate", booking: await ticketResponse(booking) });
    }
    const updated = await client.query(
      "UPDATE bookings SET scanned_at=NOW() WHERE id=$1 RETURNING *",
      [booking.id],
    );
    await client.query("COMMIT");
    res.json({ result: "valid", booking: await ticketResponse(updated.rows[0]) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Ticket scan failed:", err);
    res.status(500).json({ result: "invalid", error: "Could not validate ticket" });
  } finally {
    client.release();
  }
});

module.exports = router;
