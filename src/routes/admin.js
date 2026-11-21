// Admin panel: admin accounts, staff, creators and KYC, events, users, the
// snapshot and the audit log. Destructive actions need `confirmed` (H6).
const express = require("express");
const { requireAdmin, requireSuperAdmin, confirmed } = require("../middleware/auth");
const { audit } = require("../middleware/audit");
const { pool } = require("../db/pool");
const bcrypt = require("bcrypt");
const {
  publicAdmin,
  publicStaff,
  publicAdminCreator,
  publicCreatorEvent,
  USER_NOT_FOUND_ERROR,
  publicUser,
  publicCreatorKycDocument,
  publicCreator,
} = require("../utils/serializers");
const crypto = require("crypto");
const { cleanPathSegment, presignR2 } = require("../services/storage");
const { setTemporaryPassword, ResetError } = require("../services/passwordReset");
const { listAdminActions } = require("../services/adminAudit");
const { normalizeUserStatus, USER_ACTIVE_STATUS } = require("../utils/accounts");

const router = express.Router();

router.post("/admin/accounts", requireAdmin, requireSuperAdmin, confirmed, audit("admin.create", (req) => ({ targetType: "admin", targetId: req.body && req.body.email })), async (req, res) => {
  try {
    const { name, email, password, role, phone, permissions, notes } =
      req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "")
      .trim()
      .toLowerCase();
    const cleanPassword = String(password || "");
    const requestedRole = String(role || "Admin").trim();
    const cleanRole = requestedRole === "Super Admin" ? requestedRole : "Admin";
    if (!cleanName || !cleanEmail || cleanPassword.length < 6) {
      return res.status(400).json({
        error:
          "Name, email, and a temporary password of at least 6 characters are required",
      });
    }
    if (cleanRole === "Super Admin") {
      return res
        .status(400)
        .json({ error: "Create additional Super Admins directly in the DB" });
    }
    const result = await pool.query(
      `INSERT INTO admin_accounts (name, email, password, role, status)
       VALUES ($1,$2,$3,$4,'Active')
       RETURNING *`,
      [
        cleanName,
        cleanEmail,
        await bcrypt.hash(cleanPassword, 10),
        cleanRole,
      ],
    );
    res.status(201).json({
      admin: publicAdmin({
        ...result.rows[0],
        phone,
        permissions,
        notes,
      }),
    });
  } catch (err) {
    if (err && err.code === "23505") {
      return res.status(409).json({ error: "Admin email already exists" });
    }
    console.error("Admin account create failed:", err);
    res.status(500).json({
      error: err && err.message ? `Could not create admin account: ${err.message}` : "Could not create admin account",
    });
  }
});

router.patch(
  "/admin/accounts/:adminId/status",
  requireAdmin,
  requireSuperAdmin,
  confirmed, audit("admin.status", (req) => ({ targetType: "admin", targetId: req.params.adminId, details: { status: req.body && req.body.status } })),
  async (req, res) => {
    try {
      const adminId = Number(req.params.adminId);
      const status = String((req.body && req.body.status) || "").trim();
      if (!adminId || !["Active", "Suspended"].includes(status)) {
        return res
          .status(400)
          .json({ error: "Valid adminId and status are required" });
      }
      const result = await pool.query(
        `UPDATE admin_accounts
         SET status=$1
         WHERE id=$2
         RETURNING *`,
        [status, adminId],
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Admin account not found" });
      }
      res.json({ admin: publicAdmin(result.rows[0]) });
    } catch (err) {
      console.error("Admin account status update failed:", err);
      res.status(500).json({ error: "Could not update admin account" });
    }
  },
);

router.delete(
  "/admin/accounts/:adminId",
  requireAdmin,
  requireSuperAdmin,
  confirmed, audit("admin.delete", (req) => ({ targetType: "admin", targetId: req.params.adminId })),
  async (req, res) => {
    try {
      const adminId = Number(req.params.adminId);
      if (!adminId) {
        return res.status(400).json({ error: "Valid adminId is required" });
      }
      const result = await pool.query(
        `DELETE FROM admin_accounts
         WHERE id=$1
         RETURNING *`,
        [adminId],
      );
      if (!result.rows.length) {
        return res.json({ success: true, alreadyDeleted: true, adminId });
      }
      res.json({ success: true, admin: publicAdmin(result.rows[0]) });
    } catch (err) {
      console.error("Admin account delete failed:", err);
      res.status(500).json({ error: "Could not delete admin account" });
    }
  },
);

router.post("/admin/staff", requireAdmin, audit("staff.create", (req) => ({ targetType: "staff", targetId: req.body && req.body.staffId })), async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      staffId,
      password,
      role,
      assignedGate,
      eventId,
      permissions,
      notes,
    } = req.body || {};
    const cleanName = String(name || "").trim();
    const cleanStaffId = String(staffId || "")
      .trim()
      .toLowerCase();
    const cleanPassword = String(password || "");
    if (!cleanName || !cleanStaffId || cleanPassword.length < 6) {
      return res.status(400).json({
        error:
          "Name, staff login ID, and a temporary password of at least 6 characters are required",
      });
    }
    const id = `STF-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const shareToken = `${cleanPathSegment(cleanStaffId, "staff")}-${crypto.randomBytes(4).toString("hex")}`;
    const isCreatedBySuperAdmin = req.admin && req.admin.adminType === "super";
    const initialStatus = isCreatedBySuperAdmin ? "active" : "pending";
    const result = await pool.query(
      `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, role, assigned_gate, primary_event_id, status, share_token, created_by_admin_email)
       VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [
        id,
        cleanName,
        cleanStaffId,
        String(email || "").trim() || null,
        String(phone || "").trim() || null,
        await bcrypt.hash(cleanPassword, 10),
        String(role || "Scanner").trim(),
        String(assignedGate || "").trim() || null,
        eventId ? String(eventId).trim() : null,
        initialStatus,
        shareToken,
        req.admin && req.admin.email ? String(req.admin.email).trim().toLowerCase() : null,
      ],
    );
    res.status(201).json({
      staff: {
        ...publicStaff(result.rows[0]),
        permissions: permissions || null,
        notes: notes || "",
      },
    });
  } catch (err) {
    if (err && err.code === "23505") {
      return res
        .status(409)
        .json({ error: "Staff login ID or share link already exists" });
    }
    console.error("Admin staff create failed:", err);
    res.status(500).json({
      error: err && err.message ? `Could not create staff account: ${err.message}` : "Could not create staff account",
    });
  }
});

router.delete("/admin/staff/:staffId", requireAdmin, confirmed, audit("staff.delete", (req) => ({ targetType: "staff", targetId: req.params.staffId })), async (req, res) => {
  try {
    const staffId = String(req.params.staffId || "").trim();
    if (!staffId) {
      return res.status(400).json({ error: "Valid staffId is required" });
    }
    const adminEmail =
      req.admin && req.admin.email ? String(req.admin.email).trim().toLowerCase() : "";
    const result = await pool.query(
      `DELETE FROM staff_accounts
       WHERE id=$1
         AND creator_id IS NULL
         AND (created_by_admin_email IS NULL OR LOWER(created_by_admin_email)=LOWER($2))
       RETURNING *`,
      [staffId, adminEmail],
    );
    if (!result.rows.length) {
      return res.json({ success: true, alreadyDeleted: true, staffId });
    }
    res.json({ success: true, staff: publicStaff(result.rows[0]) });
  } catch (err) {
    console.error("Admin staff delete failed:", err);
    res.status(500).json({ error: "Could not delete staff account" });
  }
});

// Q4: an admin resets a staff member's password (temporary password).
router.post(
  "/admin/staff/:staffId/reset-password",
  requireAdmin,
  confirmed,
  audit("staff.password_reset", (req) => ({ targetType: "staff", targetId: req.params.staffId })),
  async (req, res) => {
    try {
      const temporaryPassword = await setTemporaryPassword(pool, { role: "staff", accountId: String(req.params.staffId || "") });
      res.json({ temporaryPassword, mustChangePassword: true });
    } catch (err) {
      if (err instanceof ResetError) return res.status(404).json({ error: "Staff member not found" });
      console.error("Admin staff password reset failed:", err);
      res.status(500).json({ error: "Could not reset password" });
    }
  },
);

// Q4: only a super admin can reset an admin's password. The admin's next
// login still needs the emailed code, then a forced password change.
router.post(
  "/admin/accounts/:adminId/reset-password",
  requireAdmin,
  requireSuperAdmin,
  confirmed,
  audit("admin.password_reset", (req) => ({ targetType: "admin", targetId: req.params.adminId })),
  async (req, res) => {
    try {
      const adminId = Number(req.params.adminId);
      if (!Number.isInteger(adminId) || adminId < 1) return res.status(404).json({ error: "Admin account not found" });
      const temporaryPassword = await setTemporaryPassword(pool, { role: "admin", accountId: adminId, adminType: "admin" });
      res.json({ temporaryPassword, mustChangePassword: true });
    } catch (err) {
      if (err instanceof ResetError) return res.status(404).json({ error: "Admin account not found" });
      console.error("Admin password reset failed:", err);
      res.status(500).json({ error: "Could not reset password" });
    }
  },
);

// The admin audit log, newest first. ?limit=50&before=<id> for older pages.
router.get("/admin/audit-log", requireAdmin, requireSuperAdmin, async (req, res) => {
  try {
    const rows = await listAdminActions(pool, { limit: req.query.limit, beforeId: req.query.before });
    res.json({
      entries: rows.map((row) => ({
        id: Number(row.id),
        adminType: row.admin_type,
        adminId: row.admin_id,
        adminEmail: row.admin_email,
        action: row.action,
        targetType: row.target_type,
        targetId: row.target_id,
        details: row.details,
        ip: row.ip,
        createdAt: row.created_at,
      })),
    });
  } catch (err) {
    console.error("Audit log load failed:", err);
    res.status(500).json({ error: "Could not load audit log" });
  }
});

router.get("/admin/snapshot", requireAdmin, async (req, res) => {
  try {
    const [buyers, creators, events, bookings, payments, staff, admins, refundsNeeded] =
      await Promise.all([
        pool.query(`
        SELECT u.id, u.username, u.first_name, u.last_name, u.email, u.city, u.status, u.created_at,
          COUNT(b.id)::INTEGER AS bookings
        FROM users u
        LEFT JOIN bookings b ON b.user_id=u.id OR (b.user_id IS NULL AND LOWER(b.buyer_email)=LOWER(u.email))
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `),
        pool.query(`
        SELECT c.id, c.name, c.email, c.phone, c.category, c.kyc_status, c.created_at,
          (
            SELECT COUNT(*)::INTEGER
            FROM creator_events e
            WHERE e.creator_id=c.id
          ) AS events,
          (
            SELECT COALESCE(SUM(b.total),0)::NUMERIC
            FROM creator_events e
            LEFT JOIN bookings b ON b.event_id=e.id
            WHERE e.creator_id=c.id
          ) AS revenue,
          (
            SELECT COALESCE(json_agg(d ORDER BY d.created_at DESC), '[]')
            FROM creator_kyc_documents d
            WHERE d.creator_id=c.id
          ) AS documents
        FROM creator_accounts c
        ORDER BY c.created_at DESC
      `),
        pool.query(`
        SELECT e.*,
          COALESCE(SUM(b.qty),0)::INTEGER AS booking_count,
          COALESCE(SUM(b.total),0)::NUMERIC AS revenue
        FROM creator_events e
        LEFT JOIN bookings b ON b.event_id=e.id
        GROUP BY e.id
        ORDER BY e.created_at DESC
      `),
        pool.query("SELECT * FROM bookings ORDER BY booked_at DESC"),
        pool.query(
          "SELECT * FROM payment_transactions ORDER BY updated_at DESC",
        ),
        pool.query("SELECT * FROM staff_accounts ORDER BY created_at DESC"),
        pool.query("SELECT * FROM admin_accounts ORDER BY created_at DESC"),
        // Payments PayU confirmed after the seat hold expired and the event
        // had sold out: money was taken but no ticket issued (C4).
        pool.query(
          `SELECT o.id, o.txnid, o.gateway_payment_id, o.amount, o.qty, o.tier_name, o.paid_at,
             o.event_id, e.name AS event_name, u.email AS buyer_email
           FROM orders o
           JOIN users u ON u.id = o.user_id
           LEFT JOIN creator_events e ON e.id = o.event_id
           WHERE o.status = 'paid_needs_refund'
           ORDER BY o.paid_at DESC`,
        ),
      ]);
    res.json({
      refundsNeeded: refundsNeeded.rows.map((order) => ({
        orderId: order.id,
        txnid: order.txnid,
        gatewayPaymentId: order.gateway_payment_id,
        amount: Number(order.amount || 0),
        qty: Number(order.qty || 0),
        tierName: order.tier_name,
        eventId: order.event_id,
        eventName: order.event_name,
        buyerEmail: order.buyer_email,
        paidAt: order.paid_at,
      })),
      admins: admins.rows.map(publicAdmin),
      buyers: buyers.rows.map((buyer) => ({
        id: `USR-${buyer.id}`,
        name:
          buyer.username ||
          [buyer.first_name, buyer.last_name].filter(Boolean).join(" ") ||
          buyer.email,
        email: buyer.email,
        city: buyer.city || "",
        bookings: Number(buyer.bookings || 0),
        status: normalizeUserStatus(buyer.status),
        createdAt: buyer.created_at,
      })),
      // KYC documents are for super admins only (H14).
      creators: creators.rows
        .map((creator) => (req.admin.adminType === "super" ? creator : { ...creator, documents: [] }))
        .map(publicAdminCreator),
      events: events.rows.map(publicCreatorEvent),
      bookings: bookings.rows.map((booking) => ({
        id: booking.id,
        userId: booking.user_id,
        buyerEmail: booking.buyer_email,
        buyer: booking.buyer_email || "Buyer",
        eventId: booking.event_id,
        eventName: booking.event_name,
        eventDate: booking.event_date,
        eventVenue: booking.event_venue,
        eventBanner: booking.event_banner,
        ticketType: booking.ticket_type,
        price: Number(booking.price || 0),
        qty: Number(booking.qty || 0),
        total: Number(booking.total || 0),
        status: booking.status,
        bookedAt: booking.booked_at,
      })),
      payments: payments.rows.map((payment) => ({
        txnid: payment.txnid,
        bookingId: payment.booking_id,
        eventId: payment.event_id,
        ticketType: payment.ticket_type,
        qty: Number(payment.qty || 0),
        buyerEmail: payment.buyer_email,
        amount: Number(payment.amount || 0),
        gatewayPaymentId: payment.gateway_payment_id,
        status: payment.status,
        verified: payment.verified,
        error: payment.error,
        updatedAt: payment.updated_at,
      })),
      staff: staff.rows.map((member) => ({
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
      })),
    });
  } catch (err) {
    console.error("Admin snapshot failed:", err);
    res.status(500).json({ error: "Could not load admin data" });
  }
});

router.patch("/admin/events/:eventId/status", requireAdmin, confirmed, audit("event.status", (req) => ({ targetType: "event", targetId: req.params.eventId, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const { eventId } = req.params;
    const { status } = req.body || {};
    if (!eventId || !status) {
      return res.status(400).json({ error: "eventId and status are required" });
    }
    // "pending" sends a live event back for re-approval: new sales stop, but
    // existing ticket holders keep their tickets and can still get in (D20).
    const validStatuses = ["live", "paused", "blocked", "completed", "cancelled", "pending"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`,
      });
    }
    const result = await pool.query(
      "UPDATE creator_events SET status=$1 WHERE id=$2 RETURNING *",
      [status, eventId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Event not found" });
    }
    res.json({ success: true, event: publicCreatorEvent(result.rows[0]) });
  } catch (err) {
    console.error("Event status update failed:", err);
    res.status(500).json({ error: "Could not update event status" });
  }
});

// Q6 / D20: approve or reject an event waiting for review. Only a pending
// event can be reviewed, so two admins clicking at once can't both act on it.
router.post("/admin/events/:eventId/approve", requireAdmin, audit("event.approve", (req) => ({ targetType: "event", targetId: req.params.eventId })), async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE creator_events SET status='live', review_note=NULL WHERE id=$1 AND status='pending' RETURNING *",
      [req.params.eventId],
    );
    if (!result.rows.length) return eventNotReviewable(req, res);
    res.json({ success: true, event: publicCreatorEvent(result.rows[0]) });
  } catch (err) {
    console.error("Event approval failed:", err);
    res.status(500).json({ error: "Could not approve event" });
  }
});

router.post("/admin/events/:eventId/reject", requireAdmin, audit("event.reject", (req) => ({ targetType: "event", targetId: req.params.eventId, details: { reason: req.body && req.body.reason } })), async (req, res) => {
  try {
    const reason = String((req.body && req.body.reason) || "").trim().slice(0, 500);
    if (!reason) return res.status(400).json({ error: "A reason is required" });
    const result = await pool.query(
      "UPDATE creator_events SET status='rejected', review_note=$2 WHERE id=$1 AND status='pending' RETURNING *",
      [req.params.eventId, reason],
    );
    if (!result.rows.length) return eventNotReviewable(req, res);
    res.json({ success: true, event: publicCreatorEvent(result.rows[0]) });
  } catch (err) {
    console.error("Event rejection failed:", err);
    res.status(500).json({ error: "Could not reject event" });
  }
});

// 404 when the event does not exist, 409 when it is not waiting for review.
async function eventNotReviewable(req, res) {
  const found = await pool.query("SELECT status FROM creator_events WHERE id=$1", [req.params.eventId]);
  if (!found.rows.length) return res.status(404).json({ error: "Event not found" });
  return res.status(409).json({ error: `Event is ${found.rows[0].status}, not waiting for review` });
}

router.patch("/admin/users/:userId/status", requireAdmin, confirmed, audit("user.status", (req) => ({ targetType: "user", targetId: req.params.userId, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const rawUserId = String(req.params.userId || "").replace(/^USR-/i, "");
    const userId = Number(rawUserId);
    const status = normalizeUserStatus((req.body || {}).status);
    if (!Number.isInteger(userId) || userId < 1 || !status) {
      return res.status(400).json({ error: "userId and status are required" });
    }
    if (![USER_ACTIVE_STATUS, "Suspended"].includes(status)) {
      return res
        .status(400)
        .json({ error: "Invalid status. Must be Active or Suspended" });
    }
    const result = await pool.query(
      `UPDATE users
       SET status=$1
       WHERE id=$2
       RETURNING id, username, first_name, last_name, email, phone, country_code, city,
         profile_image_url, profile_image_key, profile_image_storage, status`,
      [status, userId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: USER_NOT_FOUND_ERROR });
    }
    res.json({ success: true, user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error("User status update failed:", err);
    res.status(500).json({ error: "Could not update user status" });
  }
});

// Open one KYC document: super admin only, every view is audited, and the
// storage link it redirects to expires after 60 seconds.
router.get(
  "/admin/kyc-documents/:documentId/file",
  requireAdmin,
  requireSuperAdmin,
  audit("kyc.view", (req) => ({ targetType: "creator_document", targetId: req.params.documentId })),
  async (req, res) => {
    try {
      const documentId = Number(req.params.documentId);
      if (!Number.isInteger(documentId) || documentId < 1) return res.status(404).json({ error: "Document not found" });
      const result = await pool.query("SELECT * FROM creator_kyc_documents WHERE id=$1", [documentId]);
      const document = result.rows[0];
      if (!document || document.storage !== "r2") return res.status(404).json({ error: "Document not found" });
      res.set("Cache-Control", "no-store");
      res.redirect(presignR2({ method: "GET", key: document.object_key, expires: 60 }));
    } catch (err) {
      console.error("KYC document open failed:", err);
      res.status(500).json({ error: "Could not open document" });
    }
  },
);

router.get("/admin/creators/:creatorId", requireAdmin, requireSuperAdmin, async (req, res) => {
  try {
    const rawCreatorId = String(req.params.creatorId || "").replace(/^CRT-/i, "");
    const creatorId = Number(rawCreatorId);
    if (!Number.isInteger(creatorId) || creatorId < 1) {
      return res.status(400).json({ error: "Valid creatorId is required" });
    }
    const result = await pool.query(
      `SELECT c.id, c.name, c.email, c.phone, c.category, c.kyc_status, c.created_at,
        (
          SELECT COUNT(*)::INTEGER
          FROM creator_events e
          WHERE e.creator_id=c.id
        ) AS events,
        (
          SELECT COALESCE(SUM(b.total),0)::NUMERIC
          FROM creator_events e
          LEFT JOIN bookings b ON b.event_id=e.id
          WHERE e.creator_id=c.id
        ) AS revenue,
        (
          SELECT COALESCE(json_agg(d ORDER BY d.created_at DESC), '[]')
          FROM creator_kyc_documents d
          WHERE d.creator_id=c.id
        ) AS documents
       FROM creator_accounts c
       WHERE c.id=$1`,
      [creatorId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Creator account not found" });
    }
    res.json({ creator: publicAdminCreator(result.rows[0]) });
  } catch (err) {
    console.error("Creator detail load failed:", err);
    res.status(500).json({ error: "Could not load creator documents" });
  }
});

router.patch("/admin/creators/:creatorId/documents/:documentId/status", requireAdmin, requireSuperAdmin, audit("creator.document.status", (req) => ({ targetType: "creator_document", targetId: req.params.documentId, details: { creatorId: req.params.creatorId, status: req.body && req.body.status } })), async (req, res) => {
  try {
    const creatorId = Number(String(req.params.creatorId || "").replace(/^CRT-/i, ""));
    const documentId = Number(req.params.documentId);
    const status = String((req.body || {}).status || "").trim();
    if (!Number.isInteger(creatorId) || creatorId < 1 || !Number.isInteger(documentId) || documentId < 1) {
      return res.status(400).json({ error: "Valid creatorId and documentId are required" });
    }
    if (!["Pending", "Verified"].includes(status)) {
      return res.status(400).json({ error: "Document status must be Pending or Verified" });
    }
    const result = await pool.query(
      `UPDATE creator_kyc_documents
       SET verification_status=$1,
           verified_at=CASE WHEN $1='Verified' THEN NOW() ELSE NULL END,
           verified_by=CASE WHEN $1='Verified' THEN $2 ELSE NULL END
       WHERE id=$3 AND creator_id=$4
       RETURNING *`,
      [status, req.admin.email || String(req.admin.sub || "Super Admin"), documentId, creatorId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Creator document not found" });
    }
    res.json({ success: true, document: publicCreatorKycDocument(result.rows[0]) });
  } catch (err) {
    console.error("Creator document verification failed:", err);
    res.status(500).json({ error: "Could not update document verification" });
  }
});

router.patch("/admin/creators/:creatorId/status", requireAdmin, requireSuperAdmin, confirmed, audit("creator.status", (req) => ({ targetType: "creator", targetId: req.params.creatorId, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const rawCreatorId = String(req.params.creatorId || "").replace(/^CRT-/i, "");
    const creatorId = Number(rawCreatorId);
    const status = String((req.body || {}).status || "").trim();
    if (!Number.isInteger(creatorId) || creatorId < 1 || !status) {
      return res.status(400).json({ error: "creatorId and status are required" });
    }
    if (!["Pending", "Approved", "Rejected", "Suspended"].includes(status)) {
      return res.status(400).json({ error: "Invalid status. Must be Pending, Approved, Rejected, or Suspended" });
    }
    if (status === "Approved") {
      const documentCheck = await pool.query(
        `SELECT COUNT(*)::INTEGER AS total,
          COUNT(*) FILTER (WHERE verification_status='Verified')::INTEGER AS verified
         FROM creator_kyc_documents
         WHERE creator_id=$1`,
        [creatorId],
      );
      const counts = documentCheck.rows[0] || { total: 0, verified: 0 };
      if (!counts.total || counts.verified !== counts.total) {
        return res.status(409).json({ error: "Verify every submitted document before verifying the creator" });
      }
    }
    const result = await pool.query(
      `UPDATE creator_accounts
       SET kyc_status=$1
       WHERE id=$2
       RETURNING id, name, email, phone, category, about, kyc_status, created_at`,
      [status, creatorId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Creator account not found" });
    }
    res.json({ success: true, creator: publicCreator(result.rows[0]) });
  } catch (err) {
    console.error("Creator status update failed:", err);
    res.status(500).json({ error: "Could not update creator status" });
  }
});

router.patch("/admin/creators/status-by-email", requireAdmin, requireSuperAdmin, confirmed, audit("creator.status", (req) => ({ targetType: "creator", targetId: req.body && req.body.email, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const status = String((req.body || {}).status || "").trim();
    if (!email || !status) {
      return res.status(400).json({ error: "email and status are required" });
    }
    if (!["Pending", "Approved", "Rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status. Must be Pending, Approved, or Rejected" });
    }
    if (status === "Approved") {
      const documentCheck = await pool.query(
        `SELECT c.id, COUNT(d.id)::INTEGER AS total,
          COUNT(d.id) FILTER (WHERE d.verification_status='Verified')::INTEGER AS verified
         FROM creator_accounts c
         LEFT JOIN creator_kyc_documents d ON d.creator_id=c.id
         WHERE LOWER(c.email)=LOWER($1)
         GROUP BY c.id`,
        [email],
      );
      if (!documentCheck.rows.length) {
        return res.status(404).json({ error: "Creator account not found" });
      }
      const counts = documentCheck.rows[0];
      if (!counts.total || counts.verified !== counts.total) {
        return res.status(409).json({ error: "Verify every submitted document before verifying the creator" });
      }
    }
    const result = await pool.query(
      `UPDATE creator_accounts
       SET kyc_status=$1
       WHERE LOWER(email)=LOWER($2)
       RETURNING id, name, email, phone, category, about, kyc_status, created_at`,
      [status, email],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Creator account not found" });
    }
    res.json({ success: true, creator: publicCreator(result.rows[0]) });
  } catch (err) {
    console.error("Creator status update by email failed:", err);
    res.status(500).json({ error: "Could not update creator status" });
  }
});

router.patch("/admin/staff/:staffId/status", requireAdmin, confirmed, audit("staff.status", (req) => ({ targetType: "staff", targetId: req.params.staffId, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const { staffId } = req.params;
    const { status } = req.body || {};
    if (!staffId || !status) {
      return res.status(400).json({ error: "staffId and status are required" });
    }
    if (status !== "active" && status !== "suspended" && status !== "pending") {
      return res.status(400).json({ error: "Invalid status. Must be active, pending, or suspended" });
    }
    const existing = await pool.query(
      "SELECT * FROM staff_accounts WHERE id=$1",
      [staffId],
    );
    if (!existing.rows.length) {
      return res.status(404).json({ error: "Staff member not found" });
    }
    if (existing.rows[0].status === "pending" && status === "active" && req.admin.adminType !== "super") {
      return res.status(403).json({ error: "Super Admin verification is required to activate this staff member" });
    }
    const result = await pool.query(
      "UPDATE staff_accounts SET status=$1 WHERE id=$2 RETURNING *",
      [status, staffId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Staff member not found" });
    }
    res.json({ success: true, staff: publicStaff(result.rows[0]) });
  } catch (err) {
    console.error("Staff status update failed:", err);
    res.status(500).json({ error: "Could not update staff status" });
  }
});

module.exports = router;
