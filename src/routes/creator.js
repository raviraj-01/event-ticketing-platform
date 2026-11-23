// Organizer (creator) routes: application + KYC upload, login, events,
// staff management and assignments, analytics, finance PIN.
const express = require("express");
const { pool } = require("../db/pool");
const {
  validateUpload,
  KYC_UPLOAD_TYPES,
  saveAsset,
  cleanPathSegment,
  IMAGE_UPLOAD_TYPES,
} = require("../services/storage");
const bcrypt = require("bcrypt");
const {
  publicCreator,
  publicCreatorEvent,
  publicStaff,
  publicStaffShareUrl,
  publicStaffAssignment,
} = require("../utils/serializers");
const { rateLimit } = require("../middleware/rateLimit");
const { startSession } = require("../services/sessions");
const { requireCreator } = require("../middleware/auth");
const { creatorEventSalesQuery } = require("../db/queries");
const { withAvailability, organizerEarnings } = require("../services/orders");
const crypto = require("crypto");
const { staffWallet, recordCashSettlement, WalletError } = require("../services/staffWallet");
const { setTemporaryPassword } = require("../services/passwordReset");
const { createStaffAssignment } = require("../services/staffAssignments");
const { readPage, pageOf } = require("../utils/paging");
const { sendError } = require("../utils/httpError");
const { uploadJson } = require("../middleware/bodyLimits");

const router = express.Router();

// Public form with KYC files (up to 4 × 5 MB, base64 in JSON): rate limited
// per IP before the large body is read (M11).
const applicationLimits = [
  rateLimit({ name: "creator-application-ip", windowSeconds: 3600, max: 5, key: (req) => req.ip }),
  uploadJson("30mb"),
];
router.post("/creator/applications", ...applicationLimits, async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, email, phone, category, about, password, documents } =
      req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "")
      .trim()
      .toLowerCase();
    const cleanPhone = String(phone || "").trim();
    const cleanCategory = String(category || "").trim();
    const cleanAbout = String(about || "").trim();
    const cleanPassword = String(password || "");
    const files = Array.isArray(documents) ? documents : [];

    if (
      !cleanName ||
      !cleanEmail ||
      !cleanPhone ||
      !cleanCategory ||
      !cleanAbout ||
      !cleanPassword
    ) {
      return res.status(400).json({
        error:
          "Name, email, phone, event type, about, and password are required",
      });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res
        .status(400)
        .json({ error: "Enter a valid creator email address" });
    }
    if (cleanPassword.length < 8) {
      return res
        .status(400)
        .json({ error: "Creator password must be at least 8 characters" });
    }
    if (!files.length) {
      return res
        .status(400)
        .json({ error: "Upload at least one KYC document" });
    }
    const existing = await client.query(
      "SELECT 1 FROM creator_accounts WHERE email=$1",
      [cleanEmail],
    );
    if (existing.rows.length) {
      return res
        .status(409)
        .json({ error: "A creator account with this email already exists" });
    }

    const allowedTypes = new Set(["pan", "aadhaar", "gst", "bank"]);
    const seenTypes = new Set();
    // Validate every document first, so a bad file never leaves the earlier
    // ones orphaned in storage.
    for (const file of files) {
      const documentType = String(file.documentType || "")
        .trim()
        .toLowerCase();
      if (!allowedTypes.has(documentType) || !file.fileName || !file.dataUrl) {
        return res.status(400).json({
          error:
            "Each KYC document must include a valid type, file name, and file data",
        });
      }
      if (seenTypes.has(documentType)) {
        return res.status(400).json({ error: "Upload each KYC document type only once" });
      }
      seenTypes.add(documentType);
      validateUpload(file.dataUrl, KYC_UPLOAD_TYPES);
    }
    const uploaded = [];
    for (const file of files) {
      const documentType = String(file.documentType).trim().toLowerCase();
      const asset = await saveAsset({
        fileName: file.fileName,
        folder: `kyc-documents/${cleanPathSegment(cleanEmail, "creator")}/${documentType}`,
        dataUrl: file.dataUrl,
        allowedTypes: KYC_UPLOAD_TYPES,
        requireR2: true,
      });
      uploaded.push({ documentType, fileName: file.fileName, ...asset });
    }

    const hashedPassword = await bcrypt.hash(cleanPassword, 10);
    await client.query("BEGIN");
    const creatorResult = await client.query(
      `INSERT INTO creator_accounts (name, email, phone, category, about, password)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, name, email, phone, category, about, kyc_status, created_at`,
      [
        cleanName,
        cleanEmail,
        cleanPhone,
        cleanCategory,
        cleanAbout,
        hashedPassword,
      ],
    );
    const creator = creatorResult.rows[0];
    for (const file of uploaded) {
      await client.query(
        `INSERT INTO creator_kyc_documents (
          creator_id, document_type, file_name, object_key, storage, content_type
        ) VALUES ($1,$2,$3,$4,$5,$6)`,
        [
          creator.id,
          file.documentType,
          file.fileName,
          file.key,
          file.storage,
          file.contentType,
        ],
      );
    }
    await client.query("COMMIT");
    res.status(201).json({
      message:
        "Creator application and KYC submitted successfully. You can sign in after super admin verification.",
      creator: publicCreator(creator),
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Creator application failed:", err);
    if (err.code === "23505") {
      return res
        .status(409)
        .json({ error: "A creator account with this email already exists" });
    }
    if (err.status) return res.status(err.status).json({ error: err.message });
    res.status(500).json({ error: "Creator application failed" });
  } finally {
    client.release();
  }
});

// Creator login: exact email match, bcrypt only, one generic error (H13).
const CREATOR_LOGIN_ERROR = "Invalid email or password";
router.post(
  "/creator/login",
  rateLimit({ name: "creator-login-ip", windowSeconds: 600, max: 20, key: (req) => req.ip }),
  rateLimit({
    name: "creator-login-email",
    windowSeconds: 600,
    max: 10,
    key: (req) => String((req.body && req.body.email) || "").trim().toLowerCase() || null,
  }),
  async (req, res) => {
    try {
      const email = String((req.body && req.body.email) || "").trim().toLowerCase();
      const password = String((req.body && req.body.password) || "");
      if (!email || !password) {
        return res.status(400).json({ error: "Creator email and password are required" });
      }
      const result = await pool.query(
        `SELECT id, name, email, phone, category, about, password, kyc_status, created_at
         FROM creator_accounts
         WHERE LOWER(email) = $1`,
        [email],
      );
      const creator = result.rows[0];
      const storedHash = String((creator && creator.password) || "");
      // Only bcrypt hashes are accepted; a missing account and a wrong password
      // get the same answer so the response does not reveal which emails exist.
      const validPassword = storedHash.startsWith("$2") && (await bcrypt.compare(password, storedHash));
      if (!creator || !validPassword) {
        return res.status(401).json({ error: CREATOR_LOGIN_ERROR });
      }
      if (creator.kyc_status !== "Approved") {
        const message =
          creator.kyc_status === "Rejected"
            ? "Your creator application was rejected. Please contact support."
            : "Your creator account is pending super admin verification.";
        return res.status(403).json({ error: message, reason: "creator_not_verified", kycStatus: creator.kyc_status });
      }
      res.json({
        message: "Creator login successful",
        creator: publicCreator(creator),
        ...(await startSession(pool, req, res, { role: "creator", accountId: creator.id })),
      });
    } catch (err) {
      console.error("Creator login failed:", err);
      res.status(500).json({ error: "Creator login failed" });
    }
  },
);

router.get("/creator/session", requireCreator, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, phone, category, about, kyc_status, created_at
       FROM creator_accounts
       WHERE id=$1`,
      [req.creator.sub],
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: "Creator account not found" });
    }
    res.json({ creator: publicCreator(result.rows[0]) });
  } catch (err) {
    console.error("Creator session restore failed:", err);
    res.status(500).json({ error: "Could not restore creator session" });
  }
});

router.get("/creator/events", requireCreator, async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.creator_id=$1
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
      [req.creator.sub],
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Creator events list failed:", err);
    res.status(500).json({ error: "Could not load creator events" });
  }
});

router.get("/events", async (req, res) => {
  try {
    const page = readPage(req.query, { defaultLimit: 100, maxLimit: 100 });
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.status IN ('live', 'upcoming') AND e.visibility='Public'
       GROUP BY e.id
       ORDER BY e.created_at DESC, e.id
       LIMIT $1 OFFSET $2`,
      [page.limit + 1, page.offset],
    );
    const { rows, paging } = pageOf(result.rows, page);
    const events = await withAvailability(pool, rows);
    res.json({ events: events.map(publicCreatorEvent), paging });
  } catch (err) {
    console.error("Public events list failed:", err);
    res.status(500).json({ error: "Could not load events" });
  }
});

// One 5 MB image; the body is read only after the login check (M11).
router.post("/creator/events/banner", requireCreator, uploadJson("8mb"), async (req, res) => {
  try {
    const { fileName, dataUrl } = req.body || {};
    if (!fileName || !dataUrl) {
      return res
        .status(400)
        .json({ error: "Banner file name and data are required" });
    }
    // Banners are public images, so the local-disk fallback is allowed when R2
    // is not configured (e.g. local development).
    const asset = await saveAsset({
      fileName,
      folder: `event-banners/creator-${req.creator.sub}`,
      dataUrl,
      allowedTypes: IMAGE_UPLOAD_TYPES,
    });
    res.status(201).json(asset);
  } catch (err) {
    console.error("Creator banner upload failed:", err);
    if (err.status) return res.status(err.status).json({ error: err.message });
    res.status(500).json({ error: "Banner upload failed" });
  }
});

router.post("/creator/events", requireCreator, async (req, res) => {
  try {
    const {
      name,
      category,
      description,
      date,
      time,
      endTime,
      venue,
      city,
      capacity,
      latitude,
      longitude,
      banner,
      bannerKey,
      visibility,
      tickets,
    } = req.body || {};
    const cleanTickets = Array.isArray(tickets)
      ? tickets
          .map((ticket) => ({
            name: String(ticket.name || "").trim(),
            price: Number(ticket.price || 0),
            qty: Number(ticket.qty || 0),
            perks: String(ticket.perks || "").trim(),
          }))
          .filter(
            (ticket) => ticket.name && ticket.qty > 0 && ticket.price >= 0,
          )
      : [];
    if (
      !name ||
      !category ||
      !description ||
      !date ||
      !time ||
      !venue ||
      !city ||
      !Number(capacity)
    ) {
      return res.status(400).json({
        error:
          "Complete the event details, date, time, venue, city, and capacity",
      });
    }
    if (!banner || !bannerKey) {
      return res
        .status(400)
        .json({ error: "Upload an event banner before publishing" });
    }
    if (!cleanTickets.length) {
      return res
        .status(400)
        .json({ error: "Add at least one valid ticket tier" });
    }
    const creatorResult = await pool.query(
      "SELECT name FROM creator_accounts WHERE id=$1",
      [req.creator.sub],
    );
    if (!creatorResult.rows.length)
      return res.status(401).json({ error: "Creator account not found" });
    const id = `EVT-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const result = await pool.query(
      `INSERT INTO creator_events (
        id, creator_id, creator_name, name, category, description, event_date,
        start_time, end_time, venue, city, capacity, latitude, longitude,
        banner_url, banner_key, visibility, tickets, status
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'pending')
      RETURNING *`,
      [
        id,
        req.creator.sub,
        creatorResult.rows[0].name,
        String(name).trim(),
        String(category).trim(),
        String(description).trim(),
        String(date).trim(),
        String(time).trim(),
        String(endTime || "").trim() || null,
        String(venue).trim(),
        String(city).trim(),
        Number(capacity),
        latitude || null,
        longitude || null,
        String(banner),
        String(bannerKey),
        String(visibility || "Public"),
        JSON.stringify(cleanTickets),
      ],
    );
    if (!result.rows.length) {
      throw new Error("Event was not saved in the database");
    }
    res.status(201).json({
      // Q6 / D20: buyers see it only after an admin approves it.
      message: "Event submitted. It goes live once an admin approves it.",
      event: publicCreatorEvent(result.rows[0]),
    });
  } catch (err) {
    sendError(res, err, { message: "Event publish failed", log: "Creator event publish failed" });
  }
});

router.get("/creator/staff", requireCreator, async (req, res) => {
  try {
    const [staff, assignments, salesSummary] = await Promise.all([
      pool.query(
        `SELECT s.*,
           COALESCE(SUM(ss.qty),0)::INTEGER AS db_sold_tickets,
           COALESCE(SUM(ss.commission),0)::NUMERIC AS db_earnings
         FROM staff_accounts s
         LEFT JOIN staff_sales ss ON ss.staff_id=s.id AND ss.status='active'
         WHERE s.creator_id=$1
         GROUP BY s.id
         ORDER BY s.created_at DESC`,
        [req.creator.sub],
      ),
      pool.query(
        "SELECT * FROM staff_assignments WHERE creator_id=$1 ORDER BY created_at DESC",
        [req.creator.sub],
      ),
      pool.query(
        `SELECT
           COALESCE(SUM(qty),0)::INTEGER AS tickets_sold,
           COALESCE(SUM(total),0)::NUMERIC AS revenue
         FROM staff_sales
         WHERE creator_id=$1`,
        [req.creator.sub],
      ),
    ]);
    const summary = salesSummary.rows[0] || {};
    const wallets = await Promise.all(staff.rows.map((member) => staffWallet(pool, member.id)));
    res.json({
      staff: staff.rows.map((member, index) => {
        const mapped = {
          ...member,
          cash_owed: wallets[index].cashOwed,
          sold_tickets: Number(
            member.db_sold_tickets || member.sold_tickets || 0,
          ),
          earnings: Number(member.db_earnings || member.earnings || 0),
        };
        return publicStaff({
          ...mapped,
          share_url: publicStaffShareUrl(req, mapped),
        });
      }),
      assignments: assignments.rows.map(publicStaffAssignment),
      summary: {
        totalStaff: staff.rows.length,
        ticketsSold: Number(summary.tickets_sold || 0),
        revenue: Number(summary.revenue || 0),
      },
    });
  } catch (err) {
    console.error("Creator staff list failed:", err);
    res.status(500).json({ error: "Could not load staff" });
  }
});

// Q4: an organizer resets the password of one of their staff (e.g. staff
// without email). Returns a temporary password, shown once.
router.post("/creator/staff/:staffId/reset-password", requireCreator, async (req, res) => {
  try {
    const staffId = String(req.params.staffId || "");
    const owned = await pool.query("SELECT id FROM staff_accounts WHERE id=$1 AND creator_id=$2", [staffId, req.creator.sub]);
    if (!owned.rows.length) return res.status(404).json({ error: "Staff member not found" });
    const temporaryPassword = await setTemporaryPassword(pool, { role: "staff", accountId: staffId });
    res.json({ temporaryPassword, mustChangePassword: true });
  } catch (err) {
    console.error("Staff password reset failed:", err);
    res.status(500).json({ error: "Could not reset password" });
  }
});

// The organizer records cash a staff member handed over (reduces cash owed).
router.post("/creator/staff/:staffId/cash-settlements", requireCreator, async (req, res) => {
  try {
    const wallet = await recordCashSettlement(pool, req.creator.sub, String(req.params.staffId || ""), {
      amount: req.body && req.body.amount,
      note: req.body && req.body.note,
    });
    res.status(201).json({ wallet });
  } catch (err) {
    if (err instanceof WalletError) return res.status(err.status).json({ error: err.message });
    console.error("Cash settlement failed:", err);
    res.status(500).json({ error: "Could not record cash received" });
  }
});

router.get("/creator/analytics", requireCreator, async (req, res) => {
  try {
    const [summary, events, staff] = await Promise.all([
      pool.query(
        `SELECT
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS gross,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
         FROM creator_events e
         LEFT JOIN bookings b ON b.event_id=e.id
         WHERE e.creator_id=$1`,
        [req.creator.sub],
      ),
      pool.query(
        `SELECT e.id, e.name, e.status, e.event_date,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
         FROM creator_events e
         LEFT JOIN bookings b ON b.event_id=e.id
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
        [req.creator.sub],
      ),
      pool.query(
        `SELECT id, name, staff_id, assigned_tickets, sold_tickets, earnings
         FROM staff_accounts
         WHERE creator_id=$1
         ORDER BY earnings DESC, sold_tickets DESC, created_at DESC`,
        [req.creator.sub],
      ),
    ]);
    const { gross, fee, net, buyerFeePercent } = organizerEarnings(summary.rows[0].gross);
    const tickets = Number(summary.rows[0].tickets || 0);
    res.json({
      summary: {
        gross,
        fee,
        buyerFeePercent,
        net,
        tickets,
        averageTicketPrice: tickets ? Math.round(gross / tickets) : 0,
        payoutStatus: gross > 0 ? "Pending" : "No payout due",
      },
      events: events.rows.map((event) => ({
        id: event.id,
        name: event.name,
        status: event.status,
        date: event.event_date,
        revenue: Number(event.revenue || 0),
        tickets: Number(event.tickets || 0),
      })),
      staff: staff.rows.map((member) => ({
        id: member.id,
        name: member.name,
        staffId: member.staff_id,
        assignedTickets: Number(member.assigned_tickets || 0),
        soldTickets: Number(member.sold_tickets || 0),
        earnings: Number(member.earnings || 0),
      })),
    });
  } catch (err) {
    console.error("Creator analytics failed:", err);
    res.status(500).json({ error: "Could not load creator analytics" });
  }
});

router.post("/creator/staff", requireCreator, async (req, res) => {
  const client = await pool.connect();
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
      tierName,
      qty,
      allocationMode,
      mode,
      commissionRate,
      purchasePrice,
      resalePrice,
    } = req.body || {};
    const cleanStaffId = String(staffId || "")
      .trim()
      .toLowerCase();
    const cleanPassword = String(password || "");
    if (!name || !cleanStaffId || cleanPassword.length < 6) {
      return res.status(400).json({
        error:
          "Name, login ID, and a temporary password of at least 6 characters are required",
      });
    }
    await client.query("BEGIN");
    const id = `STF-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const shareToken = `${cleanPathSegment(cleanStaffId, "staff")}-${crypto.randomBytes(4).toString("hex")}`;
    const result = await client.query(
      `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, role, assigned_gate, primary_event_id, share_token)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [
        id,
        req.creator.sub,
        String(name).trim(),
        cleanStaffId,
        String(email || "").trim() || null,
        String(phone || "").trim() || null,
        await bcrypt.hash(cleanPassword, 10),
        String(role || "Scanner").trim(),
        String(assignedGate || "").trim() || null,
        eventId ? String(eventId) : null,
        shareToken,
      ],
    );
    let assignment = null;
    if (eventId && tierName && Number(qty) > 0) {
      assignment = await createStaffAssignment(client, {
        creatorId: req.creator.sub,
        staffId: id,
        eventId,
        tierName,
        qty: Number(qty),
        allocationMode,
        mode,
        commissionRate,
        purchasePrice,
        resalePrice,
      });
    }
    await client.query("COMMIT");
    res.status(201).json({
      message: "Staff member added successfully",
      staff: publicStaff({
        ...result.rows[0],
        share_url: publicStaffShareUrl(req, result.rows[0]),
      }),
      assignment: assignment ? publicStaffAssignment(assignment) : null,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505")
      return res.status(409).json({ error: "Staff login ID is already taken" });
    sendError(res, err, { message: "Could not add staff", log: "Creator staff create failed" });
  } finally {
    client.release();
  }
});




router.post(
  "/creator/staff/:staffId/assignments",
  requireCreator,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const assignment = await createStaffAssignment(client, {
        creatorId: req.creator.sub,
        staffId: req.params.staffId,
        eventId: req.body && req.body.eventId,
        tierName: req.body && req.body.tierName,
        qty: Number(req.body && req.body.qty),
        allocationMode: req.body && req.body.allocationMode,
        mode: req.body && req.body.mode,
        commissionRate: req.body && req.body.commissionRate,
        purchasePrice: req.body && req.body.purchasePrice,
        resalePrice: req.body && req.body.resalePrice,
      });
      await client.query("COMMIT");
      res.status(201).json({
        message: "Tickets assigned successfully",
        assignment: publicStaffAssignment(assignment),
      });
    } catch (err) {
      await client.query("ROLLBACK");
      sendError(res, err, { message: "Could not assign tickets", log: "Creator staff assignment failed" });
    } finally {
      client.release();
    }
  },
);

router.post("/creator/finance/unlock", requireCreator, async (req, res) => {
  try {
    const pin = String((req.body && req.body.pin) || "").trim();
    if (!/^\d{4}$/.test(pin))
      return res.status(400).json({ error: "Enter a valid 4-digit PIN" });
    const creator = await pool.query(
      "SELECT finance_pin FROM creator_accounts WHERE id=$1",
      [req.creator.sub],
    );
    if (!creator.rows.length)
      return res.status(401).json({ error: "Creator account not found" });
    const hash = creator.rows[0].finance_pin;
    let initialized = false;
    if (!hash) {
      await pool.query(
        "UPDATE creator_accounts SET finance_pin=$1 WHERE id=$2",
        [await bcrypt.hash(pin, 10), req.creator.sub],
      );
      initialized = true;
    } else if (!(await bcrypt.compare(pin, hash))) {
      return res.status(401).json({ error: "Incorrect finance PIN" });
    }
    const result = await pool.query(
      `SELECT
         COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS gross,
         COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
       FROM creator_events e
       LEFT JOIN bookings b ON b.event_id=e.id
       WHERE e.creator_id=$1`,
      [req.creator.sub],
    );
    // M8 / Q16: same function as analytics (net = gross; buyers pay the fee).
    const { gross, net } = organizerEarnings(result.rows[0].gross);
    res.json({
      initialized,
      gross,
      net,
      tickets: Number(result.rows[0].tickets || 0),
    });
  } catch (err) {
    console.error("Creator finance unlock failed:", err);
    res.status(500).json({ error: "Could not unlock finance" });
  }
});

// The signed-in creator's own events (H12: by creator id, never by matching
// a buyer's unverified email to a creator account).
router.get("/profile/creator-events", requireCreator, async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.creator_id=$1
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
      [req.creator.sub],
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Profile creator events failed:", err);
    res.status(500).json({ error: "Could not load your created events" });
  }
});

module.exports = router;
