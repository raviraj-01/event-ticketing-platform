// L10: load .env before requiring anything else. Some modules read their
// settings (fee %, token lifetimes, ...) at load time.
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { runMigrations } = require("./src/db/migrate");
const { WalletError, staffWallet, requestWithdrawal, recordCashSettlement } = require("./src/services/staffWallet");
const { setTemporaryPassword } = require("./src/services/passwordReset");
const { startSession } = require("./src/services/sessions");
const { isEventBookable, eventSalesClosed } = require("./src/utils/events");
const { pruneRateLimitHits, rateLimit } = require("./src/middleware/rateLimit");
const { withAvailability, expireStaleOrders } = require("./src/services/orders");
const { pool, dbSsl } = require("./src/db/pool");
const { initDb } = require("./src/db/initDb");
const { publicDir, uploadsDir, appHtmlPath } = require("./src/config");
const {
  hasR2Config,
  validateUpload,
  KYC_UPLOAD_TYPES,
  saveAsset,
  cleanPathSegment,
  IMAGE_UPLOAD_TYPES,
  presignR2,
} = require("./src/services/storage");
const {
  publicCreator,
  publicCreatorEvent,
  publicStaff,
  publicStaffShareUrl,
  publicStaffAssignment,
  publicStaffSale,
  publicStaffWithdrawal,
  EVENT_NOT_FOUND_ERROR,
} = require("./src/utils/serializers");
const { requireCreator, requireStaff } = require("./src/middleware/auth");
const { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests } = require("./src/middleware/security");
const { ticketResponse } = require("./src/services/tickets");

process.on("unhandledRejection", (err) => {
  console.error("Unhandled async error:", err);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught server error:", err);
});

const app = express();
// Number of reverse proxies in front of the app (Render: 1). Needed so req.ip is
// the real client IP for rate limiting; 0 = trust nobody (local development).
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 0));

app.use(corsMiddleware);
app.use(openerPolicy);
app.use(blockCrossSiteCookieRequests);
app.use(bodyParser.json({ limit: "30mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.get("/favicon.ico", (req, res) => {
  res.type("image/svg+xml").sendFile(path.join(publicDir, "assets", "blak-ticket-logo.svg"));
});
// index:false so "/" always goes through the no-cache route below.
app.use(express.static(publicDir, { index: false }));
// nosniff: browsers must use the stored Content-Type and never guess that a
// file is HTML/script.
app.use("/uploads", express.static(uploadsDir, {
  setHeaders: (res) => res.setHeader("X-Content-Type-Options", "nosniff"),
}));







const creatorEventSalesQuery = `
  SELECT e.*,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS booking_count,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue
  FROM creator_events e
  LEFT JOIN bookings b ON b.event_id=e.id
`;





// ─── GOOGLE TOKEN RELAY ────────────────────────────────────────────────────────
// Used by the Android APK to do Google Sign-in via the system browser.
// Flow: app generates a `code`, opens system browser → user signs in → web page
// POSTs the JWT to /google-token/store?code=XYZ → app polls /google-token/fetch?code=XYZ
const googleTokenStore = new Map(); // code → { token, profile, createdAt }

// Clean up tokens older than 5 minutes every minute
setInterval(() => {
  const now = Date.now();
  for (const [code, val] of googleTokenStore) {
    if (now - val.createdAt > 5 * 60 * 1000) googleTokenStore.delete(code);
  }
}, 60 * 1000);

app.post("/google-token/store", (req, res) => {
  const code = String(req.query.code || "").trim();
  if (!code || code.length < 8) return res.status(400).json({ error: "Invalid code" });
  const { token, profile } = req.body || {};
  if (!token || !profile) return res.status(400).json({ error: "token and profile required" });
  googleTokenStore.set(code, { token, profile, createdAt: Date.now() });
  res.json({ ok: true });
});

app.get("/google-token/fetch", (req, res) => {
  const code = String(req.query.code || "").trim();
  if (!code) return res.status(400).json({ error: "Missing code" });
  const entry = googleTokenStore.get(code);
  if (!entry) return res.json({ ready: false });
  googleTokenStore.delete(code); // consume once
  res.json({ ready: true, token: entry.token, profile: entry.profile });
});

// Standalone Google login success page (shown in system browser after OAuth)
app.get("/google-auth-success", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed In - BLAK Tickets</title>
<style>
  body{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;
       background:#0a0a0a;font-family:sans-serif;color:#fff;flex-direction:column;gap:16px}
  .icon{font-size:64px}
  h2{margin:0;font-size:22px}
  p{margin:0;color:#aaa;font-size:14px;text-align:center}
</style></head><body>
<div class="icon">✅</div>
<h2>Signed in successfully!</h2>
<p>You can close this tab and return to BLAK Tickets.</p>
</body></html>`);
});

// OPEN HTML PAGE
app.get("/", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

app.get("/vybera_26.html", (req, res) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate",
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      database: "connected",
      r2: hasR2Config() ? "configured" : "missing",
    });
  } catch (err) {
    res.status(500).json({ ok: false, database: "error", error: err.message });
  }
});

app.get("/qr", async (req, res) => {
  try {
    const text = String((req.query && req.query.text) || "").trim();
    if (!text) return res.status(400).send("Missing QR text");
    const png = await QRCode.toBuffer(text, {
      width: 420,
      margin: 2,
      errorCorrectionLevel: "M",
    });
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(png);
  } catch (err) {
    console.error("QR generation failed:", err);
    res.status(500).send("Could not generate QR");
  }
});

app.post("/creator/applications", async (req, res) => {
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
app.post(
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

app.get("/creator/session", requireCreator, async (req, res) => {
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

app.get("/creator/events", requireCreator, async (req, res) => {
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

app.get("/events", async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.status IN ('live', 'upcoming') AND e.visibility='Public'
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
    );
    const events = await withAvailability(pool, result.rows);
    res.json({ events: events.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Public events list failed:", err);
    res.status(500).json({ error: "Could not load events" });
  }
});

app.post("/creator/events/banner", requireCreator, async (req, res) => {
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

app.post("/creator/events", requireCreator, async (req, res) => {
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
        banner_url, banner_key, visibility, tickets
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
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
      message: "Event published successfully",
      event: publicCreatorEvent(result.rows[0]),
    });
  } catch (err) {
    console.error("Creator event publish failed:", err);
    res.status(500).json({ error: err.message || "Event publish failed" });
  }
});

app.get("/creator/staff", requireCreator, async (req, res) => {
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
    const wallets = await Promise.all(staff.rows.map((member) => staffWalletFor(member.id)));
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
app.post("/creator/staff/:staffId/reset-password", requireCreator, async (req, res) => {
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
app.post("/creator/staff/:staffId/cash-settlements", requireCreator, async (req, res) => {
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

app.get("/creator/analytics", requireCreator, async (req, res) => {
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
    const gross = Number(summary.rows[0].gross || 0);
    const tickets = Number(summary.rows[0].tickets || 0);
    const fee = Math.round(gross * 0.08);
    const net = gross - fee;
    res.json({
      summary: {
        gross,
        fee,
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

app.post("/creator/staff", requireCreator, async (req, res) => {
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
    console.error("Creator staff create failed:", err);
    if (err.code === "23505")
      return res.status(409).json({ error: "Staff login ID is already taken" });
    res.status(400).json({ error: err.message || "Could not add staff" });
  } finally {
    client.release();
  }
});

const createStaffAssignment = async (
  client,
  {
    creatorId,
    staffId,
    eventId,
    tierName,
    qty,
    allocationMode,
    mode,
    commissionRate,
    purchasePrice,
    resalePrice,
  },
) => {
  const cleanQty = Number(qty);
  if (!Number.isInteger(cleanQty) || cleanQty < 1)
    throw new Error("Enter a valid ticket quantity");
  // Q5b: staff resale ("staff_owned") is out of scope for now; only
  // commission-based selling for the creator is allowed.
  if (String(allocationMode || mode || "creator_quota") === "staff_owned") {
    throw new Error("Staff resale is not available yet");
  }
  const cleanMode = "creator_quota";
  const cleanCommissionRate = Math.max(0, Number(commissionRate || 0));
  const staff = await client.query(
    "SELECT id FROM staff_accounts WHERE id=$1 AND creator_id=$2",
    [staffId, creatorId],
  );
  if (!staff.rows.length) throw new Error("Staff member not found");
  const event = await client.query(
    "SELECT * FROM creator_events WHERE id=$1 AND creator_id=$2 FOR UPDATE",
    [eventId, creatorId],
  );
  if (!event.rows.length) throw new Error("Creator event not found");
  const tickets = Array.isArray(event.rows[0].tickets)
    ? event.rows[0].tickets
    : [];
  const tier = tickets.find((ticket) => ticket.name === tierName);
  if (!tier) throw new Error("Ticket tier not found");
  if (Number(tier.qty || 0) < cleanQty)
    throw new Error("Not enough tickets available");
  const basePrice = Number(tier.price || 0);
  const cleanPurchasePrice =
    Number.isFinite(Number(purchasePrice)) && Number(purchasePrice) >= 0
      ? Number(purchasePrice)
      : basePrice;
  const cleanResalePrice =
    Number.isFinite(Number(resalePrice)) && Number(resalePrice) >= 0
      ? Number(resalePrice)
      : basePrice;
  tier.qty = Number(tier.qty || 0) - cleanQty;
  await client.query("UPDATE creator_events SET tickets=$1 WHERE id=$2", [
    JSON.stringify(tickets),
    eventId,
  ]);
  await client.query(
    "UPDATE staff_accounts SET assigned_tickets=assigned_tickets+$1, primary_event_id=COALESCE(primary_event_id,$3) WHERE id=$2",
    [cleanQty, staffId, eventId],
  );
  const id = `ASN-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
  const result = await client.query(
    `INSERT INTO staff_assignments (
       id, creator_id, staff_id, event_id, event_name, tier_name, qty, price,
       allocation_mode, commission_rate, purchase_price, resale_price
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING *`,
    [
      id,
      creatorId,
      staffId,
      eventId,
      event.rows[0].name,
      tierName,
      cleanQty,
      basePrice,
      cleanMode,
      cleanCommissionRate,
      cleanPurchasePrice,
      cleanResalePrice,
    ],
  );
  if (cleanMode === "staff_owned") {
    await client.query(
      "UPDATE creator_events SET revenue=COALESCE(revenue,0)+$1 WHERE id=$2",
      [cleanPurchasePrice * cleanQty, eventId],
    );
  }
  return result.rows[0];
};


// Commission balance + cash owed to the organizer (H10 / D4).
const staffWalletFor = (staffId) => staffWallet(pool, staffId);

app.post(
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
      console.error("Creator staff assignment failed:", err);
      res
        .status(400)
        .json({ error: err.message || "Could not assign tickets" });
    } finally {
      client.release();
    }
  },
);

app.post("/staff/login", async (req, res) => {
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
        staffWalletFor(member.id),
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

app.get("/staff/share/:token", async (req, res) => {
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

app.get("/staff/dashboard", requireStaff, async (req, res) => {
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
        staffWalletFor(member.id),
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

app.post("/staff/sales", requireStaff, async (req, res) => {
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
    const wallet = await staffWalletFor(staff.rows[0].id);
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

app.post("/staff/withdrawals", requireStaff, async (req, res) => {
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

app.post("/creator/finance/unlock", requireCreator, async (req, res) => {
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
    const gross = Number(result.rows[0].gross || 0);
    res.json({
      initialized,
      gross,
      net: Math.round(gross * 0.94),
      tickets: Number(result.rows[0].tickets || 0),
    });
  } catch (err) {
    console.error("Creator finance unlock failed:", err);
    res.status(500).json({ error: "Could not unlock finance" });
  }
});

app.use(require("./src/routes/adminAuth"));

app.use(require("./src/routes/admin"));

// Public media only (event banners, profile photos). Any other key, e.g.
// kyc-documents/..., is a 404 here (H14).
const PUBLIC_MEDIA_PREFIXES = ["event-banners/", "profiles/"];
app.get("/r2/media/*key", (req, res) => {
  try {
    const key = Array.isArray(req.params.key)
      ? req.params.key.join("/")
      : req.params.key;
    if (!key || key.includes("..") || !PUBLIC_MEDIA_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      return res.status(404).send("Not found");
    }
    res.redirect(presignR2({ method: "GET", key, expires: 300 }));
  } catch (err) {
    console.error("R2 media redirect failed:", err);
    res.status(500).send("Media unavailable");
  }
});


app.use(require("./src/routes/orders"));

// The signed-in creator's own events (H12: by creator id, never by matching
// a buyer's unverified email to a creator account).
app.get("/profile/creator-events", requireCreator, async (req, res) => {
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


app.use(require("./src/routes/tickets"));

app.use(require("./src/routes/buyerAuth"));

app.use(require("./src/routes/auth"));

// Startup order: schema migrations → data fix-ups → accept requests.
// Listening only after migrations means no request can hit a missing table.
const PORT = process.env.PORT || 3003;
async function start() {
  await runMigrations({ connectionString: process.env.DATABASE_URL, ssl: dbSsl });
  await initDb();
  // Housekeeping every 5 minutes (correctness never depends on it).
  setInterval(() => {
    expireStaleOrders(pool).catch((err) => console.error("Order expiry failed:", err.message));
    pruneRateLimitHits(pool).catch((err) => console.error("Rate-limit prune failed:", err.message));
  }, 5 * 60 * 1000).unref();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Server startup failed:", err);
  process.exit(1);
});
