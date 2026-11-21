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
const { recordAdminAction, listAdminActions } = require("./src/services/adminAudit");
const { ResetError, setTemporaryPassword } = require("./src/services/passwordReset");
const { USER_ACTIVE_STATUS, normalizeUserStatus, adminTable } = require("./src/utils/accounts");
const { startSession } = require("./src/services/sessions");
const { isEventBookable, eventSalesClosed } = require("./src/utils/events");
const { pruneRateLimitHits, rateLimit } = require("./src/middleware/rateLimit");
const {
  getPayuConfig,
  cleanPayuText,
  formatPayuAmount,
  makeRequestHash,
  isValidResponseHash,
} = require("./src/services/payu");
const {
  ORDER_SETTINGS,
  OrderError,
  createOrder,
  applyPayuResult,
  getOrderForBuyer,
  withAvailability,
  expireStaleOrders,
} = require("./src/services/orders");
const { pool, dbSsl } = require("./src/db/pool");
const { initDb } = require("./src/db/initDb");
const { APP_BASE_URL, publicDir, uploadsDir, appHtmlPath } = require("./src/config");
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
  publicAdmin,
  publicAdminCreator,
  USER_NOT_FOUND_ERROR,
  publicUser,
  publicCreatorKycDocument,
} = require("./src/utils/serializers");
const { hasSmtpConfig, createMailTransporter } = require("./src/services/mail");
const {
  requireCreator,
  requireStaff,
  requireAdmin,
  ADMIN_REAUTH_MINUTES,
  requireSuperAdmin,
  confirmed,
  requireBuyer,
  requireTicketViewer,
  requireScanIdentity,
} = require("./src/middleware/auth");
const { audit } = require("./src/middleware/audit");
const { corsMiddleware, openerPolicy, blockCrossSiteCookieRequests } = require("./src/middleware/security");

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

// ── Admin login (H6) ───────────────────────────────────────────────────────
// Rate limited per IP and per email; 5 wrong passwords in a row lock the
// account for 15 minutes. Locked accounts and rate limits get the same 429
// message, so the response does not reveal which emails are admins.
const ADMIN_LOCKOUT = { maxFailures: 5, lockMinutes: 15 };
const TOO_MANY_ATTEMPTS = "Too many attempts. Please try again later.";
// Compared against when the email is unknown, so both cases take about as long.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("not-a-real-password", 10);

// Super admins live in their own table; check it first.
async function findAdminByEmail(email) {
  const superAdmin = await pool.query(
    "SELECT *, 'super' AS admin_type FROM super_admin_accounts WHERE LOWER(email)=$1",
    [email],
  );
  if (superAdmin.rows.length) return superAdmin.rows[0];
  const admin = await pool.query("SELECT *, 'admin' AS admin_type FROM admin_accounts WHERE LOWER(email)=$1", [email]);
  return admin.rows[0] || null;
}

// One atomic UPDATE: count the failure, and on the 5th lock the account and
// reset the counter. Returns true when this failure locked the account.
async function registerFailedAdminLogin(account) {
  const result = await pool.query(
    `UPDATE ${adminTable(account.admin_type)} SET
       locked_until = CASE WHEN failed_login_count + 1 >= $2
                           THEN NOW() + make_interval(mins => $3) ELSE locked_until END,
       failed_login_count = CASE WHEN failed_login_count + 1 >= $2 THEN 0 ELSE failed_login_count + 1 END
     WHERE id=$1
     RETURNING locked_until`,
    [account.id, ADMIN_LOCKOUT.maxFailures, ADMIN_LOCKOUT.lockMinutes],
  );
  const lockedUntil = result.rows[0] && result.rows[0].locked_until;
  return Boolean(lockedUntil && new Date(lockedUntil) > new Date());
}

// ── Second factor: emailed one-time code (H6 part 3) ──
const ADMIN_OTP = { ttlMinutes: 5, maxAttempts: 5 };
const otpHash = (challengeId, code) => crypto.createHash("sha256").update(`${challengeId}:${code}`).digest("hex");
// Local development without SMTP may show the code in the response. Never in production.
const adminOtpDevMode = () => process.env.ADMIN_OTP_DEV_MODE === "true" && process.env.NODE_ENV !== "production";
const maskEmail = (email) => String(email).replace(/^(.)[^@]*(@.*)$/, "$1***$2");

async function startAdminOtpChallenge(req, res, account) {
  if (!hasSmtpConfig() && !adminOtpDevMode()) {
    return res.status(503).json({ error: "Admin login needs the email service (SMTP) to send the login code." });
  }
  const challengeId = crypto.randomBytes(16).toString("hex");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await pool.query(
    `INSERT INTO admin_login_challenges (id, admin_type, admin_id, code_hash, expires_at)
     VALUES ($1, $2, $3, $4, NOW() + make_interval(mins => $5))`,
    [challengeId, account.admin_type, String(account.id), otpHash(challengeId, code), ADMIN_OTP.ttlMinutes],
  );
  if (hasSmtpConfig()) {
    await createMailTransporter().sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: account.email,
      subject: "Your admin login code",
      text: `Your admin login code is ${code}. It expires in ${ADMIN_OTP.ttlMinutes} minutes. If you did not try to log in, change your password.`,
    });
  }
  await recordAdminAction(pool, req, { action: "login.otp_sent", admin: { sub: account.id, adminType: account.admin_type, email: account.email } });
  res.json({
    otpRequired: true,
    challengeId,
    sentTo: maskEmail(account.email),
    ...(adminOtpDevMode() && !hasSmtpConfig() ? { devCode: code } : {}),
  });
}

// Password and second factor verified: start the session.
async function completeAdminLogin(req, res, account) {
  const adminType = account.admin_type;
  const fresh = await pool.query(`UPDATE ${adminTable(adminType)} SET last_login=NOW() WHERE id=$1 RETURNING *`, [account.id]);
  await recordAdminAction(pool, req, { action: "login.success", admin: { sub: account.id, adminType, email: account.email } });
  res.json({
    message: adminType === "super" ? "Super admin login successful" : "Admin login successful",
    admin: publicAdmin(adminType === "super" ? { ...fresh.rows[0], role: "Super Admin", is_super_admin: true } : fresh.rows[0]),
    ...(await startSession(pool, req, res, { role: "admin", accountId: account.id, adminType })),
  });
}

const adminLoginEmail = (req) => String((req.body && req.body.email) || "").trim().toLowerCase();

app.post(
  "/admin/login",
  rateLimit({ name: "admin-login-ip", windowSeconds: 600, max: 20, key: (req) => req.ip, message: TOO_MANY_ATTEMPTS }),
  rateLimit({ name: "admin-login-email", windowSeconds: 600, max: 10, key: (req) => adminLoginEmail(req) || null, message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    try {
      const email = adminLoginEmail(req);
      const password = String((req.body && req.body.password) || "");
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }
      const account = await findAdminByEmail(email);
      if (account && account.locked_until && new Date(account.locked_until) > new Date()) {
        await recordAdminAction(pool, req, { action: "login.blocked_locked", email }).catch(() => {});
        return res.status(429).json({ error: TOO_MANY_ATTEMPTS });
      }
      const storedHash = account && String(account.password || "").startsWith("$2") ? account.password : DUMMY_PASSWORD_HASH;
      const passwordOk = await bcrypt.compare(password, storedHash);
      if (!account || account.status !== "Active" || !passwordOk) {
        if (account && account.status === "Active") {
          const locked = await registerFailedAdminLogin(account);
          if (locked) await recordAdminAction(pool, req, { action: "login.locked", email }).catch(() => {});
        }
        await recordAdminAction(pool, req, { action: "login.failed", email }).catch(() => {});
        return res.status(401).json({ error: "Invalid admin email or password" });
      }
      await pool.query(
        `UPDATE ${adminTable(account.admin_type)} SET failed_login_count=0, locked_until=NULL WHERE id=$1`,
        [account.id],
      );
      // The password alone is not enough: send the second-factor code.
      await startAdminOtpChallenge(req, res, account);
    } catch (err) {
      console.error("Admin login failed:", err);
      res.status(500).json({ error: "Admin login failed" });
    }
  },
);


app.post(
  "/admin/reauth",
  requireAdmin,
  rateLimit({ name: "admin-reauth", windowSeconds: 600, max: 10, key: (req) => req.admin && String(req.admin.sub), message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    try {
      const password = String((req.body && req.body.password) || "");
      const table = adminTable(req.admin.adminType);
      const found = await pool.query(`SELECT *, $2::text AS admin_type FROM ${table} WHERE id=$1`, [req.admin.sub, req.admin.adminType]);
      const account = found.rows[0];
      const ok = account && String(account.password || "").startsWith("$2") && (await bcrypt.compare(password, account.password));
      if (!ok) {
        // Wrong confirmations count towards the same lockout as logins.
        if (account) await registerFailedAdminLogin(account);
        await recordAdminAction(pool, req, { action: "reauth.failed" }).catch(() => {});
        return res.status(401).json({ error: "Wrong password" });
      }
      await pool.query(
        `UPDATE ${table} SET reauth_until = NOW() + make_interval(mins => $2), failed_login_count = 0 WHERE id=$1`,
        [req.admin.sub, ADMIN_REAUTH_MINUTES],
      );
      await recordAdminAction(pool, req, { action: "reauth.success" });
      res.json({ success: true, validForMinutes: ADMIN_REAUTH_MINUTES });
    } catch (err) {
      console.error("Admin re-auth failed:", err);
      res.status(500).json({ error: "Could not confirm password" });
    }
  },
);

// Step 2 of admin login: the emailed code. The challenge row is locked so two
// parallel guesses cannot both be counted as the "first" attempt.
app.post(
  "/admin/login/verify",
  rateLimit({ name: "admin-otp-ip", windowSeconds: 600, max: 30, key: (req) => req.ip, message: TOO_MANY_ATTEMPTS }),
  async (req, res) => {
    const challengeId = String((req.body && req.body.challengeId) || "");
    const code = String((req.body && req.body.code) || "").replace(/\D/g, "");
    if (!challengeId || code.length !== 6) return res.status(400).json({ error: "Enter the 6-digit code" });
    const client = await pool.connect();
    let account = null;
    try {
      await client.query("BEGIN");
      const found = await client.query("SELECT * FROM admin_login_challenges WHERE id=$1 FOR UPDATE", [challengeId]);
      const challenge = found.rows[0];
      const usable = challenge && !challenge.used_at && new Date(challenge.expires_at) > new Date()
        && challenge.attempts < ADMIN_OTP.maxAttempts;
      if (!usable) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "The code has expired. Please log in again." });
      }
      const expected = Buffer.from(challenge.code_hash, "hex");
      const actual = Buffer.from(otpHash(challengeId, code), "hex");
      if (!crypto.timingSafeEqual(expected, actual)) {
        await client.query("UPDATE admin_login_challenges SET attempts = attempts + 1 WHERE id=$1", [challengeId]);
        await client.query("COMMIT");
        await recordAdminAction(pool, req, { action: "login.otp_failed", admin: { sub: challenge.admin_id, adminType: challenge.admin_type } }).catch(() => {});
        return res.status(401).json({ error: "Wrong code" });
      }
      await client.query("UPDATE admin_login_challenges SET used_at = NOW() WHERE id=$1", [challengeId]);
      const row = await client.query(
        `SELECT *, $2::text AS admin_type FROM ${adminTable(challenge.admin_type)} WHERE id=$1 AND status='Active'`,
        [challenge.admin_id, challenge.admin_type],
      );
      await client.query("COMMIT");
      account = row.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Admin OTP verification failed:", err);
      return res.status(500).json({ error: "Could not verify the code" });
    } finally {
      client.release();
    }
    if (!account) return res.status(401).json({ error: "Admin account not active" });
    try {
      await completeAdminLogin(req, res, account);
    } catch (err) {
      console.error("Admin login completion failed:", err);
      res.status(500).json({ error: "Admin login failed" });
    }
  },
);

app.get("/admin/session", requireAdmin, async (req, res) => {
  try {
    if (req.admin.adminType === "super") {
      const superResult = await pool.query(
        "SELECT * FROM super_admin_accounts WHERE id=$1",
        [req.admin.sub],
      );
      if (
        !superResult.rows.length ||
        superResult.rows[0].status !== "Active"
      ) {
        return res.status(401).json({ error: "Admin account not found" });
      }
      return res.json({
        admin: publicAdmin({
          ...superResult.rows[0],
          role: "Super Admin",
          is_super_admin: true,
        }),
      });
    }
    const result = await pool.query(
      "SELECT * FROM admin_accounts WHERE id=$1",
      [req.admin.sub],
    );
    if (!result.rows.length || result.rows[0].status !== "Active") {
      return res.status(401).json({ error: "Admin account not found" });
    }
    res.json({ admin: publicAdmin(result.rows[0]) });
  } catch (err) {
    console.error("Admin session restore failed:", err);
    res.status(500).json({ error: "Could not restore admin session" });
  }
});

app.post("/admin/accounts", requireAdmin, requireSuperAdmin, confirmed, audit("admin.create", (req) => ({ targetType: "admin", targetId: req.body && req.body.email })), async (req, res) => {
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

app.patch(
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

app.delete(
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

app.post("/admin/staff", requireAdmin, audit("staff.create", (req) => ({ targetType: "staff", targetId: req.body && req.body.staffId })), async (req, res) => {
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

app.delete("/admin/staff/:staffId", requireAdmin, confirmed, audit("staff.delete", (req) => ({ targetType: "staff", targetId: req.params.staffId })), async (req, res) => {
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
app.post(
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
app.post(
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
app.get("/admin/audit-log", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.get("/admin/snapshot", requireAdmin, async (req, res) => {
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

app.patch("/admin/events/:eventId/status", requireAdmin, confirmed, audit("event.status", (req) => ({ targetType: "event", targetId: req.params.eventId, details: { status: req.body && req.body.status } })), async (req, res) => {
  try {
    const { eventId } = req.params;
    const { status } = req.body || {};
    if (!eventId || !status) {
      return res.status(400).json({ error: "eventId and status are required" });
    }
    const validStatuses = ["live", "paused", "blocked", "completed", "cancelled"];
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

app.patch("/admin/users/:userId/status", requireAdmin, confirmed, audit("user.status", (req) => ({ targetType: "user", targetId: req.params.userId, details: { status: req.body && req.body.status } })), async (req, res) => {
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
app.get(
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

app.get("/admin/creators/:creatorId", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.patch("/admin/creators/:creatorId/documents/:documentId/status", requireAdmin, requireSuperAdmin, audit("creator.document.status", (req) => ({ targetType: "creator_document", targetId: req.params.documentId, details: { creatorId: req.params.creatorId, status: req.body && req.body.status } })), async (req, res) => {
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

app.patch("/admin/creators/:creatorId/status", requireAdmin, requireSuperAdmin, confirmed, audit("creator.status", (req) => ({ targetType: "creator", targetId: req.params.creatorId, details: { status: req.body && req.body.status } })), async (req, res) => {
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

app.patch("/admin/creators/status-by-email", requireAdmin, requireSuperAdmin, confirmed, audit("creator.status", (req) => ({ targetType: "creator", targetId: req.body && req.body.email, details: { status: req.body && req.body.status } })), async (req, res) => {
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

app.patch("/admin/staff/:staffId/status", requireAdmin, confirmed, audit("staff.status", (req) => ({ targetType: "staff", targetId: req.params.staffId, details: { status: req.body && req.body.status } })), async (req, res) => {
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

const makeTicketQrPayload = (bookingId, token, eventId = "") =>
  `VYBERA-TICKET|${bookingId}|${eventId || "NOEVENT"}|${token}`;

const ticketResponse = async (booking) => {
  const qrPayload = makeTicketQrPayload(booking.id, booking.qr_token, booking.event_id);
  return {
    id: booking.id,
    buyerName: booking.buyer_name || booking.buyer_email || "BLAK Tickets Guest",
    buyerEmail: booking.buyer_email,
    eventId: booking.event_id,
    eventName: booking.event_name,
    eventDate: booking.event_date,
    eventVenue: booking.event_venue,
    eventBanner: booking.event_banner,
    ticketType: booking.ticket_type,
    price: Number(booking.price || 0),
    qty: Number(booking.qty || 1),
    total: Number(booking.total || 0),
    status: booking.status,
    scannedAt: booking.scanned_at,
    qrPayload,
    qrImage: await QRCode.toDataURL(qrPayload, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: "M",
    }),
  };
};

// ── Orders & payments (C4) ────────────────────────────────────────────────
// The browser never sends a price, booking ID or "paid" flag. It asks for
// (event, tier, qty); the server prices it from the DB, reserves seats and
// either confirms a free order or returns a PayU checkout form. Tickets are
// issued only by the verified PayU callback (see src/services/orders.js).

const publicOrder = (order) => ({
  id: order.id,
  status: order.status,
  eventId: order.event_id,
  tierName: order.tier_name,
  qty: Number(order.qty),
  unitPrice: Number(order.unit_price),
  subtotal: Number(order.subtotal),
  platformFee: Number(order.platform_fee),
  gst: Number(order.gst),
  amount: Number(order.amount),
  paymentMethod: order.payment_method,
  expiresAt: order.expires_at,
  paidAt: order.paid_at,
  createdAt: order.created_at,
});

// Audit trail for the admin "payments" view. Only verified callbacks are
// written, so nobody can overwrite a payment record by posting fake data (H9).
const PAYMENT_STATUS_LABELS = {
  paid: "Success",
  already_paid: "Success",
  paid_needs_refund: "Paid - needs refund",
  failed: "Failed",
  amount_mismatch: "Amount mismatch",
};
const recordPaymentCallback = async (body, orderId, outcome) => {
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
      String(body.txnid || ""),
      String(body.email || "") || null,
      String(body.mihpayid || "") || null,
      PAYMENT_STATUS_LABELS[outcome] || outcome,
      outcome === "paid" || outcome === "already_paid" ? null : String(body.error_Message || outcome).slice(0, 200),
      orderId,
    ],
  );
};

app.get("/config/public", (req, res) => {
  res.json({
    platformFeePercent: ORDER_SETTINGS.platformFeePercent,
    gstPercent: ORDER_SETTINGS.gstPercent,
    maxTicketsPerOrder: ORDER_SETTINGS.maxTicketsPerOrder,
    freeTicketsPerUserPerEvent: ORDER_SETTINGS.freeTicketsPerUserPerEvent,
  });
});

const orderRateLimits = [
  rateLimit({ name: "orders-user", windowSeconds: 600, max: 10, key: (req) => req.buyer && String(req.buyer.sub) }),
  rateLimit({ name: "orders-ip", windowSeconds: 600, max: 30, key: (req) => req.ip }),
];

app.post("/orders", requireBuyer, ...orderRateLimits, async (req, res) => {
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
      // PayU requires a phone; Google-only accounts may not have one yet.
      phone: String(buyer.phone || "").replace(/\D/g, "").slice(-10) || "9999999999",
      surl: `${APP_BASE_URL}/payments/payu/success`,
      furl: `${APP_BASE_URL}/payments/payu/failure`,
      udf1: order.id,
    };
    fields.hash = makeRequestHash(fields, payu.salt);
    res.status(201).json({ order: publicOrder(order), payment: { action: payu.action, fields } });
  } catch (err) {
    if (err instanceof OrderError) return res.status(err.status).json({ error: err.message });
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
        await recordPaymentCallback(body, orderId, outcome).catch((err) =>
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
app.post("/payments/payu/success", handlePayuCallback(true));
app.post("/payments/payu/failure", handlePayuCallback(false));

// The buyer's own order and ticket. Someone else's order → 404, so order IDs
// cannot be probed.
app.get("/orders/:orderId", requireBuyer, async (req, res) => {
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

// A buyer's tickets = bookings whose user_id is the buyer's own id.
// No matching by email: guest bookings (user_id NULL) and staff walk-in sales
// stay unreachable here, so registering with someone's email reveals nothing (C6).
const listBuyerTickets = async (userId) => {
  const result = await pool.query(
    "SELECT * FROM bookings WHERE user_id=$1 ORDER BY booked_at DESC",
    [userId],
  );
  return Promise.all(result.rows.map(ticketResponse));
};

app.get("/bookings/mine", requireBuyer, async (req, res) => {
  try {
    res.json({ bookings: await listBuyerTickets(req.buyer.sub) });
  } catch (err) {
    console.error("Buyer booking history failed:", err);
    res.status(500).json({ error: "Could not load booking history" });
  }
});

// Same list; kept because the profile page calls this path.
app.get("/profile/tickets", requireBuyer, async (req, res) => {
  try {
    res.json({ bookings: await listBuyerTickets(req.buyer.sub) });
  } catch (err) {
    console.error("Profile tickets failed:", err);
    res.status(500).json({ error: "Could not load profile tickets" });
  }
});

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


app.get("/bookings/:bookingId/ticket", requireTicketViewer, async (req, res) => {
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

app.post("/bookings/scan", requireScanIdentity, async (req, res) => {
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
           AND (
             sa.id IS NOT NULL
             OR st.primary_event_id=b.event_id
             OR (st.creator_id IS NULL AND st.primary_event_id IS NULL)
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
