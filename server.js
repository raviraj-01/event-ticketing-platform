const express = require("express");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const QRCode = require("qrcode");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
require("dotenv").config({ path: path.join(__dirname, ".env") });

process.on("unhandledRejection", (err) => {
  console.error("Unhandled async error:", err);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught server error:", err);
});

const app = express();
// Only files inside public/ are reachable from the browser. Never point
// express.static at __dirname: that would publish server.js, CLAUDE.md, etc.
const publicDir = path.join(__dirname, "public");
const appHtmlPath = path.join(publicDir, "index.html");
const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

const corsOptions = {
  origin: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "ngrok-skip-browser-warning",
    "X-Requested-With",
  ],
  exposedHeaders: ["Content-Length", "Content-Type"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use((req, res, next) => {
  res.header("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Vary", "Origin");
  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, ngrok-skip-browser-warning, X-Requested-With",
  );
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(bodyParser.json({ limit: "30mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.get("/favicon.ico", (req, res) => {
  res.type("image/svg+xml").sendFile(path.join(publicDir, "assets", "blak-ticket-logo.svg"));
});
// index:false so "/" always goes through the no-cache route below.
app.use(express.static(publicDir, { index: false }));
app.use("/uploads", express.static(uploadsDir));

if (!process.env.DATABASE_URL) {
  console.error(
    "DATABASE_URL is missing. Add it to VYBERA/.env before starting the server.",
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

const r2Config = {
  endpoint: process.env.R2_ENDPOINT,
  bucket: process.env.R2_BUCKET,
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
};

const hasR2Config = () =>
  r2Config.endpoint &&
  r2Config.bucket &&
  r2Config.accessKeyId &&
  r2Config.secretAccessKey;

const hasTwilioVerifyConfig = () =>
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN &&
  process.env.TWILIO_VERIFY_SERVICE_SID;

const localOtpStore = new Map();
const googleClientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
const googleOAuthClient = googleClientId ? new OAuth2Client(googleClientId) : null;

if (!hasTwilioVerifyConfig()) {
  console.warn(
    "Signup OTP is disabled until TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID are added to .env.",
  );
}

// ── Email transporter ───────────────────────────────────────────────────────
const createMailTransporter = () => {
  if (process.env.SMTP_SERVICE) {
    return nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      port: Number(process.env.SMTP_PORT || 465),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

const hasSmtpConfig = () =>
  (process.env.SMTP_SERVICE || process.env.SMTP_HOST) &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS;

if (!hasSmtpConfig()) {
  console.warn(
    "Email (forgot password) is disabled until SMTP_SERVICE/SMTP_HOST, SMTP_USER, and SMTP_PASS are added to .env.",
  );
}

const hmac = (key, value, encoding) =>
  crypto.createHmac("sha256", key).update(value).digest(encoding);

const sha256 = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error(
    "JWT_SECRET is missing. Add it to VYBERA/.env before starting the server.",
  );
  process.exit(1);
}
const base64Url = (value) =>
  Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
const base64UrlJson = (value) => base64Url(JSON.stringify(value));
const signJwt = (payload, expiresInSeconds = 60 * 60 * 24 * 30) => {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const body = { ...payload, iat: now, exp: now + expiresInSeconds };
  const unsigned = `${base64UrlJson(header)}.${base64UrlJson(body)}`;
  const signature = crypto
    .createHmac("sha256", jwtSecret)
    .update(unsigned)
    .digest("base64url");
  return `${unsigned}.${signature}`;
};
const verifyJwt = (token) => {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto
    .createHmac("sha256", jwtSecret)
    .update(unsigned)
    .digest("base64url");
  const actual = Buffer.from(parts[2]);
  const wanted = Buffer.from(expected);
  if (
    actual.length !== wanted.length ||
    !crypto.timingSafeEqual(actual, wanted)
  ) {
    throw new Error("Invalid token signature");
  }
  const payload = JSON.parse(
    Buffer.from(parts[1], "base64url").toString("utf8"),
  );
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }
  return payload;
};
const publicUser = (user) => ({
  id: user.id,
  username: user.username,
  firstName: user.first_name,
  lastName: user.last_name,
  email: user.email,
  phone: user.phone,
  countryCode: user.country_code,
  city: user.city,
  profileImage: user.profile_image_url,
  profileImageKey: user.profile_image_key,
  profileImageStorage: user.profile_image_storage,
  status: user.status || "Active",
});

const USER_ACTIVE_STATUS = "Active";
const USER_BLOCKED_STATUSES = new Set(["Suspended", "Blocked", "Inactive"]);
const EVENT_AVAILABLE_STATUSES = new Set(["live", "upcoming"]);
const EVENT_NOT_FOUND_ERROR = "Event does not exist";
const USER_NOT_FOUND_ERROR = "User account not found";
const STAFF_NOT_FOUND_ERROR = "Staff account not found";

const normalizeUserStatus = (status) =>
  String(status || USER_ACTIVE_STATUS).trim();

const isUserActive = (status) =>
  !USER_BLOCKED_STATUSES.has(normalizeUserStatus(status));

const isEventBookable = (status) =>
  EVENT_AVAILABLE_STATUSES.has(String(status || "").trim().toLowerCase());

const publicCreator = (creator) => ({
  id: creator.id,
  name: creator.name,
  email: creator.email,
  phone: creator.phone,
  category: creator.category,
  about: creator.about,
  kycStatus: creator.kyc_status,
  joinedAt: creator.created_at,
});

const creatorKycDocumentUrl = (document) => {
  if (!document) return "";
  if (document.storage === "r2") return `/r2/media/${encodeR2Key(document.object_key)}`;
  if (document.storage === "local") {
    return `/uploads/${String(document.object_key || "").replace(/^local\//, "")}`;
  }
  return "";
};

const publicCreatorKycDocument = (document) => ({
  id: document.id,
  documentType: document.document_type,
  fileName: document.file_name,
  contentType: document.content_type,
  storage: document.storage,
  url: creatorKycDocumentUrl(document),
  verificationStatus: document.verification_status || "Pending",
  verifiedAt: document.verified_at,
  verifiedBy: document.verified_by,
  createdAt: document.created_at,
});

const publicAdminCreator = (creator) => ({
  id: `CRT-${creator.id}`,
  creatorId: creator.id,
  name: creator.name,
  email: creator.email,
  phone: creator.phone,
  category: creator.category,
  status: creator.kyc_status,
  events: Number(creator.events || 0),
  revenue: Number(creator.revenue || 0),
  fee: 8,
  documents: (creator.documents || []).map(publicCreatorKycDocument),
  createdAt: creator.created_at,
});

const publicCreatorEvent = (event) => ({
  id: event.id,
  creatorId: event.creator_id,
  creatorName: event.creator_name,
  name: event.name,
  category: event.category,
  description: event.description,
  date: event.event_date,
  time: event.start_time,
  endTime: event.end_time,
  venue: event.venue,
  city: event.city,
  capacity: event.capacity,
  latitude: event.latitude,
  longitude: event.longitude,
  banner: event.banner_url,
  bannerKey: event.banner_key,
  visibility: event.visibility,
  status: event.status,
  tickets: event.tickets || [],
  bookingCount: Number(event.booking_count || 0),
  revenue: Number(event.revenue || 0),
  checkins: Number(event.checkins || 0),
  createdAt: event.created_at,
});

const creatorEventSalesQuery = `
  SELECT e.*,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS booking_count,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue
  FROM creator_events e
  LEFT JOIN bookings b ON b.event_id=e.id
`;

const publicStaffAssignment = (assignment) => ({
  id: assignment.id,
  staffPk: assignment.staff_id,
  staffId: assignment.staff_id,
  eventId: assignment.event_id,
  eventName: assignment.event_name,
  tierName: assignment.tier_name,
  qty: Number(assignment.qty || 0),
  soldCount: Number(assignment.sold_count || 0),
  price: Number(assignment.price || 0),
  mode: assignment.allocation_mode || "creator_quota",
  allocationMode: assignment.allocation_mode || "creator_quota",
  commissionRate: Number(assignment.commission_rate || 0),
  purchasePrice: Number(assignment.purchase_price || assignment.price || 0),
  resalePrice: Number(assignment.resale_price || assignment.price || 0),
  assignedAt: assignment.created_at,
});

const publicStaffShareUrl = (req, member) => {
  if (!member || !member.share_token) return "";
  const origin = req ? `${req.protocol}://${req.get("host")}` : "";
  const eventId = member.primary_event_id
    ? `&event=${encodeURIComponent(member.primary_event_id)}`
    : "";
  return `${origin}/?staff=${encodeURIComponent(member.share_token)}${eventId}`;
};

const publicStaffSale = (sale) => ({
  id: sale.id,
  staffPk: sale.staff_id,
  assignmentId: sale.assignment_id,
  eventId: sale.event_id,
  eventName: sale.event_name,
  tierName: sale.tier_name,
  buyerName: sale.buyer_name,
  buyerPhone: sale.buyer_phone,
  buyerEmail: sale.buyer_email,
  qty: Number(sale.qty || 0),
  price: Number(sale.price || 0),
  total: Number(sale.total || 0),
  commission: Number(sale.commission || 0),
  revenueOwner: sale.revenue_owner || "staff",
  allocationMode: sale.allocation_mode || "creator_quota",
  paymentMode: sale.payment_mode,
  bookingId: sale.booking_id,
  soldAt: sale.created_at,
});

const publicStaffWithdrawal = (withdrawal) => ({
  id: withdrawal.id,
  staffPk: withdrawal.staff_id,
  amount: Number(withdrawal.amount || 0),
  method: withdrawal.method,
  bankAccountName: withdrawal.bank_account_name,
  bankAccountNumber: withdrawal.bank_account_number,
  bankIfsc: withdrawal.bank_ifsc,
  upiId: withdrawal.upi_id,
  status: withdrawal.status,
  requestedAt: withdrawal.created_at,
});

const publicStaff = (member) => ({
  id: member.id,
  creatorId: member.creator_id,
  name: member.name,
  staffId: member.staff_id,
  email: member.email,
  phone: member.phone,
  role: member.role,
  assignedGate: member.assigned_gate,
  gates: member.assigned_gate ? [member.assigned_gate] : [],
  primaryEventId: member.primary_event_id,
  shareToken: member.share_token,
  shareUrl: member.share_url || "",
  status: member.status,
  assignedTickets: Number(member.assigned_tickets || 0),
  soldTickets: Number(member.sold_tickets || 0),
  earnings: Number(member.earnings || 0),
  createdByAdminEmail: member.created_by_admin_email || null,
  createdAt: member.created_at,
});

const publicAdmin = (admin) => ({
  id: admin.id,
  name: admin.name,
  email: admin.email,
  role: admin.role,
  isSuperAdmin: Boolean(admin.is_super_admin),
  status: admin.status,
  lastLogin: admin.last_login,
  createdAt: admin.created_at,
});

const requireCreator = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "creator") throw new Error("Creator login required");
    req.creator = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Creator login required" });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "admin") throw new Error("Admin login required");
    const isSuper = payload.adminType === "super";
    let adminCheck = await pool.query(
      isSuper
        ? "SELECT id, status FROM super_admin_accounts WHERE id=$1"
        : "SELECT id, status FROM admin_accounts WHERE id=$1",
      [payload.sub],
    );
    if (
      !isSuper &&
      !adminCheck.rows.length &&
      payload.email
    ) {
      adminCheck = await pool.query(
        "SELECT id, status FROM super_admin_accounts WHERE LOWER(email)=LOWER($1)",
        [payload.email],
      );
      if (adminCheck.rows.length) payload.adminType = "super";
    }
    if (!adminCheck.rows.length || adminCheck.rows[0].status !== "Active") {
      throw new Error("Admin account not found");
    }
    req.admin = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Admin login required" });
  }
};

const requireSuperAdmin = async (req, res, next) => {
  try {
    if (!req.admin) {
      return res.status(403).json({ error: "Super Admin access required" });
    }
    const migrateLegacySuperAdmin = async (legacyAdmin) => {
      const migrated = await pool.query(
        `INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (email) DO UPDATE SET
           name=EXCLUDED.name,
           password=EXCLUDED.password,
           status=EXCLUDED.status,
           last_login=EXCLUDED.last_login
         RETURNING id, status`,
        [
          legacyAdmin.name,
          legacyAdmin.email,
          legacyAdmin.password,
          legacyAdmin.status,
          legacyAdmin.last_login,
          legacyAdmin.created_at,
        ],
      );
      await pool.query("DELETE FROM admin_accounts WHERE id=$1", [
        legacyAdmin.id,
      ]);
      return migrated;
    };
    let result =
      req.admin.adminType === "super"
        ? await pool.query(
            "SELECT id, status FROM super_admin_accounts WHERE id=$1",
            [req.admin.sub],
          )
        : await pool.query(
            "SELECT id, status FROM super_admin_accounts WHERE LOWER(email)=LOWER($1)",
            [req.admin.email || ""],
          );
    if (!result.rows.length) {
      const legacyById = await pool.query(
        "SELECT * FROM admin_accounts WHERE id=$1 AND role='Super Admin'",
        [req.admin.sub],
      );
      if (legacyById.rows.length) {
        result = await migrateLegacySuperAdmin(legacyById.rows[0]);
      }
    }
    if (!result.rows.length && req.admin.email) {
      const legacyByEmail = await pool.query(
        "SELECT * FROM admin_accounts WHERE LOWER(email)=LOWER($1) AND role='Super Admin'",
        [req.admin.email],
      );
      if (legacyByEmail.rows.length) {
        result = await migrateLegacySuperAdmin(legacyByEmail.rows[0]);
      }
    }
    const admin = result.rows[0];
    if (!admin || admin.status !== "Active") {
      return res.status(403).json({ error: "Super Admin access required" });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: "Could not verify admin access" });
  }
};

const requireStaff = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "staff") throw new Error("Staff login required");
    const staffCheck = await pool.query(
      "SELECT id, status FROM staff_accounts WHERE id=$1",
      [payload.sub]
    );
    if (!staffCheck.rows.length || staffCheck.rows[0].status !== "active") {
      throw new Error(STAFF_NOT_FOUND_ERROR);
    }
    req.staff = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Staff login required" });
  }
};

const requireScanIdentity = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope === "creator") {
      req.scanIdentity = { type: "creator", payload };
      return next();
    }
    if (payload.scope === "staff") {
      req.scanIdentity = { type: "staff", payload };
      return next();
    }
    throw new Error("Scanner login required");
  } catch (err) {
    res.status(401).json({ error: err.message || "Scanner login required" });
  }
};

const requireBuyer = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (!payload.sub || payload.scope) throw new Error("Buyer login required");
    const userCheck = await pool.query(
      "SELECT id, status FROM users WHERE id=$1",
      [payload.sub],
    );
    if (!userCheck.rows.length || !isUserActive(userCheck.rows[0].status)) {
      throw new Error(USER_NOT_FOUND_ERROR);
    }
    req.buyer = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Buyer login required" });
  }
};

const requireProfileIdentity = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    const email = String(payload.email || "")
      .trim()
      .toLowerCase();
    if (!email) throw new Error("Profile login required");
    req.profileIdentity = { ...payload, email };
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Profile login required" });
  }
};

const getSigningKey = (secret, dateStamp) => {
  const kDate = hmac(`AWS4${secret}`, dateStamp);
  const kRegion = hmac(kDate, "auto");
  const kService = hmac(kRegion, "s3");
  return hmac(kService, "aws4_request");
};

const encodeR2Key = (key) =>
  key
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");

const cleanFileName = (name) =>
  String(name || "upload")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "upload";

const makeObjectKey = (folder, fileName) => {
  const safeFolder = String(folder || "misc").replace(/[^a-zA-Z0-9/_-]+/g, "-");
  const safeName = cleanFileName(fileName);
  return `${safeFolder}/${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${safeName}`;
};

const presignR2 = ({ method, key, expires = 900 }) => {
  if (!hasR2Config()) {
    throw new Error("Cloudflare R2 is not configured");
  }

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const endpoint = new URL(r2Config.endpoint);
  const canonicalUri = `/${r2Config.bucket}/${encodeR2Key(key)}`;
  const credential = `${r2Config.accessKeyId}/${scope}`;
  const query = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": credential,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expires),
    "X-Amz-SignedHeaders": "host",
  };
  const canonicalQuery = Object.keys(query)
    .sort()
    .map(
      (name) =>
        `${encodeURIComponent(name)}=${encodeURIComponent(query[name])}`,
    )
    .join("&");
  const canonicalHeaders = `host:${endpoint.host}\n`;
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256(canonicalRequest),
  ].join("\n");
  const signature = hmac(
    getSigningKey(r2Config.secretAccessKey, dateStamp),
    stringToSign,
    "hex",
  );

  return `${endpoint.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
};

const parseDataUrl = (dataUrl) => {
  const match = String(dataUrl || "").match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    throw new Error("Invalid data URL");
  }
  return { contentType: match[1], buffer: Buffer.from(match[2], "base64") };
};

const saveLocalBuffer = ({ key, buffer, contentType }) => {
  const localKey = key.replace(/^\/+/, "");
  const filePath = path.join(uploadsDir, localKey);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return {
    key: `local/${localKey}`,
    mediaUrl: `/uploads/${localKey}`,
    contentType,
    storage: "local",
  };
};

const uploadBufferToR2 = async ({ key, buffer, contentType }) => {
  const uploadUrl = presignR2({ method: "PUT", key });
  const response = await fetch(uploadUrl, {
    method: "PUT",
    headers: { "Content-Type": contentType || "application/octet-stream" },
    body: buffer,
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(
      `R2 upload failed (${response.status}): ${body || response.statusText}`,
    );
  }
  return {
    key,
    mediaUrl: `/r2/media/${encodeR2Key(key)}`,
    contentType,
    storage: "r2",
  };
};

const saveAsset = async ({ fileName, folder, dataUrl, requireR2 = false }) => {
  const parsed = parseDataUrl(dataUrl);
  const key = makeObjectKey(folder, fileName);
  try {
    return await uploadBufferToR2({
      key,
      buffer: parsed.buffer,
      contentType: parsed.contentType,
    });
  } catch (err) {
    console.error("R2 asset upload failed:", err.message);
    if (requireR2) {
      throw err;
    }
    const localName = key;
    const saved = saveLocalBuffer({
      key: localName,
      buffer: parsed.buffer,
      contentType: parsed.contentType,
    });
    saved.r2Error = err.message;
    return saved;
  }
};

const cleanPathSegment = (value, fallback) =>
  String(value || fallback || "user")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) ||
  fallback ||
  "user";

const initDb = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS first_name TEXT,
      ADD COLUMN IF NOT EXISTS last_name TEXT,
      ADD COLUMN IF NOT EXISTS phone TEXT,
      ADD COLUMN IF NOT EXISTS country_code TEXT,
      ADD COLUMN IF NOT EXISTS city TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_url TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_key TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_storage TEXT,
      ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'email',
      ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Active'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      buyer_email TEXT,
      event_id TEXT,
      event_name TEXT,
      event_date TEXT,
      event_venue TEXT,
      event_banner TEXT,
      ticket_type TEXT,
      price NUMERIC,
      qty INTEGER,
      total NUMERIC,
      status TEXT DEFAULT 'upcoming',
      ticket_record_url TEXT,
      ticket_record_key TEXT,
      ticket_record_storage TEXT,
      booked_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE bookings
      ADD COLUMN IF NOT EXISTS buyer_name TEXT,
      ADD COLUMN IF NOT EXISTS qr_token TEXT,
      ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS staff_id TEXT,
      ADD COLUMN IF NOT EXISTS staff_ref TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      category TEXT NOT NULL,
      about TEXT NOT NULL,
      password TEXT NOT NULL,
      kyc_status TEXT NOT NULL DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE creator_accounts
      ADD COLUMN IF NOT EXISTS finance_pin TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_kyc_documents (
      id SERIAL PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      document_type TEXT NOT NULL,
      file_name TEXT NOT NULL,
      object_key TEXT NOT NULL,
      storage TEXT NOT NULL,
      content_type TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE creator_kyc_documents
      ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'Pending',
      ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS verified_by TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_events (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      creator_name TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      event_date TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT,
      venue TEXT NOT NULL,
      city TEXT NOT NULL,
      capacity INTEGER NOT NULL,
      latitude NUMERIC,
      longitude NUMERIC,
      banner_url TEXT NOT NULL,
      banner_key TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'Public',
      status TEXT NOT NULL DEFAULT 'live',
      tickets JSONB NOT NULL DEFAULT '[]'::jsonb,
      booking_count INTEGER NOT NULL DEFAULT 0,
      revenue NUMERIC NOT NULL DEFAULT 0,
      checkins INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'Admin',
      status TEXT NOT NULL DEFAULT 'Active',
      last_login TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS super_admin_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Active',
      last_login TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_accounts (
      id TEXT PRIMARY KEY,
      creator_id INTEGER REFERENCES creator_accounts(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      staff_id TEXT UNIQUE NOT NULL,
      email TEXT,
      phone TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      assigned_tickets INTEGER NOT NULL DEFAULT 0,
      sold_tickets INTEGER NOT NULL DEFAULT 0,
      earnings NUMERIC NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_accounts
      ADD COLUMN IF NOT EXISTS password TEXT,
      ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Scanner',
      ADD COLUMN IF NOT EXISTS assigned_gate TEXT,
      ADD COLUMN IF NOT EXISTS primary_event_id TEXT,
      ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE,
      ADD COLUMN IF NOT EXISTS created_by_admin_email TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_assignments (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
      event_name TEXT NOT NULL,
      tier_name TEXT NOT NULL,
      qty INTEGER NOT NULL,
      sold_count INTEGER NOT NULL DEFAULT 0,
      price NUMERIC NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_assignments
      ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota',
      ADD COLUMN IF NOT EXISTS commission_rate NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS purchase_price NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS resale_price NUMERIC NOT NULL DEFAULT 0
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_sales (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      assignment_id TEXT REFERENCES staff_assignments(id) ON DELETE SET NULL,
      event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
      event_name TEXT NOT NULL,
      tier_name TEXT NOT NULL,
      buyer_name TEXT,
      buyer_phone TEXT,
      buyer_email TEXT,
      qty INTEGER NOT NULL DEFAULT 1,
      price NUMERIC NOT NULL DEFAULT 0,
      total NUMERIC NOT NULL DEFAULT 0,
      payment_mode TEXT NOT NULL DEFAULT 'cash',
      booking_id TEXT REFERENCES bookings(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_sales
      ADD COLUMN IF NOT EXISTS commission NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS revenue_owner TEXT NOT NULL DEFAULT 'staff',
      ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_withdrawals (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      amount NUMERIC NOT NULL,
      method TEXT NOT NULL DEFAULT 'upi',
      bank_account_name TEXT,
      bank_account_number TEXT,
      bank_ifsc TEXT,
      upi_id TEXT,
      status TEXT NOT NULL DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_transactions (
      txnid TEXT PRIMARY KEY,
      booking_id TEXT,
      event_id TEXT,
      ticket_type TEXT,
      qty INTEGER,
      buyer_email TEXT,
      amount NUMERIC NOT NULL DEFAULT 0,
      gateway_payment_id TEXT,
      status TEXT NOT NULL DEFAULT 'Pending',
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      error TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    UPDATE creator_events e SET
      booking_count=COALESCE(s.tickets,0),
      revenue=COALESCE(s.revenue,0)
    FROM (
      SELECT event_id,
        COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
        COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
      FROM bookings
      WHERE event_id IS NOT NULL
      GROUP BY event_id
    ) s
    WHERE e.id=s.event_id
  `);

  const superAdminEmail = String(
    process.env.SUPERADMIN_EMAIL || "superadmin@blaktickets.in",
  )
    .trim()
    .toLowerCase();
  const superAdminPassword = process.env.SUPERADMIN_PASSWORD;
  await pool.query(`
    INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
    SELECT name, email, password, status, last_login, created_at
    FROM admin_accounts
    WHERE role='Super Admin'
    ON CONFLICT (email) DO UPDATE SET
      name=EXCLUDED.name,
      password=EXCLUDED.password,
      status=EXCLUDED.status,
      last_login=EXCLUDED.last_login
  `);
  await pool.query("DELETE FROM admin_accounts WHERE role='Super Admin'");
  if (!superAdminPassword) {
    console.warn(
      "SUPERADMIN_PASSWORD is missing. Skipping super-admin account bootstrap.",
    );
    return;
  }
  const existingAdmin = await pool.query(
    "SELECT id, password FROM super_admin_accounts WHERE email=$1",
    [superAdminEmail],
  );
  const passwordMatches = existingAdmin.rows[0]
    ? await bcrypt.compare(superAdminPassword, existingAdmin.rows[0].password)
    : false;
  const passwordHash = passwordMatches
    ? existingAdmin.rows[0].password
    : await bcrypt.hash(superAdminPassword, 10);
  await pool.query(
    `INSERT INTO super_admin_accounts (name, email, password, status)
     VALUES ($1,$2,$3,'Active')
     ON CONFLICT (email) DO UPDATE SET
       name=EXCLUDED.name,
       password=EXCLUDED.password,
       status=EXCLUDED.status`,
    ["BLAK Tickets Super Admin", superAdminEmail, passwordHash],
  );
  await pool.query(
    "DELETE FROM admin_accounts WHERE email=$1 AND role='Super Admin'",
    [superAdminEmail],
  );
};

initDb().catch((err) => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});

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

app.post("/r2/upload-url", (req, res) => {
  try {
    const { fileName, contentType, folder } = req.body || {};
    if (!fileName) {
      return res.status(400).json({ error: "fileName is required" });
    }
    const key = makeObjectKey(folder, fileName);
    res.json({
      key,
      uploadUrl: presignR2({ method: "PUT", key }),
      mediaUrl: `/r2/media/${encodeR2Key(key)}`,
      contentType: contentType || "application/octet-stream",
    });
  } catch (err) {
    console.error("R2 upload URL failed:", err);
    res.status(500).json({ error: err.message || "R2 upload URL failed" });
  }
});

app.post("/local-upload", (req, res) => {
  try {
    const { fileName, folder, dataUrl } = req.body || {};
    if (!fileName || !dataUrl) {
      return res
        .status(400)
        .json({ error: "fileName and dataUrl are required" });
    }
    const match = String(dataUrl).match(/^data:([^;]+);base64,(.+)$/);
    if (!match) {
      return res.status(400).json({ error: "Invalid data URL" });
    }
    const safeFolder = String(folder || "misc").replace(
      /[^a-zA-Z0-9/_-]+/g,
      "-",
    );
    const dir = path.join(uploadsDir, safeFolder);
    fs.mkdirSync(dir, { recursive: true });
    const safeName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${cleanFileName(fileName)}`;
    const filePath = path.join(dir, safeName);
    fs.writeFileSync(filePath, Buffer.from(match[2], "base64"));
    res.json({
      key: `local/${safeFolder}/${safeName}`,
      mediaUrl: `/uploads/${safeFolder}/${safeName}`,
      contentType: match[1],
      storage: "local",
    });
  } catch (err) {
    console.error("Local upload failed:", err);
    res.status(500).json({ error: err.message || "Local upload failed" });
  }
});

app.post("/assets/upload", async (req, res) => {
  try {
    const { fileName, folder, dataUrl, purpose, userId, email } =
      req.body || {};
    if (!fileName || !dataUrl) {
      return res
        .status(400)
        .json({ error: "fileName and dataUrl are required" });
    }

    const isProfileUpload = purpose === "profile";
    const cleanEmail = String(email || "")
      .trim()
      .toLowerCase();
    const cleanUserId = userId ? Number(userId) : null;
    if (isProfileUpload && !cleanUserId && !cleanEmail) {
      return res
        .status(401)
        .json({ error: "Login is required before uploading a profile image" });
    }

    const uploadFolder = isProfileUpload
      ? `profiles/${cleanUserId ? `user-${cleanUserId}` : cleanPathSegment(cleanEmail, "email-user")}`
      : folder || "misc";
    const asset = await saveAsset({
      fileName,
      folder: uploadFolder,
      dataUrl,
      requireR2: isProfileUpload,
    });

    if (isProfileUpload) {
      let updateResult;
      if (cleanUserId) {
        updateResult = await pool.query(
          `UPDATE users
           SET profile_image_url=$1, profile_image_key=$2, profile_image_storage=$3
           WHERE id=$4`,
          [asset.mediaUrl, asset.key, asset.storage, cleanUserId],
        );
      } else {
        updateResult = await pool.query(
          `UPDATE users
           SET profile_image_url=$1, profile_image_key=$2, profile_image_storage=$3
           WHERE email=$4`,
          [asset.mediaUrl, asset.key, asset.storage, cleanEmail],
        );
      }

      if (!updateResult || updateResult.rowCount < 1) {
        return res
          .status(404)
          .json({ error: "Profile user was not found for this upload" });
      }
    }

    res.json(asset);
  } catch (err) {
    console.error("Asset upload failed:", err);
    res.status(500).json({ error: err.message || "Asset upload failed" });
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
    const uploaded = [];
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
      const asset = await saveAsset({
        fileName: file.fileName,
        folder: `kyc-documents/${cleanPathSegment(cleanEmail, "creator")}/${documentType}`,
        dataUrl: file.dataUrl,
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
    res
      .status(500)
      .json({ error: err.message || "Creator application failed" });
  } finally {
    client.release();
  }
});

app.post("/creator/login", async (req, res) => {
  try {
    const readLoginValue = (value) => {
      if (!value) return "";
      if (typeof value === "object") {
        return (
          value.email ||
          value.user ||
          value.username ||
          value.loginId ||
          value.identifier ||
          value.name ||
          ""
        );
      }
      return value;
    };
    const loginIdentifier = String(
      readLoginValue(
        req.body &&
          (req.body.email ||
            req.body.user ||
            req.body.username ||
            req.body.loginId ||
            req.body.identifier ||
            req.body.login),
      ),
    ).trim();
    const cleanEmail = loginIdentifier.trim().toLowerCase();
    const password = String((req.body && req.body.password) || "");
    if (!cleanEmail || !password) {
      return res
        .status(400)
        .json({ error: "Creator email and password are required" });
    }
    const result = await pool.query(
      `SELECT id, name, email, phone, category, about, password, kyc_status, created_at
       FROM creator_accounts
       WHERE LOWER(email)=LOWER($1)
          OR LOWER(name)=LOWER($1)
          OR LOWER(split_part(email, '@', 1))=LOWER(split_part($1, '@', 1))
       ORDER BY CASE
          WHEN LOWER(email)=LOWER($1) THEN 0
          WHEN LOWER(name)=LOWER($1) THEN 1
          ELSE 2
        END
       LIMIT 1`,
      [cleanEmail],
    );
    const creator = result.rows[0];
    let validPassword = false;
    if (creator) {
      const storedPassword = String(creator.password || "");
      if (storedPassword.startsWith("$2")) {
        validPassword = await bcrypt.compare(password, storedPassword);
      } else {
        validPassword = password === storedPassword;
        if (validPassword) {
          const upgradedPassword = await bcrypt.hash(password, 10);
          await pool.query(
            "UPDATE creator_accounts SET password=$1 WHERE id=$2",
            [upgradedPassword, creator.id],
          );
        }
      }
    }
    if (!creator || !validPassword) {
      return res
        .status(401)
        .json({
          error: "Invalid creator email or password",
          reason: creator ? "password_mismatch" : "creator_not_found",
          loginReceived: loginIdentifier,
        });
    }
    if (creator.kyc_status !== "Approved") {
      const message =
        creator.kyc_status === "Rejected"
          ? "Your creator application was rejected. Please contact support."
          : "Your creator account is pending super admin verification.";
      return res.status(403).json({
        error: message,
        reason: "creator_not_verified",
        kycStatus: creator.kyc_status,
      });
    }
    res.json({
      message: "Creator login successful",
      creator: publicCreator(creator),
      token: signJwt({
        sub: creator.id,
        email: creator.email,
        scope: "creator",
      }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error("Creator login failed:", err);
    res.status(500).json({ error: "Creator login failed" });
  }
});

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
    res.json({ events: result.rows.map(publicCreatorEvent) });
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
    const asset = await saveAsset({
      fileName,
      folder: `event-banners/creator-${req.creator.sub}`,
      dataUrl,
      requireR2: true,
    });
    res.status(201).json(asset);
  } catch (err) {
    console.error("Creator banner upload failed:", err);
    res.status(500).json({ error: err.message || "Banner upload failed" });
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
           COALESCE(SUM(CASE WHEN ss.revenue_owner='staff' THEN ss.total ELSE ss.commission END),0)::NUMERIC AS db_earnings
         FROM staff_accounts s
         LEFT JOIN staff_sales ss ON ss.staff_id=s.id
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
    res.json({
      staff: staff.rows.map((member) => {
        const mapped = {
          ...member,
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
  const cleanMode =
    String(allocationMode || mode || "creator_quota") === "staff_owned"
      ? "staff_owned"
      : "creator_quota";
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

const eventSalesClosed = (event) => {
  const value = String((event && event.event_date) || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const eventDate = new Date(`${value}T23:59:59.999Z`);
  return Number.isFinite(eventDate.getTime()) && eventDate < new Date();
};

const staffWalletFor = async (staffId) => {
  const result = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN payment_mode='online' THEN
         CASE WHEN revenue_owner='staff' THEN total ELSE commission END
       ELSE 0 END),0)::NUMERIC AS online_revenue,
       COALESCE(SUM(CASE WHEN payment_mode='cash' THEN
         CASE WHEN revenue_owner='staff' THEN total ELSE commission END
       ELSE 0 END),0)::NUMERIC AS cash_revenue,
       COALESCE(SUM(CASE WHEN revenue_owner='staff' THEN total ELSE commission END),0)::NUMERIC AS total_earned,
       COALESCE(SUM(qty),0)::INTEGER AS tickets_sold
     FROM staff_sales
     WHERE staff_id=$1`,
    [staffId],
  );
  const withdrawals = await pool.query(
    `SELECT COALESCE(SUM(amount),0)::NUMERIC AS withdrawn
     FROM staff_withdrawals
     WHERE staff_id=$1 AND status <> 'Rejected'`,
    [staffId],
  );
  const row = result.rows[0] || {};
  const withdrawn = Number(
    (withdrawals.rows[0] && withdrawals.rows[0].withdrawn) || 0,
  );
  const totalEarned = Number(row.total_earned || 0);
  return {
    onlineRevenue: Number(row.online_revenue || 0),
    cashRevenue: Number(row.cash_revenue || 0),
    totalEarned,
    withdrawn,
    availableBalance: Math.max(0, totalEarned - withdrawn),
    ticketsSold: Number(row.tickets_sold || 0),
  };
};

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
    const result = await pool.query(
      `SELECT *
       FROM staff_accounts
       WHERE status='active'
         AND (
           LOWER(staff_id)=LOWER($1)
           OR LOWER(COALESCE(email,''))=LOWER($1)
           OR regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g')=$2
         )
       LIMIT 1`,
      [cleanStaffId, digits],
    );
    if (!result.rows.length || !result.rows[0].password) {
      return res
        .status(404)
        .json({ error: "Staff account not found", staffNotFound: true });
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
      token: signJwt({
        sub: member.id,
        staffId: member.staff_id,
        creatorId: member.creator_id,
        scope: "staff",
      }),
    });
  } catch (err) {
    console.error("Staff login failed:", err);
    res.status(500).json({ error: "Staff login failed" });
  }
});

app.get("/staff/lookup", async (req, res) => {
  try {
    res.setHeader("Cache-Control", "no-store");
    const identifier = String((req.query && req.query.identifier) || "").trim();
    const digits = identifier.replace(/\D/g, "");
    if (!identifier) return res.json({ exists: false });
    const result = await pool.query(
      `SELECT 1
       FROM staff_accounts
       WHERE status='active'
         AND (
           LOWER(staff_id)=LOWER($1)
           OR LOWER(COALESCE(email,''))=LOWER($1)
           OR regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g')=$2
         )
       LIMIT 1`,
      [identifier.toLowerCase(), digits],
    );
    res.json({ exists: Boolean(result.rows.length) });
  } catch (err) {
    console.error("Staff lookup failed:", err);
    res.status(500).json({ error: "Could not check staff account" });
  }
});

app.get("/staff/share/:token", async (req, res) => {
  try {
    const token = decodeURIComponent(String(req.params.token || ""))
      .trim()
      .replace(/[.)\]\s]+$/g, "");
    const digits = token.replace(/\D/g, "");
    const result = await pool.query(
      `SELECT s.id, s.name, s.staff_id, s.email, s.phone, s.share_token, s.primary_event_id, e.name AS event_name
       FROM staff_accounts s
       LEFT JOIN creator_events e ON e.id=s.primary_event_id
       WHERE s.status='active'
         AND (
           s.share_token=$1
           OR LOWER(s.staff_id)=LOWER($1)
           OR LOWER(COALESCE(s.email,''))=LOWER($1)
           OR regexp_replace(COALESCE(s.phone,''), '\\D', '', 'g')=$2
         )
       LIMIT 1`,
      [token, digits],
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
    const amount = Number(req.body && req.body.amount);
    const method =
      String((req.body && req.body.method) || "upi")
        .trim()
        .toLowerCase() === "bank"
        ? "bank"
        : "upi";
    if (!Number.isFinite(amount) || amount <= 0)
      return res.status(400).json({ error: "Enter a valid withdrawal amount" });
    const staff = await pool.query(
      "SELECT * FROM staff_accounts WHERE id=$1 AND status='active'",
      [req.staff.sub],
    );
    if (!staff.rows.length)
      return res.status(404).json({ error: "Staff account not found" });
    const wallet = await staffWalletFor(req.staff.sub);
    if (amount > wallet.availableBalance)
      return res
        .status(400)
        .json({ error: "Amount exceeds available balance" });
    const bankAccountName = String(
      (req.body && req.body.bankAccountName) || "",
    ).trim();
    const bankAccountNumber = String(
      (req.body && req.body.bankAccountNumber) || "",
    ).trim();
    const bankIfsc = String((req.body && req.body.bankIfsc) || "")
      .trim()
      .toUpperCase();
    const upiId = String((req.body && req.body.upiId) || "").trim();
    if (
      method === "bank" &&
      (!bankAccountName || !bankAccountNumber || !bankIfsc)
    ) {
      return res.status(400).json({
        error:
          "Add bank account name, account number, and IFSC before withdrawal",
      });
    }
    if (method === "upi" && !upiId) {
      return res.status(400).json({ error: "Add a UPI ID before withdrawal" });
    }
    const id = `WD-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const result = await pool.query(
      `INSERT INTO staff_withdrawals (
        id, creator_id, staff_id, amount, method, bank_account_name, bank_account_number, bank_ifsc, upi_id
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *`,
      [
        id,
        staff.rows[0].creator_id,
        staff.rows[0].id,
        amount,
        method,
        bankAccountName || null,
        bankAccountNumber || null,
        bankIfsc || null,
        upiId || null,
      ],
    );
    res.status(201).json({
      message: "Withdrawal requested successfully",
      withdrawal: publicStaffWithdrawal(result.rows[0]),
      wallet: await staffWalletFor(req.staff.sub),
    });
  } catch (err) {
    console.error("Staff withdrawal failed:", err);
    res
      .status(400)
      .json({ error: err.message || "Could not request withdrawal" });
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

app.post("/admin/login", async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || "")
      .trim()
      .toLowerCase();
    const password = String((req.body && req.body.password) || "");
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const superResult = await pool.query(
      "SELECT * FROM super_admin_accounts WHERE email=$1",
      [email],
    );
    const superAdmin = superResult.rows[0];
    if (
      superAdmin &&
      superAdmin.status === "Active" &&
      (await bcrypt.compare(password, superAdmin.password))
    ) {
      const updatedSuper = await pool.query(
        "UPDATE super_admin_accounts SET last_login=NOW() WHERE id=$1 RETURNING *",
        [superAdmin.id],
      );
      res.json({
        message: "Super admin login successful",
        admin: publicAdmin({
          ...updatedSuper.rows[0],
          role: "Super Admin",
          is_super_admin: true,
        }),
        token: signJwt({
          sub: superAdmin.id,
          email: superAdmin.email,
          scope: "admin",
          adminType: "super",
        }),
      });
      return;
    }
    const result = await pool.query(
      "SELECT * FROM admin_accounts WHERE email=$1",
      [email],
    );
    const admin = result.rows[0];
    if (
      !admin ||
      admin.status !== "Active" ||
      !(await bcrypt.compare(password, admin.password))
    ) {
      return res.status(401).json({ error: "Invalid admin email or password" });
    }
    if (admin.role === "Super Admin") {
      const migrated = await pool.query(
        `INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
         VALUES ($1,$2,$3,$4,NOW(),$5)
         ON CONFLICT (email) DO UPDATE SET
           name=EXCLUDED.name,
           password=EXCLUDED.password,
           status=EXCLUDED.status,
           last_login=NOW()
         RETURNING *`,
        [
          admin.name,
          admin.email,
          admin.password,
          admin.status,
          admin.created_at,
        ],
      );
      await pool.query("DELETE FROM admin_accounts WHERE id=$1", [admin.id]);
      res.json({
        message: "Super admin login successful",
        admin: publicAdmin({
          ...migrated.rows[0],
          role: "Super Admin",
          is_super_admin: true,
        }),
        token: signJwt({
          sub: migrated.rows[0].id,
          email: migrated.rows[0].email,
          scope: "admin",
          adminType: "super",
        }),
      });
      return;
    }
    const updated = await pool.query(
      "UPDATE admin_accounts SET last_login=NOW() WHERE id=$1 RETURNING *",
      [admin.id],
    );
    res.json({
      message: "Admin login successful",
      admin: publicAdmin(updated.rows[0]),
      token: signJwt({
        sub: admin.id,
        email: admin.email,
        scope: "admin",
        adminType: "admin",
      }),
    });
  } catch (err) {
    console.error("Admin login failed:", err);
    res.status(500).json({ error: "Admin login failed" });
  }
});

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

app.post("/admin/accounts", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.post("/admin/staff", requireAdmin, async (req, res) => {
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

app.delete("/admin/staff/:staffId", requireAdmin, async (req, res) => {
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

app.get("/admin/snapshot", requireAdmin, async (req, res) => {
  try {
    const [buyers, creators, events, bookings, payments, staff, admins] =
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
      ]);
    res.json({
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
      creators: creators.rows.map(publicAdminCreator),
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

app.patch("/admin/events/:eventId/status", requireAdmin, async (req, res) => {
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

app.patch("/admin/users/:userId/status", requireAdmin, async (req, res) => {
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

app.patch("/admin/creators/:creatorId/documents/:documentId/status", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.patch("/admin/creators/:creatorId/status", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.patch("/admin/creators/status-by-email", requireAdmin, requireSuperAdmin, async (req, res) => {
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

app.patch("/admin/staff/:staffId/status", requireAdmin, async (req, res) => {
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

app.get("/r2/media/*key", (req, res) => {
  try {
    const key = Array.isArray(req.params.key)
      ? req.params.key.join("/")
      : req.params.key;
    if (!key) {
      return res.status(404).send("Not found");
    }
    res.redirect(presignR2({ method: "GET", key, expires: 300 }));
  } catch (err) {
    console.error("R2 media redirect failed:", err);
    res.status(500).send("Media unavailable");
  }
});

app.post("/r2/ticket-record", async (req, res) => {
  try {
    const booking = req.body || {};
    if (!booking.id) {
      return res.status(400).json({ error: "booking.id is required" });
    }
    const ticketJson = `data:application/json;base64,${Buffer.from(
      JSON.stringify({
        booking,
        storedAt: new Date().toISOString(),
      }),
    ).toString("base64")}`;
    const saved = await saveAsset({
      fileName: `${booking.id}.json`,
      folder: "tickets",
      dataUrl: ticketJson,
    });
    res.json(saved);
  } catch (err) {
    console.error("Ticket record upload failed:", err);
    res.status(500).json({ error: err.message || "Ticket record upload failed" });
  }
});

const payuConfig = {
  key: process.env.PAYU_KEY,
  salt: process.env.PAYU_SALT,
  action:
    (process.env.PAYU_ENV || "test").toLowerCase() === "production"
      ? "https://secure.payu.in/_payment"
      : "https://test.payu.in/_payment",
};

const formatPayuAmount = (amount) => Number(amount || 0).toFixed(2);
const cleanPayuText = (value, maxLength) =>
  String(value || "")
    .replace(/[^a-zA-Z0-9 .,_-]/g, "")
    .trim()
    .slice(0, maxLength);
const makePayuHash = (fields) => {
  const hashString = [
    fields.key,
    fields.txnid,
    fields.amount,
    fields.productinfo,
    fields.firstname,
    fields.email,
    fields.udf1 || "",
    fields.udf2 || "",
    fields.udf3 || "",
    fields.udf4 || "",
    fields.udf5 || "",
    "",
    "",
    "",
    "",
    "",
    payuConfig.salt,
  ].join("|");
  return crypto.createHash("sha512").update(hashString).digest("hex");
};
const makePayuResponseHash = (fields) => {
  const hashString = [
    payuConfig.salt,
    fields.status || "",
    "",
    "",
    "",
    "",
    "",
    fields.udf5 || "",
    fields.udf4 || "",
    fields.udf3 || "",
    fields.udf2 || "",
    fields.udf1 || "",
    fields.email || "",
    fields.firstname || "",
    fields.productinfo || "",
    fields.amount || "",
    fields.txnid || "",
    fields.key || "",
  ].join("|");
  return crypto.createHash("sha512").update(hashString).digest("hex");
};

const savePaymentTransaction = async (fields, status, verified, error = "") => {
  const txnid = String(fields.txnid || "").trim();
  if (!txnid) return;
  await pool.query(
    `INSERT INTO payment_transactions (
      txnid, booking_id, event_id, ticket_type, qty, buyer_email, amount,
      gateway_payment_id, status, verified, error, updated_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
    ON CONFLICT (txnid) DO UPDATE SET
      booking_id=COALESCE(EXCLUDED.booking_id, payment_transactions.booking_id),
      event_id=COALESCE(EXCLUDED.event_id, payment_transactions.event_id),
      ticket_type=COALESCE(EXCLUDED.ticket_type, payment_transactions.ticket_type),
      qty=COALESCE(EXCLUDED.qty, payment_transactions.qty),
      buyer_email=COALESCE(EXCLUDED.buyer_email, payment_transactions.buyer_email),
      amount=EXCLUDED.amount,
      gateway_payment_id=COALESCE(EXCLUDED.gateway_payment_id, payment_transactions.gateway_payment_id),
      status=EXCLUDED.status,
      verified=EXCLUDED.verified,
      error=EXCLUDED.error,
      updated_at=NOW()`,
    [
      txnid,
      fields.udf1 || null,
      fields.udf2 || null,
      fields.udf3 || null,
      Number(fields.udf4 || 0) || null,
      fields.email || null,
      Number(fields.amount || 0),
      fields.mihpayid || null,
      status,
      Boolean(verified),
      error || null,
    ],
  );
};

const payuReturnHtml = (result) => `<!doctype html>
<html><head><meta charset="utf-8"><title>BLAK Tickets Payment</title></head>
<body style="background:#000;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;">
<div>Completing payment...</div>
<script>
localStorage.setItem('VYBERA_PAYU_RESULT', ${JSON.stringify(JSON.stringify(result))});
window.location.replace('/?payment=payu&booking=' + encodeURIComponent(${JSON.stringify(result.bookingId || "")}));
</script>
</body></html>`;

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

app.post("/payments/payu/initiate", async (req, res) => {
  try {
    if (!payuConfig.key || !payuConfig.salt) {
      return res.status(500).json({ error: "PAYU_KEY and PAYU_SALT must be configured" });
    }
    const amount = Number(req.body && req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Valid amount in rupees is required" });
    }
    const { eventId } = req.body;
    if (eventId) {
      const eventResult = await pool.query(
        "SELECT id, status FROM creator_events WHERE id=$1",
        [eventId],
      );
      if (!eventResult.rows.length || !isEventBookable(eventResult.rows[0].status)) {
        return res.status(404).json({ error: EVENT_NOT_FOUND_ERROR });
      }
    }
    const origin = `https://${req.get("host")}`;
    const txnid = String(
      req.body.txnid || `VYB${Date.now()}${crypto.randomBytes(3).toString("hex")}`,
    ).slice(0, 40);
    const fields = {
      key: payuConfig.key,
      txnid,
      amount: formatPayuAmount(amount),
      productinfo: cleanPayuText(req.body.productinfo || "BLAK Tickets Event Booking", 100) || "BLAK Tickets Event Booking",
      firstname: cleanPayuText(req.body.firstname || "BLAK Tickets Guest", 60) || "BLAK Tickets Guest",
      email: String(req.body.email || "guest@blaktickets.in").slice(0, 100),
      phone: String(req.body.phone || "9999999999").replace(/\D/g, "").slice(-10) || "9999999999",
      surl: `${origin}/payments/payu/success?booking=${encodeURIComponent(txnid)}`,
      furl: `${origin}/payments/payu/failure?booking=${encodeURIComponent(txnid)}`,
      udf1: cleanPayuText(req.body.bookingId || "", 64),
      udf2: cleanPayuText(req.body.eventId || "", 64),
      udf3: cleanPayuText(req.body.ticketType || "", 64),
      udf4: cleanPayuText(req.body.qty || "", 20),
      udf5: "vybera",
      service_provider: "payu_paisa",
    };
    fields.hash = makePayuHash(fields);
    await savePaymentTransaction(fields, "Pending", false);
    res.json({ action: payuConfig.action, fields });
  } catch (err) {
    console.error("PayU initiation failed:", err);
    res.status(500).json({ error: err.message || "PayU initiation failed" });
  }
});

app.post("/payments/payu/success", async (req, res) => {
  try {
    const body = req.body || {};
    const expected = makePayuResponseHash(body);
    const verified = Boolean(body.hash) && expected === body.hash;
    await savePaymentTransaction(
      body,
      verified ? "Success" : "Failed",
      verified,
      verified ? "" : "Payment signature could not be verified",
    );
    res.send(
      payuReturnHtml({
        verified,
        status: body.status || "success",
        txnid: body.txnid || "",
        mihpayid: body.mihpayid || "",
        bookingId: body.udf1 || "",
        eventId: body.udf2 || "",
        ticketType: body.udf3 || "",
        qty: body.udf4 || "",
        amount: body.amount || "",
        error: verified ? "" : "Payment signature could not be verified",
      }),
    );
  } catch (err) {
    console.error("PayU success handling failed:", err);
    res.send(payuReturnHtml({ verified: false, status: "error", error: err.message || "PayU success handling failed" }));
  }
});

app.post("/payments/payu/failure", async (req, res) => {
  try {
    const body = req.body || {};
    let verified = false;
    if (body.hash && payuConfig.salt) {
      verified = makePayuResponseHash(body) === body.hash;
    }
    await savePaymentTransaction(
      body,
      "Failed",
      verified,
      body.error_Message || body.error || "Payment failed",
    );
    res.send(
      payuReturnHtml({
        verified,
        status: body.status || "failed",
        txnid: body.txnid || "",
        mihpayid: body.mihpayid || "",
        bookingId: body.udf1 || "",
        eventId: body.udf2 || "",
        ticketType: body.udf3 || "",
        qty: body.udf4 || "",
        amount: body.amount || "",
        error: body.error_Message || body.error || "Payment failed",
      }),
    );
  } catch (err) {
    console.error("PayU failure handling failed:", err);
    res.send(payuReturnHtml({ verified: false, status: "error", error: err.message || "PayU failure handling failed" }));
  }
});

app.post("/bookings", async (req, res) => {
  const client = await pool.connect();
  try {
    const booking = req.body || {};
    if (!booking.id) {
      return res.status(400).json({ error: "booking.id is required" });
    }
    if (booking.eventId) {
      const eventResult = await client.query(
        "SELECT id, status, name FROM creator_events WHERE id=$1",
        [booking.eventId],
      );
      if (!eventResult.rows.length || !isEventBookable(eventResult.rows[0].status)) {
        return res.status(404).json({ error: EVENT_NOT_FOUND_ERROR });
      }
    }
    const ticketJson = `data:application/json;base64,${Buffer.from(
      JSON.stringify({ booking, storedAt: new Date().toISOString() }),
    ).toString("base64")}`;
    const ticketRecord = await saveAsset({
      fileName: `${booking.id}.json`,
      folder: "tickets",
      dataUrl: ticketJson,
    });
    let userId = booking.userId || null;
    const buyerEmail = String(booking.buyerEmail || "").trim();
    let buyerUser = null;
    if (!userId && booking.buyerEmail) {
      const user = await client.query(
        "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
        [booking.buyerEmail],
      );
      buyerUser = user.rows[0] || null;
      userId = buyerUser ? buyerUser.id : null;
    } else if (userId) {
      const user = await client.query(
        "SELECT id, status FROM users WHERE id=$1 LIMIT 1",
        [userId],
      );
      buyerUser = user.rows[0] || null;
    }
    if (!buyerUser && buyerEmail) {
      const user = await client.query(
        "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
        [buyerEmail],
      );
      buyerUser = user.rows[0] || null;
      if (!userId && buyerUser) userId = buyerUser.id;
    }
    if (buyerUser && !isUserActive(buyerUser.status)) {
      return res.status(404).json({ error: USER_NOT_FOUND_ERROR });
    }
    await client.query("BEGIN");
    const qrToken = crypto.randomBytes(18).toString("hex");
    let staffMember = null;
    const staffRef = String(
      booking.staffId ||
        booking.staffPk ||
        booking.staffRef ||
        (booking.staffReferral &&
          (booking.staffReferral.staffDbId ||
            booking.staffReferral.staffId ||
            booking.staffReferral.token)) ||
        "",
    ).trim();
    if (staffRef) {
      const digits = staffRef.replace(/\D/g, "");
      const staffResult = await client.query(
        `SELECT * FROM staff_accounts
         WHERE status='active'
           AND (
             id=$1 OR share_token=$1 OR LOWER(staff_id)=LOWER($1)
             OR LOWER(COALESCE(email,''))=LOWER($1)
             OR regexp_replace(COALESCE(phone,''), '\\D', '', 'g')=$2
           )
         LIMIT 1`,
        [staffRef, digits],
      );
      staffMember = staffResult.rows[0] || null;
    }
    const savedBooking = await client.query(
      `INSERT INTO bookings (
        id, user_id, buyer_name, buyer_email, event_id, event_name, event_date, event_venue,
        event_banner, ticket_type, price, qty, total, status,
        ticket_record_url, ticket_record_key, ticket_record_storage, qr_token, staff_id, staff_ref, booked_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
      ON CONFLICT (id) DO UPDATE SET
        ticket_record_url=EXCLUDED.ticket_record_url,
        ticket_record_key=EXCLUDED.ticket_record_key,
        ticket_record_storage=EXCLUDED.ticket_record_storage,
        buyer_name=COALESCE(bookings.buyer_name, EXCLUDED.buyer_name),
        staff_id=COALESCE(bookings.staff_id, EXCLUDED.staff_id),
        staff_ref=COALESCE(bookings.staff_ref, EXCLUDED.staff_ref),
        qr_token=COALESCE(bookings.qr_token, EXCLUDED.qr_token)
      RETURNING *`,
      [
        booking.id,
        userId,
        booking.buyer || booking.buyerName || null,
        booking.buyerEmail || null,
        booking.eventId || null,
        booking.eventName || null,
        booking.eventDate || null,
        booking.eventVenue || null,
        booking.eventBanner || null,
        booking.ticketType || null,
        booking.price || 0,
        booking.qty || 1,
        booking.total || 0,
        booking.status || "upcoming",
        ticketRecord.mediaUrl,
        ticketRecord.key,
        ticketRecord.storage,
        qrToken,
        staffMember ? staffMember.id : null,
        staffRef || null,
        booking.bookedAt ? new Date(booking.bookedAt) : new Date(),
      ],
    );
    if (staffMember && booking.eventId && booking.ticketType) {
      const assignmentResult = await client.query(
        `SELECT * FROM staff_assignments
         WHERE staff_id=$1 AND event_id=$2 AND tier_name=$3
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE`,
        [staffMember.id, booking.eventId, booking.ticketType],
      );
      const assignment = assignmentResult.rows[0] || null;
      const cleanQty = Number(booking.qty || 1);
      if (cleanQty > 0) {
        const existingStaffSale = await client.query(
          "SELECT id FROM staff_sales WHERE booking_id=$1 AND staff_id=$2 LIMIT 1",
          [booking.id, staffMember.id],
        );
        if (!existingStaffSale.rows.length) {
          let assignmentMode = "creator_quota";
          let salePrice = Number(booking.price || 0);
          let staffSaleTotal = salePrice * cleanQty;
          let commission = 0;
          let revenueOwner = "creator";
          let assignmentId = null;
          let saleEventName = booking.eventName || null;
          let canRecordSale = true;
          if (assignment) {
            assignmentMode =
              String(assignment.allocation_mode || "creator_quota") === "staff_owned"
                ? "staff_owned"
                : "creator_quota";
            salePrice =
              assignmentMode === "staff_owned"
                ? Number(assignment.resale_price || assignment.price || booking.price || 0)
                : Number(assignment.price || booking.price || 0);
            staffSaleTotal = salePrice * cleanQty;
            commission =
              assignmentMode === "creator_quota"
                ? Math.round((staffSaleTotal * Number(assignment.commission_rate || 0)) / 100)
                : 0;
            revenueOwner = assignmentMode === "staff_owned" ? "staff" : "creator";
            assignmentId = assignment.id;
            saleEventName = booking.eventName || assignment.event_name;
            const remaining = Number(assignment.qty || 0) - Number(assignment.sold_count || 0);
            canRecordSale = remaining >= cleanQty;
          } else if (!salePrice && booking.total) {
            salePrice = Number(booking.total || 0) / cleanQty;
            staffSaleTotal = Number(booking.total || 0);
          }
          if (canRecordSale) {
            const saleId = `SLS-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
            await client.query(
              `INSERT INTO staff_sales (
              id, creator_id, staff_id, assignment_id, event_id, event_name, tier_name,
              buyer_name, buyer_phone, buyer_email, qty, price, total, payment_mode, booking_id,
              commission, revenue_owner, allocation_mode
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
            ON CONFLICT (id) DO NOTHING`,
              [
                saleId,
                staffMember.creator_id,
                staffMember.id,
                assignmentId,
                booking.eventId,
                saleEventName,
                booking.ticketType,
                booking.buyer || booking.buyerName || "Buyer",
                booking.buyerPhone || null,
                booking.buyerEmail || null,
                cleanQty,
                salePrice,
                staffSaleTotal,
                booking.payment && booking.payment.gateway ? "online" : "cash",
                booking.id,
                commission,
                revenueOwner,
                assignmentMode,
              ],
            );
            if (assignmentId) {
              await client.query(
                "UPDATE staff_assignments SET sold_count=sold_count+$1 WHERE id=$2",
                [cleanQty, assignmentId],
              );
            }
            await client.query(
              "UPDATE staff_accounts SET sold_tickets=sold_tickets+$1, earnings=earnings+$2 WHERE id=$3",
              [
                cleanQty,
                revenueOwner === "staff" ? staffSaleTotal : commission,
                staffMember.id,
              ],
            );
          }
        }
      }
    }
    if (booking.eventId) {
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
        [booking.eventId],
      );
    }
    await client.query("COMMIT");
    res.json({ booking: await ticketResponse(savedBooking.rows[0]) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Booking save failed:", err);
    res.status(500).json({ error: err.message || "Booking save failed" });
  } finally {
    client.release();
  }
});

app.get("/bookings/mine", requireBuyer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM bookings
       WHERE user_id=$1 OR (user_id IS NULL AND LOWER(buyer_email)=LOWER($2))
       ORDER BY booked_at DESC`,
      [req.buyer.sub, req.buyer.email],
    );
    const bookings = await Promise.all(
      result.rows.map(async (booking) => {
        if (!booking.qr_token) {
          const updated = await pool.query(
            "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
            [crypto.randomBytes(24).toString("hex"), booking.id],
          );
          booking = updated.rows[0];
        }
        return ticketResponse(booking);
      }),
    );
    res.json({ bookings });
  } catch (err) {
    console.error("Buyer booking history failed:", err);
    res.status(500).json({ error: "Could not load booking history" });
  }
});

app.get("/profile/tickets", requireProfileIdentity, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*
       FROM bookings b
       LEFT JOIN users u ON u.id=b.user_id
       WHERE LOWER(COALESCE(b.buyer_email, u.email, ''))=LOWER($1)
       ORDER BY b.booked_at DESC`,
      [req.profileIdentity.email],
    );
    const bookings = await Promise.all(
      result.rows.map(async (booking) => {
        if (!booking.qr_token) {
          const updated = await pool.query(
            "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
            [crypto.randomBytes(24).toString("hex"), booking.id],
          );
          booking = updated.rows[0];
        }
        return ticketResponse(booking);
      }),
    );
    res.json({ bookings });
  } catch (err) {
    console.error("Profile tickets failed:", err);
    res.status(500).json({ error: "Could not load profile tickets" });
  }
});

app.get("/profile/creator-events", requireProfileIdentity, async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       JOIN creator_accounts c ON c.id=e.creator_id
       WHERE LOWER(c.email)=LOWER($1)
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
      [req.profileIdentity.email],
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Profile creator events failed:", err);
    res.status(500).json({ error: "Could not load your created events" });
  }
});

app.get("/bookings/:bookingId/ticket", async (req, res) => {
  try {
    const bookingId = String(req.params.bookingId || "").trim();
    let result = await pool.query("SELECT * FROM bookings WHERE id=$1", [bookingId]);
    if (!result.rows.length)
      return res.status(404).json({ error: "Ticket not found" });
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

const twilioVerifyUrl = (suffix = "") =>
  `https://verify.twilio.com/v2/Services/${encodeURIComponent(
    process.env.TWILIO_VERIFY_SERVICE_SID || "",
  )}/Verification${suffix}`;

const twilioAuthHeader = () =>
  `Basic ${Buffer.from(
    `${process.env.TWILIO_ACCOUNT_SID || ""}:${process.env.TWILIO_AUTH_TOKEN || ""}`,
  ).toString("base64")}`;

const providerErrorMessage = (data, fallback) => {
  if (!data || typeof data !== "object") return fallback;
  return data.message || data.error || data.error_message || data.description || fallback;
};

const assertTwilioConfig = () => {
  if (!hasTwilioVerifyConfig()) {
    const err = new Error(
      "OTP service is not configured. Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID to .env, then restart the server.",
    );
    err.status = 500;
    throw err;
  }
};

const assertProviderSuccess = (response, data, fallback) => {
  if (!response.ok || data.error || data.error_message) {
    const err = new Error(providerErrorMessage(data, fallback));
    err.status = response.ok ? 400 : response.status;
    throw err;
  }
};

const isLocalOtpFallbackAllowed = (req) => {
  const host = String(req.hostname || req.headers.host || "").toLowerCase();
  return (
    host.includes("localhost") ||
    host.includes("127.0.0.1") ||
    host.includes("::1")
  );
};

const pruneLocalOtpStore = () => {
  const now = Date.now();
  for (const [identifier, entry] of localOtpStore.entries()) {
    if (!entry || entry.expiresAt <= now) localOtpStore.delete(identifier);
  }
};

const createLocalOtpEntry = (identifier) => {
  pruneLocalOtpStore();
  const code = String(Math.floor(100000 + Math.random() * 900000));
  localOtpStore.set(identifier, {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  return code;
};

const verifyLocalOtpEntry = (identifier, otp) => {
  pruneLocalOtpStore();
  const entry = localOtpStore.get(identifier);
  if (!entry || entry.expiresAt <= Date.now()) {
    localOtpStore.delete(identifier);
    return false;
  }
  if (String(entry.code) !== String(otp)) return false;
  localOtpStore.delete(identifier);
  return true;
};

const makeSignupOtpToken = (identifier) =>
  signJwt({ scope: "signup-phone-otp", identifier }, 10 * 60);

const verifySignupOtpToken = async (token, countryCode, phone) => {
  const identifier = `${String(countryCode || "+91").replace(/\D/g, "")}${String(phone || "").replace(/\D/g, "")}`;
  try {
    const payload = verifyJwt(token);
    if (payload.scope !== "signup-phone-otp" || payload.identifier !== identifier) {
      throw new Error("OTP verification does not match this phone number");
    }
    return payload;
  } catch (err) {
    throw err;
  }
};

const sendSignupOtp = async (req, res) => {
  try {
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    if (!/^91\d{10}$/.test(identifier)) {
      return res.status(400).json({ error: "A valid India mobile number with country code is required" });
    }
    const allowLocalFallback = isLocalOtpFallbackAllowed(req);
    if (!hasTwilioVerifyConfig()) {
      if (!allowLocalFallback) {
        assertTwilioConfig();
      }
      const devOtp = createLocalOtpEntry(identifier);
      return res.json({
        sent: true,
        identifier,
        provider: "local-dev",
        devOtp,
        data: { status: "pending", channel: "local-dev" },
      });
    }
    const params = new URLSearchParams({
      To: `+${identifier}`,
      Channel: process.env.TWILIO_VERIFY_CHANNEL || "sms",
    });
    const response = await fetch(twilioVerifyUrl("s"), {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });
    const data = await response.json().catch(() => ({}));
    assertProviderSuccess(response, data, "Twilio OTP send failed");
    res.json({ sent: true, identifier, data });
  } catch (err) {
    console.error("Twilio OTP send failed:", err);
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    if (
      /^91\d{10}$/.test(identifier) &&
      isLocalOtpFallbackAllowed(req) &&
      (err.status === 401 || err.status === 403)
    ) {
      const devOtp = createLocalOtpEntry(identifier);
      return res.json({
        sent: true,
        identifier,
        provider: "local-dev",
        devOtp,
        data: { status: "pending", channel: "local-dev", fallback: true },
      });
    }
    res.status(err.status || 500).json({ sent: false, error: err.message || "Twilio OTP send failed" });
  }
};

const verifySignupOtp = async (req, res) => {
  try {
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    const otp = String((req.body && req.body.otp) || "").trim();
    if (!/^91\d{10}$/.test(identifier) || !/^\d{4,8}$/.test(otp)) {
      return res.status(400).json({ verified: false, error: "A valid mobile number and OTP are required" });
    }
    if (verifyLocalOtpEntry(identifier, otp)) {
      return res.json({
        verified: true,
        accessToken: makeSignupOtpToken(identifier),
        data: { status: "approved", channel: "local-dev" },
      });
    }
    assertTwilioConfig();
    const params = new URLSearchParams({ To: `+${identifier}`, Code: otp });
    const response = await fetch(twilioVerifyUrl("Check"), {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });
    const data = await response.json().catch(() => ({}));
    assertProviderSuccess(response, data, "Twilio OTP verification failed");
    if (data.status !== "approved" && !data.valid) {
      return res.status(400).json({ verified: false, error: "Invalid OTP. Try again.", data });
    }
    res.json({ verified: true, accessToken: makeSignupOtpToken(identifier), data });
  } catch (err) {
    console.error("Twilio OTP verification failed:", err);
    res.status(err.status || 500).json({ verified: false, error: err.message || "Twilio OTP verification failed" });
  }
};

const verifySignupOtpAccessToken = async (req, res) => {
  try {
    const accessToken = String(
      (req.body && (req.body.accessToken || req.body["access-token"])) || "",
    ).trim();
    if (!accessToken) {
      return res.status(400).json({ verified: false, error: "OTP access token is required" });
    }
    const payload = verifyJwt(accessToken);
    if (payload.scope !== "signup-phone-otp") {
      return res.status(400).json({ verified: false, error: "Invalid OTP token" });
    }
    res.json({ verified: true, data: payload });
  } catch (err) {
    console.error("OTP token verification failed:", err);
    res.status(err.status || 500).json({ verified: false, error: err.message || "OTP token verification failed" });
  }
};

app.post("/otp/msg91/send", sendSignupOtp);
app.post("/otp/msg91/verify", verifySignupOtp);
app.post("/otp/msg91/verify-token", verifySignupOtpAccessToken);
app.post("/otp/twilio/send", sendSignupOtp);
app.post("/otp/twilio/verify", verifySignupOtp);
app.post("/otp/twilio/verify-token", verifySignupOtpAccessToken);

// SIGNUP API
app.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, username, email, phone, countryCode, city, password, otpAccessToken } = req.body;
    const cleanFirstName = String(firstName || username || "").trim();
    const cleanLastName = String(lastName || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPhone = String(phone || "").trim();
    const cleanCountryCode = String(countryCode || "+91").trim();
    const cleanCity = String(city || "").trim();
    if (!cleanFirstName || !cleanEmail || !password) {
      return res.status(400).json({ error: "First name, email, and password are required" });
    }
    if (!cleanPhone) {
      return res.status(400).json({ error: "Phone number is required" });
    }
    if (!otpAccessToken) {
      return res.status(400).json({ error: "Please verify your phone number with OTP before creating an account" });
    }
    await verifySignupOtpToken(otpAccessToken, cleanCountryCode, cleanPhone);
    const hashedPassword = await bcrypt.hash(password, 10);
    const displayName = [cleanFirstName, cleanLastName].filter(Boolean).join(" ");
    const result = await pool.query(
      `INSERT INTO users (username, first_name, last_name, email, phone, country_code, city, password)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, username, first_name, last_name, email, phone, country_code, city, created_at`,
      [displayName || cleanFirstName, cleanFirstName, cleanLastName, cleanEmail, cleanPhone, cleanCountryCode, cleanCity, hashedPassword],
    );
    res.json({ message: "Signup successful", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    res.status(500).json({ error: "Signup failed" });
  }
});

app.get("/auth/google/client-config", (req, res) => {
  res.json({ clientId: googleClientId || "" });
});

async function upsertGoogleBuyer({ name, email, photoURL }) {
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanName = String(name || "Google User").trim() || "Google User";
  if (!cleanEmail) {
    const err = new Error("Google account did not return an email address");
    err.statusCode = 400;
    throw err;
  }
  const parts = cleanName.split(/\s+/);
  const firstName = parts.shift() || cleanName;
  const lastName = parts.join(" ");
  const existing = await pool.query(
    "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
    [cleanEmail],
  );
  if (existing.rows.length && !isUserActive(existing.rows[0].status)) {
    const err = new Error(USER_NOT_FOUND_ERROR);
    err.statusCode = 404;
    throw err;
  }
  const upsert = await pool.query(
    `INSERT INTO users (username, first_name, last_name, email, password, auth_provider, profile_image_url)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT (email) DO UPDATE SET
      username=EXCLUDED.username,
      first_name=EXCLUDED.first_name,
      last_name=EXCLUDED.last_name,
      auth_provider=EXCLUDED.auth_provider,
      profile_image_url=COALESCE(users.profile_image_url, EXCLUDED.profile_image_url)
    RETURNING id, username, first_name, last_name, email, phone, country_code, city,
      profile_image_url, profile_image_key, profile_image_storage, auth_provider, status`,
    [cleanName, firstName, lastName, cleanEmail, "oauth-provider", "google", photoURL || ""],
  );
  return upsert.rows[0];
}

app.post("/auth/google", async (req, res) => {
  try {
    if (!googleOAuthClient) {
      return res.status(500).json({ error: "Google login is not configured. Add GOOGLE_CLIENT_ID to .env and restart the server." });
    }
    const credential = String((req.body && req.body.credential) || "").trim();
    if (!credential) {
      return res.status(400).json({ error: "Google credential is required" });
    }
    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: credential,
      audience: googleClientId,
    });
    const payload = ticket.getPayload() || {};
    if (!payload.email || payload.email_verified === false) {
      return res.status(400).json({ error: "Google account email is not verified" });
    }
    const user = await upsertGoogleBuyer({
      name: payload.name || payload.email,
      email: payload.email,
      photoURL: payload.picture || "",
    });
    res.json({
      message: "Login successful",
      user: publicUser(user),
      token: signJwt({ sub: user.id, email: user.email }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error("Google login failed:", err);
    res.status(err.statusCode || 500).json({ error: err.message || "Google login failed" });
  }
});
app.post("/social-login", async (req, res) => {
  try {
    const { name, email, photoURL, provider } = req.body || {};
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanName = String(name || "Google User").trim();
    if (!cleanEmail) {
      return res.status(400).json({ error: "Email is required" });
    }
    const parts = cleanName.split(/\s+/);
    const firstName = parts.shift() || cleanName;
    const lastName = parts.join(" ");
    const result = await pool.query(
      "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [cleanEmail],
    );
    if (result.rows.length && !isUserActive(result.rows[0].status)) {
      return res.status(404).json({ error: USER_NOT_FOUND_ERROR });
    }
    const upsert = await pool.query(
      `INSERT INTO users (username, first_name, last_name, email, password, auth_provider, profile_image_url)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (email) DO UPDATE SET
        username=EXCLUDED.username,
        first_name=EXCLUDED.first_name,
        last_name=EXCLUDED.last_name,
        auth_provider=EXCLUDED.auth_provider,
        profile_image_url=COALESCE(users.profile_image_url, EXCLUDED.profile_image_url)
      RETURNING id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, auth_provider, status`,
      [cleanName, firstName, lastName, cleanEmail, "oauth-provider", provider || "google", photoURL || ""],
    );
    const user = upsert.rows[0];
    res.json({
      message: "Login successful",
      user: publicUser(user),
      token: signJwt({ sub: user.id, email: user.email }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error("Social login failed:", err);
    res.status(500).json({ error: "Social login failed" });
  }
});

// LOGIN API
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const identifier = String(email || "").trim();
    const cleanEmail = identifier.toLowerCase();
    const phoneDigits = identifier.replace(/\D/g, "");
    const cleanPhone = /^[+\d\s()-]+$/.test(identifier) && /^\d{10,12}$/.test(phoneDigits)
      ? phoneDigits
      : "";
    if (!identifier || !password) {
      return res.status(400).json({ error: "Email or phone and password are required" });
    }
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, password, status
      FROM users
      WHERE LOWER(email)=LOWER($1)
        OR ($2 <> '' AND (
          REGEXP_REPLACE(COALESCE(country_code,'') || COALESCE(phone,''), '\\D', '', 'g')=$2
          OR REGEXP_REPLACE(COALESCE(phone,''), '\\D', '', 'g')=RIGHT($2,10)
        ))
      ORDER BY created_at DESC`,
      [cleanEmail, cleanPhone],
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }
    let user = null;
    for (const candidate of result.rows) {
      if (await bcrypt.compare(password, candidate.password)) {
        user = candidate;
        break;
      }
    }
    if (!user) {
      return res.status(400).json({ error: "Invalid password" });
    }
    if (!isUserActive(user.status)) {
      return res.status(404).json({ error: USER_NOT_FOUND_ERROR });
    }
    res.json({
      message: "Login successful",
      user: publicUser(user),
      token: signJwt({ sub: user.id, email: user.email }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ── Forgot Password: Send reset email ──────────────────────────────────────
app.post("/auth/forgot-password", async (req, res) => {
  try {
    if (!hasSmtpConfig()) {
      return res.status(500).json({ error: "Email service is not configured on this server" });
    }

    const email = String((req.body && req.body.email) || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ error: "Email is required" });

    // Look up user (but don't reveal whether email exists — security best practice)
    const result = await pool.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) AND COALESCE(status,'Active') NOT IN ('Suspended','Blocked','Inactive') LIMIT 1",
      [email],
    );

    if (result.rows.length) {
      const ttlMinutes = Number(process.env.PASSWORD_RESET_TTL_MINUTES || 10);
      const token = signJwt({ scope: "password-reset", email }, ttlMinutes * 60);
      const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3003}`).replace(/\/$/, "");
      const resetLink = `${baseUrl}/?reset_token=${encodeURIComponent(token)}`;

      const transporter = createMailTransporter();
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: "Reset your BLAK Tickets password",
        html: `
          <!doctype html>
          <html>
          <body style="margin:0;padding:0;background:#0a0a0a;font-family:Arial,sans-serif;color:#ffffff;">
            <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;margin:40px auto;background:#141414;border-radius:12px;overflow:hidden;">
              <tr>
                <td style="padding:32px 40px 24px;text-align:center;background:#1a1a1a;">
                  <h1 style="margin:0;font-size:22px;font-weight:700;color:#ffffff;letter-spacing:1px;">BLAK Tickets</h1>
                </td>
              </tr>
              <tr>
                <td style="padding:32px 40px;">
                  <h2 style="margin:0 0 16px;font-size:18px;color:#ffffff;">Reset Your Password</h2>
                  <p style="margin:0 0 24px;color:#aaaaaa;font-size:14px;line-height:1.6;">
                    We received a request to reset the password for your account. Click the button below to set a new password. This link expires in <strong style="color:#ffffff;">${ttlMinutes} minutes</strong>.
                  </p>
                  <div style="text-align:center;margin:28px 0;">
                    <a href="${resetLink}" style="display:inline-block;padding:14px 32px;background:#ffffff;color:#000000;font-weight:700;font-size:15px;text-decoration:none;border-radius:8px;letter-spacing:0.5px;">
                      Reset Password
                    </a>
                  </div>
                  <p style="margin:24px 0 0;color:#666666;font-size:12px;line-height:1.6;">
                    If you didn't request a password reset, you can safely ignore this email — your password won't be changed.<br><br>
                    Or copy this link into your browser:<br>
                    <span style="color:#888888;word-break:break-all;">${resetLink}</span>
                  </p>
                </td>
              </tr>
              <tr>
                <td style="padding:16px 40px;background:#0f0f0f;text-align:center;">
                  <p style="margin:0;color:#444444;font-size:11px;">© BLAK Tickets. All rights reserved.</p>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `,
      });
    }

    // Always return success regardless of whether email was found
    res.json({ success: true, message: "If that email is registered, a reset link has been sent." });
  } catch (err) {
    console.error("Forgot password failed:", err);
    res.status(500).json({ error: "Could not send reset email. Please try again later." });
  }
});

// ── Forgot Password: Verify token then update password ─────────────────────
app.post("/auth/reset-password-by-token", async (req, res) => {
  try {
    const token = String((req.body && req.body.token) || "").trim();
    const newPassword = String((req.body && req.body.password) || "");

    if (!token) return res.status(400).json({ error: "Reset token is required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    let payload;
    try {
      payload = verifyJwt(token);
    } catch (err) {
      return res.status(400).json({ error: "Reset link is invalid or has expired. Please request a new one." });
    }

    if (payload.scope !== "password-reset" || !payload.email) {
      return res.status(400).json({ error: "Invalid reset link" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      "UPDATE users SET password=$1 WHERE LOWER(email)=LOWER($2) AND COALESCE(status,'Active') NOT IN ('Suspended','Blocked','Inactive') RETURNING id",
      [hash, payload.email],
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Account not found or is inactive" });
    }

    res.json({ success: true, message: "Password updated successfully. You can now sign in with your new password." });
  } catch (err) {
    console.error("Token password reset failed:", err);
    res.status(500).json({ error: "Could not reset password" });
  }
});

app.get("/session", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, status
       FROM users
       WHERE id=$1`,
      [payload.sub],
    );
    if (!result.rows.length || !isUserActive(result.rows[0].status)) {
      return res.status(401).json({ error: "Session user not found" });
    }
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    res.status(401).json({ error: err.message || "Invalid session" });
  }
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
