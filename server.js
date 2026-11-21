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
const { runMigrations } = require("./src/db/migrate");
const { AUDIENCE, configureTokens, signToken, verifyToken } = require("./src/utils/tokens");
const { WalletError, staffWallet, requestWithdrawal, recordCashSettlement } = require("./src/services/staffWallet");
const { recordAdminAction, audited, listAdminActions } = require("./src/services/adminAudit");
const { RESET_ROLES, ResetError, findResetTargets, createResetToken, resetPasswordWithToken, setTemporaryPassword } = require("./src/services/passwordReset");
const { parseCookies } = require("./src/utils/cookies");
const { USER_ACTIVE_STATUS, normalizeUserStatus, isUserActive } = require("./src/utils/accounts");
const {
  AuthError,
  ROLES,
  authenticateRequest,
  startSession,
  rotateSession,
  endSession,
  revokeAllSessions,
} = require("./src/services/sessions");
const { isEventBookable, eventSalesClosed } = require("./src/utils/events");
const { createRateLimiter, pruneRateLimitHits } = require("./src/middleware/rateLimit");
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
require("dotenv").config({ path: path.join(__dirname, ".env") });

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
const APP_BASE_URL = String(process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3003}`).replace(/\/+$/, "");
// Only files inside public/ are reachable from the browser. Never point
// express.static at __dirname: that would publish server.js, CLAUDE.md, etc.
const publicDir = path.join(__dirname, "public");
const appHtmlPath = path.join(publicDir, "index.html");
const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

// H16: only these origins may call the API from a browser with credentials.
// Default: the app's own origin + the Cordova WebView origin. Override with
// CORS_ORIGINS="https://a.example,https://b.example".
const allowedOrigins = new Set(
  String(process.env.CORS_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter(Boolean),
);
if (!allowedOrigins.size) {
  allowedOrigins.add(new URL(APP_BASE_URL).origin);
  allowedOrigins.add("https://localhost"); // Cordova Android WebView
}
app.use(
  cors({
    // Requests without an Origin header (same-origin GETs, curl, PayU's
    // server-side posts) are not CORS requests and are allowed through.
    origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Client", "X-Session-Role"],
    optionsSuccessStatus: 204,
  }),
);
app.use((req, res, next) => {
  res.header("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});
// CSRF defence for cookie sessions (on top of SameSite=Strict): a
// state-changing request that carries our session cookies must come from an
// allowed origin. Bearer-token clients (the app) are not cookie based.
app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || req.headers.authorization) return next();
  const hasSessionCookie = Object.keys(parseCookies(req)).some((name) => /^(at|rt)_/.test(name));
  const origin = req.headers.origin;
  if (hasSessionCookie && origin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: "Cross-site request blocked" });
  }
  next();
});
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

if (!process.env.DATABASE_URL) {
  console.error(
    "DATABASE_URL is missing. Add it to VYBERA/.env before starting the server.",
  );
  process.exit(1);
}

const dbSsl = process.env.DATABASE_URL.includes("localhost")
  ? false
  : { rejectUnauthorized: false };
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: dbSsl,
});
const rateLimit = createRateLimiter(pool);
// H6: log successful admin changes (see src/services/adminAudit.js).
const audit = (action, describe) => audited(pool, action, describe);
// Forwarder so routes defined earlier in the file can use the step-up check
// (requireRecentReauth is defined next to the admin login code).
const confirmed = (req, res, next) => requireRecentReauth(req, res, next);

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
configureTokens(jwtSecret);
// Login sessions live in src/services/sessions.js. Purpose tokens (password
// reset, signup OTP) use signToken/verifyToken with their own audience.
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

const EVENT_NOT_FOUND_ERROR = "Event does not exist";
const USER_NOT_FOUND_ERROR = "User account not found";
const STAFF_NOT_FOUND_ERROR = "Staff account not found";



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

// KYC scans (Aadhaar, PAN, bank) are never public: they are opened through
// an authenticated, audited super-admin route (H14).
const creatorKycDocumentUrl = (document) =>
  document && document.id ? `/admin/kyc-documents/${encodeURIComponent(document.id)}/file` : "";

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
  cashOwed: Number(member.cash_owed || 0),
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

// Authentication middleware. Every request re-checks the account in the DB
// (exists, active, same token_version), so suspensions and "log out
// everywhere" take effect immediately (H4, H5).
// { allowPasswordChange: true } only for the change-password and logout-all routes.
const requireRole = (roles, attach, { allowPasswordChange = false } = {}) => async (req, res, next) => {
  try {
    const session = await authenticateRequest(pool, req, roles);
    // Q4: after a reset by someone else, the only thing allowed is choosing a new password.
    if (session.account.must_change_password && !allowPasswordChange) {
      return res.status(403).json({ error: "Please choose a new password to continue", passwordChangeRequired: true });
    }
    attach(req, session);
    next();
  } catch (err) {
    if (!(err instanceof AuthError)) console.error("Authentication failed:", err);
    res.status(401).json({ error: "Login required" });
  }
};

const requireCreator = requireRole(["creator"], (req, s) => { req.creator = s.payload; });
const requireAdmin = requireRole(["admin"], (req, s) => { req.admin = s.payload; });
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

const requireStaff = requireRole(["staff"], (req, s) => { req.staff = s.payload; });
const requireBuyer = requireRole(["buyer"], (req, s) => { req.buyer = s.payload; });
const requireScanIdentity = requireRole(["creator", "staff"], (req, s) => {
  req.scanIdentity = { type: s.role, payload: s.payload };
});

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
    throw uploadError("Invalid file data");
  }
  return { contentType: match[1], buffer: Buffer.from(match[2], "base64") };
};

// ── Upload validation ──────────────────────────────────────────────────────
// A file is accepted only if its real first bytes ("magic number") match an
// allowed type. The browser-supplied name and MIME type are never trusted, and
// the stored extension comes from the detected type, so nobody can upload an
// .html/.svg file that would run as a page on our domain.
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const UPLOAD_TYPES = {
  "image/jpeg": { ext: "jpg", matches: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  "image/png": {
    ext: "png",
    matches: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  },
  "image/webp": {
    ext: "webp",
    matches: (b) => b.subarray(0, 4).toString("latin1") === "RIFF" && b.subarray(8, 12).toString("latin1") === "WEBP",
  },
  "application/pdf": { ext: "pdf", matches: (b) => b.subarray(0, 5).toString("latin1") === "%PDF-" },
  // Server-generated ticket records only (never accepted from a user upload).
  "application/json": { ext: "json", matches: (b) => b[0] === 0x7b },
};
const IMAGE_UPLOAD_TYPES = ["image/jpeg", "image/png", "image/webp"];
const KYC_UPLOAD_TYPES = [...IMAGE_UPLOAD_TYPES, "application/pdf"];

function uploadError(message, status = 400) {
  const err = new Error(message);
  err.status = status;
  return err;
}

const detectUploadType = (buffer, allowedTypes) =>
  allowedTypes.find((type) => UPLOAD_TYPES[type] && UPLOAD_TYPES[type].matches(buffer));

const validateUpload = (dataUrl, allowedTypes) => {
  const { buffer } = parseDataUrl(dataUrl);
  if (!buffer.length) throw uploadError("The file is empty");
  if (buffer.length > MAX_UPLOAD_BYTES) {
    throw uploadError(`Each file must be ${MAX_UPLOAD_BYTES / (1024 * 1024)} MB or smaller`, 413);
  }
  const contentType = detectUploadType(buffer, allowedTypes);
  if (!contentType) {
    const names = allowedTypes.map((type) => UPLOAD_TYPES[type].ext.toUpperCase()).join(", ");
    throw uploadError(`Unsupported file type. Allowed: ${names}`);
  }
  return { buffer, contentType, ext: UPLOAD_TYPES[contentType].ext };
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

// allowedTypes is required: every caller must say which file types it accepts.
// requireR2: true for private documents (KYC) that must never land in the
// public /uploads folder.
const saveAsset = async ({ fileName, folder, dataUrl, allowedTypes, requireR2 = false }) => {
  const file = validateUpload(dataUrl, allowedTypes);
  const baseName = cleanFileName(fileName).replace(/\.[^.]*$/, "") || "file";
  const key = makeObjectKey(folder, `${baseName}.${file.ext}`);
  try {
    return await uploadBufferToR2({ key, buffer: file.buffer, contentType: file.contentType });
  } catch (err) {
    console.error("R2 asset upload failed:", err.message);
    if (requireR2) {
      throw uploadError("File storage is unavailable. Please try again later.", 503);
    }
    return saveLocalBuffer({ key, buffer: file.buffer, contentType: file.contentType });
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
  // Schema lives in migrations/ (run before this). This only fixes up data.
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

  // Legacy rows: copy old "Super Admin" admin_accounts into super_admin_accounts
  // without ever overwriting an existing super admin (M1).
  await pool.query(`
    INSERT INTO super_admin_accounts (name, email, password, status, last_login, created_at)
    SELECT name, email, password, status, last_login, created_at
    FROM admin_accounts
    WHERE role='Super Admin'
    ON CONFLICT (email) DO NOTHING
  `);
  await pool.query("DELETE FROM admin_accounts WHERE role='Super Admin'");

  // First super admin from SUPERADMIN_EMAIL / SUPERADMIN_PASSWORD. Insert-only:
  // an existing super admin is never touched, so a password changed in the app
  // or reset with scripts/reset-super-admin.js survives restarts (M1, Q4).
  const superAdminEmail = String(process.env.SUPERADMIN_EMAIL || "").trim().toLowerCase();
  const superAdminPassword = process.env.SUPERADMIN_PASSWORD;
  if (!superAdminEmail || !superAdminPassword) return;
  const created = await pool.query(
    `INSERT INTO super_admin_accounts (name, email, password, status)
     VALUES ('Super Admin', $1, $2, 'Active')
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [superAdminEmail, await bcrypt.hash(superAdminPassword, 10)],
  );
  if (created.rows.length) console.log(`Created the first super admin (${superAdminEmail}).`);
};


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
const adminTable = (adminType) => (adminType === "super" ? "super_admin_accounts" : "admin_accounts");

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

// ── Step-up confirmation for destructive admin actions (H6 part 4) ──
const ADMIN_REAUTH_MINUTES = 5;

// Destructive routes need the admin's password confirmed in the last 5 minutes.
const requireRecentReauth = async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT reauth_until FROM ${adminTable(req.admin.adminType)} WHERE id=$1`,
      [req.admin.sub],
    );
    const until = result.rows[0] && result.rows[0].reauth_until;
    if (until && new Date(until) > new Date()) return next();
    res.status(403).json({ error: "Please confirm your password to continue", reauthRequired: true });
  } catch (err) {
    console.error("Re-auth check failed:", err);
    res.status(500).json({ error: "Could not verify confirmation" });
  }
};

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

// Who may see a ticket (and its QR payload): the buyer who owns it, the
// creator of its event, or staff assigned to its event. Anyone else gets 404
// (never 403), so booking IDs cannot be probed.
const requireTicketViewer = requireRole(["buyer", "creator", "staff"], (req, s) => {
  req.ticketViewer = { type: s.role, id: s.payload.sub };
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
  signToken({ identifier }, { audience: AUDIENCE.signupOtp, expiresInSeconds: 10 * 60 });

const verifySignupOtpToken = async (token, countryCode, phone) => {
  const identifier = `${String(countryCode || "+91").replace(/\D/g, "")}${String(phone || "").replace(/\D/g, "")}`;
  try {
    const payload = await verifyToken(token, { audience: AUDIENCE.signupOtp });
    if (payload.identifier !== identifier) {
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
        accessToken: await makeSignupOtpToken(identifier),
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
    res.json({ verified: true, accessToken: await makeSignupOtpToken(identifier), data });
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
    let payload;
    try {
      payload = await verifyToken(accessToken, { audience: AUDIENCE.signupOtp });
    } catch (verifyErr) {
      return res.status(400).json({ verified: false, error: "Invalid OTP token" });
    }
    res.json({ verified: true, data: payload });
  } catch (err) {
    console.error("OTP token verification failed:", err);
    res.status(err.status || 500).json({ verified: false, error: err.message || "OTP token verification failed" });
  }
};

// Every OTP costs an SMS, so sending is limited per phone and per IP (H3).
// (The unused /otp/msg91/* aliases were removed.)
const otpPhoneKey = (req) => String((req.body && req.body.identifier) || "").replace(/\D/g, "") || null;
app.post(
  "/otp/twilio/send",
  rateLimit({ name: "otp-send-phone", windowSeconds: 600, max: 3, key: otpPhoneKey,
    message: "Too many OTP requests for this number. Please wait a few minutes." }),
  rateLimit({ name: "otp-send-ip", windowSeconds: 3600, max: 10, key: (req) => req.ip,
    message: "Too many OTP requests. Please try again later." }),
  sendSignupOtp,
);
app.post(
  "/otp/twilio/verify",
  rateLimit({ name: "otp-verify-phone", windowSeconds: 600, max: 10, key: otpPhoneKey,
    message: "Too many attempts. Request a new OTP in a few minutes." }),
  verifySignupOtp,
);
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
    // Checks Google's signature, expiry, issuer and that the token was issued
    // for OUR client ID. A forged or foreign token is a 401, not a 500.
    let payload;
    try {
      const ticket = await googleOAuthClient.verifyIdToken({
        idToken: credential,
        audience: googleClientId,
      });
      payload = ticket.getPayload() || {};
    } catch (verifyErr) {
      console.error("Google ID token rejected:", verifyErr.message);
      return res.status(401).json({ error: "Google sign-in could not be verified" });
    }
    if (!payload.email || payload.email_verified !== true) {
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
      ...(await startSession(pool, req, res, { role: "buyer", accountId: user.id })),
    });
  } catch (err) {
    console.error("Google login failed:", err);
    res.status(err.statusCode || 500).json({ error: err.message || "Google login failed" });
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
      ...(await startSession(pool, req, res, { role: "buyer", accountId: user.id })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ── Forgot Password: Send reset email ──────────────────────────────────────
// Each request can send an email, so limit it per address and per IP (H3).
const forgotPasswordLimits = [
  rateLimit({ name: "forgot-email", windowSeconds: 3600, max: 3,
    key: (req) => String((req.body && req.body.email) || "").trim().toLowerCase() || null }),
  rateLimit({ name: "forgot-ip", windowSeconds: 3600, max: 10, key: (req) => req.ip }),
];

const escapeEmailHtml = (value) =>
  String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);

// One email; for staff there can be several accounts with the same address,
// so each gets its own link labelled with its login ID.
function resetEmailHtml(links, ttlMinutes, accountLabel) {
  const buttons = links
    .map((link) => `<p style="margin:16px 0;"><a href="${escapeEmailHtml(link.url)}" style="display:inline-block;padding:12px 24px;background:#ffffff;color:#000000;font-weight:700;text-decoration:none;border-radius:8px;">Reset password${link.loginId ? ` for ${escapeEmailHtml(link.loginId)}` : ""}</a></p>`)
    .join("");
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#0a0a0a;font-family:Arial,sans-serif;color:#ffffff;">
    <div style="max-width:520px;margin:0 auto;background:#141414;border-radius:12px;padding:32px;">
      <h1 style="margin:0 0 16px;font-size:20px;">BLAK Tickets</h1>
      <p style="color:#aaaaaa;line-height:1.6;">We received a request to reset the password of your ${escapeEmailHtml(accountLabel)}. The link expires in <strong style="color:#fff;">${ttlMinutes} minutes</strong> and works once.</p>
      ${buttons}
      <p style="color:#666666;font-size:12px;line-height:1.6;">If you didn't ask for this, ignore this email; your password stays the same.</p>
    </div></body></html>`;
}

// Step 1: email a single-use reset link (buyers, organizers, staff with email).
// The answer is the same whether or not the email exists.
app.post("/auth/forgot-password", ...forgotPasswordLimits, async (req, res) => {
  try {
    if (!hasSmtpConfig()) {
      return res.status(500).json({ error: "Email service is not configured on this server" });
    }
    const email = String((req.body && req.body.email) || "").trim().toLowerCase();
    const role = String((req.body && req.body.role) || "buyer");
    if (!email) return res.status(400).json({ error: "Email is required" });
    if (!RESET_ROLES[role]) return res.status(400).json({ error: "Password reset by email is not available for this account type" });

    const accounts = await findResetTargets(pool, role, email);
    if (accounts.length) {
      const ttlMinutes = Number(process.env.PASSWORD_RESET_TTL_MINUTES || 10);
      const links = [];
      for (const account of accounts) {
        const token = await createResetToken(role, account, ttlMinutes);
        links.push({ url: `${APP_BASE_URL}/?reset_token=${encodeURIComponent(token)}`, loginId: account.login_id || "" });
      }
      await createMailTransporter().sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: "Reset your password",
        html: resetEmailHtml(links, ttlMinutes, RESET_ROLES[role].label),
      });
    }
    res.json({ success: true, message: "If that email is registered, a reset link has been sent." });
  } catch (err) {
    console.error("Forgot password failed:", err);
    res.status(500).json({ error: "Could not send reset email. Please try again later." });
  }
});

// Step 2: the link's token + a new password. Works once (password_version).
app.post("/auth/reset-password-by-token", async (req, res) => {
  try {
    const token = String((req.body && req.body.token) || "").trim();
    const newPassword = String((req.body && req.body.password) || "");
    if (!token) return res.status(400).json({ error: "Reset token is required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    const role = await resetPasswordWithToken(pool, token, await bcrypt.hash(newPassword, 10));
    res.json({ success: true, role, message: "Password updated successfully. You can now sign in with your new password." });
  } catch (err) {
    if (err instanceof ResetError) return res.status(err.status).json({ error: err.message });
    console.error("Token password reset failed:", err);
    res.status(500).json({ error: "Could not reset password" });
  }
});

// Change your own password (also the forced change after a temporary
// password). Ends all sessions and starts a fresh one for this client.
const PASSWORD_TABLES = {
  buyer: "users", creator: "creator_accounts", staff: "staff_accounts",
  admin: "admin_accounts", super: "super_admin_accounts",
};
app.post(
  "/auth/change-password",
  requireRole(ROLES, (req, s) => { req.session = s; }, { allowPasswordChange: true }),
  rateLimit({ name: "change-password", windowSeconds: 600, max: 10, key: (req) => `${req.session.role}:${req.session.payload.sub}` }),
  async (req, res) => {
    try {
      const { role, payload, account } = req.session;
      const currentPassword = String((req.body && req.body.currentPassword) || "");
      const newPassword = String((req.body && req.body.newPassword) || "");
      if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });
      if (newPassword === currentPassword) return res.status(400).json({ error: "Choose a password different from the current one" });
      if (!String(account.password || "").startsWith("$2") || !(await bcrypt.compare(currentPassword, account.password))) {
        return res.status(401).json({ error: "Current password is wrong" });
      }
      const table = PASSWORD_TABLES[role === "admin" && payload.adminType === "super" ? "super" : role];
      const hasForcedFlag = ["staff_accounts", "admin_accounts", "super_admin_accounts"].includes(table);
      const hasVersion = ["users", "creator_accounts", "staff_accounts"].includes(table);
      await pool.query(
        `UPDATE ${table} SET password = $1${hasForcedFlag ? ", must_change_password = FALSE" : ""}${hasVersion ? ", password_version = password_version + 1" : ""} WHERE id = $2`,
        [await bcrypt.hash(newPassword, 10), payload.sub],
      );
      await revokeAllSessions(pool, { role, accountId: payload.sub, adminType: payload.adminType });
      if (role === "admin") await recordAdminAction(pool, req, { action: "password.change" });
      res.json({
        success: true,
        ...(await startSession(pool, req, res, { role, accountId: payload.sub, adminType: payload.adminType })),
      });
    } catch (err) {
      console.error("Password change failed:", err);
      res.status(500).json({ error: "Could not change password" });
    }
  },
);

// The logged-in buyer's profile. Only buyer sessions are accepted, so a
// creator/admin token with the same numeric id can no longer read a buyer (H12).
app.get("/session", requireBuyer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, status
       FROM users WHERE id=$1`,
      [req.buyer.sub],
    );
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error("Session load failed:", err);
    res.status(500).json({ error: "Could not load session" });
  }
});

// ── Session lifecycle (H5) ─────────────────────────────────────────────────
const sessionRole = (req) => {
  const role = String((req.body && req.body.role) || "");
  return ROLES.includes(role) ? role : null;
};

// New access token (and a rotated refresh token) for a valid refresh token.
app.post(
  "/auth/refresh",
  rateLimit({ name: "refresh-ip", windowSeconds: 600, max: 120, key: (req) => req.ip }),
  async (req, res) => {
    const role = sessionRole(req);
    if (!role) return res.status(400).json({ error: "Valid role is required" });
    try {
      res.json(await rotateSession(pool, req, res, role));
    } catch (err) {
      if (!(err instanceof AuthError)) console.error("Session refresh failed:", err);
      res.status(401).json({ error: "Session expired. Please log in again." });
    }
  },
);

// End this login (revokes its refresh token family, clears cookies).
app.post("/auth/logout", async (req, res) => {
  const role = sessionRole(req);
  if (!role) return res.status(400).json({ error: "Valid role is required" });
  try {
    await endSession(pool, req, res, role);
    res.json({ success: true });
  } catch (err) {
    console.error("Logout failed:", err);
    res.status(500).json({ error: "Logout failed" });
  }
});

// Log this account out on every device.
app.post(
  "/auth/logout-all",
  requireRole(ROLES, (req, s) => { req.session = s; }, { allowPasswordChange: true }),
  async (req, res) => {
    try {
      const { role, payload } = req.session;
      await revokeAllSessions(pool, { role, accountId: payload.sub, adminType: payload.adminType });
      await endSession(pool, req, res, role);
      res.json({ success: true });
    } catch (err) {
      console.error("Logout everywhere failed:", err);
      res.status(500).json({ error: "Could not log out everywhere" });
    }
  },
);

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
