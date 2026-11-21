// File storage: Cloudflare R2 (hand-written SigV4 presigning) with a local
// uploads/ fallback, plus upload validation by magic bytes (C5).
const path = require("path");
const { uploadsDir } = require("../config");
const fs = require("fs");
const crypto = require("crypto");

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

const hmac = (key, value, encoding) =>
  crypto.createHmac("sha256", key).update(value).digest(encoding);

const sha256 = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

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

module.exports = {
  hasR2Config,
  validateUpload,
  KYC_UPLOAD_TYPES,
  saveAsset,
  cleanPathSegment,
  IMAGE_UPLOAD_TYPES,
  presignR2,
};
