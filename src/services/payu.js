// PayU hosted-checkout helpers: request hash, response-hash verification.
// Docs: https://docs.payu.in (hash = SHA-512 over pipe-separated fields + salt).
const crypto = require("crypto");

function getPayuConfig() {
  const env = String(process.env.PAYU_ENV || "test").toLowerCase();
  return {
    key: process.env.PAYU_KEY || "",
    salt: process.env.PAYU_SALT || "",
    action: env === "production" ? "https://secure.payu.in/_payment" : "https://test.payu.in/_payment",
  };
}

const sha512 = (value) => crypto.createHash("sha512").update(value).digest("hex");

// PayU only allows a small character set in these text fields.
const cleanPayuText = (value, maxLength) =>
  String(value || "")
    .replace(/[^a-zA-Z0-9 .,_-]/g, "")
    .trim()
    .slice(0, maxLength);

const formatPayuAmount = (amount) => Number(amount || 0).toFixed(2);

// Request hash: key|txnid|amount|productinfo|firstname|email|udf1..udf5||||||salt
function makeRequestHash(fields, salt) {
  return sha512(
    [
      fields.key, fields.txnid, fields.amount, fields.productinfo, fields.firstname, fields.email,
      fields.udf1 || "", fields.udf2 || "", fields.udf3 || "", fields.udf4 || "", fields.udf5 || "",
      "", "", "", "", "", salt,
    ].join("|"),
  );
}

// Response ("reverse") hash:
//   [additionalCharges|]salt|status||||||udf5|udf4|udf3|udf2|udf1|email|firstname|productinfo|amount|txnid|key
function makeResponseHash(body, salt) {
  const parts = [
    salt, body.status || "", "", "", "", "", "",
    body.udf5 || "", body.udf4 || "", body.udf3 || "", body.udf2 || "", body.udf1 || "",
    body.email || "", body.firstname || "", body.productinfo || "", body.amount || "",
    body.txnid || "", body.key || "",
  ];
  if (body.additionalCharges) parts.unshift(body.additionalCharges);
  return sha512(parts.join("|"));
}

// Constant-time comparison so the check does not leak how many characters matched.
function isValidResponseHash(body, salt) {
  if (!salt || !body || typeof body.hash !== "string") return false;
  const expected = Buffer.from(makeResponseHash(body, salt), "utf8");
  const actual = Buffer.from(body.hash.toLowerCase(), "utf8");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

module.exports = {
  getPayuConfig,
  cleanPayuText,
  formatPayuAmount,
  makeRequestHash,
  makeResponseHash,
  isValidResponseHash,
};
