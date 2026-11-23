// M13: one password rule for every place a password is SET (signup, organizer
// application, staff/admin accounts, change, reset). Login never checks it, so
// existing accounts with shorter passwords keep working until they change it.
const MIN_LENGTH = 8;
// bcrypt only uses the first 72 bytes; anything longer would be silently cut.
const MAX_BYTES = 72;
const bcrypt = require("bcrypt");

// M6: when no account matches, logins still run one bcrypt comparison against
// this hash, so the response time doesn't reveal whether the account exists.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("not-a-real-password", 10);

// Compare only against real bcrypt hashes (Google-only accounts store a
// placeholder, which bcrypt cannot compare).
const isBcryptHash = (value) => String(value || "").startsWith("$2");

// Returns a message for the user, or null when the password is acceptable.
function passwordProblem(password, label = "Password") {
  const value = typeof password === "string" ? password : "";
  if (value.length < MIN_LENGTH) return `${label} must be at least ${MIN_LENGTH} characters`;
  if (Buffer.byteLength(value, "utf8") > MAX_BYTES) return `${label} is too long (at most ${MAX_BYTES} bytes)`;
  return null;
}

module.exports = { passwordProblem, MIN_LENGTH, MAX_BYTES, DUMMY_PASSWORD_HASH, isBcryptHash };
