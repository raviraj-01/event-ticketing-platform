// Checks that a new .env reuses no value from an old one (Q17):
//
//   node scripts/compare-env.js .env ../VYBERA/.env
//
// Compares SHA-256 hashes only and prints key names, never values. Commented
// lines (# KEY=value) are compared too, and every old secret is also looked
// for anywhere inside the new file (a value pasted under a different key).
// Exit code 1 if any secret is reused.
const crypto = require("crypto");
const fs = require("fs");

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

// Keys whose values are credentials or point at a real account.
const SECRET_KEY = /(DATABASE_URL|SECRET|PASSWORD|PASS\b|_PASS$|TOKEN|_KEY|KEY_ID|SALT|_SID|CLIENT_ID|ENDPOINT|BUCKET|_USER$|_EMAIL$|_FROM$)/i;

// KEY=value pairs, including commented-out ones ("# KEY=value").
function readPairs(file) {
  const pairs = [];
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const match = raw.match(/^\s*(#\s*)?(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    let value = match[3].trim();
    const quoted = value.match(/^(['"])(.*)\1$/);
    value = quoted ? quoted[2] : value.replace(/\s+#.*$/, "").trim();
    if (value) pairs.push({ key: match[2], value, commented: Boolean(match[1]) });
  }
  return pairs;
}

function compareEnv(newFile, oldFile) {
  const fresh = readPairs(newFile);
  const old = readPairs(oldFile);
  const oldHashes = new Map(old.map((pair) => [hash(pair.value), pair.key]));
  const newText = fs.readFileSync(newFile, "utf8");

  const reusedSecrets = [];
  const reusedPlain = [];
  for (const pair of fresh) {
    const oldKey = oldHashes.get(hash(pair.value));
    if (!oldKey) continue;
    const label = `${pair.commented ? "# " : ""}${pair.key}${oldKey !== pair.key ? ` (same as old ${oldKey})` : ""}`;
    // A number ("10") or a short word ("test") is a setting, not a credential.
    const trivial = /^\d+$/.test(pair.value) || pair.value.length < 6;
    (!trivial && (SECRET_KEY.test(pair.key) || SECRET_KEY.test(oldKey)) ? reusedSecrets : reusedPlain).push(label);
  }
  // An old secret hidden inside a longer new value (e.g. the old DB password in a new URL).
  const embedded = old
    .filter((pair) => SECRET_KEY.test(pair.key) && pair.value.length >= 8)
    .filter((pair) => newText.includes(pair.value) && !fresh.some((f) => f.value === pair.value))
    .map((pair) => `old ${pair.key} appears inside the new file`);
  return { checked: fresh.length, reusedSecrets: [...reusedSecrets, ...embedded], reusedPlain };
}

module.exports = { compareEnv, readPairs };

if (require.main === module) {
  const [newFile, oldFile] = process.argv.slice(2);
  if (!newFile || !oldFile) {
    console.error("Usage: node scripts/compare-env.js <new .env> <old .env>");
    process.exit(2);
  }
  const result = compareEnv(newFile, oldFile);
  console.log(`Compared ${result.checked} values (hashes only).`);
  for (const label of result.reusedPlain) console.log(`same, not a secret: ${label}`);
  for (const label of result.reusedSecrets) console.log(`REUSED SECRET: ${label}`);
  if (result.reusedSecrets.length) process.exit(1);
  console.log("No secret from the old file is reused.");
}
