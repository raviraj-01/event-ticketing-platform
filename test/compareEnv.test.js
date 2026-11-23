// scripts/compare-env.js: finds reused secrets by hash, prints key names only.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { compareEnv } = require("../scripts/compare-env");

function files(oldText, newText) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "envcmp-"));
  fs.writeFileSync(path.join(dir, "old.env"), oldText);
  fs.writeFileSync(path.join(dir, "new.env"), newText);
  return [path.join(dir, "new.env"), path.join(dir, "old.env")];
}

test("all values new: nothing reused", () => {
  const result = compareEnv(...files("JWT_SECRET=old-secret-aaaa\nPORT=3003\n", "JWT_SECRET=new-secret-bbbb\nPORT=3004\n"));
  assert.deepEqual(result.reusedSecrets, []);
  assert.deepEqual(result.reusedPlain, []);
});

test("a reused secret is found, also under another key, quoted, or commented out", () => {
  const old = "JWT_SECRET=old-secret-aaaa\nTWILIO_AUTH_TOKEN=old-token-cccc\n# SUPERADMIN_PASSWORD=old-pass-dddd\n";
  const fresh = 'JWT_SECRET="old-secret-aaaa"\nR2_SECRET_ACCESS_KEY=old-token-cccc\n# ADMIN_PASSWORD=old-pass-dddd\n';
  const result = compareEnv(...files(old, fresh));
  assert.equal(result.reusedSecrets.length, 3, JSON.stringify(result));
  assert.ok(result.reusedSecrets.some((label) => label.startsWith("R2_SECRET_ACCESS_KEY (same as old TWILIO_AUTH_TOKEN)")));
  // Labels carry key names only, never a value.
  assert.ok(result.reusedSecrets.every((label) => !/old-(secret|token|pass)/.test(label)));
});

test("an old password inside a new connection string is found", () => {
  const old = "DATABASE_URL=postgres://u:oldpassword123@old-host/db\nSMTP_PASS=oldpassword123\n";
  const fresh = "DATABASE_URL=postgres://u2:oldpassword123@new-host/db\n";
  const result = compareEnv(...files(old, fresh));
  assert.deepEqual(result.reusedSecrets, ["old SMTP_PASS appears inside the new file"]);
});

test("equal non-secret settings are listed separately and do not fail the check", () => {
  const result = compareEnv(...files("PORT=3003\nSMTP_SERVICE=gmail\n", "PORT=3003\nSMTP_SERVICE=gmail\n"));
  assert.deepEqual(result.reusedSecrets, []);
  assert.deepEqual(result.reusedPlain, ["PORT", "SMTP_SERVICE"]);
});

test("numbers and short words are settings, not reused secrets", () => {
  const result = compareEnv(...files("PASSWORD_RESET_TTL_MINUTES=10\nPAYU_ENV=test\n", "PASSWORD_RESET_TTL_MINUTES=10\nR2_BUCKET=test\n"));
  assert.deepEqual(result.reusedSecrets, []);
  assert.equal(result.reusedPlain.length, 2);
});
