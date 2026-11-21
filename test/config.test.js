// L10: .env must be loaded before any module that reads settings at load time
// (src/services/orders.js ORDER_SETTINGS, src/services/sessions.js
// SESSION_SETTINGS). Checked statically: the test must not create a .env file.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

test("L10: server.js loads .env before requiring any other module", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const requires = [...source.matchAll(/require\("([^"]+)"\)/g)].map((match) => match[1]);
  const dotenvAt = requires.indexOf("dotenv");
  assert.ok(dotenvAt >= 0, "server.js must load dotenv");
  assert.deepEqual(requires.slice(0, dotenvAt), ["path"], "only path may be required before dotenv");
});
