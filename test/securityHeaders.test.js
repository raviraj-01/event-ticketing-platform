// M15: security headers and the Content-Security-Policy.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer } = require("./helpers/testServer");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

test("M15: the app page is served with security headers and a CSP", async () => {
  const res = await fetch(`${server.baseUrl}/`);
  const h = (name) => res.headers.get(name) || "";
  const csp = h("content-security-policy");
  assert.match(csp, /frame-ancestors 'none'/, "no clickjacking");
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /form-action 'self' https:\/\/test\.payu\.in https:\/\/secure\.payu\.in/);
  assert.match(csp, /default-src 'self'/);
  assert.doesNotMatch(csp, /upgrade-insecure-requests/, "would break http://localhost development");
  assert.equal(h("x-content-type-options"), "nosniff");
  assert.match(h("strict-transport-security"), /max-age=\d+/);
  assert.equal(h("cross-origin-opener-policy"), "same-origin-allow-popups", "Google sign-in popup");
  assert.equal(h("cross-origin-resource-policy"), "cross-origin", "the Android app loads our images");
  assert.equal(h("referrer-policy"), "strict-origin-when-cross-origin", "Google Identity Services needs the origin");
});

test("M15: both PayU checkout hosts are allowed as form targets", () => {
  const { getPayuConfig } = require("../src/services/payu");
  const { contentSecurityPolicy } = require("../src/middleware/securityHeaders");
  const before = process.env.PAYU_ENV;
  try {
    for (const env of ["test", "production"]) {
      process.env.PAYU_ENV = env;
      const origin = new URL(getPayuConfig().action).origin;
      assert.ok(contentSecurityPolicy.directives.formAction.includes(origin), `${env}: ${origin}`);
    }
    // ...and the payment page PayU redirects the form post to.
    assert.ok(contentSecurityPolicy.directives.formAction.includes("https://*.payu.in"), "redirect to apitest.payu.in / api.payu.in");
  } finally {
    if (before === undefined) delete process.env.PAYU_ENV; else process.env.PAYU_ENV = before;
  }
});
