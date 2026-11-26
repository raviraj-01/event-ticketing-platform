// DEMO_MODE=true (public demo deployment): banner flag for the app, and the
// site is kept out of search engines. Off by default.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { startTestServer, startApp } = require("./helpers/testServer");

let server;
before(async () => {
  server = await startTestServer({ DEMO_MODE: "true" });
});
after(async () => {
  if (server) await server.stop();
});

test("DEMO_MODE=true: every response says noindex, robots.txt disallows all, the app is told to show the banner", async () => {
  for (const urlPath of ["/", "/health", "/assets/blak-ticket-logo.svg", "/config/public"]) {
    const res = await fetch(server.baseUrl + urlPath);
    assert.equal(res.headers.get("x-robots-tag"), "noindex, nofollow", urlPath);
  }
  const robots = await fetch(`${server.baseUrl}/robots.txt`);
  assert.equal(robots.status, 200);
  assert.equal(await robots.text(), "User-agent: *\nDisallow: /\n");
  const config = await (await fetch(`${server.baseUrl}/config/public`)).json();
  assert.equal(config.demoMode, true);
});

test("DEMO_MODE off (default): no noindex, no robots.txt, no banner", async () => {
  const app = await startApp(server.databaseUrl, { DEMO_MODE: "" });
  try {
    const page = await fetch(`${app.baseUrl}/`);
    assert.equal(page.headers.get("x-robots-tag"), null);
    assert.equal((await fetch(`${app.baseUrl}/robots.txt`)).status, 404);
    const config = await (await fetch(`${app.baseUrl}/config/public`)).json();
    assert.equal(config.demoMode, false);
  } finally {
    app.stop();
  }
});

test("the banner is hidden until the server says demo mode; bars move down by its height only then", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  assert.match(html, /<body class="on-splash">\n<div id="demoBanner" class="demo-banner" role="note" hidden><strong>Demo site<\/strong>/);
  assert.match(html, /if\(cfg\.demoMode===true\)\{document\.documentElement\.classList\.add\('demo-mode'\);document\.getElementById\('demoBanner'\)\.hidden=false;\}/);
  assert.match(html, /:root\{--demo-h:0px;\}\nhtml\.demo-mode\{--demo-h:32px;\}/);
  assert.match(html, /\.buyer-nav\{top:var\(--demo-h\);/);
  assert.match(html, /body\.creator-mode \.creator-nav\{top:var\(--demo-h\);/);
  assert.match(html, /body\.creator-mode\{padding-top:calc\(64px \+ var\(--demo-h\)\);\}/);
  assert.match(html, /\.sub-page\.active,#page-admin \.adm-sidebar\{top:var\(--demo-h\);\}/);
  assert.match(fs.readFileSync(path.join(__dirname, "..", ".env.example"), "utf8"), /^DEMO_MODE=false$/m);
});
