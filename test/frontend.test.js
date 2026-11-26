// Static checks on the frontend source (no server needed).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { check } = require("../scripts/check-html-escaping");

test("H7: every value put into an HTML string is escaped for its context", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  const problems = check(html);
  assert.deepEqual(problems, [], problems.join("\n"));
});

test("H7: the checker catches unescaped values and wrong escapers", () => {
  const page = [
    "<script>",
    "el.innerHTML = '<div>' + ev.name + '</div>';",                                  // unescaped text
    "el.innerHTML = '<b onclick=\"go(\\'' + escapeHtml(ev.id) + '\\')\">x</b>';",  // escapeHtml inside onclick
    "el.innerHTML = '<a href=\"' + escapeHtml(link) + '\">x</a>';",                  // escapeHtml for a URL
    "el.innerHTML = '<div>' + escapeHtml(ev.name) + '</div>';",                      // correct
    "el.innerHTML = `<p>${ev.city}</p>`;",                                           // unescaped template
    "</script>",
  ].join("\n");
  assert.equal(check(page).length, 4);
});

test("L8: console warnings and errors are never silenced", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  const silenced = html.match(/\[([^\]]*)\]\.forEach\(function\(k\)\{window\.console\[k\]=function\(\)\{\};\}\)/);
  assert.ok(silenced, "the debug switch is still there");
  assert.doesNotMatch(silenced[1], /'warn'|'error'/);
});

test("login: errors stay on the form; admin login is not on the public form but opens from /#admin", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /<div id="loginError" class="form-alert" role="alert"/);
  assert.match(html, /catch\(err\)\{\s*showLoginError\(err\.message/);
  assert.match(html, /id="adminRoleBtn" data-login-role="admin"[^>]*style="display:none;/);
  assert.match(html, /var ADMIN_LOGIN_LINK=window\.location\.hash==='#admin';\s*if\(history&&history\.replaceState\)/);
});

test("L14: /#admin works in an open tab, beats other saved sessions, and admin sign-out returns to it", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /addEventListener\('hashchange',function\(\)\{\s*if\(window\.location\.hash!=='#admin'\)return;/);
  assert.match(html, /if\(await restoreAdminSession\(\)\)return true;[^]*?if\(ADMIN_LOGIN_LINK\)\{openAdminLogin\(\);return true;\}\s*if\(await restoreStaffSession\(\)\)/);
  assert.match(html, /function admSignOut\(\)\{[^}]*openAdminLogin\(\);/);
});

test("L15: organizer dashboard has a Log out button; organizer and staff sign-out return to their sign-in form", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /<button type="button" id="creatorLogoutBtn" class="btn btn-secondary" onclick="signOutCreator\(\)">Log out<\/button>/);
  assert.match(html, /function performCreatorSignOut\(\)\{[^]*?logoutSession\('creator'\);[^]*?openRoleLogin\('creator'\);\s*\}/);
  assert.match(html, /function performStaffSignOut\(\)\{[^]*?logoutSession\('staff'\);[^]*?openRoleLogin\('staff'\);\s*\}/);
});

test("L16: a login ends the other roles' sessions, so a refresh cannot switch to an earlier role", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /async function saveSession\(role,data\)\{[^]*?await endOtherRoleSessions\(role\);[^]*?\n\}/);
  assert.match(html, /async function endOtherRoleSessions\(keepRole\)\{[^]*?r!==keepRole&&hasSession\(r\)[^]*?await logoutSession\(r\);/);
});

test("H19 instant check: only the order ID is stored at checkout, checked on load, cleared when final", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /rememberPendingOrder\(data\.order&&data\.order\.id\);\s*NEW_PAYMENT_OK_EVENT=null;\s*if\(payuWin&&!payuWin\.closed\)\{\s*submitPayUForm\(data\.payment\.action, data\.payment\.fields, PAYU_WINDOW_NAME\);/);
  assert.match(html, /function rememberPendingOrder\(orderId\)\{if\(orderId\)localStorage\.setItem\(PENDING_ORDER_KEY,String\(orderId\)\);\}/);
  assert.match(html, /restoreSavedSession\(\)\.then\(resumePendingPaymentCheck\)/);
  assert.match(html, /'\/orders\/'\+encodeURIComponent\(orderId\)\+'\/check'/);
  for (const status of ["paid", "paid_needs_refund", "expired"]) {
    assert.match(html, new RegExp(`order\.status==='${status}'[^\n]*\{[^]{0,40}forgetPendingOrder\(\)`), status);
  }
  assert.match(html, /<div id="pendingPaymentNotice" role="status"/);
  assert.match(html, /NEW_PAYMENT_OK_EVENT!==CURRENT_EVENT\.id\)\{\s*var inProgress=await fetchPendingOrder\(CURRENT_EVENT\.id\);\s*if\(inProgress\)\{[^]*?return;/);
});

test("staff login updates the address to #page-staff-dashboard (it kept #page-login)", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  assert.match(html, /function enterStaffPanel\(\)\{[^]*?history\.replaceState\(\{vyberaPage:'page-staff-dashboard'\},'','#page-staff-dashboard'\);/);
});

test("design system: tokens in one block, legacy names point to them, a11y basics present", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  const ds = html.slice(html.indexOf('<style id="design-system">'), html.indexOf("</style>", html.indexOf('<style id="design-system">')));
  for (const token of ["--c-primary", "--c-accent", "--c-text", "--c-text-2", "--c-text-muted", "--c-surface", "--c-border", "--c-success", "--c-warning", "--c-danger", "--c-focus", "--fs-12", "--sp-4", "--r-md", "--sh-md", "--dur", "--tap"]) {
    assert.match(ds, new RegExp(`${token}:`), token);
  }
  assert.ok(html.indexOf('<style id="design-system">') < html.indexOf('<style data-platform="app"'), "APK-only styles still come after and can override");
  assert.match(html, /--muted: var\(--c-text-muted\);/);
  assert.match(html, /--neon: var\(--c-accent\);/);
  assert.match(ds, /:focus-visible\{\s*outline:2px solid var\(--c-focus\)!important/);
  assert.match(ds, /@media \(prefers-reduced-motion:reduce\)/);
  assert.match(html, /region\.setAttribute\('role','status'\);\s*region\.setAttribute\('aria-live','polite'\);/);
  assert.match(html, /if\(e\.key==='Escape'\)\{if\(closeTopDialog\(\)\)e\.preventDefault\(\);return;\}/);
  assert.match(html, /panel\.setAttribute\('aria-modal','true'\);/);
  assert.doesNotMatch(html, /RESET_(INPUT|LABEL)_STYLE_OLD/);
});

test("UI step 2 auth: no forced light-theme overrides; labelled fields; real buttons; organizer page sends its fields", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  assert.doesNotMatch(html, /body\.on-login #page-login/, "the !important light-theme block is gone");
  for (const id of ["siEmail", "siPassword", "suFirst", "suLast", "suEmail", "suPhone", "suPassword", "suCity", "creatorLoginEmail", "creatorLoginPwd"]) {
    assert.match(html, new RegExp(`<label[^>]*for="${id}"`), id);
  }
  assert.match(html, /<button type="button" class="input-action" onclick="togglePwd\('siPassword', this\)" aria-label="Show password"/);
  assert.match(html, /id="termsCheck" class="toggle" role="switch" aria-checked="false"/);
  assert.match(html, /onclick="creatorPageLogin\(\)"/);
  assert.match(html, /async function creatorPageLogin\(\)\{[^]*?await loginAsCreator\(email,pwd\);/);
  const signup = html.slice(html.indexOf("function doSignUp("), html.indexOf("setButtonBusy('signupBtn',true"));
  assert.doesNotMatch(signup, /alert\(/, "sign-up problems show on the form");
});

test("UI: no text under 12px outside the APK-only blocks; clickable non-buttons are keyboard-usable", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8");
  const web = html.split(/<style data-platform="app" media="not all">[\s\S]*?<\/style>/).join("");
  const tiny = [...web.matchAll(/font-size:\s*([0-9.]+)px/g)].map((m) => Number(m[1])).filter((n) => n < 12);
  assert.deepEqual(tiny, [], `font sizes under 12px: ${tiny.join(",")}`);
  assert.match(html, /function makeClickablesAccessible\(root\)\{[^]*?el\.setAttribute\('tabindex','0'\);/);
  assert.match(html, /if\(e\.key!=='Enter'&&e\.key!==' '\)return;/);
});

test("UI step 2 buyer: navigation bar, desktop column, 240px QR, grouped booking ref, states", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  assert.match(html, /<nav class="bottom-nav buyer-nav" id="buyerNav" aria-label="Main">/);
  for (const page of ["page-home", "page-explore", "page-mytickets", "page-profile"]) assert.match(html, new RegExp(`data-nav-page="${page}"`));
  assert.match(html, /document\.body\.setAttribute\('data-page',id\);/);
  assert.match(html, /#page-home,#page-explore,#page-mytickets,#page-notifications,#page-detail\{max-width:1120px;margin:0 auto;\}/);
  assert.match(html, /\.qr-img\{display:block;width:240px;height:240px;/);
  assert.match(html, /\.qr-ring\{width:240px;height:240px;/);
  assert.match(html, /set\('ticketBookingId',formatBookingRef\(booking\.id\)\);/);
  assert.doesNotMatch(html, /\.ticket-card, \.ticket-card \* \{ color: #ffffff !important; \}/, "dark ticket card overrides removed");
  assert.match(html, /uiState\(list,'empty',\{icon:'🎟️'/);
  assert.match(html, /uiSkeleton\(document\.getElementById\('exploreGrid'\),4,'card'\);/);
  assert.match(html, /<span id="totalAmt" class="order-total">/);
});

test("formatBookingRef groups the reference for reading out; the QR keeps the real value", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  const src = html.slice(html.indexOf("function formatBookingRef(id){"), html.indexOf("function copyBookingRef(){"));
  const vm = require("vm"); const box = {}; vm.runInNewContext(`${src}\nthis.f=formatBookingRef;`, box);
  assert.equal(box.f("BKG-6ea9686b28807c4ed79adfd2"), "BKG-6EA9 686B 2880 7C4E D79A DFD2");
  assert.equal(box.f(""), "");
});

test("UI step 3 organizer: no black pages, light organizer nav with desktop top bar, 44px controls", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  for (const id of ["page-scanner", "page-revenue", "page-staff-manage"]) {
    const tag = html.match(new RegExp(`<div class="page" id="${id}"[^>]*>`))[0];
    assert.doesNotMatch(tag, /background:#000/, id);
  }
  assert.match(html, /<nav class="bottom-nav creator-nav" id="creatorNavBar" aria-label="Organizer" style="display:none;">/);
  assert.match(html, /body\.creator-mode \.creator-nav\{top:var\(--demo-h\);bottom:auto;height:64px;/);
  assert.match(html, /#page-creator,#page-create,#page-scanner,#page-revenue,#page-staff-manage\{max-width:1120px;margin:0 auto;\}/);
  assert.match(html, /<input id="scannerPayload" class="form-input" aria-label="Ticket QR value"/);
  assert.match(html, /--c-text-muted:#6B6B73;/);
});

test("UI step 3 staff: light staff panel, tabs by class + aria-selected, 44px buttons", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  const tag = html.match(/<div class="page" id="page-staff-dashboard"[^>]*>/)[0];
  assert.doesNotMatch(tag, /background:#000/);
  assert.match(html, /<div class="staff-tabs" role="tablist" aria-label="Staff sections">/);
  assert.match(html, /b\.classList\.toggle\('active',a\);\s*b\.setAttribute\('aria-selected',a\?'true':'false'\);/);
  assert.doesNotMatch(html, /b\.style\.color=a\?'#00D4D4'/);
  assert.match(html, /#page-staff-dashboard button,#page-staff-qr button\{min-height:var\(--tap\);\}/);
  assert.match(html, /<input aria-label="Your sell link"/);
});

test("UI step 3 admin: one set of theme values (on the tokens), shell sets its own colours, phone-safe grids", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  // the old per-page --adm-* values overrode the token mapping; only the design-system ones remain
  assert.deepEqual(html.match(/--adm-bg:[^;]+/g), ["--adm-bg:var(--c-surface)", "--adm-bg:var(--c-surface-2)", "--adm-bg:var(--c-surface)"]);
  assert.doesNotMatch(html, /--adm-bg:#050505/);
  assert.match(html, /\.adm-shell \{ display:flex; min-height:100vh; background:var\(--adm-bg\); color:var\(--adm-text\); \}/);
  assert.doesNotMatch(html, /\.adm-light #page-admin select/); // could never match: #page-admin is outside the shell
  assert.match(html, /\.adm-stat-delta \{[^}]*color:var\(--adm-text2\);/);
  assert.doesNotMatch(html.slice(html.indexOf('<div class="page" id="page-admin"')), /transition:background \.3s/);
  assert.match(html, /@keyframes admPanelIn\{from\{opacity:0;transform:translateY\(4px\)\}/);
  assert.match(html, /div\[style\*="display:grid"\]:has\(> \.adm-card\)\{grid-template-columns:minmax\(0,1fr\)!important;\}/);
  assert.equal((html.match(/class="adm-swatch" aria-label="Accent colour: /g) || []).length, 5);
  assert.match(html, /id="payFilterPeriod" aria-label="Filter by period"/);
  assert.match(html, /\.adm-light \.adm-badge\.orange\{color:#C2410C;\}/);
});

test("final UI pass: sticky price readable on red, ticket actions fit a phone, carousel dots named", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
  // the price inherited the (now dark) page text colour on the red bar: 2.0:1
  assert.match(html, /\.sticky-cta-inner\{background:var\(--red\);color:#fff;/);
  // four 44px buttons did not fit 270px and the last one was clipped
  assert.match(html, /\.ticket-actions\{display:grid;grid-template-columns:repeat\(auto-fit,minmax\(110px,1fr\)\);/);
  assert.equal((html.match(/onclick="goToSlide\(\d\)" aria-label="Show featured event \d"/g) || []).length, 3);
});
