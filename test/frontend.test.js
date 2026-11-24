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
  assert.match(html, /<div id="loginError" role="alert"/);
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
  assert.match(html, /<button id="creatorLogoutBtn" onclick="signOutCreator\(\)"/);
  assert.match(html, /function performCreatorSignOut\(\)\{[^]*?logoutSession\('creator'\);[^]*?openRoleLogin\('creator'\);\s*\}/);
  assert.match(html, /function performStaffSignOut\(\)\{[^]*?logoutSession\('staff'\);[^]*?openRoleLogin\('staff'\);\s*\}/);
});
