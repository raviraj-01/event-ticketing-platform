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
