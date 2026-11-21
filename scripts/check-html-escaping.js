// Guards against stored XSS (H7): every value concatenated into an HTML string
// in public/index.html must go through the escaper that matches its context.
//
//   node scripts/check-html-escaping.js            (exit 1 if anything is unescaped)
//
// How it works: parse each inline <script> with acorn, find string-building
// expressions ('...'+x+'...' chains and `...${x}...` templates) that contain
// HTML, and check each interpolated value:
//   - text / quoted attribute  -> escapeHtml(x)
//   - inside onclick="...'x'"  -> jsStr(x)      (JS string inside an attribute)
//   - inside onclick="...x..." -> jsArg(x)      (whole JS value)
//   - src= / href= / url(      -> safeUrl(x) or cssUrl(x)
// Numbers, formatted prices and constants are allowed. Variables whose names
// mark them as ready-made HTML (html, *Label, *Icon, options...) are allowed
// because the code that builds them is checked too.
const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");

const FILE = path.join(__dirname, "..", "public", "index.html");
const ESCAPERS = new Set(["escapeHtml", "jsStr", "jsArg", "safeUrl", "cssUrl"]);
const NUMERIC_CALLS = new Set(["Number", "parseInt", "parseFloat", "formatPrice", "formatTicketCount"]);
const NUMERIC_METHODS = new Set(["toLocaleString", "toFixed"]);
const NUMERIC_OPS = new Set(["-", "*", "/", "%"]);
const FRAGMENT_NAME = /html|Html|HTML|badge|Badge|Label$|label$|Style$|style$|icon|Icon|rows?$|Rows?$|items$|Items$|options|Options|cards|Cards|btn|Btn|actions|Actions|chips|Chips|markup|Markup|pill|Pill/;
const SAFE_IDENTS = new Set(["i", "idx", "index", "pct", "percent", "width", "count", "step", "rank"]);

const literalText = (node) => {
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) return node.quasis[0].value.cooked;
  return null;
};
const flatten = (node, out) => {
  if (node.type === "BinaryExpression" && node.operator === "+") { flatten(node.left, out); flatten(node.right, out); } else out.push(node);
  return out;
};
const isHtmlChain = (node) =>
  node.type === "BinaryExpression" && node.operator === "+" &&
  flatten(node, []).some((p) => { const t = literalText(p); return t !== null && t.includes("<"); });
const calleeName = (node) => (node.type === "CallExpression" && node.callee.type === "Identifier" ? node.callee.name : "");

function isNumericOrConst(node) {
  switch (node.type) {
    case "Literal": return true;
    case "TemplateLiteral": return node.expressions.length === 0;
    case "UnaryExpression": return true;
    case "BinaryExpression": return NUMERIC_OPS.has(node.operator);
    case "CallExpression":
      if (NUMERIC_CALLS.has(calleeName(node))) return true;
      if (node.callee.type === "MemberExpression" && !node.callee.computed && NUMERIC_METHODS.has(node.callee.property.name)) return true;
      return node.callee.type === "MemberExpression" && node.callee.object.type === "Identifier" && node.callee.object.name === "Math";
    case "MemberExpression": return !node.computed && node.property.name === "length";
    case "Identifier": return SAFE_IDENTS.has(node.name);
    default: return false;
  }
}

function contextOf(before) {
  const tail = before.slice(-400);
  const handler = tail.match(/\son\w+\s*=\s*"([^"]*)$/i);
  if (handler) return (handler[1].match(/(^|[^\\])'/g) || []).length % 2 === 1 ? "jsstr" : "jsraw";
  if (/(src|href|action)\s*=\s*["']?$/i.test(tail) || /url\(\s*['"]?$/i.test(tail)) return "url";
  return "html";
}

const EXPECTED = { html: ["escapeHtml"], url: ["safeUrl", "cssUrl"], jsstr: ["jsStr"], jsraw: ["jsArg"] };

function problemFor(node, ctx) {
  const name = calleeName(node);
  if (ESCAPERS.has(name)) return EXPECTED[ctx].includes(name) || (ctx === "html" && name !== "jsStr") ? null : `${name}() is the wrong escaper here (use ${EXPECTED[ctx].join(" or ")})`;
  if (isNumericOrConst(node) && (ctx === "html" || ctx === "url" || node.type === "Literal" || (ctx === "jsraw" && node.type !== "Identifier"))) return null;
  if (isHtmlChain(node)) return null;
  if (node.type === "ConditionalExpression") {
    return [node.consequent, node.alternate].map((b) => (literalText(b) === null ? problemFor(b, ctx) : null)).find(Boolean) || null;
  }
  if (node.type === "LogicalExpression" && [node.left, node.right].some((x) => { const t = literalText(x); return t !== null && t.includes("<"); })) {
    return [node.left, node.right].map((b) => (literalText(b) === null ? problemFor(b, ctx) : null)).find(Boolean) || null;
  }
  if (node.type === "Identifier" && FRAGMENT_NAME.test(node.name)) return null;
  if (node.type === "CallExpression" && node.callee.type === "MemberExpression" && node.callee.property.name === "join") return null;
  if (node.type === "CallExpression" && /Html|html|Badge|Label|Icon/.test(name)) return null;
  return `unescaped value in ${ctx} context (use ${EXPECTED[ctx].join(" or ")})`;
}

function check(html) {
  const problems = [];
  const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    if (/src=|type=["']module/.test(m[1] || "") || !m[2].trim()) continue;
    const code = m[2];
    const offset = m.index + m[0].indexOf(">") + 1;
    const lineOf = (pos) => html.slice(0, offset + pos).split("\n").length;
    const report = (node, ctx) => {
      const problem = problemFor(node, ctx);
      if (problem) problems.push(`index.html:${lineOf(node.start)}  ${code.slice(node.start, node.end).replace(/\s+/g, " ").slice(0, 60)}  -> ${problem}`);
    };
    const ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", allowReturnOutsideFunction: true });
    walk.ancestor(ast, {
      BinaryExpression(node, ancestors) {
        if (node.operator !== "+") return;
        const parent = ancestors[ancestors.length - 2];
        if (parent && parent.type === "BinaryExpression" && parent.operator === "+") return;
        const parts = flatten(node, []);
        if (!parts.some((p) => { const t = literalText(p); return t !== null && (t.includes("<") || /=\s*["']/.test(t)); })) return;
        if (parts.some((p) => { const t = literalText(p); return t !== null && /form\.submit\(\)|document\.createElement/.test(t); })) return;
        let before = "";
        for (const part of parts) {
          const text = literalText(part);
          if (text !== null) { before += text; continue; }
          report(part, contextOf(before));
          before += "X";
        }
      },
      TemplateLiteral(node) {
        if (!node.expressions.length || !node.quasis.some((q) => q.value.cooked.includes("<"))) return;
        let before = "";
        node.quasis.forEach((quasi, i) => {
          before += quasi.value.cooked;
          if (i < node.expressions.length) { report(node.expressions[i], contextOf(before)); before += "X"; }
        });
      },
    });
  }
  return problems;
}

module.exports = { check };

if (require.main === module) {
  const problems = check(fs.readFileSync(FILE, "utf8"));
  if (problems.length) {
    console.error(`HTML escaping check failed (${problems.length}):\n` + problems.join("\n"));
    process.exit(1);
  }
  console.log("HTML escaping check passed.");
}
