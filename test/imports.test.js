// Every name taken from a local module with
//   const { a, b } = require("./module")
// must be in that module's module.exports. ESLint can't see this: importing a
// name a module doesn't export just gives undefined, which only fails when
// that code runs (it happened once while moving the security headers).
// Checked by parsing the files, never by loading them.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const acorn = require("acorn");

const ROOT = path.join(__dirname, "..");

function jsFiles() {
  const files = [path.join(ROOT, "server.js")];
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).forEach((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p); else if (p.endsWith(".js")) files.push(p);
  });
  walk(path.join(ROOT, "src"));
  walk(path.join(ROOT, "scripts"));
  return files;
}

const parse = (file) => acorn.parse(fs.readFileSync(file, "utf8"), { ecmaVersion: 2024, sourceType: "script" });

function exportedNames(file) {
  for (const node of parse(file).body) {
    const e = node.type === "ExpressionStatement" && node.expression;
    if (e && e.type === "AssignmentExpression" && e.left.type === "MemberExpression"
      && e.left.object.name === "module" && e.left.property.name === "exports") {
      if (e.right.type !== "ObjectExpression") return null; // e.g. a Router: not destructured
      return e.right.properties.map((p) => p.key.name);
    }
  }
  return [];
}

function resolveLocal(fromFile, spec) {
  const base = path.resolve(path.dirname(fromFile), spec);
  for (const candidate of [base, `${base}.js`, path.join(base, "index.js")]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

test("destructured local imports exist in the module's exports", () => {
  const problems = [];
  for (const file of jsFiles()) {
    const walk = (node) => {
      if (!node || typeof node.type !== "string") return;
      if (node.type === "VariableDeclarator" && node.id.type === "ObjectPattern" && node.init
        && node.init.type === "CallExpression" && node.init.callee.name === "require"
        && node.init.arguments[0] && /^\.\.?\//.test(node.init.arguments[0].value)) {
        const target = resolveLocal(file, node.init.arguments[0].value);
        const exported = target && exportedNames(target);
        if (!target) problems.push(`${path.relative(ROOT, file)}: cannot find ${node.init.arguments[0].value}`);
        else if (exported) {
          for (const prop of node.id.properties) {
            if (prop.key && !exported.includes(prop.key.name)) {
              problems.push(`${path.relative(ROOT, file)}: ${prop.key.name} is not exported by ${path.relative(ROOT, target)}`);
            }
          }
        }
      }
      for (const value of Object.values(node)) {
        if (Array.isArray(value)) value.forEach(walk);
        else if (value && typeof value.type === "string") walk(value);
      }
    };
    walk(parse(file));
  }
  assert.deepEqual(problems, []);
});
