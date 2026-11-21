// Lint only for mistakes that break at runtime: a name that is used but never
// defined or imported (easy to miss when moving code between files), and
// names that are defined but never used (leftovers after a move).
const globals = require("globals");

module.exports = [
  {
    files: ["server.js", "src/**/*.js", "scripts/**/*.js", "test/**/*.js", "eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "commonjs",
      globals: { ...globals.node },
    },
    rules: {
      "no-undef": "error",
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
      "no-redeclare": "error",
    },
  },
];
