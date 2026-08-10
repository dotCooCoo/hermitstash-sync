/**
 * Canonical ESLint config — used by both local dev (`npx eslint .`) and CI.
 *
 * This lived as a heredoc inside .github/workflows/ci.yml, which made the gate
 * impossible to run locally: the config only existed while the workflow step
 * was executing. A lint break therefore could not be found before pushing, and
 * one went unnoticed for two days while it blocked every docker-publish run —
 * the release workflow still published binaries, so nothing else was obviously
 * wrong. Keeping the rules in a committed file means `npx eslint .` reproduces
 * exactly what CI runs.
 *
 * When editing: every rule here runs in CI. If a rule produces false positives
 * for this codebase, turn it off here — don't add per-line disable-comments.
 */
var security = require("eslint-plugin-security");

module.exports = [
  {
    ignores: [
      "tests/", "node_modules/**", "vendor/**", "build/**",
      // Gitignored, so CI never checks it out. Without this a local run
      // reports findings CI cannot see, and the two stop agreeing — which is
      // the whole point of having one config.
      ".scratch/**",
    ],
  },
  {
    files: ["**/*.js"],
    plugins: { security: security },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        require: "readonly", module: "readonly", exports: "readonly",
        __dirname: "readonly", __filename: "readonly",
        process: "readonly", console: "readonly", Buffer: "readonly",
        setTimeout: "readonly", setInterval: "readonly", setImmediate: "readonly",
        clearTimeout: "readonly", clearInterval: "readonly",
        URL: "readonly", URLSearchParams: "readonly",
        global: "readonly", crypto: "readonly",
        TextEncoder: "readonly", TextDecoder: "readonly",
        Atomics: "readonly", SharedArrayBuffer: "readonly", Int32Array: "readonly",
      },
    },
    rules: {
      // Built-in
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-console": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-self-compare": "error",
      "no-constructor-return": "error",
      "no-new-wrappers": "error",
      "no-throw-literal": "error",
      // Security plugin
      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "warn",
      "security/detect-unsafe-regex": "error",
      "security/detect-buffer-noassert": "error",
      "security/detect-new-buffer": "error",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "warn",
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-non-literal-require": "off",
      "security/detect-non-literal-regexp": "off",
    },
  },
];
