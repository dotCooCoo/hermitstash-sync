#!/usr/bin/env node
"use strict";
/**
 * Branch-coverage union for the sync client.
 *
 * Every suite writes raw V8 coverage into one directory via NODE_V8_COVERAGE,
 * which accumulates across processes — the runner spawns each test file as its
 * own child, and the variable is inherited, so one report covers all of them.
 *
 *   node scripts/coverage.js                # full suite, then the report
 *   node scripts/coverage.js --report-only  # re-report existing raw output
 *   node scripts/coverage.js --check        # exit non-zero below THRESHOLDS
 *
 * What this measures is the CLIENT. Its tests drive a real HermitStash server,
 * so a run also produces coverage for the server's files; those are excluded
 * here and belong to that repo's own union, which measures them properly by
 * running its unit and integration suites alongside.
 *
 * c8's CLI cannot run under Node 26 — its bundled yargs fails to load — so this
 * drives the report engine directly rather than shelling out to the binary.
 */
var cp = require("node:child_process");
var fs = require("node:fs");
var path = require("node:path");

var REPO = path.resolve(__dirname, "..");
var COV = path.join(REPO, ".coverage");
var RAW = path.join(COV, "raw");

// Measured floors, rounded down to a whole percent, not opinions about what is
// enough. They exist to catch a regression, so raise them as gaps close and
// never lower one to make a run pass.
var THRESHOLDS = { lines: 80, branches: 74, functions: 84, statements: 80 };

// `all: true` counts files no test loaded, which is the point — an untouched
// file is exactly the gap worth seeing. It also means anything on disk under
// src counts, so gitignored working directories have to be named here or a
// developer's local scratch drags the percentage around and the thresholds
// stop meaning the same thing on two machines.
// build/ holds the executable builder and, once anyone runs build:sea, the
// generated single-file bundle — the whole client concatenated. Measuring that
// would count every line twice and swing the totals on nothing more than
// whether a developer had built the binary before running this.
var EXCLUDE = [
  "vendor/**", "tests/**", "scripts/**", "build/**", "node_modules/**",
  ".coverage/**", "coverage/**", ".scratch/**", "**/*.test.js", "**/*.min.js",
];

// Clearing the raw directory is not best-effort. A leftover file from an
// earlier run merges into this one, and it merges in the flattering direction:
// coverage only ever adds. The union would read higher than the code earns and
// --check would pass over a real regression.
function clearRaw() {
  try { fs.rmSync(RAW, { recursive: true, force: true }); } catch (_e) { /* checked below */ }
  var left = [];
  try { left = fs.readdirSync(RAW); } catch (_e) { return; } // gone, as intended
  if (left.length) {
    console.error("could not clear " + RAW + " — " + left.length + " file(s) remain.");
    console.error("Stale coverage would merge into this run and read higher than it should.");
    console.error("Close whatever holds them (Dropbox sync, a virus scanner, an editor) and retry.");
    process.exit(2);
  }
}

function runSuite() {
  process.stdout.write("  full suite … ");
  var started = Date.now();
  try {
    cp.execFileSync("node", ["tests/run-all.js"], {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      env: Object.assign({}, process.env, { NODE_V8_COVERAGE: RAW }),
    });
    console.log("ok (" + Math.round((Date.now() - started) / 1000) + "s)");
    return true;
  } catch (e) {
    // A failing suite still leaves coverage behind, and a partial union beats
    // none — report and continue so one failure does not hide every number.
    console.log("FAILED (" + Math.round((Date.now() - started) / 1000) + "s)");
    var out = ((e.stdout || "") + (e.stderr || "")).toString().trim().split("\n").slice(-8);
    out.forEach(function (l) { console.log("      " + l); });
    return false;
  }
}

async function report(check) {
  var Report = require(path.join(REPO, "node_modules", "c8", "lib", "report.js"));
  var r = new Report({
    include: [],
    exclude: EXCLUDE,
    extension: [".js"],
    reporter: ["text-summary", "html", "json-summary"],
    reportsDirectory: path.join(COV, "report"),
    tempDirectory: RAW,
    // Named source roots rather than the repo root. With all:true, anything
    // reachable from src counts, so pointing at the root meant every new
    // top-level tooling file (eslint.config.js today, the next one tomorrow)
    // landed in the client's totals and moved a threshold that has nothing to
    // do with the client.
    src: [path.join(REPO, "lib"), path.join(REPO, "bin")],
    all: true,
    excludeNodeModules: true,
    omitRelative: false,
    resolve: "",
    wrapperLength: 0,
    watermarks: {},
  });
  await r.run();

  var summaryPath = path.join(COV, "report", "coverage-summary.json");
  if (!fs.existsSync(summaryPath)) {
    console.log("\n  no summary written — nothing to check against");
    return 0;
  }
  var total = JSON.parse(fs.readFileSync(summaryPath, "utf8")).total;
  console.log("\n  union: "
    + ["lines", "branches", "functions", "statements"].map(function (k) {
      return k + " " + total[k].pct + "%";
    }).join("  ·  "));
  console.log("  html: " + path.join(COV, "report", "index.html"));

  if (!check) return 0;
  var failed = Object.keys(THRESHOLDS).filter(function (k) {
    return total[k].pct < THRESHOLDS[k];
  });
  failed.forEach(function (k) {
    console.log("  FAIL " + k + " " + total[k].pct + "% < " + THRESHOLDS[k] + "%");
  });
  return failed.length ? 1 : 0;
}

async function main() {
  var argv = process.argv.slice(2);
  var reportOnly = argv.indexOf("--report-only") !== -1;
  var suitePassed = true;

  if (!reportOnly) {
    clearRaw();
    fs.mkdirSync(RAW, { recursive: true });
    console.log("coverage — running the suite into one V8 output directory");
    suitePassed = runSuite();
  }

  if (!fs.existsSync(RAW) || fs.readdirSync(RAW).length === 0) {
    console.log("\n  no raw coverage in " + RAW + " — run without --report-only first");
    process.exit(2);
  }

  // Report first, then fail. A failing suite still leaves useful coverage, and
  // the numbers are worth seeing either way — but the run must not exit 0 on
  // the strength of a threshold when the suite underneath it was red.
  var thresholdCode = await report(argv.indexOf("--check") !== -1);
  if (!suitePassed) {
    console.log("\n  FAIL — the suite failed; the coverage above describes a red run.");
    process.exit(1);
  }
  process.exit(thresholdCode);
}

main().catch(function (e) {
  console.error("coverage failed: " + (e && e.stack ? e.stack : e));
  process.exit(2);
});
