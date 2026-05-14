#!/usr/bin/env node
'use strict';

// Release-time VEX builder. Reads vex/statements.json, expands each
// entry into a CSAF 2.1 §3.2.3 vulnerability statement via b.vex.statement
// (handles cveId / ids[] / cweId / justification flags / product_status),
// wraps them in a b.vex.document, and writes the serialized JSON to
//
//   build/hermitstash-sync-vX.Y.Z.vex.json
//
// Empty statements array = no output, exit 0. Operators add statements
// as transitive-CVE assessments accumulate; the file is committed source.
//
// Usage:
//   node scripts/build-vex.js [--out <dir>] [--date <iso>]
//
// CI:
//   .github/workflows/release.yml runs this in the `release` job after
//   downloading the per-platform artifacts. The output is uploaded
//   alongside the binaries via softprops/action-gh-release.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const b = require('../vendor/blamejs');

const REPO_ROOT = nodePath.resolve(__dirname, '..');
const INPUT_PATH = nodePath.join(REPO_ROOT, 'vex', 'statements.json');

// All platform IDs the release pipeline produces. Keep in sync with
// .github/workflows/release.yml `build.strategy.matrix` and the
// container image emitted by docker-publish.yml.
const PLATFORMS = ['linux-x64', 'linux-arm64', 'win-x64', 'macos-arm64'];
const HAS_CONTAINER = true;

function parseArgs(argv) {
  const opts = { outDir: nodePath.join(REPO_ROOT, 'build'), dateIso: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && argv[i + 1]) { opts.outDir = nodePath.resolve(argv[++i]); continue; }
    if (argv[i] === '--date' && argv[i + 1]) { opts.dateIso = argv[++i]; continue; }
  }
  return opts;
}

function readInput() {
  if (!nodeFs.existsSync(INPUT_PATH)) {
    return { statements: [] };
  }
  const raw = nodeFs.readFileSync(INPUT_PATH, 'utf8');
  const parsed = b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) });
  if (!parsed || !Array.isArray(parsed.statements)) {
    throw new Error(`vex/statements.json missing top-level "statements" array`);
  }
  return parsed;
}

function readVersion() {
  return require(nodePath.join(REPO_ROOT, 'lib', 'constants')).VERSION;
}

function expandProductScope(scope, version) {
  const all = PLATFORMS.map(p => `hermitstash-sync@${version}:${p}`);
  if (HAS_CONTAINER) all.push(`hermitstash-sync@${version}:container`);
  if (scope === 'all' || scope == null) return all;
  if (!Array.isArray(scope)) {
    throw new Error(`productScope must be "all" or an array; got ${typeof scope}`);
  }
  // Operator-supplied product IDs pass through verbatim — they may
  // reference a different release version (e.g. a CVE first surfaced
  // in 0.5.x but assessed at 0.7.x).
  return scope;
}

function buildStatements(entries, version) {
  const out = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const productIds = expandProductScope(e.productScope, version);
    try {
      out.push(b.vex.statement({
        cveId:           e.cveId,
        cweId:           e.cweId,
        ids:             e.ids,
        status:          e.status,
        productIds:      productIds,
        justification:   e.justification,
        impactStatement: e.impactStatement,
        references:      e.references,
        firstReleased:   e.firstReleased,
        lastUpdated:     e.lastUpdated,
      }));
    } catch (err) {
      const label = e.cveId || (e.ids && e.ids[0] && e.ids[0].text) || `#${i}`;
      throw new Error(`statement ${label}: ${err.message}`);
    }
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const version = readVersion();
  const tag = `v${version}`;
  const input = readInput();

  if (!input.statements.length) {
    process.stderr.write(
      `[build-vex] vex/statements.json has no statements — skipping VEX emission for ${tag}.\n` +
      `[build-vex] Add CVE assessments to vex/statements.json when there are CVEs worth statementing.\n`
    );
    return 0;
  }

  const statements = buildStatements(input.statements, version);
  const dateIso = args.dateIso || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  const doc = b.vex.document({
    documentId:         `hermitstash-sync-${tag}-vex`,
    title:              `HermitStash Sync ${tag} — CSAF 2.1 VEX`,
    publisher: {
      category:  'vendor',
      name:      'dotCooCoo',
      namespace: 'https://github.com/dotCooCoo/hermitstash-sync',
    },
    trackingId:         `hermitstash-sync@${version}`,
    trackingVersion:    '1',
    currentReleaseDate: dateIso,
    initialReleaseDate: dateIso,
    statements:         statements,
    tlp:                input.tlp || 'CLEAR',
  });

  nodeFs.mkdirSync(args.outDir, { recursive: true });
  const outPath = nodePath.join(args.outDir, `hermitstash-sync-${tag}.vex.json`);
  nodeFs.writeFileSync(outPath, b.vex.serialize(doc) + '\n', { mode: 0o644 });
  process.stderr.write(
    `[build-vex] Wrote ${nodePath.relative(REPO_ROOT, outPath)} ` +
    `(${statements.length} statement${statements.length === 1 ? '' : 's'}).\n`
  );
  return 0;
}

if (require.main === module) {
  try {
    process.exit(main()); // allow:process-exit — release-time CLI utility, sysexits-style status to the workflow runner
  } catch (err) {
    process.stderr.write(`[build-vex] ${err.message}\n`);
    process.exit(1); // allow:process-exit — release-time CLI utility
  }
}

module.exports = { main, buildStatements, expandProductScope };
