#!/usr/bin/env node
'use strict';

/**
 * Keep the hand-typed version references in the operator-facing docs in lockstep
 * with their single source of truth, so a vendor bump can't leave a stale
 * version stranded in the prose (e.g. the README still claiming blamejs v0.15.19
 * after the tree moved to v0.15.20).
 *
 * Sources of truth:
 *   - vendored blamejs version  -> vendor/MANIFEST.json (packages.blamejs.version)
 *   - Node.js runtime floor      -> package.json (engines.node)
 *
 * Each rule anchors on a SPECIFIC phrasing so a deliberate, unrelated version on
 * the same line is never touched — e.g. the README line that names both the
 * server's blamejs compatibility floor ("blamejs v0.8.43+") and this client's
 * vendored version ("this client (on blamejs vX.Y.Z)") only has the
 * parenthetical client version checked. Each rule also requires at least one
 * match (an anchor-rot guard): if the prose is reworded so a rule matches
 * nothing, the gate fails loud rather than silently going no-op.
 *
 * Modes:
 *   node scripts/check-doc-versions.js          # gate: fail on drift (default)
 *   node scripts/check-doc-versions.js --check   # same as default
 *   node scripts/check-doc-versions.js --fix     # rewrite the docs to the source
 *
 * --fix is invoked mechanically by scripts/vendor-hash.js on every blamejs
 * refresh (auto-update), and the gate runs in scripts/release.js prepare and in
 * CI alongside the changelog + SBOM-projection drift gates. Mirrors how the
 * release SBOM's transitive surface is kept in sync.
 */

const fs = require('node:fs');
const path = require('node:path');
const b = require('../vendor/blamejs');

const REPO_ROOT = path.resolve(__dirname, '..');

// Operator-facing docs that carry version prose. Scanned by every rule, so a
// reference added to another of these files later is covered automatically.
const DOC_FILES = ['README.md', 'SECURITY.md', 'RELEASING.md'];

function readJson(abs) {
  return b.safeJson.parse(fs.readFileSync(abs, 'utf8'), { maxBytes: b.constants.BYTES.mib(1) });
}

// The authoritative versions every doc reference must agree with.
function sourcesOfTruth(repoRoot) {
  const manifest = readJson(path.join(repoRoot, 'vendor', 'MANIFEST.json'));
  const blamejs = manifest && manifest.packages && manifest.packages.blamejs;
  if (!blamejs || typeof blamejs.version !== 'string') {
    throw new Error('vendor/MANIFEST.json: packages.blamejs.version is missing');
  }
  const blamejsVersion = blamejs.version;
  const blamejsMinor = blamejsVersion.split('.').slice(0, 2).join('.');

  const pkg = readJson(path.join(repoRoot, 'package.json'));
  const nodeRange = (pkg.engines && typeof pkg.engines.node === 'string') ? pkg.engines.node : '';
  const nodeFloor = nodeRange.replace(/^[\s>=~^]+/, '').trim();
  if (!/^\d+\.\d+\.\d+$/.test(nodeFloor)) {
    throw new Error(`package.json engines.node ("${nodeRange}") is not a plain floor like ">=24.19.0"`);
  }

  return { blamejsVersion, blamejsMinor, nodeFloor };
}

// Each rule: an anchored literal regex (global, ONE capture group = the version
// token to check), the canonical value it must equal, and a label. The regexes
// are literals — never built from a string — so there is no dynamic-RegExp /
// ReDoS surface; they are consumed via matchAll/replace, which do not mutate the
// source regex's lastIndex, so the same rule is safe to reuse across files.
function rulesFor(s) {
  return [
    { label: 'vendored blamejs version', re: /\(on blamejs v(\d+\.\d+\.\d+)\)/g, expect: s.blamejsVersion },
    { label: 'blamejs minor line',       re: /matching v(\d+\.\d+)\.x blamejs/g, expect: s.blamejsMinor },
    { label: 'Node.js runtime floor',    re: /Node\.js (\d+\.\d+\.\d+)\+/g,      expect: s.nodeFloor },
  ];
}

// Evaluate one rule across all docs. Returns { matches, drift: [{file, found, expect}] }.
function evalRule(repoRoot, rule) {
  let matches = 0;
  const drift = [];
  for (const file of DOC_FILES) {
    const abs = path.join(repoRoot, file);
    if (!fs.existsSync(abs)) continue;
    const text = fs.readFileSync(abs, 'utf8');
    for (const m of text.matchAll(rule.re)) {
      matches++;
      if (m[1] !== rule.expect) drift.push({ file, found: m[1], expect: rule.expect });
    }
  }
  return { matches, drift };
}

function checkDocs(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  const s = sourcesOfTruth(repoRoot);
  const problems = [];
  for (const rule of rulesFor(s)) {
    const { matches, drift } = evalRule(repoRoot, rule);
    if (matches === 0) {
      problems.push(`  ! "${rule.label}": anchor matched nothing in ${DOC_FILES.join('/')} — the prose was reworded; ` +
        `update the rule in scripts/check-doc-versions.js or restore the reference.`);
      continue;
    }
    for (const d of drift) {
      problems.push(`  ~ ${d.file}: "${rule.label}" says ${d.found}, source of truth is ${d.expect}`);
    }
  }
  if (problems.length === 0) {
    process.stdout.write(`[check-doc-versions] OK — operator-facing docs match blamejs ${s.blamejsVersion} and Node ${s.nodeFloor}.\n`);
    return 0;
  }
  process.stderr.write(
    '[check-doc-versions] DRIFT — operator-facing docs disagree with the source of truth:\n' +
    problems.join('\n') + '\n' +
    '  Fix: run `node scripts/check-doc-versions.js --fix` (normally done by scripts/vendor-hash.js) and commit.\n'
  );
  return 1;
}

// Rewrite every doc reference to its source of truth. Returns the replacement
// count. Anchored, so only the captured version token moves.
function fixDocs(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  const s = sourcesOfTruth(repoRoot);
  let replaced = 0;
  for (const file of DOC_FILES) {
    const abs = path.join(repoRoot, file);
    if (!fs.existsSync(abs)) continue;
    let text = fs.readFileSync(abs, 'utf8');
    let changed = false;
    for (const rule of rulesFor(s)) {
      text = text.replace(rule.re, (whole, found) => {
        if (found === rule.expect) return whole;
        replaced++;
        changed = true;
        return whole.replace(found, rule.expect);
      });
    }
    if (changed) fs.writeFileSync(abs, text);
  }
  return replaced;
}

function main(argv) {
  if (argv.indexOf('--fix') !== -1) {
    const n = fixDocs();
    process.stdout.write(`[check-doc-versions] rewrote ${n} stale version reference${n === 1 ? '' : 's'} in the operator-facing docs.\n`);
    return 0;
  }
  return checkDocs();
}

if (require.main === module) {
  try {
    process.exit(main(process.argv.slice(2))); // allow:process-exit — release-time CLI utility, sysexits-style status
  } catch (err) {
    process.stderr.write(`[check-doc-versions] ${err.message}\n`);
    process.exit(1); // allow:process-exit — release-time CLI utility
  }
}

module.exports = { sourcesOfTruth, checkDocs, fixDocs, main };
