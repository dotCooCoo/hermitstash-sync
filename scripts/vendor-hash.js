#!/usr/bin/env node
'use strict';

/**
 * Compute SHA256 hashes for the consumed entry points of vendored
 * blamejs and write them into `vendor/MANIFEST.json` under the shape
 * `b.configDrift.verifyVendorIntegrity()` expects:
 *
 *   packages.blamejs.files  = { <kind>: <relativePath>, ... }
 *   packages.blamejs.hashes = { <kind>: "sha256:<hex>", ... }
 *
 * Run after every `vendor/blamejs/` refresh:
 *
 *   node scripts/vendor-hash.js
 *
 * The boot path in `bin/hermitstash-sync.js` reads the manifest and
 * refuses to start if any consumed file's bytes don't match the recorded
 * hash. Catches a half-applied vendor refresh, a corrupted clone, or
 * tampering with a vendored cjs after the manifest was committed.
 *
 * Uses node:fs + node:crypto + node:path plus the vendored blamejs
 * `b.safeJson.parse` to read the manifest under the same size/depth caps
 * the sibling manifest readers (build-sbom.js, check-blamejs-version.js)
 * apply to the very same file.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const { projectInto } = require('./project-transitive-manifest');
const { fixDocs } = require('./check-doc-versions');

const MANIFEST_PATH = path.join(__dirname, '..', 'vendor', 'MANIFEST.json');
const REPO_ROOT = path.resolve(__dirname, '..');

// The set of vendored files we directly require + their semantic kind.
// Adding a new consumer means adding its lib path here so the integrity
// check covers it. Files outside this set are not validated — they're
// reachable transitively through `require('vendor/blamejs')` which loads
// the index, so a corrupted transitive dep would surface at smoke-load
// time rather than via this check. The list is the framework surface
// hermitstash-sync directly names; integrity-verifying it gives us
// boot-time tamper detection without committing to hashing 240+ files.
const CONSUMED = {
  'index':                  'vendor/blamejs/index.js',
  'safe-json':              'vendor/blamejs/lib/safe-json.js',
  'safe-url':               'vendor/blamejs/lib/safe-url.js',
  'pqc-agent':              'vendor/blamejs/lib/pqc-agent.js',
  'pqc-software':           'vendor/blamejs/lib/pqc-software.js',
  'http-client':            'vendor/blamejs/lib/http-client.js',
  'ws-client':              'vendor/blamejs/lib/ws-client.js',
  'log-stream':             'vendor/blamejs/lib/log-stream.js',
  'log-stream-local':       'vendor/blamejs/lib/log-stream-local.js',
  'atomic-file':            'vendor/blamejs/lib/atomic-file.js',
  'app-shutdown':           'vendor/blamejs/lib/app-shutdown.js',
  'retry':                  'vendor/blamejs/lib/retry.js',
  'framework-error':        'vendor/blamejs/lib/framework-error.js',
  'process-spawn':          'vendor/blamejs/lib/process-spawn.js',
  'config-drift':           'vendor/blamejs/lib/config-drift.js',
  'middleware-api-encrypt': 'vendor/blamejs/lib/middleware/api-encrypt.js',
  // The release checks decide whether a base-image pin is current and whether
  // the vendored framework is the version it claims, and they reach those
  // verdicts by matching with this. Bytes that decide what a release is allowed
  // to ship belong under the same integrity check as the rest of the surface.
  'regex-linear':           'vendor/blamejs/lib/regex-linear.js',
  'noble-post-quantum':     'vendor/blamejs/lib/vendor/noble-post-quantum.cjs',
  'noble-ciphers':          'vendor/blamejs/lib/vendor/noble-ciphers.cjs',
};

function sha256File(rel) {
  const abs = path.join(REPO_ROOT, rel);
  const buf = fs.readFileSync(abs);
  return 'sha256:' + crypto.createHash('sha256').update(buf).digest('hex');
}

// Refresh the operator-shipped copy of blamejs's node:-builtins-only standalone
// verifier. scripts/standalone-verifier.js is consumed by the Docker
// verify stage + deploy/install.sh + deploy/update.sh — contexts that
// don't have vendor/blamejs/ on disk yet. We carry a verbatim copy so
// the install pipeline only needs the trio (verify-release.js +
// standalone-verifier.js + autoupdate-pubkey.js). Refreshing it
// automatically as part of every vendor-hash run keeps the copy in
// lockstep with whatever blamejs version we just vendored.
function refreshStandaloneVerifier() {
  const src = path.join(REPO_ROOT, 'vendor', 'blamejs', 'lib', 'self-update-standalone-verifier.js');
  const dst = path.join(REPO_ROOT, 'scripts', 'standalone-verifier.js');
  if (!fs.existsSync(src)) {
    console.warn('scripts/standalone-verifier.js: upstream source not found at', src, '— skipping');
    return false;
  }
  fs.copyFileSync(src, dst);
  return true;
}

(function main() {
  const raw = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const manifest = b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) });
  if (!manifest.packages || !manifest.packages.blamejs) {
    console.error('vendor/MANIFEST.json missing packages.blamejs');
    process.exit(1);
  }

  const files = {};
  const hashes = {};
  for (const [kind, rel] of Object.entries(CONSUMED)) {
    files[kind] = rel;
    hashes[kind] = sha256File(rel);
  }
  manifest.packages.blamejs.files = files;
  manifest.packages.blamejs.hashes = hashes;

  // Mechanically project blamejs's own authoritative transitive manifest
  // (the noble-* / simplewebauthn / public-suffix bundles it vendors) into
  // packages.blamejs.transitive in the SAME write that records the consumed
  // hashes. This keeps the release SBOM's transitive surface a committed,
  // reviewable, drift-gated artifact instead of a release-time reach into the
  // vendored subtree — the projection is re-checked by
  // `scripts/project-transitive-manifest.js --check` in release prepare + CI.
  const transitiveCount = projectInto(manifest, REPO_ROOT);

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n');
  const refreshed = refreshStandaloneVerifier();

  // Keep the hand-typed version references in the operator-facing docs (the
  // vendored blamejs version, its minor line, and the Node floor) in lockstep
  // with their source of truth, so a vendor bump can't leave a stale version
  // stranded in the README. Gated by `check-doc-versions.js --check` in release
  // prepare + CI.
  const docFixes = fixDocs(REPO_ROOT);

  console.log('vendor/MANIFEST.json updated:', Object.keys(CONSUMED).length, 'file hashes recorded; ' +
              transitiveCount + ' transitive bundles projected.' +
              (refreshed ? ' scripts/standalone-verifier.js refreshed from upstream.' : '') +
              (docFixes ? ' ' + docFixes + ' doc version reference(s) synced.' : ''));
})();
