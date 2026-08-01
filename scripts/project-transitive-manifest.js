#!/usr/bin/env node
'use strict';

/**
 * Project blamejs's own authoritative transitive manifest into the parent
 * vendor/MANIFEST.json as a committed, reviewable, drift-gated snapshot.
 *
 * The release SBOM (scripts/build-sbom.js) enumerates the transitive
 * (noble-*, simplewebauthn, public-suffix, …) bundles that blamejs vendors
 * inside itself. Those versions + hashes live in
 *
 *   vendor/blamejs/lib/vendor/MANIFEST.json   (authoritative)
 *
 * and change whenever the vendored framework is refreshed. Without a
 * projection, a transitive version/hash bump would flow straight into the
 * shipped SBOM with no record in our own committed manifest and no gate —
 * the same silent-drift hole the changelog (release-notes JSON -> CHANGELOG.md)
 * and the rollup (per-patch -> consolidated) close with their own
 * --check gates. This script closes it the same way:
 *
 *   packages.blamejs.transitive   in vendor/MANIFEST.json   (projected)
 *
 * Modes:
 *   node scripts/project-transitive-manifest.js          # write the projection
 *   node scripts/project-transitive-manifest.js --check  # gate: fail on drift
 *
 * The write mode is invoked mechanically by scripts/vendor-hash.js on every
 * blamejs refresh (auto-populate), so the snapshot is never hand-maintained.
 * The --check mode runs in scripts/release.js `prepare` and in CI alongside
 * the changelog gate, so a refresh that skipped vendor-hash, or a hand-edit,
 * fails loud instead of shipping a stale SBOM.
 *
 * The projection is exactly the SBOM-material subset build-sbom.js consumes,
 * filtered to the bundles whose runtime file actually ships under
 * vendor/blamejs/ — the IDENTICAL shipped-surface filter build-sbom.js
 * applies — so the projected snapshot is byte-faithful to the SBOM's
 * transitive input. Volatile, non-SBOM fields (refreshedAt, _about, bundler,
 * exports, …) are intentionally excluded so a pure-timestamp upstream refresh
 * is a no-op and only a material change (version, hash, license, identity)
 * moves the gate.
 */

const fs = require('node:fs');
const path = require('node:path');
const b = require('../vendor/blamejs');

const REPO_ROOT = path.resolve(__dirname, '..');

// The SBOM-material fields build-sbom.js reads off each transitive entry, in a
// fixed emission order. Anything not in this list is excluded from the
// projection by design (see the header note on drift-gate noise).
const PROJECTED_FIELDS = Object.freeze([
  'version', 'license', 'license_is_spdx', 'author',
  'source', 'cpe', 'description', 'files', 'hashes', 'bundledAt',
  // `components` carries the nested package versions of a meta-bundle that
  // vendors its own sub-packages. The release SBOM enumerates each nested
  // package so a CVE scanner can key on its own version rather than only the
  // aggregate bundle, so the nested versions must ride the projection (and be
  // drift-gated) too. No shipped bundle nests today, so this is currently unused.
  'components',
]);

const PROJECTION_NOTE =
  'Mechanically projected from vendor/blamejs/lib/vendor/MANIFEST.json by ' +
  'scripts/project-transitive-manifest.js. Run by scripts/vendor-hash.js on ' +
  'every blamejs refresh and gated by its --check (scripts/release.js prepare + CI). ' +
  'Do not hand-edit — re-run the projector. Filtered to bundles whose files.server ' +
  'ships under vendor/blamejs/, carrying only the fields the release SBOM consumes.';

function readJson(absPath) {
  return b.safeJson.parse(fs.readFileSync(absPath, 'utf8'), { maxBytes: b.constants.BYTES.mib(1) });
}

// Stable, recursively key-sorted serialization via the framework primitive,
// so the committed projection and a freshly-built one compare equal
// regardless of object key order. Comparison-only — the serialized form is
// never persisted, so the serializer choice cannot shift any on-disk bytes.
function canonical(value) {
  return b.canonicalJson.stringify(value);
}

// Build the projected transitive-bundle map from blamejs's authoritative
// vendor manifest. Package keys are sorted; each entry carries the
// PROJECTED_FIELDS subset in fixed order. Returns { key: {fields…}, … }.
function buildProjection(repoRoot) {
  const top = readJson(path.join(repoRoot, 'vendor', 'MANIFEST.json'));
  const blame = top && top.packages && top.packages.blamejs;
  if (!blame || typeof blame.transitive_manifest !== 'string') {
    throw new Error('vendor/MANIFEST.json: packages.blamejs.transitive_manifest is missing');
  }
  const transRel = blame.transitive_manifest;
  const trans = readJson(path.join(repoRoot, transRel));
  if (!trans || !trans.packages || typeof trans.packages !== 'object' || Array.isArray(trans.packages)) {
    throw new Error(`${transRel}: missing "packages" map`);
  }

  // Preserve the authoritative manifest's key order so the projected snapshot
  // — and the SBOM built from it — is byte-faithful to reading the live
  // manifest directly. The --check comparison is order-insensitive (canonical()
  // sorts keys), so determinism does not depend on the projection's ordering.
  const out = {};
  for (const key of Object.keys(trans.packages)) {
    if (key.charAt(0) === '_') continue;
    const entry = trans.packages[key];
    if (!entry || typeof entry !== 'object' || typeof entry.version !== 'string') continue;
    // Shipped-surface filter — identical to build-sbom.js: only bundles whose
    // runtime file is actually present under vendor/blamejs/ are part of the
    // SEA's transitive surface.
    if (!entry.files || typeof entry.files.server !== 'string') continue;
    const onDisk = path.join(repoRoot, 'vendor', 'blamejs', entry.files.server);
    if (!fs.existsSync(onDisk)) continue;

    const projected = {};
    for (const field of PROJECTED_FIELDS) {
      if (entry[field] !== undefined) projected[field] = entry[field];
    }
    out[key] = projected;
  }
  return out;
}

// Mutate a parsed parent-manifest object in place, setting
// packages.blamejs.transitive to a fresh projection. Exported so the vendor
// step (scripts/vendor-hash.js) can populate it in the same write that records
// the consumed-file hashes — no second manifest write, no ordering hazard.
function projectInto(manifest, repoRoot) {
  if (!manifest || !manifest.packages || !manifest.packages.blamejs) {
    throw new Error('parent manifest missing packages.blamejs');
  }
  const packages = buildProjection(repoRoot);
  manifest.packages.blamejs.transitive = {
    _note: PROJECTION_NOTE,
    source: manifest.packages.blamejs.transitive_manifest,
    packages,
  };
  return Object.keys(packages).length;
}

function writeProjection(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  const manifestPath = path.join(repoRoot, 'vendor', 'MANIFEST.json');
  const manifest = readJson(manifestPath);
  const count = projectInto(manifest, repoRoot);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  process.stdout.write(
    `vendor/MANIFEST.json: projected ${count} transitive bundle` +
    `${count === 1 ? '' : 's'} from ${path.posix.join('vendor/blamejs', 'lib/vendor/MANIFEST.json')}.\n`
  );
  return 0;
}

function checkProjection(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  const manifest = readJson(path.join(repoRoot, 'vendor', 'MANIFEST.json'));
  const blame = manifest && manifest.packages && manifest.packages.blamejs;
  const committed = blame && blame.transitive && blame.transitive.packages;
  if (!committed || typeof committed !== 'object' || Array.isArray(committed)) {
    process.stderr.write(
      '[project-transitive] vendor/MANIFEST.json has no projected packages.blamejs.transitive block.\n' +
      '  Fix: run `node scripts/project-transitive-manifest.js` (normally done by scripts/vendor-hash.js).\n'
    );
    return 1;
  }
  const fresh = buildProjection(repoRoot);
  if (canonical(committed) === canonical(fresh)) {
    const n = Object.keys(fresh).length;
    process.stdout.write(`[project-transitive] OK — ${n} transitive bundle${n === 1 ? '' : 's'} in sync with the vendored manifest.\n`);
    return 0;
  }

  // Report exactly which bundles drifted so the failure is actionable.
  const committedKeys = new Set(Object.keys(committed));
  const freshKeys = new Set(Object.keys(fresh));
  const lines = [];
  for (const k of [...new Set([...committedKeys, ...freshKeys])].sort()) {
    if (!committedKeys.has(k)) { lines.push(`  + ${k} (added upstream, not yet projected)`); continue; }
    if (!freshKeys.has(k)) { lines.push(`  - ${k} (removed upstream, still in projection)`); continue; }
    if (canonical(committed[k]) !== canonical(fresh[k])) {
      lines.push(`  ~ ${k} (committed ${committed[k].version} vs vendored ${fresh[k].version})`);
    }
  }
  process.stderr.write(
    '[project-transitive] DRIFT — vendor/MANIFEST.json transitive projection is stale ' +
    'relative to vendor/blamejs/lib/vendor/MANIFEST.json:\n' +
    lines.join('\n') + '\n' +
    '  Fix: run `node scripts/project-transitive-manifest.js` and commit vendor/MANIFEST.json.\n'
  );
  return 1;
}

function main(argv) {
  const check = argv.indexOf('--check') !== -1;
  return check ? checkProjection() : writeProjection();
}

if (require.main === module) {
  try {
    process.exit(main(process.argv.slice(2))); // allow:process-exit — release-time CLI utility, sysexits-style status
  } catch (err) {
    process.stderr.write(`[project-transitive] ${err.message}\n`);
    process.exit(1); // allow:process-exit — release-time CLI utility
  }
}

module.exports = { buildProjection, projectInto, canonical, writeProjection, checkProjection, main };
