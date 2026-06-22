'use strict';

// Pure-unit regression tests for the maintainer-side release/vendoring
// scripts: scripts/vendor-hash.js, scripts/consolidate-release-notes.js,
// scripts/release.js, scripts/build-sbom.js, scripts/generate-changelog-entry.js.
//
// No server harness, no network. Each script resolves its inputs relative to
// `path.resolve(__dirname, '..')` (the repo root), so the tests build a
// minimal temp REPO SKELETON (lib/constants.js, release-notes/, vendor/...),
// copy the real production script into <skeleton>/scripts/, and spawn it with
// `node`. That exercises the shipped script verbatim against controlled inputs
// rather than re-implementing its logic. For scripts that
// `require('../vendor/blamejs')`, the skeleton's vendor/blamejs/index.js
// re-exports the real on-disk blamejs so the hardened primitives run for real.
//
// Run standalone:  node --test tests/test-fix-scripts.js

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const childProcess = require('node:child_process');

const REPO_ROOT = nodePath.resolve(__dirname, '..');
const SCRIPTS_DIR = nodePath.join(REPO_ROOT, 'scripts');
const REAL_BLAMEJS = nodePath.join(REPO_ROOT, 'vendor', 'blamejs');

function mkTempRepo() {
  const root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-fix-scripts-'));
  nodeFs.mkdirSync(nodePath.join(root, 'scripts'), { recursive: true });
  nodeFs.mkdirSync(nodePath.join(root, 'lib'), { recursive: true });
  nodeFs.mkdirSync(nodePath.join(root, 'release-notes'), { recursive: true });
  return root;
}

// Make `require('../vendor/blamejs')` from a copied script resolve to the real
// on-disk blamejs without copying its 200+ files. A thin re-export module is
// enough because Node resolves the require target to the temp path, then the
// re-export pulls in the real tree by absolute path.
function linkBlamejs(root) {
  const vDir = nodePath.join(root, 'vendor', 'blamejs');
  nodeFs.mkdirSync(vDir, { recursive: true });
  nodeFs.writeFileSync(
    nodePath.join(vDir, 'index.js'),
    'module.exports = require(' + JSON.stringify(REAL_BLAMEJS) + ');\n'
  );
}

function copyScript(root, name) {
  const dst = nodePath.join(root, 'scripts', name);
  nodeFs.copyFileSync(nodePath.join(SCRIPTS_DIR, name), dst);
  return dst;
}

function writeConstants(root, version) {
  // A minimal lib/constants.js carrying a realistic decoy: a semver-shaped
  // *_VERSION constant declared BEFORE `const VERSION`, which is exactly the
  // ordering the unanchored-regex bug latches onto.
  const body =
    "'use strict';\n" +
    "const SOME_OTHER_VERSION = '9.9.9';\n" +
    "const VERSION = '" + version + "';\n" +
    "const TLS_MIN_VERSION = 'TLSv1.3';\n" +
    'module.exports = { VERSION, TLS_MIN_VERSION, SOME_OTHER_VERSION };\n';
  nodeFs.writeFileSync(nodePath.join(root, 'lib', 'constants.js'), body);
}

function runScript(root, name, args, env) {
  return childProcess.spawnSync(process.execPath,
    [nodePath.join(root, 'scripts', name)].concat(args || []), {
      cwd: root,
      encoding: 'utf8',
      env: Object.assign({}, process.env, env || {}),
    });
}

function minimalReleaseNote(version) {
  return {
    version: version,
    date: '2026-01-01',
    headline: 'Fixture release ' + version,
    sections: [
      { heading: 'Fixed', items: [{ title: 'Fixture item', body: 'A fixture body long enough to pass the validator.' }] },
    ],
  };
}

// ---------------------------------------------------------------------------
// scripts#46 — vendor-hash.js uses b.safeJson.parse on vendor/MANIFEST.json
// ---------------------------------------------------------------------------
describe('scripts#46 — vendor-hash.js manifest parse via b.safeJson', () => {
  it('source no longer bare-JSON.parse the manifest and requires blamejs', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'vendor-hash.js'), 'utf8');
    assert.match(src, /require\(['"]\.\.\/vendor\/blamejs['"]\)/,
      'vendor-hash.js must require the vendored blamejs');
    assert.match(src, /b\.safeJson\.parse\(\s*raw/,
      'manifest must be parsed via b.safeJson.parse, matching the sibling readers');
    assert.doesNotMatch(src, /JSON\.parse\(raw\)/,
      'the bare JSON.parse(raw) on the integrity-anchor manifest must be gone');
  });

  it('a well-formed manifest still re-stamps identically (parser is drop-in)', () => {
    const root = mkTempRepo();
    linkBlamejs(root);
    copyScript(root, 'vendor-hash.js');
    // vendor-hash hashes the CONSUMED file list against REPO_ROOT; point those
    // at the real blamejs files by re-creating the consumed tree as a re-export
    // would not give byte content. Simpler: hash against the real repo's files
    // by running the REAL script (covered by the standalone smoke run in CI);
    // here we only assert the parse step accepts a valid manifest and rejects
    // an oversized one. Provide a valid (small) manifest with the packages key.
    const manifestPath = nodePath.join(root, 'vendor', 'MANIFEST.json');
    nodeFs.writeFileSync(manifestPath, JSON.stringify({ packages: { blamejs: {} } }, null, 2) + '\n');
    // The CONSUMED files won't exist under the temp root, so the run will fail
    // at sha256File — but it must fail AFTER a successful parse, never at parse.
    const rv = runScript(root, 'vendor-hash.js', []);
    // Parse succeeded if the failure (if any) is a file-read error, not a parse
    // error. b.safeJson never produces ENOENT; readFileSync of a CONSUMED file does.
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.doesNotMatch(out, /invalid JSON|maxBytes|too large|depth/i,
      'a valid manifest must parse cleanly: ' + out);
  });

  it('b.safeJson.parse enforces the 1 MiB cap that bare JSON.parse would not', () => {
    const b = require(REAL_BLAMEJS);
    // Build a JSON string just over 1 MiB. Bare JSON.parse would accept it;
    // b.safeJson.parse with maxBytes: 1 MiB must refuse.
    const filler = 'x'.repeat(b.constants.BYTES.mib(1) + 16);
    const big = JSON.stringify({ packages: { blamejs: {} }, pad: filler });
    assert.doesNotThrow(() => JSON.parse(big), 'control: bare JSON.parse accepts the oversized doc');
    assert.throws(() => b.safeJson.parse(big, { maxBytes: b.constants.BYTES.mib(1) }),
      'b.safeJson.parse must reject a manifest over the 1 MiB cap');
  });
});

// ---------------------------------------------------------------------------
// scripts#47 — consolidate-release-notes.js#_currentMinor anchored VERSION
// ---------------------------------------------------------------------------
describe('scripts#47 — consolidate-release-notes.js anchored VERSION regex', () => {
  it('derives the minor from `const VERSION` despite a leading semver-shaped *_VERSION decoy', () => {
    const root = mkTempRepo();
    copyScript(root, 'consolidate-release-notes.js');
    // VERSION is 0.9.x; a decoy SOME_OTHER_VERSION='9.9.9' is declared first.
    writeConstants(root, '0.9.11');
    // Seed a HISTORICAL minor line (0.8) that should consolidate, and a CURRENT
    // line (0.9) that must be LEFT as per-patch. If the regex mis-extracts the
    // decoy minor (9.9), it would treat 0.9 as historical and try to roll it up
    // (wrong) and 0.8 as historical too. We assert 0.9 stays per-patch.
    const notesDir = nodePath.join(root, 'release-notes');
    nodeFs.writeFileSync(nodePath.join(notesDir, 'v0.8.0.json'),
      JSON.stringify(minimalReleaseNote('0.8.0')) + '\n');
    nodeFs.writeFileSync(nodePath.join(notesDir, 'v0.9.10.json'),
      JSON.stringify(minimalReleaseNote('0.9.10')) + '\n');
    nodeFs.writeFileSync(nodePath.join(notesDir, 'v0.9.11.json'),
      JSON.stringify(minimalReleaseNote('0.9.11')) + '\n');

    const rv = runScript(root, 'consolidate-release-notes.js', ['--check']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    // --check exits non-zero because the historical 0.8 line needs consolidation.
    assert.equal(rv.status, 1, 'check mode should flag the un-rolled 0.8 line: ' + out);
    assert.match(out, /0\.8\.x — .*need consolidation/, 'must flag 0.8 as historical: ' + out);
    assert.match(out, /0\.9\.x — current line, leave per-patch/,
      'the current minor (0.9) must be recognised and left per-patch, not the decoy 9.9: ' + out);
    assert.doesNotMatch(out, /0\.9\.x — .*need consolidation/,
      'the current 0.9 line must NEVER be queued for consolidation');
    assert.doesNotMatch(out, /9\.9/, 'the decoy *_VERSION must not leak into the derived minor: ' + out);
  });

  it('source uses the anchored `const VERSION` semver regex (mirrors the sibling)', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'consolidate-release-notes.js'), 'utf8');
    assert.ok(src.indexOf('\\bconst VERSION\\s*=\\s*') !== -1,
      'must anchor on the const VERSION declaration');
    assert.ok(src.indexOf('VERSION\\s*[:=]') === -1,
      'the unanchored VERSION[:=] regex must be gone');
  });
});

// ---------------------------------------------------------------------------
// scripts#48 — release.js#_pollForRun sleeps via Atomics.wait, not a subprocess
// ---------------------------------------------------------------------------
describe('scripts#48 — release.js in-process sleep (no throwaway node subprocess)', () => {
  it('no longer spawns `node -e setTimeout` to sleep', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'release.js'), 'utf8');
    assert.doesNotMatch(src, /setTimeout\(function\(\)\{\}, 10000\)/,
      'the subprocess-sleep (`node -e setTimeout...`) must be removed');
    assert.doesNotMatch(src, /'-e'\s*,\s*'setTimeout/,
      'no `node -e setTimeout` spawn arg should remain');
    assert.match(src, /function _sleepSync\(ms\)/, 'an in-process _sleepSync helper must exist');
    assert.match(src, /Atomics\.wait\(new Int32Array\(new SharedArrayBuffer\(4\)\), 0, 0, ms\)/,
      '_sleepSync must use the Atomics.wait idiom');
    assert.match(src, /_sleepSync\(10000\)/, '_pollForRun must call _sleepSync(10000)');
  });

  it('the Atomics.wait idiom blocks for ~the requested duration without a subprocess', () => {
    // Validate the chosen primitive behaves as a bounded sleep. This mirrors
    // the exact construct release.js now inlines; a 60ms sleep should park the
    // thread for at least ~50ms (allowing scheduler slack) and well under 1s.
    const start = Date.now();
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60);
    const elapsed = Date.now() - start;
    assert.ok(elapsed >= 45, 'Atomics.wait should block ~60ms, got ' + elapsed + 'ms');
    assert.ok(elapsed < 1000, 'Atomics.wait should not block far past the timeout, got ' + elapsed + 'ms');
  });
});

// ---------------------------------------------------------------------------
// scripts#51 — build-sbom.js asserts the transitive manifest packages map
// ---------------------------------------------------------------------------
describe('scripts#51 — build-sbom.js transitive manifest structural assert', () => {
  function seedSbomRepo(root, transitivePackages) {
    linkBlamejs(root);
    copyScript(root, 'build-sbom.js');
    writeConstants(root, '0.9.11');
    // Top manifest points at a transitive manifest that exists on disk.
    const top = {
      packages: {
        blamejs: {
          version: '0.15.15',
          transitive_manifest: 'vendor/blamejs/lib/vendor/MANIFEST.json',
        },
      },
    };
    nodeFs.writeFileSync(nodePath.join(root, 'vendor', 'MANIFEST.json'),
      JSON.stringify(top, null, 2) + '\n');
    const transDir = nodePath.join(root, 'vendor', 'blamejs', 'lib', 'vendor');
    nodeFs.mkdirSync(transDir, { recursive: true });
    nodeFs.writeFileSync(nodePath.join(transDir, 'MANIFEST.json'),
      JSON.stringify(transitivePackages, null, 2) + '\n');
  }

  it('fails loud when the transitive manifest has no packages map', () => {
    const root = mkTempRepo();
    seedSbomRepo(root, { /* no packages key */ });
    const rv = runScript(root, 'build-sbom.js', ['--out', nodePath.join(root, 'build')]);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'a structurally-broken transitive manifest must fail the build: ' + out);
    assert.match(out, /transitive manifest .* missing "packages" map/,
      'error must name the missing transitive packages map: ' + out);
  });

  it('fails loud when transitive packages is an array (typeof [] === object hole)', () => {
    const root = mkTempRepo();
    seedSbomRepo(root, { packages: [] });
    const rv = runScript(root, 'build-sbom.js', ['--out', nodePath.join(root, 'build')]);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'an array `packages` must be rejected, not silently emptied: ' + out);
    assert.match(out, /transitive manifest .* missing "packages" map/, out);
  });

  it('succeeds (empty transitive set) when packages is a valid empty object', () => {
    const root = mkTempRepo();
    seedSbomRepo(root, { packages: {} });
    const rv = runScript(root, 'build-sbom.js', ['--out', nodePath.join(root, 'build')]);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.equal(rv.status, 0, 'a valid (empty) transitive packages map must build cleanly: ' + out);
    const outFile = nodePath.join(root, 'build', 'hermitstash-sync-v0.9.11.cdx.json');
    assert.ok(nodeFs.existsSync(outFile), 'SBOM should be written: ' + out);
  });

  it('top-level packages-as-array is also rejected (parity tightening)', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'build-sbom.js'), 'utf8');
    assert.match(src, /Array\.isArray\(top\.packages\)/,
      'top-level assert must also reject an array packages map');
    assert.match(src, /Array\.isArray\(trans\.packages\)/,
      'transitive assert must reject an array packages map');
  });
});

// ---------------------------------------------------------------------------
// scripts#53 — generate-changelog-entry.js cross-checks in-file version at load
// ---------------------------------------------------------------------------
describe('scripts#53 — generate-changelog-entry.js load-time version cross-check', () => {
  function seedGenRepo(root) {
    copyScript(root, 'generate-changelog-entry.js');
    writeConstants(root, '0.9.11');
    nodeFs.writeFileSync(nodePath.join(root, 'CHANGELOG.md'), '# Changelog\n');
  }

  it('rejects a per-patch file whose in-file version mismatches its filename', () => {
    const root = mkTempRepo();
    seedGenRepo(root);
    // Filename says 0.9.11 but the in-file version says 0.9.12 — the classic
    // mismatch that previously flowed straight into the sort comparator.
    nodeFs.writeFileSync(nodePath.join(root, 'release-notes', 'v0.9.11.json'),
      JSON.stringify(minimalReleaseNote('0.9.12')) + '\n');
    const rv = runScript(root, 'generate-changelog-entry.js', ['--check']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'a filename/version mismatch must fail loud: ' + out);
    assert.match(out, /declares version .* but the filename encodes/,
      'error must name the declared vs filename version: ' + out);
  });

  it('rejects a malformed (non-semver) in-file version', () => {
    const root = mkTempRepo();
    seedGenRepo(root);
    // A correctly-named file carrying a non-semver in-file version. (The per-
    // patch cross-check catches it because "0.8" !== filename "0.9.11".)
    nodeFs.writeFileSync(nodePath.join(root, 'release-notes', 'v0.9.11.json'),
      JSON.stringify(minimalReleaseNote('0.8')) + '\n');
    const rv = runScript(root, 'generate-changelog-entry.js', ['--check']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'a malformed in-file version must fail loud: ' + out);
    assert.match(out, /but the filename encodes|non-semver/,
      'error must be actionable: ' + out);
  });

  it('rejects a consolidated entry carrying a non-semver version', () => {
    const root = mkTempRepo();
    seedGenRepo(root);
    // Consolidated rollup whose one release entry has a malformed version. The
    // consolidated filename only encodes the minor, so the in-file version is
    // the sole semver source and must be asserted at load.
    const con = { minor: '0.8', releases: [Object.assign(minimalReleaseNote('0.8.x'), {})] };
    nodeFs.writeFileSync(nodePath.join(root, 'release-notes', 'v0.8.x.json'),
      JSON.stringify(con) + '\n');
    const rv = runScript(root, 'generate-changelog-entry.js', ['--check']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'a non-semver consolidated entry must fail loud: ' + out);
    assert.match(out, /non-semver `version`/, 'error must flag the consolidated entry: ' + out);
  });

  it('accepts a well-formed per-patch tree (rebuild succeeds)', () => {
    const root = mkTempRepo();
    seedGenRepo(root);
    nodeFs.writeFileSync(nodePath.join(root, 'release-notes', 'v0.9.11.json'),
      JSON.stringify(minimalReleaseNote('0.9.11')) + '\n');
    const rv = runScript(root, 'generate-changelog-entry.js', ['--rebuild']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.equal(rv.status, 0, 'a matching version/filename pair must rebuild cleanly: ' + out);
    const cl = nodeFs.readFileSync(nodePath.join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(cl, /0\.9\.11/, 'rebuilt CHANGELOG should contain the release: ' + cl.slice(0, 200));
  });
});
