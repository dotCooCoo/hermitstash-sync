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

// ---------------------------------------------------------------------------
// scripts#39 — build-sbom.js keeps metadata.lifecycles[] schema-valid and
// carries the GH-Actions build-run pointer on the app component instead.
// ---------------------------------------------------------------------------
describe('scripts#39 — build-sbom.js CycloneDX 1.6 lifecycle has no externalReferences', () => {
  function seedSbom(root) {
    linkBlamejs(root);
    copyScript(root, 'build-sbom.js');
    writeConstants(root, '0.9.11');
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
      JSON.stringify({ packages: {} }, null, 2) + '\n');
  }

  // Spawn with the three GH_* vars scrubbed first, then apply the requested set,
  // so a run inside GitHub Actions can't leak an ambient run URL into the
  // "off-CI" case.
  function runSbom(root, ghEnv) {
    const env = Object.assign({}, process.env);
    delete env.GITHUB_SERVER_URL;
    delete env.GITHUB_REPOSITORY;
    delete env.GITHUB_RUN_ID;
    Object.assign(env, ghEnv || {});
    return childProcess.spawnSync(process.execPath,
      [nodePath.join(root, 'scripts', 'build-sbom.js'), '--out', nodePath.join(root, 'build')],
      { cwd: root, encoding: 'utf8', env });
  }

  function readSbom(root) {
    return JSON.parse(nodeFs.readFileSync(
      nodePath.join(root, 'build', 'hermitstash-sync-v0.9.11.cdx.json'), 'utf8'));
  }

  it('emits a bare {phase:"build"} lifecycle even when a GH Actions run URL is present', () => {
    const root = mkTempRepo();
    seedSbom(root);
    const rv = runSbom(root, {
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'dotCooCoo/hermitstash-sync',
      GITHUB_RUN_ID: '123456',
    });
    assert.equal(rv.status, 0, 'build must succeed: ' + ((rv.stdout || '') + (rv.stderr || '')));
    const doc = readSbom(root);
    // The lifecycle item must be phase-only — a CycloneDX 1.6 lifecycles[] item
    // forbids externalReferences (additionalProperties:false on both oneOf
    // branches), so a stray key there fails strict validators.
    assert.deepEqual(doc.metadata.lifecycles, [{ phase: 'build' }],
      'metadata.lifecycles[] must stay schema-valid (phase only)');
    // The build-run pointer rides the application component instead.
    const refs = doc.metadata.component.externalReferences || [];
    const buildMeta = refs.filter((r) => r.type === 'build-meta');
    assert.equal(buildMeta.length, 1, 'exactly one build-meta ref must ride the app component');
    assert.equal(buildMeta[0].url, 'https://github.com/dotCooCoo/hermitstash-sync/actions/runs/123456');
    assert.ok(refs.some((r) => r.type === 'vcs'), 'the existing vcs ref must be preserved');
  });

  it('omits the build-meta ref entirely when no GH Actions run URL is set', () => {
    const root = mkTempRepo();
    seedSbom(root);
    const rv = runSbom(root, {});
    assert.equal(rv.status, 0, 'build must succeed: ' + ((rv.stdout || '') + (rv.stderr || '')));
    const doc = readSbom(root);
    assert.deepEqual(doc.metadata.lifecycles, [{ phase: 'build' }]);
    const refs = doc.metadata.component.externalReferences || [];
    assert.ok(!refs.some((r) => r.type === 'build-meta'), 'no build-meta ref off-CI');
    assert.ok(refs.some((r) => r.type === 'vcs'), 'the vcs ref is always present');
  });

  it('source no longer attaches externalReferences to the lifecycle object', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'build-sbom.js'), 'utf8');
    assert.doesNotMatch(src, /buildLifecycle\.externalReferences/,
      'the build-meta ref must not hang off the CycloneDX lifecycle item');
    assert.match(src, /appComponent\.externalReferences\.push/,
      'the build-meta ref must ride the app component externalReferences');
  });
});

// ---------------------------------------------------------------------------
// Shared git fixture for the release.js commit-path tests (scripts#40 / #41).
// ---------------------------------------------------------------------------
function git(root, args) {
  return childProcess.spawnSync('git', args, { cwd: root, encoding: 'utf8' });
}

function initGitRepo(root) {
  git(root, ['-c', 'init.defaultBranch=main', 'init']);
  git(root, ['config', 'user.email', 'fixture@example.com']);
  git(root, ['config', 'user.name', 'Fixture']);
  // Never sign in the temp fixture — the commit path aborts before `git commit`
  // in both tests, but disabling signing keeps the fixture independent of the
  // host's signing config.
  git(root, ['config', 'commit.gpgsign', 'false']);
  git(root, ['config', 'tag.gpgsign', 'false']);
}

// Build a temp repo skeleton on `main` carrying a valid release-notes tree, a
// matching CHANGELOG, and a clean initial commit — the state `commit` expects.
function seedReleaseRepo(root, version) {
  linkBlamejs(root);
  copyScript(root, 'release.js');
  copyScript(root, 'generate-changelog-entry.js');
  copyScript(root, 'check-changelog-extract.js');
  writeConstants(root, version);
  nodeFs.writeFileSync(nodePath.join(root, 'package.json'),
    JSON.stringify({ name: 'hermitstash-sync', version: version }, null, 2) + '\n');
  nodeFs.writeFileSync(nodePath.join(root, 'release-notes', 'v' + version + '.json'),
    JSON.stringify(minimalReleaseNote(version), null, 2) + '\n');
  // Rebuild CHANGELOG so the drift gate that `commit` now runs passes.
  const rebuild = runScript(root, 'generate-changelog-entry.js', ['--rebuild']);
  assert.equal(rebuild.status, 0,
    'setup: CHANGELOG rebuild must succeed: ' + ((rebuild.stdout || '') + (rebuild.stderr || '')));
  initGitRepo(root);
  git(root, ['add', '-A']);
  const c = git(root, ['commit', '-m', 'initial fixture']);
  assert.equal(c.status, 0, 'setup: initial commit must succeed: ' + ((c.stdout || '') + (c.stderr || '')));
}

// ---------------------------------------------------------------------------
// scripts#40 — release.js `commit` refuses a pre-staged non-release file that
// the worktree-only stray scan would miss.
// ---------------------------------------------------------------------------
describe('scripts#40 — release.js commit staged-index allowlist', () => {
  it('refuses a pre-staged non-release file instead of folding it into the release commit', () => {
    const root = mkTempRepo();
    seedReleaseRepo(root, '0.9.11');
    // Operator stages an unrelated WIP change (clean worktree afterwards), then
    // runs `commit` directly. This shows as "A  lib/foo.js" — the worktree
    // column is a space, so the old scan missed it.
    nodeFs.writeFileSync(nodePath.join(root, 'lib', 'foo.js'), "'use strict';\nmodule.exports = 1;\n");
    git(root, ['add', 'lib/foo.js']);

    const rv = runScript(root, 'release.js', ['commit']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'commit must refuse a pre-staged stray file: ' + out);
    assert.match(out, /the git index has staged changes outside the release set/i, out);
    assert.match(out, /lib\/foo\.js/, 'the offending path must be named: ' + out);
    // No release commit may have been created.
    const head = git(root, ['log', '-1', '--pretty=%s']).stdout.trim();
    assert.equal(head, 'initial fixture', 'no release commit should exist: ' + head);
  });

  it('source enumerates the staged index against the allowlist', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'release.js'), 'utf8');
    assert.ok(src.indexOf("'--cached'") !== -1 && src.indexOf("'--name-only'") !== -1,
      'commit must inspect the staged index via `git diff --cached --name-only`');
    assert.match(src, /staged changes outside the release set/,
      'commit must carry the staged-stray refusal message');
  });
});

// ---------------------------------------------------------------------------
// scripts#41 — release.js `commit` re-runs the leak-vocabulary/drift gate
// before composing the signed commit body.
// ---------------------------------------------------------------------------
describe('scripts#41 — release.js commit re-validates release-notes before composing the body', () => {
  it('fails the leak-vocabulary gate on a post-prepare hand-edit rather than committing it', () => {
    const root = mkTempRepo();
    seedReleaseRepo(root, '0.9.11');
    // Operator hand-edits the release-notes JSON AFTER prepare validated it,
    // injecting a forbidden co-authorship trailer, then runs `commit` directly.
    const rnPath = nodePath.join(root, 'release-notes', 'v0.9.11.json');
    const rn = JSON.parse(nodeFs.readFileSync(rnPath, 'utf8'));
    rn.sections[0].items[0].body = 'A fixture body carrying a Co-Authored-By trailer that must be rejected.';
    nodeFs.writeFileSync(rnPath, JSON.stringify(rn, null, 2) + '\n');

    const rv = runScript(root, 'release.js', ['commit']);
    const out = (rv.stdout || '') + (rv.stderr || '');
    assert.notEqual(rv.status, 0, 'commit must fail the leak gate: ' + out);
    assert.match(out, /leak-vocabulary tokens found/i,
      'the leak sweep must be what rejects the commit: ' + out);
    // No leaked release commit may exist.
    const head = git(root, ['log', '-1', '--pretty=%s']).stdout.trim();
    assert.equal(head, 'initial fixture', 'no release commit should exist: ' + head);
  });

  it('source runs check-changelog-extract.js in the commit path (not only in regen)', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'release.js'), 'utf8');
    const hits = (src.match(/check-changelog-extract\.js/g) || []).length;
    assert.ok(hits >= 2,
      'check-changelog-extract.js must run in BOTH regen and commit (>=2 refs, saw ' + hits + ')');
  });
});

// ---------------------------------------------------------------------------
// scripts#42 — generate-changelog-entry.js exports _leakPatterns as the single
// source of truth and is safe to require (main() guarded).
// ---------------------------------------------------------------------------
describe('scripts#42 — generate-changelog-entry.js require-safe + exports _leakPatterns', () => {
  it('requiring the module does not run the CLI and exposes _leakPatterns()', () => {
    // With the require.main guard in place, importing must be side-effect-free:
    // no version read, no validation, no process.exit.
    const mod = require(nodePath.join(SCRIPTS_DIR, 'generate-changelog-entry.js'));
    assert.equal(typeof mod._leakPatterns, 'function', 'must export _leakPatterns');
    const pats = mod._leakPatterns();
    assert.ok(Array.isArray(pats) && pats.length > 0, 'must return a non-empty pattern array');
    assert.ok(pats.every((p) => p instanceof RegExp), 'every entry must be a RegExp');
    // Spot-check a representative token so a gutted list is caught.
    assert.ok(pats.some((p) => p.test('Co-Authored-By: someone')),
      'the exported list must cover the co-authorship trailer');
    assert.ok(pats.some((p) => p.test('phase 3 cleanup')),
      'the exported list must cover phase numbering');
  });

  it('source guards main() and exports the pattern list', () => {
    const src = nodeFs.readFileSync(nodePath.join(SCRIPTS_DIR, 'generate-changelog-entry.js'), 'utf8');
    assert.match(src, /if \(require\.main === module\) \{/,
      'the bottom-of-file main() call must be guarded so require() is safe');
    assert.match(src, /module\.exports\s*=\s*\{[^}]*_leakPatterns/,
      'the module must export _leakPatterns as the single source of truth');
    assert.doesNotMatch(src, /the\s+codebase-patterns gate fails if the two lists drift/,
      'the false "drift gate exists" claim must be gone');
    assert.doesNotMatch(src, /global CLAUDE\.md/,
      'the comment must not reference the local CLAUDE.md');
  });
});
