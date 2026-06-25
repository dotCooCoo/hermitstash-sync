'use strict';

// Tests for scripts/project-transitive-manifest.js — the mechanical
// projection of blamejs's own authoritative transitive manifest into the
// parent vendor/MANIFEST.json, and the --check drift gate that keeps the
// release SBOM's transitive surface from silently going stale.
//
// Three concerns:
//   1. The projection is a faithful, SBOM-material subset of the
//      authoritative manifest, filtered to the bundles whose runtime file
//      actually ships — identical to build-sbom.js's filter — and excludes
//      volatile fields (refreshedAt, _about, …) so a pure-timestamp refresh
//      is a no-op.
//   2. The committed projection in the real repo is in sync (i.e. CI's
//      --check would pass right now), and the gate FAILS on a drifted or
//      missing projection — exercised against synthetic temp repos so the
//      real working tree is never mutated.
//   3. The release SBOM built from the projection carries the same
//      transitive components it would from the live manifest.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const projector = require('../scripts/project-transitive-manifest');
const sbom = require('../scripts/build-sbom');

const REPO_ROOT = path.resolve(__dirname, '..');

// Fields the projection is allowed to carry — anything else is excluded.
const ALLOWED = new Set([
  'version', 'license', 'license_is_spdx', 'author',
  'source', 'cpe', 'description', 'files', 'hashes', 'bundledAt',
]);

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// Build a minimal synthetic repo: a parent vendor/MANIFEST.json pointing at a
// blamejs transitive manifest, with the referenced runtime files on disk so
// the shipped-surface filter keeps them.
function makeSyntheticRepo(label, transitivePackages, onDiskServers) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `hs-proj-${label}-`));
  const transDir = path.join(root, 'vendor', 'blamejs', 'lib', 'vendor');
  fs.mkdirSync(transDir, { recursive: true });
  for (const rel of onDiskServers) {
    const abs = path.join(root, 'vendor', 'blamejs', rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '// stub\n');
  }
  fs.writeFileSync(
    path.join(transDir, 'MANIFEST.json'),
    JSON.stringify({ packages: transitivePackages }, null, 2) + '\n'
  );
  fs.writeFileSync(
    path.join(root, 'vendor', 'MANIFEST.json'),
    JSON.stringify({
      packages: {
        blamejs: {
          version: '0.0.0-test',
          transitive_manifest: 'vendor/blamejs/lib/vendor/MANIFEST.json',
        },
      },
    }, null, 2) + '\n'
  );
  return root;
}

const TEST_PKGS = {
  '@test/shipped': {
    version: '1.2.3',
    license: 'MIT',
    author: 'Test Author',
    source: 'https://github.com/test/shipped',
    cpe: 'cpe:2.3:a:test:shipped:1.2.3:*:*:*:*:node.js:*:*',
    files: { server: 'lib/vendor/shipped.cjs' },
    hashes: { server: 'sha256:' + 'a'.repeat(64) },
    bundledAt: '2026-01-01T00:00:00Z',
    // Volatile / non-SBOM fields that must NOT be projected:
    refreshedAt: '2026-06-22T16:29:46.590Z',
    _about: 'lots of prose',
    bundler: 'esbuild',
    exports: ['x', 'y'],
  },
  '@test/not-shipped': {
    version: '9.9.9',
    license: 'MIT',
    files: { server: 'lib/vendor/absent.cjs' },
    hashes: { server: 'sha256:' + 'b'.repeat(64) },
  },
};

describe('project-transitive-manifest — buildProjection', () => {
  it('filters to shipped bundles and carries only SBOM-material fields', () => {
    const root = makeSyntheticRepo('build', TEST_PKGS, ['lib/vendor/shipped.cjs']);
    const proj = projector.buildProjection(root);

    assert.deepEqual(Object.keys(proj), ['@test/shipped'],
      'a bundle whose files.server is absent on disk must be filtered out');
    const e = proj['@test/shipped'];
    assert.equal(e.version, '1.2.3');
    assert.equal(e.cpe, 'cpe:2.3:a:test:shipped:1.2.3:*:*:*:*:node.js:*:*');
    assert.deepEqual(e.hashes, { server: 'sha256:' + 'a'.repeat(64) });
    for (const k of Object.keys(e)) {
      assert.ok(ALLOWED.has(k), `projected field "${k}" is not SBOM-material and must be excluded`);
    }
    assert.equal(e.refreshedAt, undefined, 'volatile refreshedAt must not be projected');
    assert.equal(e._about, undefined, '_about prose must not be projected');
  });

  it('against the real repo projects exactly the shipped transitive surface', () => {
    const proj = projector.buildProjection(REPO_ROOT);
    const keys = Object.keys(proj);
    assert.ok(keys.length >= 5, `expected the real shipped transitive set, got ${keys.length}`);
    // The two bundles this client directly consumes must be present.
    assert.ok(keys.includes('@noble/ciphers'), 'noble-ciphers must be projected');
    assert.ok(keys.includes('@noble/post-quantum'), 'noble-post-quantum must be projected');
    for (const k of keys) {
      assert.equal(typeof proj[k].version, 'string', `${k} must carry a version`);
      assert.equal(typeof proj[k].files.server, 'string', `${k} must carry files.server`);
    }
  });
});

describe('project-transitive-manifest — write + --check round trip', () => {
  it('write then check is in sync; a version drift is caught', () => {
    const root = makeSyntheticRepo('rt', TEST_PKGS, ['lib/vendor/shipped.cjs']);
    assert.equal(projector.writeProjection(root), 0);
    assert.equal(projector.checkProjection(root), 0, 'a freshly written projection must pass --check');

    // Drift the committed projection's version away from the authoritative one.
    const manifestPath = path.join(root, 'vendor', 'MANIFEST.json');
    const m = readJson(manifestPath);
    m.packages.blamejs.transitive.packages['@test/shipped'].version = '0.0.0-drifted';
    fs.writeFileSync(manifestPath, JSON.stringify(m, null, 2) + '\n');
    assert.equal(projector.checkProjection(root), 1, 'a drifted version must fail --check');
  });

  it('an upstream bundle missing from the projection is caught', () => {
    const root = makeSyntheticRepo('add', TEST_PKGS, ['lib/vendor/shipped.cjs']);
    assert.equal(projector.writeProjection(root), 0);
    // Authoritative now ships a second bundle the committed projection lacks.
    const transPath = path.join(root, 'vendor', 'blamejs', 'lib', 'vendor', 'MANIFEST.json');
    fs.writeFileSync(path.join(root, 'vendor', 'blamejs', 'lib', 'vendor', 'second.cjs'), '// stub\n');
    const t = readJson(transPath);
    t.packages['@test/second'] = {
      version: '2.0.0', license: 'MIT',
      files: { server: 'lib/vendor/second.cjs' },
      hashes: { server: 'sha256:' + 'c'.repeat(64) },
    };
    fs.writeFileSync(transPath, JSON.stringify(t, null, 2) + '\n');
    assert.equal(projector.checkProjection(root), 1, 'a newly-shipped upstream bundle must fail --check until re-projected');
  });

  it('a manifest with no projected transitive block fails closed', () => {
    const root = makeSyntheticRepo('none', TEST_PKGS, ['lib/vendor/shipped.cjs']);
    // No writeProjection() — the parent manifest has no transitive block.
    assert.equal(projector.checkProjection(root), 1, 'absent projection must fail --check');
  });
});

describe('project-transitive-manifest — real repo is in sync', () => {
  it('checkProjection(REPO_ROOT) passes (CI gate would pass now)', () => {
    assert.equal(projector.checkProjection(REPO_ROOT), 0,
      'vendor/MANIFEST.json transitive projection is stale — run `node scripts/project-transitive-manifest.js`');
  });

  it('the committed projection matches a fresh build', () => {
    const committed = readJson(path.join(REPO_ROOT, 'vendor', 'MANIFEST.json'))
      .packages.blamejs.transitive.packages;
    const fresh = projector.buildProjection(REPO_ROOT);
    assert.equal(projector.canonical(committed), projector.canonical(fresh));
  });
});

describe('project-transitive-manifest — SBOM consumes the projection', () => {
  it('the release SBOM carries every projected transitive bundle and nested package as a component', () => {
    const { doc } = sbom.build();
    const proj = projector.buildProjection(REPO_ROOT);
    const refs = new Set(doc.components.map(c => c['bom-ref']));

    let nestedCount = 0;
    for (const key of Object.keys(proj)) {
      const ref = `blamejs/${key}@${proj[key].version}`;
      assert.ok(refs.has(ref), `SBOM is missing transitive component ${ref}`);
      // A meta-bundle's nested packages (e.g. peculiar-pki -> @peculiar/x509,
      // pkijs) must each be enumerated so a CVE scanner can key on their own
      // version, not just the aggregate bundle.
      const components = proj[key].components;
      if (components && typeof components === 'object') {
        for (const nestedKey of Object.keys(components)) {
          nestedCount++;
          const nestedRef = `blamejs/${key}/${nestedKey}@${components[nestedKey].version}`;
          assert.ok(refs.has(nestedRef), `SBOM is missing nested component ${nestedRef}`);
          const nestedComp = doc.components.find(c => c['bom-ref'] === nestedRef);
          assert.equal(nestedComp.version, components[nestedKey].version);
          // A dependency edge bundle -> nested package must exist.
          const edge = doc.dependencies.find(e => e.ref === ref);
          assert.ok(edge && edge.dependsOn.includes(nestedRef),
            `SBOM is missing the dependency edge ${ref} -> ${nestedRef}`);
        }
      }
    }
    // blamejs itself + every shipped transitive bundle + every nested package.
    assert.equal(doc.components.length, 1 + Object.keys(proj).length + nestedCount);
  });

  it('enumerates the peculiar-pki nested packages with their own purls', () => {
    const { doc } = sbom.build();
    const x509 = doc.components.find(c => c.name === '@peculiar/x509');
    const pkijs = doc.components.find(c => c.name === 'pkijs');
    assert.ok(x509, '@peculiar/x509 must be a distinct SBOM component');
    assert.ok(pkijs, 'pkijs must be a distinct SBOM component');
    assert.match(x509.purl, /^pkg:github\/peculiarventures\/x509@/);
    assert.match(pkijs.purl, /^pkg:github\/peculiarventures\/pki\.js@/);
  });
});
