#!/usr/bin/env node
'use strict';

// Release-time CycloneDX 1.6 SBOM builder. Reads vendor/MANIFEST.json
// (direct vendored bundle: blamejs) and vendor/blamejs/lib/vendor/
// MANIFEST.json (transitive: noble-ciphers + noble-post-quantum bundled
// inside blamejs) and emits
//
//   build/hermitstash-sync-vX.Y.Z.cdx.json
//
// covering the SEA binary's full vendored surface. Top-level component
// is the hermitstash-sync application; it depends on blamejs; blamejs
// depends on the noble-* sub-components. Downstream tooling
// (Dependency-Track, OWASP Dependency-Check, Snyk SBOM Monitor) walks
// the dependency graph via CPE 2.3 + purl to map CVE advisories
// against every leaf bundle.
//
// Usage:
//   node scripts/build-sbom.js [--out <dir>]
//
// CI: .github/workflows/release.yml runs this alongside build-vex.js;
// output uploads to the GitHub Release via softprops/action-gh-release.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const b = require('../vendor/blamejs');

const REPO_ROOT = nodePath.resolve(__dirname, '..');
const TOP_MANIFEST = nodePath.join(REPO_ROOT, 'vendor', 'MANIFEST.json');

const SPDX_LICENSE_IDS = Object.freeze({
  '0BSD': 1, 'Apache-2.0': 1, 'BSD-2-Clause': 1, 'BSD-3-Clause': 1,
  'CC0-1.0': 1, 'CC-BY-3.0': 1, 'CC-BY-4.0': 1,
  'GPL-2.0-only': 1, 'GPL-2.0-or-later': 1, 'GPL-3.0-only': 1,
  'GPL-3.0-or-later': 1, 'AGPL-3.0-only': 1, 'AGPL-3.0-or-later': 1,
  'ISC': 1, 'MIT': 1, 'MPL-2.0': 1, 'Unlicense': 1, 'Zlib': 1,
});

function parseArgs(argv) {
  const opts = { outDir: nodePath.join(REPO_ROOT, 'build') };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && argv[i + 1]) { opts.outDir = nodePath.resolve(argv[++i]); continue; }
  }
  return opts;
}

function readJson(absPath) {
  const raw = nodeFs.readFileSync(absPath, 'utf8');
  return b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) });
}

function readVersion() {
  return require(nodePath.join(REPO_ROOT, 'lib', 'constants')).VERSION;
}

function licenseBlock(entry) {
  if (!entry || !entry.license) return null;
  if (entry.license_is_spdx === false) return [{ license: { name: entry.license } }];
  if (SPDX_LICENSE_IDS[entry.license]) return [{ license: { id: entry.license } }];
  return [{ license: { name: entry.license } }];
}

// Translate a manifest entry's hash map into CycloneDX integrity data.
// `component.hashes[]` is a set of digests of the SAME artifact under DIFFERENT
// algorithms — so a single-artifact entry (one hash slot) maps cleanly there.
// A vendored DIRECTORY/manifest entry instead carries a per-FILE hash map (many
// slots, all SHA-256 of different files); emitting those as component.hashes
// would assert that one component simultaneously hashes to many contradictory
// SHA-256 values, which breaks hash-keyed SBOM consumers (Dependency-Track,
// Dependency-Check, Snyk). For those, surface each file digest as a namespaced
// property, where multiple values are valid.
function integrityBlocks(entry) {
  const hashes = [];
  const properties = [];
  if (!entry || !entry.hashes) return { hashes, properties };
  const sha256 = (slot) => {
    const m = /^sha256:([a-f0-9]{64})$/i.exec(entry.hashes[slot]);
    return m ? m[1] : null;
  };
  const slots = Object.keys(entry.hashes).filter((s) => typeof entry.hashes[s] === 'string');
  if (slots.length === 1) {
    const h = sha256(slots[0]);
    if (h) hashes.push({ alg: 'SHA-256', content: h });
  } else {
    for (const slot of slots) {
      const h = sha256(slot);
      if (h) properties.push({ name: `hermitstash:fileHash:${slot}`, value: `sha256:${h}` });
    }
  }
  return { hashes, properties };
}

function purlFor(entry, fallbackPkg) {
  if (entry && typeof entry.purl === 'string' && entry.purl.length > 0) return entry.purl;
  if (entry && entry.source && /^https:\/\/github\.com\//.test(entry.source)) {
    const m = /^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/.exec(entry.source);
    if (m && entry.version) return `pkg:github/${m[1].toLowerCase()}/${m[2].toLowerCase()}@${entry.version}`;
  }
  if (fallbackPkg && entry && entry.version) return `pkg:generic/${fallbackPkg}@${entry.version}`;
  return undefined;
}

function buildComponent(key, entry) {
  const c = {
    type:    'library',
    'bom-ref': `${key}@${entry.version}`,
    name:    key,
    version: entry.version,
    scope:   'required',
  };
  const purl = purlFor(entry, key);
  if (purl) c.purl = purl;
  if (entry.author) {
    c.author   = entry.author;
    c.supplier = { name: entry.author };
  }
  if (entry.description) c.description = entry.description;
  const licenses = licenseBlock(entry);
  if (licenses) c.licenses = licenses;
  if (typeof entry.cpe === 'string' && entry.cpe.length > 0) c.cpe = entry.cpe;
  const extRefs = [];
  if (entry.source) extRefs.push({ type: 'vcs', url: entry.source });
  if (extRefs.length) c.externalReferences = extRefs;
  const { hashes, properties: hashProps } = integrityBlocks(entry);
  if (hashes.length) c.hashes = hashes;
  const props = hashProps.slice();
  if (entry.bundledAt) props.push({ name: 'hermitstash:bundledAt', value: entry.bundledAt });
  if (props.length) c.properties = props;
  return c;
}

function githubActionsRunUrl() {
  const server = process.env.GITHUB_SERVER_URL;
  const repo   = process.env.GITHUB_REPOSITORY;
  const runId  = process.env.GITHUB_RUN_ID;
  if (typeof server === 'string' && server.length > 0 &&
      typeof repo === 'string' && repo.length > 0 &&
      typeof runId === 'string' && runId.length > 0) {
    return `${server}/${repo}/actions/runs/${runId}`;
  }
  return null;
}

function build() {
  const version = readVersion();
  const tag = `v${version}`;
  const top = readJson(TOP_MANIFEST);
  if (!top || !top.packages || typeof top.packages !== 'object' || Array.isArray(top.packages)) {
    throw new Error('vendor/MANIFEST.json missing "packages" map');
  }

  const components = [];
  const subDeps = [];

  for (const key of Object.keys(top.packages)) {
    if (key.charAt(0) === '_') continue;
    const entry = top.packages[key];
    if (!entry || typeof entry !== 'object' || typeof entry.version !== 'string') continue;
    const parent = buildComponent(key, entry);
    components.push(parent);

    if (typeof entry.transitive_manifest === 'string') {
      const transPath = nodePath.join(REPO_ROOT, entry.transitive_manifest);
      if (nodeFs.existsSync(transPath)) {
        const trans = readJson(transPath);
        // A transitive manifest present on disk but structurally broken
        // (no `packages` map, or `packages` is null/an array) would
        // otherwise collapse to an empty set and ship an SBOM with zero
        // transitive (noble-*) components — the highest-CVE-value leaves —
        // with no error. Mirror the top-level assert so a half-applied or
        // hand-mangled refresh fails the release loud. A manifest that is
        // simply absent stays a no-op via the existsSync guard above.
        if (!trans || !trans.packages || typeof trans.packages !== 'object' || Array.isArray(trans.packages)) {
          throw new Error(`transitive manifest ${entry.transitive_manifest} missing "packages" map`);
        }
        const transPkgs = trans.packages;
        for (const subKey of Object.keys(transPkgs)) {
          if (subKey.charAt(0) === '_') continue;
          const subEntry = transPkgs[subKey];
          if (!subEntry || typeof subEntry !== 'object' || typeof subEntry.version !== 'string') continue;
          // Only surface transitive bundles whose runtime CJS file is
          // actually present on disk — the upstream manifest lists
          // every blamejs vendor dep, but the SEA only ships the ones
          // present under vendor/blamejs/lib/vendor/. Filter by file
          // existence so the SBOM matches the shipped surface.
          if (!subEntry.files || typeof subEntry.files.server !== 'string') continue;
          const onDisk = nodePath.join(REPO_ROOT, 'vendor', 'blamejs', subEntry.files.server);
          if (!nodeFs.existsSync(onDisk)) continue;
          const sub = buildComponent(subKey, subEntry);
          sub['bom-ref'] = `${key}/${subKey}@${subEntry.version}`;
          components.push(sub);
          subDeps.push({ parentRef: parent['bom-ref'], childRef: sub['bom-ref'] });
        }
      }
    }
  }

  const appRef = `hermitstash-sync@${version}`;
  const appComponent = {
    'bom-ref':   appRef,
    type:        'application',
    name:        'hermitstash-sync',
    version:     version,
    description: 'CLI daemon that syncs a local folder with a HermitStash server over PQC-TLS + mTLS.',
    supplier:    { name: 'dotCooCoo', url: ['https://github.com/dotCooCoo/hermitstash-sync'] },
    purl:        `pkg:github/dotcoocoo/hermitstash-sync@${tag}`,
    licenses:    [{ license: { id: 'AGPL-3.0-or-later' } }],
    externalReferences: [{ type: 'vcs', url: 'https://github.com/dotCooCoo/hermitstash-sync' }],
  };

  const childRefs = Object.create(null);
  for (const d of subDeps) childRefs[d.childRef] = true;
  const topLevelRefs = components.map(c => c['bom-ref']).filter(ref => !childRefs[ref]);

  const dependencies = [{ ref: appRef, dependsOn: topLevelRefs }];
  const byParent = Object.create(null);
  for (const d of subDeps) {
    if (!byParent[d.parentRef]) byParent[d.parentRef] = [];
    byParent[d.parentRef].push(d.childRef);
  }
  for (const p of Object.keys(byParent)) {
    dependencies.push({ ref: p, dependsOn: byParent[p] });
  }

  const buildLifecycle = { phase: 'build' };
  const runUrl = githubActionsRunUrl();
  if (runUrl) buildLifecycle.externalReferences = [{ type: 'build-meta', url: runUrl }];

  const doc = {
    $schema:      'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat:    'CycloneDX',
    specVersion:  '1.6',
    serialNumber: `urn:uuid:${nodeCrypto.randomUUID()}`,
    version:      1,
    metadata: {
      timestamp:  new Date().toISOString(),
      lifecycles: [buildLifecycle],
      supplier:   { name: 'dotCooCoo', url: ['https://github.com/dotCooCoo/hermitstash-sync'] },
      tools: [{ vendor: 'dotCooCoo', name: 'build-sbom.js', version: version }],
      component:  appComponent,
    },
    components:   components,
    dependencies: dependencies,
  };

  return { doc, version, tag };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const { doc, tag } = build();
  nodeFs.mkdirSync(args.outDir, { recursive: true });
  const outPath = nodePath.join(args.outDir, `hermitstash-sync-${tag}.cdx.json`);
  nodeFs.writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n', { mode: 0o644 });
  process.stderr.write(
    `[build-sbom] Wrote ${nodePath.relative(REPO_ROOT, outPath)} ` +
    `(${doc.components.length} component${doc.components.length === 1 ? '' : 's'}).\n`
  );
  return 0;
}

if (require.main === module) {
  try {
    process.exit(main()); // allow:process-exit — release-time CLI utility, sysexits-style status to the workflow runner
  } catch (err) {
    process.stderr.write(`[build-sbom] ${err.message}\n`);
    process.exit(1); // allow:process-exit — release-time CLI utility
  }
}

module.exports = { build, main };
