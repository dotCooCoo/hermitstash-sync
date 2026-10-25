'use strict';

// Tests for scripts/check-doc-versions.js — the drift gate that keeps the
// hand-typed version references in the operator-facing docs (the vendored
// blamejs version and the Node floor) in lockstep with their source of truth
// (vendor/MANIFEST.json + package.json engines), so a vendor bump can't leave a
// stale version stranded in the README.
//
// Four concerns:
//   1. The real repo's docs are in sync (CI's --check would pass now).
//   2. A stale blamejs version is caught, and --fix corrects exactly the
//      anchored token (not a deliberate, unrelated version on the same line —
//      e.g. the server's "blamejs v0.8.43+" floor).
//   3. The Node-floor reference is checked too.
//   4. The anchor-rot guard fails closed if the prose is reworded so a rule
//      matches nothing — exercised against synthetic temp repos so the real
//      working tree is never mutated.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const doc = require('../scripts/check-doc-versions');

const REPO_ROOT = path.resolve(__dirname, '..');

// Build a minimal synthetic repo: vendor/MANIFEST.json (blamejs version),
// package.json (engines.node), and a README with version prose.
function makeRepo(label, blamejsVersion, nodeFloor, readme) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `hs-docver-${label}-`));
  fs.mkdirSync(path.join(root, 'vendor'), { recursive: true });
  fs.writeFileSync(
    path.join(root, 'vendor', 'MANIFEST.json'),
    JSON.stringify({ packages: { blamejs: { version: blamejsVersion } } }, null, 2) + '\n'
  );
  fs.writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name: 'x', version: '0.0.0', engines: { node: '>=' + nodeFloor } }, null, 2) + '\n'
  );
  fs.writeFileSync(path.join(root, 'README.md'), readme);
  return root;
}

// A README that exercises every rule, plus a deliberate server floor on the
// same line as the client version (must NOT be touched).
function readme(clientVer, nodeFloor) {
  return [
    `- Node.js ${nodeFloor}+ (the runtime floor).`,
    `- v1.9.19 ships blamejs v0.8.43+ which emits envelopes; this client (on blamejs v${clientVer}) requires that posture.`,
    '- The encrypted routes work with a server built on blamejs v0.14.0 or later.',
    '',
  ].join('\n');
}

describe('check-doc-versions — sources of truth', () => {
  it('reads the blamejs version and the Node floor', () => {
    const root = makeRepo('src', '0.15.20', '24.16.0', readme('0.15.20', '24.16.0'));
    const s = doc.sourcesOfTruth(root);
    assert.equal(s.blamejsVersion, '0.15.20');
    assert.equal(s.nodeFloor, '24.16.0');
  });
});

describe('check-doc-versions — drift detection + fix', () => {
  it('passes when the docs match', () => {
    const root = makeRepo('ok', '0.15.20', '24.16.0', readme('0.15.20', '24.16.0'));
    assert.equal(doc.checkDocs(root), 0);
  });

  it('catches a stale blamejs version and --fix corrects only the anchored token', () => {
    const root = makeRepo('drift', '0.15.20', '24.16.0', readme('0.15.19', '24.16.0'));
    assert.equal(doc.checkDocs(root), 1, 'a stale client version must fail the gate');
    const fixed = doc.fixDocs(root);
    assert.equal(fixed, 1, 'exactly one token rewritten');
    assert.equal(doc.checkDocs(root), 0, 'fix brings the docs back in sync');
    const text = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
    assert.ok(text.includes('on blamejs v0.15.20)'), 'client version updated');
    assert.ok(text.includes('blamejs v0.8.43+'), 'the deliberate server floor must NOT be touched');
  });

  it('catches a stale Node floor and leaves a server version floor alone', () => {
    const stale = makeRepo('node', '0.16.0', '26.0.0', readme('0.16.0', '24.16.0'));
    assert.equal(doc.checkDocs(stale), 1, 'a stale node floor must fail');
    doc.fixDocs(stale);
    assert.equal(doc.checkDocs(stale), 0);
    const text = fs.readFileSync(path.join(stale, 'README.md'), 'utf8');
    assert.ok(text.includes('Node.js 26.0.0+'), 'node floor updated');
    assert.ok(text.includes('blamejs v0.14.0 or later'), 'the server version floor must NOT be touched');
  });

  it('anchor-rot guard: fails closed if a reference is reworded away', () => {
    // README with no "(on blamejs vX.Y.Z)" anchor at all.
    const root = makeRepo('rot', '0.15.20', '24.16.0',
      '- Node.js 24.16.0+ floor.\n- A server built on blamejs v0.15.0 or later.\n');
    assert.equal(doc.checkDocs(root), 1, 'a vanished anchor must fail the gate, not silently pass');
  });

  it('anchor-rot guard: fails closed when the Node-floor reference is reworded away', () => {
    const root = makeRepo('rot-node', '0.15.20', '24.16.0',
      '- Requires Node.js 24.16.0 or newer.\n- this client (on blamejs v0.15.20) requires that posture.\n');
    assert.equal(doc.checkDocs(root), 1, 'a vanished Node-floor anchor must fail the gate, not silently pass');
  });
});

describe('check-doc-versions — real repo is in sync', () => {
  it('checkDocs(REPO_ROOT) passes (CI gate would pass now)', () => {
    assert.equal(doc.checkDocs(REPO_ROOT), 0,
      'operator-facing docs are stale — run `node scripts/check-doc-versions.js --fix`');
  });
});
