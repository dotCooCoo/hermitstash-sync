'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

/**
 * Vendored-dependency integrity guards that the boot gate cannot enforce.
 *
 * bin/hermitstash-sync.js hashes the WORKING-TREE bytes of each consumed
 * vendored file against vendor/MANIFEST.json and refuses to start on a
 * mismatch. That gate is line-ending blind: on a checkout whose working tree
 * carries Windows CRLF, scripts/vendor-hash.js records CRLF-based hashes, the
 * boot gate then sees matching CRLF bytes and passes — while git stores the
 * file with LF (.gitattributes `vendor/blamejs/** text eol=lf`). The committed
 * bytes a fresh clone or CI checks out are LF, so they do NOT match the
 * recorded CRLF hashes, and a from-source start fails the boot gate. Prebuilt
 * binaries skip the gate, so the break ships invisibly.
 *
 * Two invariants close that gap:
 *   1. No consumed file carries a CR byte — the working tree must be LF, so the
 *      hashes vendor-hash records are the LF hashes git also stores.
 *   2. The git-index (committed) bytes hash to exactly what MANIFEST records —
 *      the definitive "what a fresh clone sees" check. Skipped only where git
 *      is unavailable (the CR-byte + working-tree checks still run).
 *
 * Self-contained (no server): run directly with
 *   node --test tests/test-vendor-integrity.js
 */

const REPO_ROOT = nodePath.resolve(__dirname, '..');
const MANIFEST = require('../vendor/MANIFEST.json');

function sha256(buf) {
  return 'sha256:' + nodeCrypto.createHash('sha256').update(buf).digest('hex');
}

// Mirror the boot gate: iterate every package that declares files + hashes.
function consumedEntries() {
  const out = [];
  const pkgs = (MANIFEST && MANIFEST.packages) || {};
  for (const [pkgName, pkg] of Object.entries(pkgs)) {
    if (!pkg || !pkg.files || !pkg.hashes) continue;
    for (const [kind, rel] of Object.entries(pkg.files)) {
      out.push({ pkgName, kind, rel, expected: pkg.hashes[kind] });
    }
  }
  return out;
}

let gitAvailable = true;
function gitIndexBytes(rel) {
  // `git show :<path>` yields the staged/committed blob — the bytes a fresh
  // clone checks out (LF, after .gitattributes normalization).
  return execFileSync('git', ['show', ':' + rel.split(nodePath.sep).join('/')], {
    cwd: REPO_ROOT,
    maxBuffer: 64 * 1024 * 1024,
  });
}

describe('vendored dependency integrity', () => {
  const entries = consumedEntries();

  it('declares at least the blamejs consumed surface', () => {
    assert.ok(entries.length >= 15, `expected the consumed-file set to be populated, got ${entries.length}`);
  });

  it('records a sha256 hash for every declared consumed file', () => {
    for (const e of entries) {
      assert.match(e.expected || '', /^sha256:[0-9a-f]{64}$/, `${e.pkgName}/${e.kind} (${e.rel}) has no sha256 hash in MANIFEST`);
    }
  });

  it('no consumed file carries a CR byte (working tree must be LF)', () => {
    const offenders = [];
    for (const e of entries) {
      const buf = nodeFs.readFileSync(nodePath.join(REPO_ROOT, e.rel));
      if (buf.includes(0x0d)) offenders.push(e.rel);
    }
    assert.deepEqual(
      offenders,
      [],
      'CRLF in a consumed vendored file. Re-vendor with LF (clone with `git -c core.autocrlf=false`) ' +
        'and re-run `node scripts/vendor-hash.js` so the recorded hashes match the committed LF bytes:\n  ' +
        offenders.join('\n  ')
    );
  });

  it('working-tree bytes hash to the recorded MANIFEST value', () => {
    for (const e of entries) {
      const buf = nodeFs.readFileSync(nodePath.join(REPO_ROOT, e.rel));
      assert.equal(sha256(buf), e.expected, `${e.rel} working-tree hash != MANIFEST (run \`node scripts/vendor-hash.js\`)`);
    }
  });

  it('committed (git-index) bytes hash to the recorded MANIFEST value', () => {
    let checked = 0;
    for (const e of entries) {
      let idx;
      try {
        idx = gitIndexBytes(e.rel);
      } catch (_err) {
        gitAvailable = false;
        break; // git missing / not a work tree / file not staged — skip the whole index pass
      }
      assert.equal(
        sha256(idx),
        e.expected,
        `${e.rel} committed bytes != MANIFEST — a fresh clone would fail the boot gate. ` +
          'Re-run `node scripts/vendor-hash.js` on an LF working tree and commit.'
      );
      checked++;
    }
    if (!gitAvailable) {
      // Not a failure: the working-tree + CR-byte guards above still hold.
      assert.ok(true, 'git unavailable — skipped the committed-bytes cross-check');
    } else {
      assert.ok(checked === consumedEntries().length, 'expected every consumed file to be cross-checked against the git index');
    }
  });
});
