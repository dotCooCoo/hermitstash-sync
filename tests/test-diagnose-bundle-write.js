'use strict';

// Unit coverage for the diagnose bundle writer's on-disk hardening.
//
// buildBundle(outPath) writes a redacted diagnostics .zip to an
// operator-influenced path (cwd default or --out). The bytes carry cert
// CN/serial/fingerprint/SPKI-pin and redacted config, so the project
// 0600-protects them. The write must:
//   1. enforce 0600 even when a file already exists at outPath (a bare
//      fs.writeFileSync leaves an existing file's mode untouched), and
//   2. refuse a symlink pre-planted at outPath rather than following it to
//      the link target (CWE-59 arbitrary write).
// Both come from routing through b.atomicFile.writeSync (O_EXCL|O_NOFOLLOW
// staging + atomic rename) instead of a raw fs.writeFileSync.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// CONFIG_DIR is resolved from HERMITSTASH_SYNC_CONFIG_DIR at module-load
// time, so point it at an empty temp dir BEFORE requiring lib/diagnose. The
// bundle then has no config/db/log to collect — irrelevant here, since the
// thing under test is the final .zip write, not the bundle contents.
const cfgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-diag-cfg-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = cfgDir;

const diagnose = require('../lib/diagnose');

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hs-diag-' + tag + '-'));
}

test('buildBundle enforces 0600 even when outPath already exists world-readable', () => {
  const dir = tmpDir('mode');
  const outPath = path.join(dir, 'bundle.zip');

  // Pre-create a world-readable regular file at the target. A raw
  // fs.writeFileSync(outPath, buf, { mode: 0o600 }) keeps THIS file's
  // existing permissions (the mode option only applies on create), leaving
  // the bundle world-readable. The atomic write replaces it via a fresh
  // 0600 temp + rename, so the result is always 0600.
  fs.writeFileSync(outPath, 'stale', { mode: 0o644 });
  fs.chmodSync(outPath, 0o644);

  const res = diagnose.buildBundle(outPath);
  assert.equal(res.path, outPath);
  assert.ok(res.sizeBytes > 0, 'bundle should have bytes');
  assert.ok(res.entryCount >= 1, 'bundle should have at least one entry (info.json)');

  // The bytes must be the new archive, not the stale placeholder.
  const head = fs.readFileSync(outPath);
  assert.equal(head.slice(0, 2).toString('latin1'), 'PK', 'output should be a zip (PK magic)');

  if (process.platform !== 'win32') {
    const mode = fs.statSync(outPath).mode & 0o777;
    assert.equal(mode, 0o600, 'pre-existing target must end up 0600, not 0644');
  }
});

test('buildBundle refuses a symlink planted at outPath (does not write through to its target)', { skip: process.platform === 'win32' ? 'symlink semantics differ on win32' : false }, () => {
  const dir = tmpDir('symlink');
  const sentinelDir = tmpDir('sentinel');
  const sentinel = path.join(sentinelDir, 'victim.txt');
  fs.writeFileSync(sentinel, 'DO NOT OVERWRITE', { mode: 0o600 });

  const outPath = path.join(dir, 'bundle.zip');
  fs.symlinkSync(sentinel, outPath);

  // The atomic write opens its staging temp O_EXCL|O_NOFOLLOW and renames
  // over outPath; a symlink at outPath itself is replaced by the rename
  // (the LINK is overwritten, never followed), so the sentinel target is
  // left intact.
  assert.doesNotThrow(() => diagnose.buildBundle(outPath));

  // The sentinel (link target) must be untouched.
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'DO NOT OVERWRITE',
    'symlink target must not be written through');

  // outPath is now a real zip file (the link was replaced), not still a link.
  const lst = fs.lstatSync(outPath);
  assert.equal(lst.isSymbolicLink(), false, 'outPath should be a regular file after the write');
  assert.equal(fs.readFileSync(outPath).slice(0, 2).toString('latin1'), 'PK');
});

test('buildBundle return shape: path + entryCount + sizeBytes', () => {
  const dir = tmpDir('shape');
  const outPath = path.join(dir, 'b.zip');
  const res = diagnose.buildBundle(outPath);
  assert.deepEqual(Object.keys(res).sort(), ['entryCount', 'path', 'sizeBytes']);
  assert.equal(typeof res.entryCount, 'number');
  assert.equal(typeof res.sizeBytes, 'number');
  assert.equal(res.sizeBytes, fs.statSync(outPath).size);
});
