'use strict';

// Unit coverage for the auto-update rollback-marker read.
//
// readMarker() drives destructive rollback decisions: marker.prevBinaryPath is
// fed to unlinkSync and copied onto the running executable. The daemon WRITES
// the marker 0o644 via b.atomicFile.writeSync (atomic temp + rename), so a
// symlink at the marker path is never legitimate. The read must therefore open
// the path symlink-refusing (b.atomicFile.fdSafeReadSync with refuseSymlink)
// rather than following a planted link to an attacker-chosen file, and any
// failure — symlink, missing, oversize, malformed — must collapse to null so
// the caller treats it as "no pending update" instead of acting on a swapped
// marker.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');

const { createUpdater } = require('../lib/updater');

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hs-marker-' + tag + '-'));
}

// Minimal updater whose only exercised surface is _internals.readMarker.
// Passing httpsAgent flips the updater into its test-env branch so no PQC
// agent / network egress is built; readMarker only consults markerPath.
function mkUpdater(markerPath) {
  return createUpdater({
    currentVersion: '9.9.9',
    pubkeyPem: null,
    markerPath,
    getExecPath: () => path.join(path.dirname(markerPath), 'hs'),
    getArgv: () => [],
    isSeaBinary: () => true,
    httpsAgent: new https.Agent({ keepAlive: false }),
    spawnFn: () => ({ unref() {} }),
    exitFn: () => {},
  });
}

test('readMarker parses a regular marker file written by the daemon', () => {
  const dir = tmpDir('ok');
  const markerPath = path.join(dir, 'update-pending.json');
  const payload = { newVersion: '9.9.9', prevBinaryPath: path.join(dir, 'hs.prev'), installedAt: Date.now() };
  fs.writeFileSync(markerPath, JSON.stringify(payload), { mode: 0o644 });

  const up = mkUpdater(markerPath);
  const marker = up._internals.readMarker();
  assert.ok(marker, 'a regular marker file should parse');
  assert.equal(marker.newVersion, '9.9.9');
  assert.equal(marker.prevBinaryPath, payload.prevBinaryPath);
});

test('readMarker returns null when the marker file is absent', () => {
  const dir = tmpDir('absent');
  const up = mkUpdater(path.join(dir, 'update-pending.json'));
  assert.equal(up._internals.readMarker(), null);
});

test('readMarker returns null for a malformed marker rather than throwing', () => {
  const dir = tmpDir('malformed');
  const markerPath = path.join(dir, 'update-pending.json');
  fs.writeFileSync(markerPath, '{ this is not json', { mode: 0o644 });
  const up = mkUpdater(markerPath);
  assert.equal(up._internals.readMarker(), null);
});

test('readMarker refuses a symlinked marker path (does not follow the link to its target)', { skip: process.platform === 'win32' ? 'symlink semantics differ on win32' : false }, () => {
  const dir = tmpDir('symlink');
  const targetDir = tmpDir('symlink-target');
  // The link target is a valid marker pointing at a foreign prevBinaryPath an
  // attacker would want unlinked / copied onto the running binary. If the read
  // followed the link, readMarker would parse this and hand it to the rollback
  // path; refusing the symlink keeps that decision out of attacker control.
  const target = path.join(targetDir, 'foreign-marker.json');
  fs.writeFileSync(target, JSON.stringify({
    newVersion: '9.9.9',
    prevBinaryPath: '/etc/hosts',
    installedAt: Date.now() - 60_000,
  }), { mode: 0o644 });

  const markerPath = path.join(dir, 'update-pending.json');
  fs.symlinkSync(target, markerPath);

  const up = mkUpdater(markerPath);
  // fdSafeReadSync({ refuseSymlink: true }) lstat-refuses the link; readMarker's
  // catch collapses that to null. The link's target contents must NOT surface.
  assert.equal(up._internals.readMarker(), null,
    'a symlinked marker path must be refused, not followed to its target');

  // The symlink itself is untouched by the read (it neither follows nor unlinks).
  assert.equal(fs.lstatSync(markerPath).isSymbolicLink(), true);
});
