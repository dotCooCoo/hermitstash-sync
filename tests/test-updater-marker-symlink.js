'use strict';

// The auto-update rollback marker (~/.hermitstash-sync/update-pending.json)
// drives destructive decisions: its prevBinaryPath is unlinked and copied
// onto the running executable on rollback. readMarker therefore reads it
// through b.atomicFile.fdSafeReadSync with refuseSymlink:true so a symlink
// planted at the marker path (the daemon only ever writes it as a regular
// file via b.atomicFile.writeSync) is refused rather than followed to an
// attacker-chosen file. These tests pin that refusal end-to-end:
//   - readMarker returns null for a symlinked marker (no parse of the link
//     target's contents into the rollback decision)
//   - checkRollback treats a symlinked marker as "no-marker" — no spurious
//     downgrade driven by a swapped file
//
// Symlink creation needs a privilege Windows withholds from an unprivileged
// process (EPERM); those cases self-skip there and exercise on POSIX CI. The
// non-symlink assertions (missing marker, regular-file round-trip) run on
// every platform.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');

const { createUpdater } = require('../lib/updater');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hs-marker-sym-'));
}

// Probe once whether this platform lets an unprivileged process create a
// symlink. Windows returns EPERM/EACCES unless the process is elevated or
// developer mode is on; POSIX always allows it.
function canSymlink(dir) {
  const tgt = path.join(dir, '.symprobe-target');
  const lnk = path.join(dir, '.symprobe-link');
  try {
    fs.writeFileSync(tgt, 'x');
    fs.symlinkSync(tgt, lnk);
    fs.unlinkSync(lnk);
    fs.unlinkSync(tgt);
    return true;
  } catch {
    try { fs.unlinkSync(lnk); } catch { /* not created */ }
    try { fs.unlinkSync(tgt); } catch { /* may not exist */ }
    return false;
  }
}

function mkUpdater(markerPath, execPath, caps) {
  return createUpdater({
    currentVersion: '9.9.9',
    pubkeyPem: 'unused-here',
    pollMs: 60_000,
    initialDelayMs: 60_000,
    probationMs: 1000,
    markerPath,
    getExecPath: () => execPath,
    getArgv: () => [],
    isSeaBinary: () => true,
    httpsAgent: new https.Agent({ keepAlive: true }),
    spawnFn: (cmd, args) => { caps.spawns.push({ cmd, args }); return { unref() {} }; },
    exitFn: (code) => { caps.exits.push(code); },
  });
}

test('readMarker returns null when the marker file is absent', () => {
  const dir = tempDir();
  const markerPath = path.join(dir, 'update-pending.json');
  const up = mkUpdater(markerPath, path.join(dir, 'hs'), { spawns: [], exits: [] });
  assert.strictEqual(up._internals.readMarker(), null);
});

test('readMarker parses a regular-file marker (round-trip via the production writer)', () => {
  const dir = tempDir();
  const markerPath = path.join(dir, 'update-pending.json');
  const execPath = path.join(dir, 'hs');
  const up = mkUpdater(markerPath, execPath, { spawns: [], exits: [] });
  // writeMarker is the only legitimate producer; confirm readMarker accepts
  // exactly what it writes (so the symlink-refusing read did not break the
  // normal regular-file path).
  up._internals.writeMarker('9.9.9', path.join(dir, 'hs.prev'));
  const marker = up._internals.readMarker();
  assert.ok(marker, 'marker should parse');
  assert.strictEqual(marker.newVersion, '9.9.9');
  assert.strictEqual(marker.prevBinaryPath, path.join(dir, 'hs.prev'));
  assert.ok(Number.isFinite(marker.installedAt) && marker.installedAt > 0);
});

test('readMarker refuses a symlinked marker path (returns null, does not follow the link)', { skip: false }, (t) => {
  const dir = tempDir();
  if (!canSymlink(dir)) { t.skip('platform does not permit unprivileged symlink creation'); return; }

  const markerPath = path.join(dir, 'update-pending.json');
  const execPath = path.join(dir, 'hs');

  // A foreign, attacker-controlled JSON file that, if followed, would parse
  // into a marker pointing prevBinaryPath at a victim file.
  const foreign = path.join(dir, 'attacker.json');
  fs.writeFileSync(foreign, JSON.stringify({
    newVersion: '9.9.9',
    prevBinaryPath: '/etc/hosts',
    installedAt: Date.now() - 60_000,
  }));
  fs.symlinkSync(foreign, markerPath);

  const up = mkUpdater(markerPath, execPath, { spawns: [], exits: [] });
  // The symlink is refused at the O_NOFOLLOW/lstat boundary — readMarker must
  // not return the link target's parsed contents.
  assert.strictEqual(up._internals.readMarker(), null);
});

test('checkRollback treats a symlinked marker as no-marker (no spurious rollback)', async (t) => {
  const dir = tempDir();
  if (!canSymlink(dir)) { t.skip('platform does not permit unprivileged symlink creation'); return; }

  const markerPath = path.join(dir, 'update-pending.json');
  const execPath = path.join(dir, 'hs');
  fs.writeFileSync(execPath, 'HEALTHY NEW', { mode: 0o755 });

  // A past-window, no-gracefulAt marker would normally force a rollback. Plant
  // it behind a symlink: the refusing read collapses it to null, so checkRollback
  // sees "no-marker" and never downgrades.
  const foreign = path.join(dir, 'attacker.json');
  fs.writeFileSync(foreign, JSON.stringify({
    newVersion: '9.9.9',
    prevBinaryPath: path.join(dir, 'hs.prev'),
    installedAt: Date.now() - 60_000,
  }));
  fs.symlinkSync(foreign, markerPath);

  const caps = { spawns: [], exits: [] };
  const up = mkUpdater(markerPath, execPath, caps);
  assert.strictEqual(await up.checkRollback(), 'no-marker');
  assert.strictEqual(caps.spawns.length, 0, 'no restart spawned');
  assert.strictEqual(caps.exits.length, 0, 'process not exited');
  assert.strictEqual(fs.readFileSync(execPath, 'utf8'), 'HEALTHY NEW', 'binary untouched');
});
