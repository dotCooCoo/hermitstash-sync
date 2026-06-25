'use strict';

// Coverage for lib/logger.js symlink-defence on the active log path.
//
// Exercises the REAL production logger (no reimplementation). Symlink refusal
// is delegated to b.logStream's local sink, which opens the active log file
// with O_NOFOLLOW append and throws a typed SYMLINK_REFUSED LogStreamError;
// lib/logger.js#init translates that into the actionable "refusing to write
// logs through it" message.
//
// The symlink case is POSIX-only: O_NOFOLLOW does not exist on win32
// (blamejs falls back to `| 0`), so a symlinked active path would be
// followed there. We skip that assertion on win32 but always run the
// happy path.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const log = require('../lib/logger');

const IS_WIN = process.platform === 'win32';

function freshDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hs-logaudit-'));
}

describe('logger symlink defence (fix-audit)', () => {
  const created = [];

  after(async () => {
    await log.close();
    for (const d of created) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  it('happy path: fresh dir init + info writes the active log', async () => {
    const dir = freshDir();
    created.push(dir);
    const file = path.join(dir, 'hermitstash-sync.log');

    log.init({ file, stdout: false });
    log.info('audit-happy-path-marker', { ok: true });

    // Drain the fire-and-forget emit before asserting the file exists.
    await log.close();

    const active = path.join(dir, 'hermitstash-sync.log');
    assert.ok(fs.existsSync(active), 'active log file should be created');
    const body = fs.readFileSync(active, 'utf8');
    assert.match(body, /audit-happy-path-marker/, 'emitted record should reach the file');
  });

  it('refuses to follow a symlinked active log path (POSIX)', { skip: IS_WIN ? 'O_NOFOLLOW unavailable on win32' : false }, () => {
    const dir = freshDir();
    created.push(dir);

    // Sentinel that an attacker symlink would redirect writes into.
    const sentinel = path.join(dir, 'sentinel.txt');
    fs.writeFileSync(sentinel, 'ORIGINAL', 'utf8');

    // Plant a symlink at the active log path the sink will try to open.
    const active = path.join(dir, 'hermitstash-sync.log');
    fs.symlinkSync(sentinel, active);

    const file = path.join(dir, 'hermitstash-sync.log');
    assert.throws(
      () => log.init({ file, stdout: false }),
      /refusing to write logs through it/,
      'a symlinked active path must be refused with the actionable message');

    // The sentinel must be byte-untouched — no writes followed the link,
    // and the fix no longer silently unlinks the planted symlink.
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'ORIGINAL',
      'sentinel target must be untouched');
    assert.ok(fs.lstatSync(active).isSymbolicLink(),
      'planted symlink must remain (no silent unlink)');
  });
});
