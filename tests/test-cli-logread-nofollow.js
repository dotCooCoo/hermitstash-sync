'use strict';

// Coverage for the O_NOFOLLOW log-read hardening in lib/cli.js#cmdLog
// (non-follow path). The read opens via
//   fd = b.atomicFile.openNoFollowSync(LOG_FILE)
//   content = readFileSync(fd)        // does NOT close the fd
//   finally { if (fd !== undefined) closeSync(fd); }
// plus a die() on ELOOP. Two things this covers, both server-independent:
//   1. Regular-file read still works end-to-end through the new fd dance, and
//      the fd is closed EXACTLY ONCE — a double-close would throw EBADF and
//      crash the command (the regression a careless fd-ownership change ships).
//   2. On POSIX, a symlink planted at the log path is refused (ELOOP) rather
//      than read through to an off-directory target (CWE-59). O_NOFOLLOW is a
//      no-op on Windows (fs.constants.O_NOFOLLOW === undefined → flag 0), so the
//      refusal assertion is POSIX-only and skips on win32 where the kernel
//      primitive does not exist.
//
// Drives the REAL production lib/cli.js#run('log') by pointing CONFIG_DIR at a
// temp dir via HERMITSTASH_SYNC_CONFIG_DIR BEFORE the lib is loaded (constants.js
// resolves LOG_FILE from CONFIG_DIR at module-load). No HTTPS server, no ctx.url.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodeOs = require('node:os');
const nodePath = require('node:path');

const TMP_CONFIG_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-logread-'));
// Must be set before requiring constants/cli so LOG_FILE binds to our temp dir.
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_CONFIG_DIR;

const cli = require('../lib/cli');
const { LOG_FILE } = require('../lib/constants');

// Capture console.log / process.exit so we can drive cmdLog and inspect what it
// emitted without it tearing the test process down on the die() path.
function withCapturedConsole(fn) {
  const origLog = console.log;
  const origErr = console.error;
  const origExit = process.exit;
  const out = [];
  const err = [];
  let exitCode = null;
  console.log = (...a) => { out.push(a.join(' ')); };
  console.error = (...a) => { err.push(a.join(' ')); };
  // die() calls process.exit(1); turn it into a throwable so the test can assert
  // refusal without killing the runner.
  process.exit = (code) => { exitCode = code; throw new Error('__EXIT__:' + code); };
  let threw = null;
  try {
    fn();
  } catch (e) {
    if (!String(e.message).startsWith('__EXIT__')) threw = e;
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.exit = origExit;
  }
  if (threw) throw threw;
  return { out, err, exitCode };
}

describe('cmdLog non-follow O_NOFOLLOW read', () => {
  before(() => {
    // LOG_FILE must live directly under our temp CONFIG_DIR.
    assert.equal(nodePath.dirname(LOG_FILE), TMP_CONFIG_DIR,
      'LOG_FILE did not bind to the temp CONFIG_DIR — env override ordering is wrong');
  });

  after(() => {
    try { nodeFs.rmSync(TMP_CONFIG_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('reads a regular log file and closes the fd exactly once (no double-close crash)', () => {
    const lines = [];
    for (let i = 1; i <= 60; i += 1) lines.push(`line-${i}`);
    nodeFs.writeFileSync(LOG_FILE, lines.join('\n') + '\n');

    // If the fix double-closed the fd, closeSync on an already-closed fd throws
    // EBADF and cmdLog rejects/throws — withCapturedConsole would re-surface it.
    const { out } = withCapturedConsole(() => cli.run(['log']));

    // cmdLog prints the last 50 lines joined; assert the tail rendered and the
    // head was trimmed (proves the full read happened through the fd).
    const printed = out.join('\n');
    assert.ok(printed.includes('line-60'), 'last line missing — read through fd failed');
    assert.ok(printed.includes('line-11'), 'line-11 (50th-from-last) missing');
    assert.ok(!printed.includes('line-10\n') && !/\bline-10\b/.test(printed),
      'line-10 should have been trimmed by the last-50 slice');
  });

  it('prints the no-log message when the file is absent (existsSync guard intact)', () => {
    try { nodeFs.rmSync(LOG_FILE, { force: true }); } catch { /* ignore */ }
    const { out } = withCapturedConsole(() => cli.run(['log']));
    assert.ok(out.join('\n').includes('No log file found.'),
      'absent-file branch regressed');
  });

  // POSIX-only: O_NOFOLLOW does not exist on Windows (flag resolves to 0), so the
  // symlink-refusal behavior cannot be exercised there. Skip rather than assert a
  // vacuous pass.
  const symlinkSupported = process.platform !== 'win32'
    && typeof nodeFs.constants.O_NOFOLLOW === 'number'
    && nodeFs.constants.O_NOFOLLOW !== 0;

  it('refuses to read the log through a symlink (ELOOP → die) on POSIX', { skip: !symlinkSupported }, () => {
    const realTarget = nodePath.join(TMP_CONFIG_DIR, 'off-dir-secret.txt');
    nodeFs.writeFileSync(realTarget, 'SENTINEL-SHOULD-NEVER-BE-PRINTED\n');
    try { nodeFs.rmSync(LOG_FILE, { force: true }); } catch { /* ignore */ }
    nodeFs.symlinkSync(realTarget, LOG_FILE);

    const { out, err, exitCode } = withCapturedConsole(() => cli.run(['log']));

    const all = out.concat(err).join('\n');
    assert.ok(!all.includes('SENTINEL-SHOULD-NEVER-BE-PRINTED'),
      'symlink target contents leaked — O_NOFOLLOW refusal failed');
    assert.equal(exitCode, 1, 'expected die() (exit 1) on the ELOOP refusal');
    assert.ok(/symlink/i.test(err.join('\n')),
      'expected an actionable symlink-refusal message on stderr');
  });
});
