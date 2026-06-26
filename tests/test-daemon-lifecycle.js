'use strict';

// Host-side lifecycle coverage for lib/daemon.js — PID-file write/stale-detect/
// remove and the phase-ordered, idempotent SIGTERM teardown. No Docker and no
// HermitStash server are required: the config dir is redirected to a temp
// directory before lib/daemon.js loads, so the PID file and shutdown
// orchestration are exercised in isolation.
//
// The full container enroll -> sync -> restart -> SIGTERM loop lives in the
// docker-backed e2e suite; this file pins the regression-prone primitives that
// suite only covers transitively: PID-file reaping of a dead owner, and the
// teardown phases firing in registered order exactly once even on a repeated
// stop signal.
//
// Run standalone:
//   node --test tests/test-daemon-lifecycle.js

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

// Redirect the config dir BEFORE lib/constants.js (required transitively by
// lib/daemon.js) snapshots PID_FILE/CONFIG_DIR from the environment. Done at
// module top so the require below resolves the temp paths.
const CONFIG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-daemon-lifecycle-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = CONFIG_DIR;

const daemon = require('../lib/daemon');
const { PID_FILE } = require('../lib/constants');

process.on('exit', () => {
  try { fs.rmSync(CONFIG_DIR, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
});

test('writePid -> isRunning -> removePid round-trips the live PID', () => {
  daemon.writePid();
  try {
    assert.ok(fs.existsSync(PID_FILE), 'PID file should exist after writePid');
    const recorded = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    assert.equal(recorded, process.pid, 'PID file should record this process');
    assert.equal(daemon.isRunning(), process.pid, 'isRunning returns the live PID');
  } finally {
    daemon.removePid();
  }
  assert.equal(fs.existsSync(PID_FILE), false, 'removePid deletes the PID file');
  assert.equal(daemon.isRunning(), false, 'isRunning is false once the PID file is gone');
});

test('isRunning reaps a stale PID file (dead owner)', () => {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  // A PID that cannot belong to a live process. process.kill(pid, 0) raises
  // ESRCH, so isRunning() treats it as dead and unlinks the file.
  fs.writeFileSync(PID_FILE, '2147480000\n');
  assert.equal(daemon.isRunning(), false, 'a dead PID is not running');
  assert.equal(fs.existsSync(PID_FILE), false, 'a stale PID file is reaped');
});

test('isRunning treats a malformed PID file as not-running', () => {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(PID_FILE, 'not-a-number\n');
  assert.equal(daemon.isRunning(), false, 'a garbage PID file is not running');
  // Clean up so a later test starts from a known state.
  try { fs.unlinkSync(PID_FILE); } catch (_e) { /* may already be gone */ }
});

test('installSignalHandlers runs teardown phases in registered order, exactly once', async () => {
  // Snapshot listeners so we can detach only the ones we add — node:test owns
  // its own SIGINT/uncaughtException listeners and must keep them.
  const watched = ['SIGTERM', 'SIGINT', 'SIGHUP', 'uncaughtException', 'unhandledRejection'];
  const before = {};
  for (const sig of watched) before[sig] = process.listeners(sig).slice();

  const order = [];
  let engineCalls = 0;
  const orchestrator = daemon.installSignalHandlers(
    async () => { engineCalls++; order.push('engine'); },
    null,
    null
  );

  try {
    // Drive the orchestrator directly rather than raising a real signal: the
    // signal path ends in process.exit(), which would terminate the test
    // runner. The orchestrator is the same instance the SIGTERM handler awaits.
    const first = await orchestrator.shutdown();
    // A second shutdown() (the moral equivalent of a double SIGTERM) must be
    // idempotent: same Promise, phases do not re-run.
    const second = await orchestrator.shutdown();

    assert.equal(first, second, 'shutdown() is idempotent — returns the same result');
    assert.deepEqual(
      first.phases.map(p => p.name),
      ['engine', 'pidfile'],
      'phases fire in registered order'
    );
    assert.equal(engineCalls, 1, 'the engine phase runs exactly once across two shutdown() calls');
    assert.equal(first.ok, true, 'all phases completed cleanly');
  } finally {
    // Detach only the listeners installSignalHandlers added, leaving node:test's
    // own handlers intact.
    for (const sig of watched) {
      for (const fn of process.listeners(sig)) {
        if (!before[sig].includes(fn)) process.removeListener(sig, fn);
      }
    }
  }
});

// The real signal path (catchable SIGTERM -> phase teardown -> process.exit(0))
// only works on POSIX. On Windows, process.kill(pid, 'SIGTERM') terminates the
// target unconditionally instead of delivering a catchable JS event, so this
// child-driven check is POSIX-only.
test('SIGTERM drives a clean exit-0 teardown with phases firing once', { skip: process.platform === 'win32' }, async () => {
  const childSrc = `
    'use strict';
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-daemon-sig-'));
    process.env.HERMITSTASH_SYNC_CONFIG_DIR = dir;
    const daemon = require(${JSON.stringify(path.resolve(__dirname, '..', 'lib', 'daemon'))});
    let engineCalls = 0;
    daemon.installSignalHandlers(async () => {
      engineCalls++;
      process.stdout.write('ENGINE\\n');
    }, null, null);
    process.on('exit', () => {
      process.stdout.write('ENGINE_CALLS=' + engineCalls + '\\n');
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    });
    process.stdout.write('READY\\n');
    // Keep the event loop alive until the signal arrives.
    setInterval(() => {}, 1000);
  `;

  const child = spawn(process.execPath, ['-e', childSrc], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', c => { out += c.toString('utf8'); });
  child.stderr.on('data', c => { out += c.toString('utf8'); });

  // Wait for READY, then deliver SIGTERM twice (the second is a no-op the
  // _shuttingDown guard swallows).
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('child never printed READY:\n' + out)), 10000);
    const iv = setInterval(() => {
      if (out.includes('READY')) {
        clearInterval(iv);
        clearTimeout(deadline);
        resolve();
      }
    }, 50);
  });

  child.kill('SIGTERM');
  // A rapid second SIGTERM exercises the idempotence guard in handleTerm.
  child.kill('SIGTERM');

  const code = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('child did not exit in time:\n' + out)); }, 10000);
    child.on('exit', c => { clearTimeout(deadline); resolve(c); });
    child.on('error', reject);
  });

  assert.equal(code, 0, 'SIGTERM teardown exits 0; output:\n' + out);
  assert.ok(out.includes('ENGINE\n'), 'the engine phase ran; output:\n' + out);
  assert.ok(out.includes('ENGINE_CALLS=1'), 'the engine phase ran exactly once across a double SIGTERM; output:\n' + out);
});

// A SIGHUP must NOT reload/resync once a graceful shutdown has begun — otherwise
// the reload re-opens the WebSocket and the resync clear()s the state DB the
// teardown is draining. handleTerm sets _shuttingDown synchronously (before its
// first await), so a SIGHUP delivered immediately after a SIGTERM is swallowed
// by the guard. Driven in-process by invoking the installed handlers directly
// (process.exit is stubbed so the SIGTERM path doesn't kill the test runner).
// SIGHUP is POSIX-only (daemon.js gates the listener on process.platform).
test('SIGHUP during shutdown is ignored (no reload/resync mid-teardown)', { skip: process.platform === 'win32' }, async () => {
  const watched = ['SIGTERM', 'SIGINT', 'SIGHUP', 'uncaughtException', 'unhandledRejection'];
  const before = {};
  for (const sig of watched) before[sig] = process.listeners(sig).slice();
  const added = (sig) => process.listeners(sig).filter(fn => !before[sig].includes(fn));

  let reloads = 0, resyncs = 0, engineCalls = 0, exitCalls = 0;
  const realExit = process.exit;
  process.exit = () => { exitCalls++; }; // neutralize the handler's terminal exit during the test

  try {
    daemon.installSignalHandlers(
      async () => { engineCalls++; },   // shutdownFn (engine phase)
      async () => { resyncs++; },        // resyncFn
      async () => { reloads++; }         // reloadFn
    );
    const myTerm = added('SIGTERM')[0];
    const myHup = added('SIGHUP')[0];
    assert.equal(typeof myTerm, 'function', 'SIGTERM handler installed');
    assert.equal(typeof myHup, 'function', 'SIGHUP handler installed (POSIX)');

    // Begin graceful shutdown; _shuttingDown is now true (set synchronously).
    myTerm('SIGTERM');
    // A SIGHUP arriving mid-shutdown must hit the guard and return early.
    myHup('SIGHUP');
    // Let handleTerm's awaited shutdown settle (process.exit is stubbed).
    await new Promise(r => setTimeout(r, 50));

    assert.equal(reloads, 0, 'SIGHUP reload must NOT run during shutdown');
    assert.equal(resyncs, 0, 'SIGHUP resync must NOT run during shutdown');
    assert.equal(engineCalls, 1, 'the shutdown engine phase still ran once');
    assert.ok(exitCalls >= 1, 'handleTerm reached its terminal exit');
  } finally {
    process.exit = realExit;
    for (const sig of watched) {
      for (const fn of process.listeners(sig)) {
        if (!before[sig].includes(fn)) process.removeListener(sig, fn);
      }
    }
  }
});

// Positive control: a SIGHUP during NORMAL operation still runs reload + resync,
// so the guard above is not over-blocking.
test('SIGHUP during normal operation runs reload + resync', { skip: process.platform === 'win32' }, async () => {
  const watched = ['SIGTERM', 'SIGINT', 'SIGHUP', 'uncaughtException', 'unhandledRejection'];
  const before = {};
  for (const sig of watched) before[sig] = process.listeners(sig).slice();
  const added = (sig) => process.listeners(sig).filter(fn => !before[sig].includes(fn));

  let reloads = 0, resyncs = 0;
  try {
    daemon.installSignalHandlers(
      async () => {},
      async () => { resyncs++; },
      async () => { reloads++; }
    );
    const myHup = added('SIGHUP')[0];
    assert.equal(typeof myHup, 'function', 'SIGHUP handler installed');
    await myHup('SIGHUP'); // async handler — await reload + resync
    assert.equal(reloads, 1, 'a normal SIGHUP runs the config reload');
    assert.equal(resyncs, 1, 'a normal SIGHUP runs the resync');
  } finally {
    for (const sig of watched) {
      for (const fn of process.listeners(sig)) {
        if (!before[sig].includes(fn)) process.removeListener(sig, fn);
      }
    }
  }
});

// A genuine stop failure (b.daemon.stop throws — e.g. process.kill EPERM) must
// set a non-zero exit code so `hermitstash-sync stop && <next>` automation does
// not proceed as if the daemon stopped. The benign "no daemon running" path is
// not a failure and must stay exit 0.
test('stop() sets a non-zero exit code on a genuine failure but not on no-daemon-running', async () => {
  const b = require('../vendor/blamejs');
  const realStop = b.daemon.stop;
  const realExitCode = process.exitCode;
  try {
    // Genuine failure: the underlying stop throws.
    b.daemon.stop = async () => { throw new Error('kill failed: EPERM'); };
    process.exitCode = 0;
    const r1 = await daemon.stop();
    assert.equal(r1, false, 'stop returns false on a genuine failure');
    assert.equal(process.exitCode, 1, 'a genuine stop failure sets a non-zero exit code');

    // Benign: no daemon to stop — not a failure.
    b.daemon.stop = async () => ({ stopped: false, reason: 'no-pidfile' });
    process.exitCode = 0;
    const r2 = await daemon.stop();
    assert.equal(r2, false, 'stop returns false when no daemon is running');
    assert.equal(process.exitCode, 0, 'no-daemon-running keeps exit code 0 (nothing to stop is not a failure)');
  } finally {
    b.daemon.stop = realStop;
    process.exitCode = realExitCode;
  }
});
