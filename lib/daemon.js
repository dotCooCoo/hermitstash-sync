'use strict';

// codebase-patterns:allow-file console-direct — daemon lifecycle commands (start/stop/status banners) write directly to stdout/stderr; the structured logger lives downstream and isn't initialised until after writePid() succeeds.
// codebase-patterns:allow-file process-exit — daemonize/uncaught-exception paths intentionally terminate to surface a clean exit code; signal handling lives in b.appShutdown which already owns graceful teardown.

const nodeFs = require('node:fs');
const b = require('../vendor/blamejs');
const { PID_FILE, LOG_FILE, CONFIG_DIR } = require('./constants');
const log = require('./logger');

const C = b.constants;

// b.daemon owns detached-fork spawn (filtered env via b.processSpawn,
// stale-PID reap, atomic pidfile write) and signal-driven stop with
// SIGTERM→SIGKILL escalation. b.appShutdown.pidLock owns the foreground
// O_EXCL pidfile lock + reap. We compose them here behind the same
// surface lib/cli.js already calls.

let _foregroundLock = null;

function daemonize() {
  nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
  const args = process.argv.slice(1).filter(a => a !== '--daemon');
  // b.daemon.start handles Windows correctly as of blamejs v0.10.13
  // (issue #101): on win32 it spawns with `stdio: "ignore"` +
  // `windowsHide: true` so the child has no inherited FDs to lose
  // when the parent's handle closes. On POSIX it keeps the
  // log-FD-inherit pattern that makes pre-logger boot panics
  // survive to the log file. Same call, both platforms.
  let handle;
  try {
    handle = b.daemon.start({
      command: process.execPath,
      args:    args,
      pidFile: PID_FILE,
      logFile: LOG_FILE,
    });
  } catch (err) {
    if (err && /already-running/.test(err.code || '')) {
      const existing = _readPid();
      console.error(`Daemon already running (PID ${existing || '?'})`);
      process.exit(1);
    }
    throw err;
  }
  console.log(`Daemon started (PID ${handle.pid})`);
  console.log(`Log: ${LOG_FILE}`);
  console.log(`PID: ${PID_FILE}`);
  process.exit(0);
}

function _readPid() {
  try {
    const raw = nodeFs.readFileSync(PID_FILE, 'utf8').trim();
    const pid = parseInt(raw, 10);
    return isFinite(pid) && pid > 0 ? pid : null;
  } catch (_e) {
    return null;
  }
}

function isRunning() {
  const pid = _readPid();
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return pid;
  } catch (e) {
    if (e && e.code === 'EPERM') return pid;
    try { nodeFs.unlinkSync(PID_FILE); } catch (_e) {} // allow:silent-catch — stale-PID cleanup; missing/locked PID file is harmless on the dead-process path
    return false;
  }
}

async function stop() {
  let r;
  try {
    r = await b.daemon.stop({ pidFile: PID_FILE, timeoutMs: C.TIME.seconds(5) });
  } catch (err) {
    console.error(`Failed to stop daemon: ${err.message}`);
    return false;
  }
  if (!r.stopped) {
    if (r.reason === 'no-pidfile') {
      console.log('No daemon running');
      return false;
    }
    if (r.reason === 'stale') {
      console.log(`Cleared stale PID file (PID ${r.pid} no longer running)`);
      return false;
    }
  }
  console.log(`Sent SIGTERM to PID ${r.pid}`);
  console.log('Daemon stopped');
  return true;
}

function writePid() {
  nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
  _foregroundLock = b.appShutdown.pidLock(PID_FILE);
  try {
    _foregroundLock.acquire();
  } catch (err) {
    if (err && /pidlock-held/.test(err.code || '')) {
      const existing = _readPid();
      throw new Error(`Another instance is running (PID ${existing || '?'})`);
    }
    throw err;
  }
}

function removePid() {
  if (_foregroundLock) {
    // allow:silent-catch — release is idempotent; the orchestrator may have already torn it down
    try { _foregroundLock.release(); } catch (_e) {}
    _foregroundLock = null;
    return;
  }
  try {
    if (nodeFs.existsSync(PID_FILE)) nodeFs.unlinkSync(PID_FILE);
  } catch (_e) {} // allow:silent-catch — best-effort PID cleanup on shutdown; another orchestrator phase may have raced us
}

function installSignalHandlers(shutdownFn, resyncFn, reloadFn) {
  const orchestrator = b.appShutdown.create({
    graceMs: C.TIME.seconds(30),
    phases: [
      {
        name: 'engine',
        run:  async () => { await shutdownFn(); },
        timeoutMs: C.TIME.seconds(20),
      },
      {
        name: 'pidfile',
        run:  () => { removePid(); },
        timeoutMs: C.TIME.seconds(1),
      },
      {
        // Force an explicit clean exit after graceful shutdown completes.
        // b.appShutdown.create's signal callback sets `process.exitCode = 0`
        // after phases finish and relies on the event loop draining to
        // actually exit. In the SEA-packaged daemon under tini in a
        // container, dangling handles (HTTP keep-alive pools, b.logStream
        // worker, sd_notify socket) can keep the loop alive long enough
        // for tini to report the child as signal-terminated — exit code
        // 143 (128 + SIGTERM) instead of the 0 the shutdown earned.
        // `docker stop --time 15` then reports container exit 143
        // despite a successful "shutdown complete (2/2 phases ok)" log
        // line. Forcing process.exit at the end of the phase chain makes
        // the exit code deterministic across SEA, container, and dev runs.
        name: 'forceExit',
        run:  () => {
          setImmediate(() => process.exit(process.exitCode || 0));
        },
        timeoutMs: C.TIME.seconds(1),
      },
    ],
    installSignalHandlers: true,
  });

  if ((resyncFn || reloadFn) && process.platform !== 'win32') {
    process.on('SIGHUP', async () => {
      log.info('Received SIGHUP — reloading config and triggering resync');
      // Reload config first so the resync sees the new ignore/include
      // patterns. A reload failure logs but doesn't block resync —
      // the old patterns stay in effect, daemon stays alive.
      if (reloadFn) {
        try { await reloadFn(); }
        catch (err) { log.warn('SIGHUP config reload failed; keeping previous patterns', { error: err.message }); }
      }
      if (resyncFn) {
        try { resyncFn(); }
        catch (err) { log.warn('SIGHUP resync failed', { error: err.message }); }
      }
    });
  }

  process.on('uncaughtException', err => {
    log.error('Uncaught exception', err);
    removePid();
    process.exit(1);
  });

  process.on('unhandledRejection', err => {
    log.error('Unhandled rejection', err);
  });

  return orchestrator;
}

module.exports = { daemonize, isRunning, stop, writePid, removePid, installSignalHandlers };
