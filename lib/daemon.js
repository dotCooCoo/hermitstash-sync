'use strict';

// codebase-patterns:allow-file console-direct — daemon lifecycle commands (start/stop/status banners) write directly to stdout/stderr; the structured logger lives downstream and isn't initialised until after writePid() succeeds.
// codebase-patterns:allow-file process-exit — daemonize/uncaught-exception paths intentionally terminate to surface a clean exit code; signal handling lives in b.appShutdown which already owns graceful teardown.
// codebase-patterns:allow-file sea-sigterm-bug — handleTerm composes b.appShutdown phase orchestration with explicit process.exit(0) after orchestrator.shutdown resolves. SEA-packaged Node has been observed to surface the signal default (exit 143 = 128 + SIGTERM) on SIGTERM-driven graceful shutdown despite the explicit process.exit(0). Container deployments remap via `tini -e 143` in the Dockerfile entrypoint; systemd units whitelist via `SuccessExitStatus=143 SIGTERM` in deploy/hermitstash-sync.service. The data-path teardown completes normally regardless of which exit code the supervisor records.

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

// Create CONFIG_DIR 0o700 (not the umask-default 0o755) so the dir holding
// credentials, state.db, mTLS material, and the PID/log files is not
// world-traversable. b.atomicFile.ensureDir applies the restrictive mode on
// creation; mkdir's mode is a no-op on a dir an older version already created
// loosely, so on POSIX also tighten an existing dir to 0o700 once at boot.
function _ensureConfigDir() {
  b.atomicFile.ensureDir(CONFIG_DIR, 0o700);
  if (process.platform !== 'win32') {
    try {
      const st = nodeFs.statSync(CONFIG_DIR);
      if ((st.mode & 0o077) !== 0) nodeFs.chmodSync(CONFIG_DIR, 0o700);
    } catch (_e) { /* allow:silent-catch — best-effort upgrade-path tightening; absence/race is harmless */ }
  }
}

function daemonize() {
  _ensureConfigDir();
  // Strip --daemon (so the child doesn't re-fork) and append --child so the
  // re-spawned worker is detectable in `ps` and via args. The args marker is
  // belt-and-suspenders for the env marker set just below.
  const args = process.argv.slice(1).filter(a => a !== '--daemon');
  args.push('--child');
  // The detached child must see HERMITSTASH_SYNC_DAEMON=1 so cmdStart's
  // `isChild` resolves true — that disables the stdout log sink (otherwise the
  // POSIX child double-writes the log file with ANSI escapes) and suppresses
  // the foreground "Syncing..." banner. b.daemon.start spawns via
  // b.processSpawn.filteredEnv, which carries process.env through verbatim
  // except for secret-shaped names; this marker isn't secret-shaped, so
  // setting it on the parent's env here propagates it into the child.
  process.env.HERMITSTASH_SYNC_DAEMON = '1';                                    // allow:raw-process-env — child-marker handoff; filteredEnv carries it into the detached worker
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
    // 30s matches the daemon's own graceful-teardown budget (SHUTDOWN_WALL_MS
    // ~22s over a 20s engine phase) and the shipped systemd TimeoutStopSec=30.
    // A shorter CLI stop would SIGKILL the orderly drain mid-flight.
    r = await b.daemon.stop({ pidFile: PID_FILE, timeoutMs: C.TIME.seconds(30) });
  } catch (err) {
    console.error(`Failed to stop daemon: ${err.message}`);
    // A genuine stop failure (e.g. process.kill EPERM) must not exit 0, or
    // `hermitstash-sync stop && <next>` automation proceeds as if the daemon
    // stopped. The benign no-pidfile / stale-PID paths below stay exit 0 —
    // there was nothing to stop, which is not a failure.
    process.exitCode = 1;
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
  // b.daemon.stop escalates SIGTERM→SIGKILL when the process doesn't exit
  // within timeoutMs; on that path it sets signal:'SIGKILL', escalated:true.
  // Surface the force-kill so the operator knows the graceful drain was cut short.
  if (r.escalated || r.signal === 'SIGKILL') {
    console.log(`Daemon did not exit in time; sent SIGKILL to PID ${r.pid} (graceful shutdown was interrupted)`);
    return true;
  }
  console.log(`Sent SIGTERM to PID ${r.pid}`);
  console.log('Daemon stopped');
  return true;
}

function writePid() {
  _ensureConfigDir();
  // Startup ordering note: in `start --daemon`, the parent writes the child's
  // PID atomically, then the detached child re-runs and calls pidLock.acquire()
  // here. The vendored pidLock reaps a stale pidfile before acquiring; for the
  // legitimate parent-handoff case the recorded PID is this child's own, which
  // pidLock recognises and keeps in place. A concurrent `stop` racing that
  // narrow window can momentarily observe no live owner and report
  // 'No daemon running'; the impact is benign and self-healing (re-run `stop`).
  // The isRunning() guard in cmdStart only prevents a second `start` from
  // launching — it does NOT serialise against `stop`. Eliminating the window
  // entirely is an upstream pidLock change (take ownership of the existing
  // inode when it already records process.pid), tracked against blamejs rather
  // than patched in the vendor tree.
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
  // We compose b.appShutdown's phase orchestration but install our own
  // SIGTERM/SIGINT listeners (installSignalHandlers:false). The library's
  // built-in handler path sets process.exitCode and lets the event loop
  // drain; under SEA + tini that has been observed to surface the signal
  // default (exit 143) even when all phases complete cleanly. Owning the
  // listeners keeps the explicit process.exit() in handleTerm() below as
  // the single termination point; see handleTerm for the exit-code-leak
  // mitigation in containers (`tini -e 143`) and systemd
  // (`SuccessExitStatus=143 SIGTERM`).
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
    ],
    installSignalHandlers: false,
  });

  // SEA-packaged Node has been observed to exit 143 (128 + SIGTERM, the
  // signal default) after a SIGTERM-driven graceful shutdown completes,
  // bypassing the explicit process.exit(0) below. Reduced reproductions
  // (one-line handlers, multi-phase async handlers on debian-slim and
  // alpine, Node 24 and Node 26) all exit 0 cleanly — the leak only
  // surfaces in the full production-image shape. Root cause unisolated;
  // the data-path teardown still runs cleanly (engine.stop, pidfile,
  // log.close all complete before process.exit fires). Container exits
  // are remapped to 0 via `tini -e 143` in the Dockerfile entrypoint;
  // systemd whitelists via `SuccessExitStatus=143 SIGTERM` in
  // deploy/hermitstash-sync.service.
  // Wall-clock cap on the whole graceful-shutdown path. Phase-level timeouts
  // already exist (engine: 20s, pidfile: 1s) but `await orchestrator.shutdown()`
  // would still hang forever if a phase's run() returned a never-settling
  // Promise (e.g. b.logStream.shutdown worker stuck on a closed FD). Without
  // a wall-clock cap the daemon would sit there until docker/systemd SIGKILLs
  // it (container exit 137 — not remapped by tini -e 143). Cap is the sum of
  // engine.timeoutMs + pidfile.timeoutMs + small buffer; if shutdown runs past
  // that we exit forcibly so the supervisor reaps cleanly.
  const SHUTDOWN_WALL_MS = C.TIME.seconds(22);
  let _shuttingDown = false;
  async function handleTerm(sig) {
    if (_shuttingDown) return;
    _shuttingDown = true;
    log.info(`Received ${sig} — graceful shutdown`);
    let timeoutHit = false;
    const wallTimeout = new Promise((resolve) => {
      setTimeout(() => { timeoutHit = true; resolve(); }, SHUTDOWN_WALL_MS).unref();
    });
    try {
      await Promise.race([orchestrator.shutdown(), wallTimeout]);
    } catch (err) {
      log.error('Shutdown phase threw', { error: err && err.message });
      process.exit(1);
      return;
    }
    if (timeoutHit) {
      log.warn('Shutdown wall-clock cap hit; forcing exit');
      process.exit(1);
      return;
    }
    process.exit(0);
  }
  process.on('SIGTERM', () => handleTerm('SIGTERM'));
  process.on('SIGINT',  () => handleTerm('SIGINT'));

  if ((resyncFn || reloadFn) && process.platform !== 'win32') {
    process.on('SIGHUP', async () => {
      // A SIGHUP racing an in-progress graceful shutdown must not re-arm the
      // engine the teardown is tearing down (reloadFn/resyncFn would re-open
      // the WebSocket and clear the state DB mid-stop). handleTerm sets this
      // synchronously on the first SIGTERM/SIGINT, so once shutdown has begun
      // the reload is a no-op. The engine-side resync() guard backs this up.
      if (_shuttingDown) {
        log.info('Ignoring SIGHUP — shutdown in progress');
        return;
      }
      log.info('Received SIGHUP — reloading config and triggering resync');
      // Reload config first so the resync sees the new ignore/include
      // patterns. A reload failure logs but doesn't block resync —
      // the old patterns stay in effect, daemon stays alive.
      if (reloadFn) {
        try { await reloadFn(); }
        catch (err) { log.warn('SIGHUP config reload failed; keeping previous patterns', { error: err.message }); }
      }
      if (resyncFn) {
        // Await so the try/catch actually catches a rejected resync (an
        // un-awaited call would escape to unhandledRejection) and so a
        // second SIGHUP serializes behind the first — the engine's
        // in-flight-promise guard makes the body itself idempotent, and
        // this await rides that same promise rather than interleaving a
        // fresh teardown mid-drain.
        try { await resyncFn(); }
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
