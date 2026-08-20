'use strict';

// codebase-patterns:allow-file console-direct — daemon lifecycle commands (start/stop/status banners) write directly to stdout/stderr; the structured logger lives downstream and isn't initialised until after writePid() succeeds.
// codebase-patterns:allow-file process-exit — daemonize/uncaught-exception paths intentionally terminate to surface a clean exit code; signal handling lives in b.appShutdown which already owns graceful teardown.
// codebase-patterns:allow-file sea-sigterm-bug — handleTerm composes b.appShutdown phase orchestration with explicit process.exit(0) after orchestrator.shutdown resolves. SEA-packaged Node has been observed to surface the signal default (exit 143 = 128 + SIGTERM) on SIGTERM-driven graceful shutdown despite the explicit process.exit(0). Container deployments remap via `tini -e 143` in the Dockerfile entrypoint; systemd units whitelist via `SuccessExitStatus=143 SIGTERM` in deploy/hermitstash-sync.service. The data-path teardown completes normally regardless of which exit code the supervisor records.

const nodeFs = require('node:fs');
const b = require('../vendor/blamejs');
const { PID_FILE, LOG_FILE, CONFIG_DIR, isSeaBinary } = require('./constants');
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

async function daemonize() {
  _ensureConfigDir();
  // Strip --daemon (so the child doesn't re-fork) and append --child so the
  // re-spawned worker is detectable in `ps` and via args. The args marker is
  // belt-and-suspenders for the env marker set just below.
  //
  // Argv shape differs by packaging: in a SEA binary Node inserts execPath at
  // argv[1] and user args begin at argv[2]; in source mode argv[1] is the
  // entry script and must be re-passed so the child re-runs it. Feeding the
  // SEA duplicate through (slice(1)) would make the child's dispatcher parse
  // the exec path as its command and die with "Unknown command" — the parent
  // would still print success. Same shape lib/updater.js uses for its
  // self-replace respawn.
  const userArgs = process.argv.slice(2).filter(a => a !== '--daemon');
  userArgs.push('--child');
  const args = isSeaBinary() ? userArgs : [process.argv[1], ...userArgs];
  // The detached child must see HERMITSTASH_SYNC_DAEMON=1 so cmdStart's
  // `isChild` resolves true — that disables the stdout log sink (otherwise the
  // POSIX child double-writes the log file with ANSI escapes) and suppresses
  // the foreground "Syncing..." banner. b.daemon.start spawns via
  // b.processSpawn.filteredEnv, which carries process.env through verbatim
  // except for secret-shaped names; this marker isn't secret-shaped, so
  // setting it on the parent's env here propagates it into the child.
  process.env.HERMITSTASH_SYNC_DAEMON = '1';                                    // allow:raw-process-env — child-marker handoff; filteredEnv carries it into the detached worker
  // b.daemon.start covers both platforms from one call. On win32 it spawns
  // with `stdio: "ignore"` + `windowsHide: true`, so the child holds no
  // inherited FDs to lose when the parent's handle closes. On POSIX it keeps
  // the log-FD-inherit pattern that lets a pre-logger boot panic reach the
  // log file.
  let handle;
  try {
    handle = b.daemon.start({
      command: process.execPath,
      args:    args,
      pidFile: PID_FILE,
      logFile: LOG_FILE,
      // Detach the child from the operator's launch directory so `start
      // --daemon` from a removable mount or NFS dir doesn't pin it forever.
      // Every path the daemon touches (config, state DB, sync folder, mTLS
      // material) is stored absolute, so the chdir is behavior-neutral.
      cwd: CONFIG_DIR,
    });
  } catch (err) {
    if (err && /already-running/.test(err.code || '')) {
      const existing = _readPid();
      console.error(`Daemon already running (PID ${existing || '?'})`);
      process.exit(1);
    }
    throw err;
  }
  // b.daemon.start now subscribes the child's async 'error' and throws on a
  // failed spawn (a bad command / unresolvable execPath) instead of writing an
  // undefined pid (blamejs v0.17.13+) — but it still has no post-spawn LIVENESS
  // probe, so a child that spawns cleanly then dies during boot (bad config,
  // argv bug, port clash) would leave the operator with a false "Daemon
  // started" and, on Windows (stdio 'ignore'), no trace at all. Poll the PID
  // briefly so an instantly-dying child fails loudly. Best-effort: a child that
  // dies later (e.g. keychain errors after this window) still needs `status`/the log.
  let alive = true;
  const probeDeadline = Date.now() + C.TIME.seconds(1);
  while (Date.now() < probeDeadline) {
    await b.safeAsync.sleep(C.TIME.seconds(0.1));
    try {
      process.kill(handle.pid, 0);
      alive = true;
    } catch (e) {
      alive = !!(e && e.code === 'EPERM'); // EPERM = alive but not ours
    }
    if (!alive) break;
  }
  if (!alive) {
    console.error(`Daemon child (PID ${handle.pid}) exited immediately after spawn.`);
    console.error(`Run "hermitstash-sync start" in the foreground to see the error, or check the log: ${LOG_FILE}`);
    try { if (nodeFs.existsSync(PID_FILE)) nodeFs.unlinkSync(PID_FILE); } catch (_e) { /* allow:silent-catch — stale-PID cleanup after failed spawn; next start re-checks liveness anyway */ }
    process.exit(1);
  }
  console.log(`Daemon started (PID ${handle.pid})`);
  console.log(`Log: ${LOG_FILE}`);
  console.log(`PID: ${PID_FILE}`);
  process.exit(0);
}

function _readPid() {
  try {
    // fd-safe read: symlink at the PID path refused, size-capped so a
    // corrupted/replaced file can't buffer unbounded bytes — the same read
    // posture the vendored daemon/stop path applies to its own pid reads.
    const raw = String(b.atomicFile.fdSafeReadSync(PID_FILE, {
      maxBytes: C.BYTES.kib(1),
      refuseSymlink: true,
    })).trim();
    const pid = parseInt(raw, 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
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

// Read-only liveness probe for the observability commands (status / stats).
// Unlike isRunning(), this NEVER unlinks a stale pidfile: `status` is documented
// as a Docker HEALTHCHECK / k8s-liveness / systemd probe, so a monitoring poll
// must not mutate lifecycle-visible state (a reaped sidecar would make a
// subsequent `stop` report 'No daemon running' instead of 'Cleared stale PID
// file'). b.daemon.status() reports a dead PID as { running:false, pid,
// reason:'stale' } and leaves the sidecar in place (stop() is the only reaper).
// Returns the SAME pid-or-false shape isRunning() returns so the callers'
// `=== process.pid` handoff exemption and printed-PID paths are unchanged; a
// live-but-not-ours process (EPERM) still reports its pid. Malformed opts throw
// daemon/bad-pid-file upstream; isRunning swallowed all errors to false, so
// preserve that fail-safe here.
function status() {
  let r;
  try {
    r = b.daemon.status({ pidFile: PID_FILE });
  } catch (_e) {
    return false;
  }
  return (r && r.running && r.pid) ? r.pid : false;
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
  // here. The pidfile already records the child's own PID, so the vendored
  // pidLock ADOPTS the existing inode in place (blamejs v0.17.13+) instead of
  // unlinking and O_EXCL-recreating it — closing the momentary no-pidfile
  // window the parent-handoff previously left open, in which a concurrent
  // `stop` racing that gap could observe no live owner and report 'No daemon
  // running'. The isRunning() guard in cmdStart still only prevents a second
  // `start` from launching and does not serialise against `stop`, but the
  // adopt path means the pidfile is never briefly absent for `stop` to misread.
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
    // graceMs is an equal-split NUMERATOR, not a wall budget: _runPhase caps
    // each phase at min(phase.timeoutMs, floor(remainingGrace/remainingPhases)).
    // At 30s the engine phase was silently clamped to 15s and its configured
    // 20s was dead config — every derived budget (SHUTDOWN_WALL_MS=22s, CLI
    // stop 30s, systemd TimeoutStopSec=30) assumes the 20s that never applied.
    // 40s is the minimal value that un-clamps it: engine min(20s, 40s/2)=20s,
    // pidfile min(1s, ~20s)=1s, worst case ~21s < SHUTDOWN_WALL_MS. With
    // installSignalHandlers:false the library's graceMs watchdog is never
    // armed, so this feeds ONLY the per-phase budgets — do not "fix" it back
    // down to match the wall caps.
    graceMs: C.TIME.seconds(40),
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
    let result;
    try {
      result = await Promise.race([orchestrator.shutdown(), wallTimeout]);
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
    // A phase that soft-timed-out (e.g. an engine drain cut at its budget)
    // resolves ok:false without throwing. Surface it durably before exit —
    // log.warn only queues on the async file sink, and log.close() may not
    // have run on this path, so drain with a bounded timeout the same way the
    // uncaughtException handler does. Exit stays 0: the supervisor contract
    // (SuccessExitStatus=143 SIGTERM, tini -e 143) whitelists only 0/143, and
    // a truncated drain is a delayed-upload condition the next boot's
    // reconcile retries — not a failed stop.
    if (result && result.ok === false) {
      log.warn('Graceful shutdown completed with a truncated phase (drain cut at its budget); pending transfers resume on next start', {
        phases: (result.phases || []).filter(p => p && p.ok === false).map(p => p.name),
      });
      try {
        await b.safeAsync.withTimeout(log.close(), C.TIME.seconds(2), { name: 'shutdown-warn-drain' });
      } catch (_e) { /* allow:silent-catch — best-effort log drain; exit regardless */ }
    }
    process.exit(0);
  }
  process.on('SIGTERM', () => handleTerm('SIGTERM'));
  process.on('SIGINT',  () => handleTerm('SIGINT'));

  // Windows cooperative-stop receiver. On Windows an external
  // process.kill(pid, 'SIGTERM') maps to TerminateProcess and never invokes the
  // JS SIGTERM handler above, so b.daemon.stop() requests a graceful stop by
  // writing a sibling <PID_FILE>.stop sentinel and polling for the daemon to
  // drain. We deliberately don't run the foreground path through b.daemon.start
  // (we own pidLock + appShutdown here for the exit-143 mitigation and
  // installSignalHandlers:false design), so b.daemon's own
  // _installStopSentinelWatcher never runs — install the receiver side here.
  // Poll existsSync on the sentinel every STOP_SENTINEL_POLL_MS and, on first
  // observation, remove it and route into the SAME handleTerm('SIGTERM') the
  // POSIX path uses so the engine drain + pidfile-release phases run (and
  // updater.markGracefulShutdown() semantics hold) — NOT a raw terminate.
  // Synchronous existsSync, NOT fs.watch: ReadDirectoryChangesW abort()s the
  // process on a Windows 8.3 short-name path (the shape of a temp/CONFIG dir),
  // which no try/catch can recover. The interval is unref'd so it never holds
  // the daemon alive, and it clears itself once shutdown begins.
  if (process.platform === 'win32') {
    const sentinelPath = PID_FILE + '.stop';
    const STOP_SENTINEL_POLL_MS = 250;
    let stopPoll = null;
    const pollStopSentinel = () => {
      if (_shuttingDown) { if (stopPoll) clearInterval(stopPoll); return; }
      let present = false;
      try { present = nodeFs.existsSync(sentinelPath); }
      catch (_e) { present = false; } // allow:silent-catch — a probe error is treated as "not requested"
      if (!present) return;
      if (stopPoll) clearInterval(stopPoll);
      // Best-effort remove so a later start doesn't observe a stale request;
      // b.daemon.stop also cleans it up on its side.
      try { nodeFs.unlinkSync(sentinelPath); } catch (_e) { /* allow:silent-catch — best-effort; may already be gone */ }
      log.info('Cooperative stop-request observed — initiating graceful shutdown');
      handleTerm('SIGTERM');
    };
    stopPoll = setInterval(pollStopSentinel, STOP_SENTINEL_POLL_MS);
    if (stopPoll && typeof stopPoll.unref === 'function') stopPoll.unref();
  }

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

  process.on('uncaughtException', async err => {
    log.error('Uncaught exception', err);
    removePid();
    // log.error only QUEUES the crash record on the async b.logStream file-sink
    // worker (fire-and-forget). A bare process.exit(1) terminates before that
    // microtask flushes, so the crash line never reaches the rotated log file —
    // the one durable place a post-mortem depends on (the daemon child has no
    // stdout sink at all). Drain the log stream first, capped by a wall-clock
    // timeout so a stuck sink can't hang the crash exit — b.safeAsync.withTimeout
    // rejects with async/timeout on the deadline, which the catch swallows so we
    // exit regardless. log.close() is idempotent, so a graceful phase that
    // already closed it makes this a no-op.
    try {
      await b.safeAsync.withTimeout(log.close(), C.TIME.seconds(2), { name: 'crash-log-drain' });
    } catch (_e) { /* allow:silent-catch — best-effort log drain on the crash path; exit regardless */ }
    process.exit(1);
  });

  process.on('unhandledRejection', err => {
    log.error('Unhandled rejection', err);
  });

  return orchestrator;
}

module.exports = { daemonize, isRunning, status, stop, writePid, removePid, installSignalHandlers };
