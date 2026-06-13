'use strict';

const nodePath = require('node:path');
const { EventEmitter } = require('node:events');
const b = require('../vendor/blamejs');
const { WATCHER_DEBOUNCE_MS } = require('./constants');
const log = require('./logger');
const pathFilter = require('./path-filter');

const C = b.constants;
const DEFAULT_POLL_INTERVAL_MS = C.TIME.seconds(1);
const MIN_POLL_INTERVAL_MS = 100; // floor — sub-second poll cycle to keep desktop UX responsive without thrashing disk

// Bounded backoff for re-creating the underlying handle after a fatal
// watcher stop. The first retry is near-immediate; subsequent retries
// back off so a root that keeps overflowing doesn't spin. After
// MAX_RECOVERY_ATTEMPTS consecutive failures the wrapper stays down with
// an actionable message rather than looping forever.
const RECOVERY_BACKOFF_MS = Object.freeze([
  C.TIME.seconds(0.5), C.TIME.seconds(2), C.TIME.seconds(5), C.TIME.seconds(15),
]);
const MAX_RECOVERY_ATTEMPTS = RECOVERY_BACKOFF_MS.length;
// A restarted handle is only declared healthy (and the attempt counter
// reset) after it survives this window. Without it, a tree that
// re-overflows the instant it restarts would reset the counter on every
// create and loop forever instead of settling into the degraded state.
const RECOVERY_STABLE_MS = C.TIME.seconds(30);

// Fatal watcher error codes — the underlying b.watcher handle is stopped
// (or never started) by the time onError fires with one of these, so the
// wrapper must re-create the handle to keep detecting local changes
// rather than treating it as a transient blip.
const FATAL_WATCHER_CODES = new Set([
  'watcher/overflow',
  'watcher/poll-overflow',
  'watcher/start-failed',
  'watcher/recursive-unsupported',
]);

// Resolve the watcher mode at module-load. `fs.watch` is the fastest
// backend on real Linux/macOS/Windows kernels, but it's silent on
// filesystems where the kernel→userspace event bridge doesn't exist:
//   - Docker Desktop bind-mounts on Windows / macOS hosts (gRPC-FUSE
//     / VirtioFS doesn't propagate inotify events through the VM
//     boundary)
//   - NFS / SMB mounts that don't fire change notifications
//   - Some FUSE filesystems
//
// blamejs v0.9.43+ ships `b.watcher.create({ mode: "auto" })`, which
// reads /proc/self/mountinfo + checks /.dockerenv to auto-fall-back
// to poll when the underlying fstype is non-inotify (fuse / virtiofs
// / 9p / nfs / cifs / smbfs) or when /data is a Docker bind-mount.
// That replaces the explicit env-var dance we used to do (the Docker
// entrypoint flipped `HERMITSTASH_WATCHER_MODE=poll` by hand).
//
// HERMITSTASH_WATCHER_MODE accepts:
//   - "auto" (default) — let blamejs decide. Best for most deployments.
//   - "poll" — force poll mode regardless of fstype.
//   - "fs"   — force native fs.watch regardless of fstype.
function _resolveMode() {
  var raw = b.safeEnv.readVar('HERMITSTASH_WATCHER_MODE', { type: 'string', default: '' }).toLowerCase().trim();
  if (raw === 'poll' || raw === 'fs' || raw === 'auto') return raw;
  return 'auto';
}
function _resolvePollIntervalMs() {
  var raw = parseInt(b.safeEnv.readVar('HERMITSTASH_WATCHER_POLL_INTERVAL_MS', { type: 'string', default: '' }), 10);
  return (Number.isFinite(raw) && raw >= MIN_POLL_INTERVAL_MS) ? raw : DEFAULT_POLL_INTERVAL_MS;
}

// Pending-event ceiling before the underlying watcher self-terminates on
// an event storm. Tunable so an operator with a legitimately bursty tree
// can raise it instead of losing change detection. Positive-int floor;
// undefined (default) lets b.watcher apply its own DEFAULT_MAX_PENDING.
function _resolveMaxPending() {
  var raw = parseInt(b.safeEnv.readVar('HERMITSTASH_WATCHER_MAX_PENDING', { type: 'string', default: '' }), 10);
  return (Number.isFinite(raw) && raw >= 1) ? raw : null;
}

// Per-tick poll-walk file cap. Raising it lets operators with a
// legitimately huge in-scope tree avoid the poll-overflow stop, but the
// dir/** ignore-forwarding below is the primary defence — it stops the
// walk descending into node_modules/.git entirely. Positive-int floor;
// undefined lets b.watcher apply its own DEFAULT_POLL_MAX_FILES.
function _resolvePollMaxFiles() {
  var raw = parseInt(b.safeEnv.readVar('HERMITSTASH_WATCHER_POLL_MAX_FILES', { type: 'string', default: '' }), 10);
  return (Number.isFinite(raw) && raw >= 1) ? raw : null;
}

// The dir/**-shaped subset of the ignore patterns — the only shape
// b.watcher's prefix-glob `ignore` dialect understands, and the only one
// worth forwarding: it lets the poll walk (and the fs.watch dispatch)
// skip whole subtrees (node_modules/**, .git/**, …) before stat'ing
// them. Basename / *.ext / *~ patterns stay on the hook-side _shouldSync
// filter, whose semantics are richer than blamejs's basename-glob and
// must remain the source of truth for what actually syncs.
function _dirPrefixIgnores(patterns) {
  if (!Array.isArray(patterns)) return [];
  return patterns.filter(p => typeof p === 'string' && p.endsWith('/**') && p.indexOf('*') === p.length - 2);
}

// b.watcher owns fs.watch + cross-platform event coalescing + symlink
// rejection + debounce. We wrap it in an EventEmitter and keep our own
// ignore-pattern matcher so DEFAULT_IGNORES semantics (basename-anywhere
// for filename-only patterns, dir/** prefix, *.ext) stay byte-identical
// to pre-blamejs behavior — b.watcher's own ignore dialect is glob-only
// and would change which files get synced. We DO forward the dir/**
// subset to b.watcher so the walk stops descending into ignored
// subtrees, then filter the surviving events here.
class Watcher extends EventEmitter {
  constructor(syncFolder, ignorePatterns = [], includePatterns = []) {
    super();
    this._syncFolder = syncFolder;
    this._ignorePatterns = ignorePatterns;
    this._includePatterns = includePatterns;
    this._handle = null;
    this._stopped = false;          // operator-requested stop — suppresses self-recovery
    this._recovering = false;       // a recovery re-create is scheduled / in flight
    this._recoveryAttempts = 0;     // consecutive recovery cycles since the last healthy window
    this._recoveryTimer = null;
    this._stableTimer = null;       // confirms a restarted handle survived RECOVERY_STABLE_MS
    this._dirIgnores = _dirPrefixIgnores(ignorePatterns); // last-forwarded dir/** subset
  }

  _buildOpts() {
    var mode = _resolveMode();
    var pollIntervalMs = _resolvePollIntervalMs();
    var maxPending = _resolveMaxPending();
    var pollMaxFiles = _resolvePollMaxFiles();
    var opts = {
      root: this._syncFolder,
      debounceMs: WATCHER_DEBOUNCE_MS,
      audit: false,
      // Forward only the dir/** subset — byte-compatible with b.watcher's
      // prefix-glob dialect. The hook-side _shouldSync below stays the
      // authoritative emit filter.
      ignore: this._dirIgnores,
      onChange: ev => {
        if (ev.type === 'dir') return;
        if (!this._shouldSync(ev.relativePath)) return;
        this.emit('change', {
          type: 'change',
          relativePath: ev.relativePath.split(nodePath.sep).join('/'),
          fullPath: ev.fullPath,
          size: ev.size,
          mtime: ev.mtime ? ev.mtime.getTime() : 0,
        });
      },
      onDelete: ev => {
        if (!this._shouldSync(ev.relativePath)) return;
        this.emit('change', {
          type: 'delete',
          relativePath: ev.relativePath.split(nodePath.sep).join('/'),
          fullPath: ev.fullPath,
        });
      },
      onError: err => this._onWatcherError(err),
    };
    opts.mode = mode;
    if (mode === 'poll' || mode === 'auto') {
      // pollIntervalMs is consumed by both modes — "auto" only honors
      // it when it falls back to poll.
      opts.pollIntervalMs = pollIntervalMs;
      if (pollMaxFiles !== null) opts.pollMaxFiles = pollMaxFiles;
    }
    if (maxPending !== null) opts.maxPending = maxPending;
    return opts;
  }

  start() {
    if (this._handle) return;
    this._stopped = false;
    var opts = this._buildOpts();
    log.info('Starting file watcher', {
      folder: this._syncFolder,
      mode: opts.mode,
      pollIntervalMs: opts.mode === 'fs' ? null : opts.pollIntervalMs,
      ignoredSubtrees: this._dirIgnores.length,
    });
    try {
      this._handle = b.watcher.create(opts);
      // A clean start clears any prior recovery state.
      this._recoveryAttempts = 0;
    } catch (err) {
      log.error('Failed to start file watcher', err);
      throw err;
    }
  }

  // Classify the underlying watcher's error. Fatal codes mean the handle
  // has already stopped (or never started) — local change detection is
  // now dead, so the wrapper re-creates the handle after a bounded
  // backoff and emits a distinct 'fatal' event with an actionable
  // message. Non-fatal codes stay on the transient 'error' channel and
  // do not trigger a re-create (the handle is still live).
  _onWatcherError(err) {
    var code = err && err.code;
    // After an operator stop() the wrapper is torn down — a late error from
    // a socket / fd closing is expected. Swallow it at debug rather than
    // re-surfacing as an 'error' (which would throw with no listener) or
    // triggering a recovery the operator explicitly stopped.
    if (this._stopped) {
      log.debug('File watcher error after stop (ignored)', err);
      return;
    }
    if (FATAL_WATCHER_CODES.has(code)) {
      var maxPending = _resolveMaxPending();
      var ceiling = maxPending !== null ? maxPending : 'its internal';
      log.error(
        'File watcher stopped after a fatal error (' + code + '). ' +
        'Local changes are no longer being detected until it restarts. ' +
        'If this recurs, raise HERMITSTASH_WATCHER_MAX_PENDING (current ceiling: ' + ceiling + '), ' +
        'narrow your ignore patterns, or restart the daemon.',
        err
      );
      // Drop the dead handle so start()/_recreate()'s guard doesn't block
      // the re-create. maxPending-overflow self-stops inside b.watcher, and
      // start-failed / recursive-unsupported never produced a handle — but
      // a poll-overflow leaves the handle's poll timer still ticking, so
      // stop() it explicitly (idempotent) before nulling to avoid orphaning
      // that timer across the restart.
      if (this._handle) {
        try { this._handle.stop(); } catch (_e) {} // allow:silent-catch — idempotent; b.watcher swallows double-stop
      }
      this._handle = null;
      // A fatal stop within the post-restart window means the last
      // restart wasn't stable — cancel the pending healthy-reset so the
      // attempt counter keeps climbing toward the cap.
      if (this._stableTimer) {
        try { clearTimeout(this._stableTimer); } catch (_e) {} // allow:silent-catch — best-effort
        this._stableTimer = null;
      }
      // Distinct fatal event — a listener may surface a degraded status /
      // emit a metric. Recovery does NOT depend on a listener; the
      // wrapper restarts itself regardless.
      this.emit('fatal', err);
      this._scheduleRecovery();
      return;
    }
    // Transient — keep the existing log + 'error' surface unchanged.
    log.error('File watcher error', err);
    this.emit('error', err);
  }

  _scheduleRecovery() {
    if (this._stopped || this._recovering || this._handle) return;
    if (this._recoveryAttempts >= MAX_RECOVERY_ATTEMPTS) {
      log.error(
        'File watcher could not be restarted after ' + MAX_RECOVERY_ATTEMPTS + ' attempts. ' +
        'Local change detection is OFF — restart the daemon, narrow your ignore ' +
        'patterns, or raise HERMITSTASH_WATCHER_MAX_PENDING.'
      );
      this.emit('degraded');
      return;
    }
    this._recovering = true;
    var delay = RECOVERY_BACKOFF_MS[this._recoveryAttempts] || RECOVERY_BACKOFF_MS[RECOVERY_BACKOFF_MS.length - 1];
    this._recoveryTimer = setTimeout(() => {
      this._recoveryTimer = null;
      this._recovering = false;
      this._recreate();
    }, delay);
    if (this._recoveryTimer && typeof this._recoveryTimer.unref === 'function') this._recoveryTimer.unref();
  }

  // Re-create the underlying handle after a fatal stop. On success the
  // watcher establishes a fresh baseline (it won't replay pre-restart
  // events), so we emit 'rescan' to let a listener reconcile any local
  // changes missed during the dead window. The attempt counter is only
  // reset once the fresh handle survives RECOVERY_STABLE_MS — a handle
  // that immediately re-overflows keeps counting toward the cap so the
  // watcher settles into the degraded state instead of looping. On a
  // create failure we count the attempt and back off again.
  _recreate() {
    if (this._stopped || this._handle) return;
    this._recoveryAttempts += 1;
    var attempt = this._recoveryAttempts;
    try {
      // Re-derive opts at re-create time so a config edit (new ignores,
      // raised maxPending) that arrived during the dead window takes
      // effect on the fresh handle.
      this._dirIgnores = _dirPrefixIgnores(this._ignorePatterns);
      this._handle = b.watcher.create(this._buildOpts());
      log.info('File watcher restarted after a fatal error', { folder: this._syncFolder, attempt: attempt });
      this.emit('rescan');
      if (this._stableTimer) { try { clearTimeout(this._stableTimer); } catch (_e) {} } // allow:silent-catch — best-effort
      this._stableTimer = setTimeout(() => {
        this._stableTimer = null;
        // Survived the window without another fatal stop — healthy again.
        if (this._handle && !this._stopped) this._recoveryAttempts = 0;
      }, RECOVERY_STABLE_MS);
      if (this._stableTimer && typeof this._stableTimer.unref === 'function') this._stableTimer.unref();
    } catch (err) {
      log.error('File watcher restart attempt ' + attempt + ' failed', err);
      this._scheduleRecovery();
    }
  }

  stop() {
    this._stopped = true;
    if (this._recoveryTimer) {
      try { clearTimeout(this._recoveryTimer); } catch (_e) {} // allow:silent-catch — timer teardown is best-effort
      this._recoveryTimer = null;
    }
    if (this._stableTimer) {
      try { clearTimeout(this._stableTimer); } catch (_e) {} // allow:silent-catch — timer teardown is best-effort
      this._stableTimer = null;
    }
    this._recovering = false;
    if (this._handle) {
      try { this._handle.stop(); } catch (_e) {} // allow:silent-catch — watcher teardown is idempotent; b.watcher swallows double-stop internally
      this._handle = null;
    }
    log.info('File watcher stopped');
  }

  // Runtime pattern reload — called by the sync engine on SIGHUP so a
  // user editing config.ignore / config.include doesn't have to bounce
  // the daemon. The hook-side arrays are pure setters (matching is
  // per-call). The dir/** subset is forwarded to the underlying handle
  // at create-time only — b.watcher has no live ignore setter — so if
  // that subset actually changed, bounce the handle (stop + start) to
  // re-skip the right subtrees on the next walk. Gate on a real change
  // to avoid churn on edits that only touch basename / *.ext patterns.
  updatePatterns(ignorePatterns, includePatterns) {
    this._ignorePatterns = ignorePatterns || [];
    this._includePatterns = includePatterns || [];
    var nextDirIgnores = _dirPrefixIgnores(this._ignorePatterns);
    var changed = nextDirIgnores.length !== this._dirIgnores.length ||
      nextDirIgnores.some((p, i) => p !== this._dirIgnores[i]);
    this._dirIgnores = nextDirIgnores;
    if (changed && this._handle && !this._stopped) {
      log.info('Watcher ignore subtrees changed — restarting watcher to re-skip', {
        ignoredSubtrees: this._dirIgnores.length,
      });
      try { this._handle.stop(); } catch (_e) {} // allow:silent-catch — idempotent
      this._handle = null;
      this.start();
    }
  }

  isIgnored(relativePath) {
    return this._isIgnored(relativePath);
  }

  // Combined "should this path be synced" filter — true iff the path
  // is in scope (include empty OR matches an include pattern) AND not
  // ignored. Used by the watcher's onChange/onDelete hooks and by the
  // sync engine's initial-scan walkDir filter.
  shouldSync(relativePath) {
    return this._shouldSync(relativePath);
  }

  _isIgnored(relativePath) {
    return pathFilter.isIgnored(relativePath, this._ignorePatterns);
  }

  _shouldSync(relativePath) {
    return pathFilter.shouldSync(relativePath, {
      include: this._includePatterns,
      ignore:  this._ignorePatterns,
    });
  }
}

module.exports = Watcher;
