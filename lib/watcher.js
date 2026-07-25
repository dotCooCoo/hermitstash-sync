'use strict';

const nodePath = require('node:path');
const { EventEmitter } = require('node:events');
const b = require('../vendor/blamejs');
const { WATCHER_DEBOUNCE_MS } = require('./constants');
const log = require('./logger');
const pathFilter = require('./path-filter');

const C = b.constants;
const DEFAULT_POLL_INTERVAL_MS = C.TIME.seconds(1);

// b.watcher.create's _compileIgnore caps, consumed from the exported
// constants (vendor/blamejs/lib/watcher.js MAX_IGNORE_PATTERN_LEN /
// MAX_IGNORE_STAR_COUNT — exported since blamejs v0.17.13). Consuming the
// exported values instead of re-pinning a literal here means the mirror can
// never drift from the vendored source. A forwarded ignore pattern past either
// cap makes b.watcher.create throw `watcher/bad-ignore` SYNCHRONOUSLY — which
// would abort the initial (unguarded) start() or drive the SIGHUP recovery
// loop to a permanent 'degraded' state. Forwarding is only the walk-prune
// optimization (the hook-side _shouldSync still enforces the FULL ignore set),
// so an over-cap pattern is dropped from the forwarded subset rather than
// allowed to kill the whole watcher. Length is measured in UTF-16 code units to
// match b.watcher's own `p.length` check (NOT Buffer.byteLength).
const WATCHER_IGNORE_MAX_LEN = b.watcher.MAX_IGNORE_PATTERN_LEN;
const WATCHER_IGNORE_MAX_STARS = b.watcher.MAX_IGNORE_STAR_COUNT;

// Byte cap for a watcher tunable env value. These are small integers or a
// 3-word enum, so a deliberate tightening from the 64 KiB framework default
// — anything past this is operator error and degrades to the default.
const WATCHER_ENV_MAX_BYTES = C.BYTES.bytes(256);

// Canonical Unicode form for an emitted relativePath. macOS (and any
// NFD-surfacing volume) hands back decomposed names from readdir; the
// server and most other platforms store the composed (NFC) form. Emitting
// the raw decomposed bytes would make the same file render as a distinct
// key from its server-side identity and churn as a phantom remove + add.
// Normalizing here keeps the path identity byte-stable from the watcher
// boundary inward.
function _nfc(relativePath) {
  return typeof relativePath === 'string' ? relativePath.normalize('NFC') : relativePath;
}
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
// rather than treating it as a transient blip. b.watcher marks a genuinely
// fatal runtime error with `err.fatal === true`; _onWatcherError treats that
// flag as authoritative (future-proof against new upstream fatal codes) and
// this set is the explicit, documented roster of the codes that carry it:
//   - watcher/handle-dead — fs backend native handle died (EPERM/EBADF/ENOSPC/
//     EMFILE/ENFILE/EACCES); change detection is off until re-created.
//   - watcher/root-lost   — poll backend can no longer read the watched root.
//   - watcher/overflow, watcher/poll-overflow — event-storm / poll-walk cap hit;
//     b.watcher self-stops the handle.
// (watcher/start-failed and watcher/recursive-unsupported are thrown
// SYNCHRONOUSLY from create() and caught by start()'s try/catch, so they never
// reach onError — kept here only for documentation; they are harmless no-ops on
// this channel.)
const FATAL_WATCHER_CODES = new Set([
  'watcher/handle-dead',
  'watcher/root-lost',
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
// Read a watcher tunable, degrading to the documented default on a
// malformed value rather than hard-failing watcher start(). These tunables
// are small integers or a 3-word enum, so a value past 256 bytes is
// operator error — b.safeEnv.readVar throws `env/too-large` above its cap
// (and would throw on a future enum/required opt too), which without this
// catch would propagate out of _buildOpts() → start() and leave local
// change detection permanently off. The maxBytes:256 floor is a deliberate
// tightening from the 64 KiB framework default for these small scalars.
function _readEnvRaw(name) {
  try {
    return b.safeEnv.readVar(name, { type: 'string', default: '', maxBytes: WATCHER_ENV_MAX_BYTES });
  } catch (_e) {
    log.warn('Ignoring malformed ' + name + ' env value; using default', _e);
    return '';
  }
}

function _resolveMode() {
  var raw = _readEnvRaw('HERMITSTASH_WATCHER_MODE').toLowerCase().trim();
  if (raw === 'poll' || raw === 'fs' || raw === 'auto') return raw;
  return 'auto';
}
function _resolvePollIntervalMs() {
  var raw = parseInt(_readEnvRaw('HERMITSTASH_WATCHER_POLL_INTERVAL_MS'), 10);
  return (Number.isFinite(raw) && raw >= MIN_POLL_INTERVAL_MS) ? raw : DEFAULT_POLL_INTERVAL_MS;
}

// Pending-event ceiling before the underlying watcher self-terminates on
// an event storm. Tunable so an operator with a legitimately bursty tree
// can raise it instead of losing change detection. Positive-int floor;
// undefined (default) lets b.watcher apply its own DEFAULT_MAX_PENDING.
function _resolveMaxPending() {
  var raw = parseInt(_readEnvRaw('HERMITSTASH_WATCHER_MAX_PENDING'), 10);
  return (Number.isFinite(raw) && raw >= 1) ? raw : null;
}

// Per-tick poll-walk file cap. Raising it lets operators with a
// legitimately huge in-scope tree avoid the poll-overflow stop, but the
// dir/** ignore-forwarding below is the primary defence — it stops the
// walk descending into node_modules/.git entirely. Positive-int floor;
// undefined lets b.watcher apply its own DEFAULT_POLL_MAX_FILES.
function _resolvePollMaxFiles() {
  var raw = parseInt(_readEnvRaw('HERMITSTASH_WATCHER_POLL_MAX_FILES'), 10);
  return (Number.isFinite(raw) && raw >= 1) ? raw : null;
}

// The subtree-exclude subset of the ignore patterns — the shapes worth
// forwarding to b.watcher's `ignore` so the poll walk (and the fs.watch
// dispatch) skips whole subtrees (node_modules/**, .git/**, data/cache, …)
// before stat'ing them, instead of counting their files toward the
// poll-overflow ceiling. path-filter classifies exactly two shapes as a
// subtree exclude: 'recursive-dir' (foo/**) and 'path-qualified'
// (data/cache — matched at a path-segment boundary, which operators
// routinely write without the trailing /**). b.watcher prunes both at the
// walk boundary (prefix-glob and exact-dir respectively). Reusing
// classifyPattern keeps the forwarded set exactly aligned with _shouldSync's
// exclude semantics and never wider, so a sibling like data/cache.txt is
// never pruned. Basename / *.ext / *~ patterns are NOT subtree excludes and
// stay on the hook-side _shouldSync filter, whose semantics are richer than
// blamejs's basename-glob and must remain the source of truth for what syncs.
function _dirPrefixIgnores(patterns) {
  if (!Array.isArray(patterns)) return [];
  const out = [];
  const seen = new Set();
  for (const p of patterns) {
    const kind = pathFilter.classifyPattern(p);
    if (kind !== 'recursive-dir' && kind !== 'path-qualified') continue;
    // classifyPattern only returns these two kinds for a non-empty string, so
    // p.normalize() below is safe. Forward BOTH the composed (NFC) and
    // decomposed (NFD) Unicode forms of each subtree pattern so b.watcher's
    // poll walk prunes the ignored subtree whether the on-disk dir entry
    // surfaces as NFC (most platforms) or NFD (macOS/APFS + some SMB mounts).
    // The hook-side _shouldSync stays authoritative and NFC-normalizes the
    // event path, so a raw path matching either forwarded form is Unicode-
    // canonical-equivalent to the ignored subtree and would be dropped there
    // too — b.watcher can never over-prune a path the operator meant to keep.
    // NFD/NFC expansion is a no-op for ASCII patterns (dedup collapses them).
    // Case folding on a case-insensitive volume is handled by forwarding
    // `ignoreCaseFold: this._caseFolds` to b.watcher.create (v0.17.13+): the
    // framework folds BOTH the pattern and the walked path to lower case, so an
    // on-disk 'Node_Modules' is pruned by a 'node_modules/**' ignore. The prior
    // manual lowercase-pattern forwarding here was an incomplete mitigation —
    // it lowercased the pattern but not the walked path, so the poll-prune
    // (case-sensitive at the time) still missed the mixed-case directory; the
    // native option supersedes it and closes the gap fully.
    //
    // Fold a Windows-style backslash separator to '/' FIRST — b.watcher's
    // poll-prune compares against a path it has already split on the OS path
    // separator and re-joined with '/', so a raw 'data\cache' pattern would never match
    // and the subtree would go un-pruned (toward pollMaxFiles → poll-overflow).
    // path-filter's classifyPattern + matchAny fold the same '\\'→'/' before
    // matching, so the hook-side _shouldSync already treats 'data\cache' as
    // 'data/cache' — normalizing here keeps the forwarded set exactly ALIGNED
    // with _shouldSync (never wider), so it can never over-prune a path the
    // operator meant to keep.
    const slashed = p.split('\\').join('/');
    const forms = [slashed, slashed.normalize('NFC'), slashed.normalize('NFD')];
    for (const form of forms) {
      if (seen.has(form)) continue;
      // Drop any form b.watcher.create's _compileIgnore would reject — an
      // over-cap forward throws `watcher/bad-ignore` synchronously and takes
      // down the whole watcher (see the cap constants above). NFD expansion
      // can push a near-cap pattern over the length limit, so cap AFTER
      // normalizing each form.
      if (form.length === 0 || form.length > WATCHER_IGNORE_MAX_LEN) continue;
      let stars = 0;
      for (let i = 0; i < form.length; i += 1) if (form.charCodeAt(i) === 42 /* '*' */) stars += 1;
      if (stars > WATCHER_IGNORE_MAX_STARS) continue;
      seen.add(form);
      out.push(form);
    }
  }
  return out;
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
  constructor(syncFolder, ignorePatterns = [], includePatterns = [], caseFolds = false) {
    super();
    this._syncFolder = syncFolder;
    this._ignorePatterns = ignorePatterns;
    this._includePatterns = includePatterns;
    // Whether the sync folder lives on a case-insensitive filesystem. The
    // engine probes this once and passes it in so ignore/include matching
    // folds case identically to the state-DB identity layer. Defaults OFF
    // (byte-exact, Linux-correct) when the caller doesn't supply it.
    this._caseFolds = caseFolds;
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
      // On a case-insensitive volume, have b.watcher fold BOTH the forwarded
      // ignore patterns and the walked path to lower case (v0.17.13+), so the
      // poll-prune skips a mixed-case on-disk directory (e.g. 'Node_Modules'
      // pruned by 'node_modules/**'). Correctness still rests on the hook-side
      // _shouldSync, which folds case independently; this only aligns the
      // walk-prune so the overflow defence isn't defeated by a casing mismatch.
      ignoreCaseFold: this._caseFolds,
      onChange: ev => {
        if (ev.type === 'dir') return;
        // Normalize once and filter on the NFC path so a non-ASCII
        // ignore/include pattern (stored NFC) matches the live event the
        // same way the rescan walk filters its NFC'd path. fullPath stays
        // the raw on-disk byte path used for hashing.
        var relativePath = _nfc(ev.relativePath.split(nodePath.sep).join('/'));
        if (!this._shouldSync(relativePath)) return;
        this.emit('change', {
          type: 'change',
          relativePath: relativePath,
          fullPath: ev.fullPath,
          size: ev.size,
          mtime: ev.mtime ? ev.mtime.getTime() : 0,
        });
      },
      onDelete: ev => {
        // Normalize once and filter on the NFC path — see onChange.
        var relativePath = _nfc(ev.relativePath.split(nodePath.sep).join('/'));
        if (!this._shouldSync(relativePath)) return;
        this.emit('change', {
          type: 'delete',
          relativePath: relativePath,
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
    // Treat b.watcher's `err.fatal` flag as authoritative (it is set on every
    // runtime-fatal signal the onError channel delivers — watcher/handle-dead,
    // watcher/root-lost, the overflow codes) so a future upstream fatal code is
    // recovered even before its string is added to the set. The code-set check
    // is the belt-and-suspenders fallback for any fatal error that ever arrives
    // without the flag.
    if ((err && err.fatal === true) || FATAL_WATCHER_CODES.has(code)) {
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
    if (!changed || this._stopped) return;
    // The forwarded subtree set actually changed and the watcher isn't
    // operator-stopped. Two cases:
    //   - live handle: bounce it (stop + start) so the next walk re-skips the
    //     updated subtree set.
    //   - no handle because recovery exhausted its budget and gave up
    //     (degraded: _handle null, _stopped false): re-arm it. This is the
    //     live-reload remediation the degraded-state error advertises ("narrow
    //     your ignore patterns"); it was previously a no-op because the restart
    //     was gated on a live handle, leaving local change detection off until
    //     a full daemon restart. The re-arm branch zeroes _recoveryAttempts
    //     before start() (below) so the freshly-narrowed config gets a full
    //     retry budget even if its first create() throws.
    if (this._handle) {
      log.info('Watcher ignore subtrees changed — restarting watcher to re-skip', {
        ignoredSubtrees: this._dirIgnores.length,
      });
      try { this._handle.stop(); } catch (_e) {} // allow:silent-catch — idempotent
      this._handle = null;
    } else {
      log.info('Re-arming the file watcher from a degraded state after an ignore-pattern change', {
        ignoredSubtrees: this._dirIgnores.length,
      });
      // Clear any residual recovery bookkeeping so start() begins clean. In the
      // degraded state _recovering is already false and no recovery timer is
      // armed (the cap short-circuits _scheduleRecovery), but guard defensively.
      this._recovering = false;
      if (this._recoveryTimer) {
        try { clearTimeout(this._recoveryTimer); } catch (_e) {} // allow:silent-catch — best-effort
        this._recoveryTimer = null;
      }
      // Reset the attempt counter HERE, before start(). start() only zeroes it
      // AFTER a successful b.watcher.create; if this re-arm's create throws
      // (e.g. the root is still briefly unavailable), the catch below routes to
      // _scheduleRecovery which — with the counter still at MAX from the prior
      // exhaustion — would immediately re-degrade with zero backoff retries.
      // Zeroing it up front gives the freshly-narrowed config the full
      // RECOVERY_BACKOFF_MS budget this branch's log line promises.
      this._recoveryAttempts = 0;
    }
    try {
      this.start();
    } catch (err) {
      // start() rethrows on a b.watcher.create failure. Route it into the
      // recovery state machine instead of letting it propagate to the
      // SIGHUP caller (which would log a misleading 'keeping previous
      // patterns' while leaving the watcher permanently dead). Mirror the
      // fatal-error path in _onWatcherError: drop the handle, surface the
      // degraded signal via 'fatal', and let the bounded-backoff machine
      // retry the re-create.
      this._handle = null;
      this.emit('fatal', err);
      this._scheduleRecovery();
      return;
    }
    // The fresh handle starts from a clean baseline and never replays
    // events that fired during the stop/start bounce window. Emit
    // 'rescan' (mirroring _recreate) so the engine re-walks the synced
    // folder and re-detects any local-only file changed during the
    // bounce — a config-driven reload otherwise loses those silently,
    // since a bundleId-only resync skips the local-upload scan.
    this.emit('rescan');
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
    return pathFilter.isIgnored(relativePath, this._ignorePatterns, this._caseFolds);
  }

  _shouldSync(relativePath) {
    return pathFilter.shouldSync(relativePath, {
      include:  this._includePatterns,
      ignore:   this._ignorePatterns,
      caseFold: this._caseFolds,
    });
  }
}

module.exports = Watcher;
