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

// b.watcher owns fs.watch + cross-platform event coalescing + symlink
// rejection + debounce. We wrap it in an EventEmitter and keep our own
// ignore-pattern matcher so DEFAULT_IGNORES semantics (basename-anywhere
// for filename-only patterns, dir/** prefix, *.ext) stay byte-identical
// to pre-blamejs behavior — b.watcher's own ignore dialect is glob-only
// and would change which files get synced. Pass [] to b.watcher and
// filter the events here.
class Watcher extends EventEmitter {
  constructor(syncFolder, ignorePatterns = [], includePatterns = []) {
    super();
    this._syncFolder = syncFolder;
    this._ignorePatterns = ignorePatterns;
    this._includePatterns = includePatterns;
    this._handle = null;
  }

  start() {
    if (this._handle) return;
    var mode = _resolveMode();
    var pollIntervalMs = _resolvePollIntervalMs();
    log.info('Starting file watcher', {
      folder: this._syncFolder,
      mode: mode,
      pollIntervalMs: mode === 'fs' ? null : pollIntervalMs,
    });
    try {
      var opts = {
        root: this._syncFolder,
        debounceMs: WATCHER_DEBOUNCE_MS,
        audit: false,
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
        onError: err => {
          log.error('File watcher error', err);
          this.emit('error', err);
        },
      };
      opts.mode = mode;
      if (mode === 'poll' || mode === 'auto') {
        // pollIntervalMs is consumed by both modes — "auto" only honors
        // it when it falls back to poll.
        opts.pollIntervalMs = pollIntervalMs;
      }
      this._handle = b.watcher.create(opts);
    } catch (err) {
      log.error('Failed to start file watcher', err);
      throw err;
    }
  }

  stop() {
    if (this._handle) {
      try { this._handle.stop(); } catch (_e) {} // allow:silent-catch — watcher teardown is idempotent; b.watcher swallows double-stop internally
      this._handle = null;
    }
    log.info('File watcher stopped');
  }

  // Runtime pattern reload — called by the sync engine on SIGHUP so a
  // user editing config.ignore / config.include doesn't have to bounce
  // the daemon. Pure setter; matching is per-call so the next event
  // uses the new arrays.
  updatePatterns(ignorePatterns, includePatterns) {
    this._ignorePatterns = ignorePatterns || [];
    this._includePatterns = includePatterns || [];
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
