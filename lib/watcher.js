'use strict';

const path = require('node:path');
const { EventEmitter } = require('node:events');
const b = require('../vendor/blamejs');
const { WATCHER_DEBOUNCE_MS } = require('./constants');
const log = require('./logger');

const C = b.constants;
const DEFAULT_POLL_INTERVAL_MS = C.TIME.seconds(1);
const MIN_POLL_INTERVAL_MS = 100; // floor — sub-second poll cycle to keep desktop UX responsive without thrashing disk

// Resolve the watcher mode at module-load. Default `fs.watch` is the
// fastest backend on real Linux/macOS/Windows kernels, but it's silent
// on filesystems where the kernel→userspace event bridge doesn't
// exist:
//   - Docker Desktop bind-mounts on Windows / macOS hosts (gRPC-FUSE
//     / VirtioFS doesn't propagate inotify events through the VM
//     boundary)
//   - NFS / SMB mounts that don't fire change notifications
//   - Some FUSE filesystems
//
// `b.watcher` since v0.8.68 supports `mode: "poll"` which scans the
// tree on a fixed interval and diffs against the previous snapshot.
// Operators opt in via `HERMITSTASH_WATCHER_MODE=poll` (the
// `entrypoint.sh` in the Docker image flips this on automatically when
// it detects `/data` is a bind mount; native installs default to fs).
function _resolveMode() {
  var raw = b.safeEnv.readVar('HERMITSTASH_WATCHER_MODE', { type: 'string', default: '' }).toLowerCase().trim();
  return raw === 'poll' ? 'poll' : 'fs';
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
  constructor(syncFolder, ignorePatterns = []) {
    super();
    this._syncFolder = syncFolder;
    this._ignorePatterns = ignorePatterns;
    this._handle = null;
  }

  start() {
    if (this._handle) return;
    var mode = _resolveMode();
    var pollIntervalMs = _resolvePollIntervalMs();
    log.info('Starting file watcher', { folder: this._syncFolder, mode: mode, pollIntervalMs: mode === 'poll' ? pollIntervalMs : null });
    try {
      var opts = {
        root: this._syncFolder,
        debounceMs: WATCHER_DEBOUNCE_MS,
        audit: false,
        onChange: ev => {
          if (ev.type === 'dir') return;
          if (this._isIgnored(ev.relativePath)) return;
          this.emit('change', {
            type: 'change',
            relativePath: ev.relativePath.split(path.sep).join('/'),
            fullPath: ev.fullPath,
            size: ev.size,
            mtime: ev.mtime ? ev.mtime.getTime() : 0,
          });
        },
        onDelete: ev => {
          if (this._isIgnored(ev.relativePath)) return;
          this.emit('change', {
            type: 'delete',
            relativePath: ev.relativePath.split(path.sep).join('/'),
            fullPath: ev.fullPath,
          });
        },
        onError: err => {
          log.error('File watcher error', err);
          this.emit('error', err);
        },
      };
      if (mode === 'poll') {
        opts.mode = 'poll';
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

  isIgnored(relativePath) {
    return this._isIgnored(relativePath);
  }

  _isIgnored(relativePath) {
    const normalized = relativePath.split(path.sep).join('/');
    for (const pattern of this._ignorePatterns) {
      if (this._matchPattern(normalized, pattern)) return true;
    }
    return false;
  }

  _matchPattern(filepath, pattern) {
    if (filepath === pattern) return true;

    if (!pattern.includes('/')) {
      const basename = path.basename(filepath);
      if (basename === pattern) return true;
      if (pattern.startsWith('*.')) {
        const ext = pattern.slice(1);
        if (basename.endsWith(ext)) return true;
      }
      if (pattern === '*~' && basename.endsWith('~')) return true;
      return false;
    }

    if (pattern.endsWith('/**')) {
      const dir = pattern.slice(0, -3);
      if (filepath.startsWith(dir + '/') || filepath === dir) return true;
      return false;
    }

    return false;
  }
}

module.exports = Watcher;
