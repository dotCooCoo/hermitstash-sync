'use strict';

const path = require('node:path');
const { EventEmitter } = require('node:events');
const b = require('../vendor/blamejs');
const { WATCHER_DEBOUNCE_MS } = require('./constants');
const log = require('./logger');

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
    log.info('Starting file watcher', { folder: this._syncFolder });
    try {
      this._handle = b.watcher.create({
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
      });
    } catch (err) {
      log.error('Failed to start file watcher', err);
      throw err;
    }
  }

  stop() {
    if (this._handle) {
      try { this._handle.stop(); } catch (_e) {}
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
