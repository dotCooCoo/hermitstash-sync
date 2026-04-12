'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { WATCHER_DEBOUNCE_MS } = require('./constants');
const log = require('./logger');

class Watcher extends EventEmitter {
  constructor(syncFolder, ignorePatterns = []) {
    super();
    this._syncFolder = syncFolder;
    this._ignorePatterns = ignorePatterns;
    this._watchers = [];
    this._debounceTimers = new Map();
    this._running = false;
  }

  start() {
    if (this._running) return;
    this._running = true;

    log.info('Starting file watcher', { folder: this._syncFolder });

    // Watch the root folder recursively
    try {
      const watcher = fs.watch(this._syncFolder, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        // Normalize path separators
        const relativePath = filename.replace(/\\/g, '/');
        if (this._isIgnored(relativePath)) return;
        this._debounce(relativePath);
      });

      watcher.on('error', err => {
        log.error('File watcher error', err);
        this.emit('error', err);
      });

      this._watchers.push(watcher);
    } catch (err) {
      log.error('Failed to start file watcher', err);
      throw err;
    }
  }

  stop() {
    this._running = false;
    for (const watcher of this._watchers) {
      watcher.close();
    }
    this._watchers = [];
    for (const timer of this._debounceTimers.values()) {
      clearTimeout(timer);
    }
    this._debounceTimers.clear();
    log.info('File watcher stopped');
  }

  _debounce(relativePath) {
    // Cancel any pending timer for this path
    const existing = this._debounceTimers.get(relativePath);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(() => {
      this._debounceTimers.delete(relativePath);
      this._processChange(relativePath);
    }, WATCHER_DEBOUNCE_MS);

    this._debounceTimers.set(relativePath, timer);
  }

  _processChange(relativePath) {
    const fullPath = path.join(this._syncFolder, relativePath);

    try {
      if (fs.existsSync(fullPath)) {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) return; // We only sync files
        this.emit('change', {
          type: 'change',
          relativePath,
          fullPath,
          size: stat.size,
          mtime: stat.mtimeMs,
        });
      } else {
        this.emit('change', {
          type: 'delete',
          relativePath,
          fullPath,
        });
      }
    } catch (err) {
      // File might have been deleted between check and stat
      if (err.code === 'ENOENT') {
        this.emit('change', {
          type: 'delete',
          relativePath,
          fullPath,
        });
      } else {
        log.warn('Error processing file change', { relativePath, error: err.message });
      }
    }
  }

  /**
   * Check if a relative path matches any ignore pattern.
   * Supports: exact match, *.ext, dir/**, prefix*
   */
  _isIgnored(relativePath) {
    for (const pattern of this._ignorePatterns) {
      if (this._matchPattern(relativePath, pattern)) return true;
    }
    return false;
  }

  _matchPattern(filepath, pattern) {
    // Exact match
    if (filepath === pattern) return true;

    // Filename-only pattern (no slash) — match against basename
    if (!pattern.includes('/')) {
      const basename = path.basename(filepath);
      if (basename === pattern) return true;

      // *.ext pattern
      if (pattern.startsWith('*.')) {
        const ext = pattern.slice(1); // .ext
        if (basename.endsWith(ext)) return true;
      }

      // *~ pattern
      if (pattern === '*~' && basename.endsWith('~')) return true;

      return false;
    }

    // dir/** pattern — match any file under that directory
    if (pattern.endsWith('/**')) {
      const dir = pattern.slice(0, -3); // remove /**
      if (filepath.startsWith(dir + '/') || filepath === dir) return true;
      return false;
    }

    return false;
  }
}

module.exports = Watcher;
