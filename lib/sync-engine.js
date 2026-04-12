'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const {
  MSG, FILE_STATUS, SYNC_STATE,
  UPLOAD_MAX_RETRIES, UPLOAD_RETRY_DELAY_MS, MIN_FREE_DISK_BYTES,
} = require('./constants');
const log = require('./logger');
const stateDb = require('./state-db');
const { hashFile, hashFileWorker, hashFilesParallel, startPool, stopPool, getPool } = require('./checksum');
const Watcher = require('./watcher');
const WsClient = require('./ws-client');
const HttpClient = require('./http-client');

class SyncEngine extends EventEmitter {
  constructor(config, apiKey) {
    super();
    this._config = config;
    this._apiKey = apiKey;
    this._state = SYNC_STATE.DISCONNECTED;
    this._ws = null;
    this._http = null;
    this._watcher = null;
    this._downloadingPaths = new Set(); // H1: tracks paths being downloaded to avoid re-upload
    this._activeOps = 0; // M8: active operation counter for state management
  }

  get state() { return this._state; }

  async start(ignorePatterns) {
    log.info('Sync engine starting');

    // Start worker pool for parallel checksums
    startPool();
    var pool = getPool();
    if (pool) log.info('Worker thread pool started', { size: pool.size });

    // Open state database
    stateDb.open();

    // Create HTTP client
    this._http = new HttpClient(this._config, this._apiKey);

    // Create file watcher
    this._watcher = new Watcher(this._config.syncFolder, ignorePatterns);
    this._watcher.on('change', ev => this._onLocalChange(ev));
    this._watcher.on('error', err => log.error('Watcher error', err));

    // Create WebSocket client
    this._ws = new WsClient(this._config, this._apiKey);

    this._ws.on('open', () => {
      this._setState(SYNC_STATE.CATCHING_UP);

      // On first connection with no local state, do initial sync from bundle metadata
      const lastSeq = stateDb.getLastSeq();
      if (lastSeq === 0 && this._config.shareId) {
        this._initialSync().catch(err => log.error('Initial sync failed', { error: err.message }));
      }
    });

    this._ws.on('message', msg => this._onServerMessage(msg));

    this._ws.on('close', () => {
      if (this._state !== SYNC_STATE.DISCONNECTED) {
        this._setState(SYNC_STATE.RECONNECTING);
      }
    });

    this._ws.on('error', err => {
      log.error('WebSocket error', err);
      this._setState(SYNC_STATE.ERROR);
    });

    this._ws.on('auth_error', ({ status, body }) => {
      log.error(`Authentication failed (HTTP ${status}). Check your API key.`);
      this._setState(SYNC_STATE.ERROR);
      this.emit('auth_error');
    });

    this._ws.on('reconnecting', attempt => {
      this._setState(SYNC_STATE.RECONNECTING);
    });

    // Connect WebSocket
    const lastSeq = stateDb.getLastSeq();
    this._setState(SYNC_STATE.CONNECTING);
    this._ws.connect(this._config.bundleId, lastSeq);

    // H4: Clean up leftover temp files from interrupted downloads
    this._cleanupTempFiles();

    // Start file watcher
    this._watcher.start();
  }

  async stop() {
    log.info('Sync engine stopping');
    this._setState(SYNC_STATE.DISCONNECTED);

    if (this._watcher) {
      this._watcher.stop();
      this._watcher = null;
    }

    if (this._ws) {
      this._ws.close();
      this._ws = null;
    }

    if (this._http) {
      this._http.destroy();
      this._http = null;
    }

    // Shut down worker pool
    await stopPool();

    stateDb.close();
    log.info('Sync engine stopped');
  }

  getStatus() {
    return {
      state: this._state,
      lastSeq: stateDb.getLastSeq(),
      lastSync: stateDb.getMeta('last_sync_time'),
      fileCount: stateDb.getAllFiles().length,
      activeOps: this._activeOps,
    };
  }

  async resync() {
    log.info('Full resync requested');
    stateDb.clearAll();
    if (this._ws) {
      this._ws.close();
      this._setState(SYNC_STATE.CONNECTING);
      this._ws.connect(this._config.bundleId, 0);
    }
  }

  // --- State management ---

  _setState(newState) {
    if (this._state === newState) return;
    const prev = this._state;
    this._state = newState;
    log.debug('State change', { from: prev, to: newState });
    this.emit('state', newState, prev);
  }

  // --- Server message handling ---

  _onServerMessage(msg) {
    const { type } = msg;

    switch (type) {
      case MSG.FILE_ADDED:
        this._handleFileAdded(msg);
        break;
      case MSG.FILE_REPLACED:
        this._handleFileReplaced(msg);
        break;
      case MSG.FILE_REMOVED:
        this._handleFileRemoved(msg);
        break;
      case MSG.HEARTBEAT:
        this._handleHeartbeat(msg);
        break;
      default:
        log.debug('Unknown server message type', { type });
    }
  }

  async _handleFileAdded(msg) {
    const { fileId, relativePath, checksum, size, seq } = msg;

    if (!this._safePath(relativePath)) {
      log.error('Path traversal attempt blocked in file_added', { relativePath });
      return;
    }

    log.info('Server: file added', { relativePath, size });

    // Check if we already have this file with the same checksum
    const existing = stateDb.getFile(relativePath);
    if (existing && existing.localChecksum === checksum) {
      // Already in sync — just update seq
      stateDb.upsertFile({ ...existing, serverSeq: seq, serverChecksum: checksum, serverFileId: fileId });
      this._updateSeq(seq);
      return;
    }

    // Queue download
    stateDb.upsertFile({
      relativePath,
      serverFileId: fileId,
      serverChecksum: checksum,
      size,
      serverSeq: seq,
      status: FILE_STATUS.PENDING_DOWNLOAD,
    });

    await this._downloadFile(relativePath, fileId, checksum);
    this._updateSeq(seq);
  }

  async _handleFileReplaced(msg) {
    const { fileId, relativePath, checksum, size, seq } = msg;

    if (!this._safePath(relativePath)) {
      log.error('Path traversal attempt blocked in file_replaced', { relativePath });
      return;
    }

    log.info('Server: file replaced', { relativePath, size });

    // Check if we're the one who uploaded this change
    const existing = stateDb.getFile(relativePath);
    if (existing && existing.localChecksum === checksum) {
      stateDb.upsertFile({ ...existing, serverSeq: seq, serverChecksum: checksum, serverFileId: fileId });
      this._updateSeq(seq);
      return;
    }

    stateDb.upsertFile({
      relativePath,
      serverFileId: fileId,
      serverChecksum: checksum,
      size,
      serverSeq: seq,
      status: FILE_STATUS.PENDING_DOWNLOAD,
    });

    await this._downloadFile(relativePath, fileId, checksum);
    this._updateSeq(seq);
  }

  async _handleFileRemoved(msg) {
    const { relativePath, seq } = msg;

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_removed', { relativePath });
      return;
    }

    log.info('Server: file removed', { relativePath });
    try {
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
        log.info('Deleted local file', { relativePath });
      }
    } catch (err) {
      log.error('Failed to delete local file', { relativePath, error: err.message });
    }

    stateDb.removeFile(relativePath);
    this._updateSeq(seq);
  }

  /**
   * Initial sync — fetch bundle metadata and download all existing files.
   * Called on first connection when no local state exists.
   * Uses worker pool for parallel checksum verification of existing local files.
   */
  async _initialSync() {
    log.info('Starting initial sync — fetching bundle metadata');
    try {
      const meta = await this._http.getBundleMetadata(this._config.shareId);
      const files = meta.files || [];
      log.info('Initial sync', { fileCount: files.length, totalSize: meta.totalSize });

      // Pre-hash existing local files in parallel to avoid serial I/O
      const existingLocalPaths = [];
      for (const file of files) {
        const fullPath = this._safePath(file.relativePath);
        if (fullPath && fs.existsSync(fullPath)) {
          existingLocalPaths.push(fullPath);
        }
      }
      const localHashes = new Map();
      if (existingLocalPaths.length > 0) {
        log.info('Verifying local files', { count: existingLocalPaths.length });
        const t0 = Date.now();
        const results = await hashFilesParallel(existingLocalPaths);
        const elapsed = Date.now() - t0;
        log.info('Parallel verification complete', { count: existingLocalPaths.length, ms: elapsed });
        for (const r of results) {
          localHashes.set(r.filePath, r.checksum);
        }
      }

      for (const file of files) {
        const fullPath = this._safePath(file.relativePath);
        const localChecksum = fullPath ? localHashes.get(fullPath) : null;

        if (localChecksum && localChecksum === file.checksum) {
          // File exists locally with matching checksum — mark synced, skip download
          const existing = stateDb.getFile(file.relativePath);
          stateDb.upsertFile({
            ...existing,
            relativePath: file.relativePath,
            serverFileId: file.id,
            localChecksum,
            serverChecksum: file.checksum,
            size: file.size,
            serverSeq: file.seq || 0,
            status: FILE_STATUS.SYNCED,
          });
          continue;
        }

        stateDb.upsertFile({
          relativePath: file.relativePath,
          serverFileId: file.id,
          serverChecksum: file.checksum,
          size: file.size,
          serverSeq: file.seq || 0,
          status: FILE_STATUS.PENDING_DOWNLOAD,
        });

        await this._downloadFile(file.relativePath, file.id, file.checksum);
      }

      // Also scan local folder for files not on server — queue them for upload
      await this._scanLocalForUpload(files);

      log.info('Initial sync complete');
    } catch (err) {
      log.error('Initial sync failed — will rely on WebSocket catch-up', err);
    }
  }

  /**
   * Scan local sync folder for files that aren't on the server yet.
   * Uses worker pool for parallel checksum computation on new files.
   */
  async _scanLocalForUpload(serverFiles) {
    const serverPaths = new Set(serverFiles.map(f => f.relativePath));
    const localFiles = this._walkDir(this._config.syncFolder);

    // Collect files that need uploading
    const toUpload = [];
    for (const fullPath of localFiles) {
      const relativePath = path.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/');
      if (this._watcher && this._watcher.isIgnored(relativePath)) continue;
      if (serverPaths.has(relativePath)) continue;

      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) continue;
        toUpload.push({ fullPath, relativePath, size: stat.size, mtime: stat.mtimeMs });
      } catch { continue; }
    }

    if (toUpload.length === 0) return;

    // Parallel hash all new files via worker pool
    log.info('Hashing local files for upload', { count: toUpload.length });
    const t0 = Date.now();
    const hashes = await hashFilesParallel(toUpload.map(f => f.fullPath));
    const elapsed = Date.now() - t0;
    log.info('Parallel hash complete', { count: toUpload.length, ms: elapsed });

    // Upload each file
    for (var i = 0; i < toUpload.length; i++) {
      const { fullPath, relativePath, size, mtime } = toUpload[i];
      const localChecksum = hashes[i].checksum;

      const existing = stateDb.getFile(relativePath);
      if (existing && existing.localChecksum === localChecksum) continue;

      log.info('Local file not on server, uploading', { relativePath });
      stateDb.upsertFile({
        relativePath,
        serverFileId: existing?.serverFileId || null,
        localChecksum,
        serverChecksum: existing?.serverChecksum || null,
        localMtime: mtime,
        size,
        serverSeq: existing?.serverSeq || 0,
        status: FILE_STATUS.PENDING_UPLOAD,
      });

      await this._uploadFile(relativePath, fullPath);
    }
  }

  /**
   * Recursively walk a directory, returning file paths.
   * H2: Skips symlinks. L5: Checks ignore patterns during traversal.
   */
  _walkDir(dir) {
    const results = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // H2: Skip symlinks entirely
      try {
        const lstat = fs.lstatSync(fullPath);
        if (lstat.isSymbolicLink()) continue;
      } catch { continue; }

      if (entry.isDirectory()) {
        // L5: Check ignore patterns before recursing into subdirectories
        const relDir = path.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/');
        if (this._watcher && this._watcher.isIgnored(relDir)) continue;
        results.push(...this._walkDir(fullPath));
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
    return results;
  }

  _handleHeartbeat(msg) {
    const { seq } = msg;
    log.debug('Heartbeat', { seq });

    // If catching up and heartbeat seq matches our last applied seq, we're caught up
    if (this._state === SYNC_STATE.CATCHING_UP) {
      const lastSeq = stateDb.getLastSeq();
      if (seq <= lastSeq || seq === 0) {
        this._setState(SYNC_STATE.SYNCED);
        stateDb.setMeta('last_sync_time', new Date().toISOString());
        log.info('Catch-up complete, now synced');
      }
    }

    // Send ack
    if (this._ws) {
      this._ws.send({ type: MSG.ACK, seq });
    }
  }

  _updateSeq(seq) {
    if (seq > stateDb.getLastSeq()) {
      stateDb.setLastSeq(seq);
    }
    stateDb.setMeta('last_sync_time', new Date().toISOString());
    // L10: Keep WebSocket client's `since` in sync for reconnections
    if (this._ws) {
      this._ws.updateSince(seq);
    }
  }

  // --- File downloads ---

  async _downloadFile(relativePath, fileId, expectedChecksum) {
    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in download', { relativePath });
      return;
    }

    this._downloadingPaths.add(relativePath);
    this._activeOps++;
    this._setState(SYNC_STATE.DOWNLOADING);

    try {
      // Check disk space
      const freeSpace = this._getFreeDiskSpace();
      if (freeSpace < MIN_FREE_DISK_BYTES) {
        log.warn('Low disk space, pausing download', { freeSpace, relativePath });
        stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
        this._downloadingPaths.delete(relativePath);
        this._activeOps--;
        if (this._activeOps <= 0) { this._activeOps = 0; this._setState(SYNC_STATE.SYNCED); }
        return;
      }

      // M11: Checksum verification is done inside downloadFile before rename
      await this._http.downloadFile(fileId, fullPath, expectedChecksum);

      const localChecksum = expectedChecksum;
      const stat = fs.statSync(fullPath);
      const fileRecord = stateDb.getFile(relativePath);
      stateDb.upsertFile({
        ...fileRecord,
        relativePath,
        localChecksum,
        localMtime: stat.mtimeMs,
        size: stat.size,
        status: FILE_STATUS.SYNCED,
      });

      log.info('Downloaded', { relativePath });
    } catch (err) {
      log.error('Download failed', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }

    this._downloadingPaths.delete(relativePath);
    this._activeOps--;
    if (this._activeOps <= 0) {
      this._activeOps = 0;
      this._setState(SYNC_STATE.SYNCED);
    }
  }

  // --- Local change handling ---

  async _onLocalChange(ev) {
    try {
      if (this._state === SYNC_STATE.DISCONNECTED || this._state === SYNC_STATE.ERROR) return;

      const { type, relativePath, fullPath, size, mtime } = ev;

      // H1: Skip changes for files currently being downloaded to avoid re-upload race
      if (this._downloadingPaths.has(relativePath)) {
        log.debug('Skipping local change for file being downloaded', { relativePath });
        return;
      }

      if (type === 'delete') {
        await this._handleLocalDelete(relativePath);
      } else {
        await this._handleLocalModify(relativePath, fullPath, size, mtime);
      }
    } catch (err) {
      log.error('Error handling local change', { error: err.message });
    }
  }

  async _handleLocalModify(relativePath, fullPath, size, mtime) {
    // Compute checksum (dispatched to worker pool if available)
    let localChecksum;
    try {
      localChecksum = await hashFileWorker(fullPath);
    } catch (err) {
      if (err.code === 'ENOENT') return; // File was deleted between detection and hashing
      log.error('Failed to hash file', { relativePath, error: err.message });
      return;
    }

    // Check if this is actually a change
    const existing = stateDb.getFile(relativePath);
    if (existing && existing.localChecksum === localChecksum) {
      return; // No actual change
    }

    // Check for conflict: pending download for this file?
    if (existing && existing.status === FILE_STATUS.PENDING_DOWNLOAD) {
      log.warn('Conflict: local change during pending download', { relativePath });
      // Last-write-wins: local change takes priority
    }

    log.info('Local change detected', { relativePath, size });

    stateDb.upsertFile({
      relativePath,
      serverFileId: existing?.serverFileId || null,
      localChecksum,
      serverChecksum: existing?.serverChecksum || null,
      localMtime: mtime,
      size,
      serverSeq: existing?.serverSeq || 0,
      status: FILE_STATUS.PENDING_UPLOAD,
    });

    await this._uploadFile(relativePath, fullPath);
  }

  async _handleLocalDelete(relativePath) {
    const existing = stateDb.getFile(relativePath);
    if (!existing || !existing.serverFileId) {
      // File wasn't synced — just remove from state
      stateDb.removeFile(relativePath);
      return;
    }

    log.info('Local delete detected', { relativePath });

    try {
      await this._http.deleteFile(existing.serverFileId);
      stateDb.removeFile(relativePath);
      log.info('Deleted from server', { relativePath });
    } catch (err) {
      log.error('Failed to delete from server', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }
  }

  async _uploadFile(relativePath, fullPath, attempt = 1) {
    // Only increment on first attempt — retries reuse the same operation slot
    if (attempt === 1) {
      this._activeOps++;
    }
    this._setState(SYNC_STATE.UPLOADING);

    try {
      const result = await this._http.uploadFile(this._config.bundleId, relativePath, fullPath);
      log.info('Uploaded', { relativePath, fileId: result.fileId || result.id });

      const localChecksum = await hashFileWorker(fullPath);
      const stat = fs.statSync(fullPath);

      stateDb.upsertFile({
        relativePath,
        serverFileId: result.fileId || result.id,
        localChecksum,
        serverChecksum: result.checksum || localChecksum,
        localMtime: stat.mtimeMs,
        size: stat.size,
        serverSeq: result.seq || 0,
        status: FILE_STATUS.SYNCED,
      });
    } catch (err) {
      if (attempt < UPLOAD_MAX_RETRIES) {
        log.warn(`Upload failed (attempt ${attempt}/${UPLOAD_MAX_RETRIES}), retrying`, {
          relativePath, error: err.message,
        });
        await this._sleep(UPLOAD_RETRY_DELAY_MS);
        return this._uploadFile(relativePath, fullPath, attempt + 1);
      }
      log.error('Upload failed after retries', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }

    this._activeOps--;
    if (this._activeOps <= 0) {
      this._activeOps = 0;
      this._setState(SYNC_STATE.SYNCED);
    }
  }

  // --- Temp file cleanup ---

  /**
   * H4: Remove leftover .tmp. files from interrupted downloads on startup.
   */
  _cleanupTempFiles() {
    try {
      const files = fs.readdirSync(this._config.syncFolder);
      for (const f of files) {
        if (f.includes('.tmp.')) {
          try { fs.unlinkSync(path.join(this._config.syncFolder, f)); } catch {}
        }
      }
    } catch {}
  }

  // --- Path safety ---

  /**
   * Resolve a server-provided relativePath and verify it stays within the sync folder.
   * Returns the full path, or null if traversal is detected.
   */
  _safePath(relativePath) {
    const fullPath = path.resolve(this._config.syncFolder, relativePath);
    const resolvedBase = path.resolve(this._config.syncFolder);
    if (!fullPath.startsWith(resolvedBase + path.sep) && fullPath !== resolvedBase) {
      return null; // traversal attempt
    }
    return fullPath;
  }

  // --- Utilities ---

  _getFreeDiskSpace() {
    try {
      const stat = fs.statfsSync(this._config.syncFolder);
      return stat.bfree * stat.bsize;
    } catch {
      return Infinity; // Can't check — assume OK
    }
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = SyncEngine;
