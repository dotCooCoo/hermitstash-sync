'use strict';

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const { EventEmitter } = require('node:events');
const {
  MSG, FILE_STATUS, SYNC_STATE,
  UPLOAD_MAX_RETRIES, UPLOAD_RETRY_DELAY_MS, MIN_FREE_DISK_BYTES,
  UPLOAD_CB_FAILURES, UPLOAD_CB_COOLDOWN_MS, UPLOAD_CB_SUCCESSES,
  UPLOAD_DEFAULT_CONCURRENCY,
} = require('./constants');
const log = require('./logger');
const stateDb = require('./state-db');
const metrics = require('./metrics');
const { hashFile, hashFilesParallel } = require('./checksum');
const Watcher = require('./watcher');
const WsClient = require('./ws-client');
const HttpClient = require('./http-client');
const pathFilter = require('./path-filter');
const { longPath } = require('./long-path');
const b = require('../vendor/blamejs');

const C = b.constants;
// allow:raw-time-literal — calendar-day threshold; the value compares against a `daysLeft` integer, not a millisecond duration
const CERT_RENEWAL_THRESHOLD_DAYS = 60;
const OPENSSL_PROBE_TIMEOUT_MS = C.TIME.seconds(5);

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
    this._pendingDeletes = new Map(); // Rename detection: { relativePath -> { checksum, fileId, timer } }

    // Per-target circuit breaker on the upload path. b.retry.withBreaker
    // composes the breaker around b.retry.withRetry so one retry-loop
    // invocation = one breaker call (the breaker counts a fully-exhausted
    // retry as a single failure, not three). After UPLOAD_CB_FAILURES
    // consecutive failures the breaker opens for UPLOAD_CB_COOLDOWN_MS
    // and fast-fails new uploads, then probes — keeping the daemon from
    // spinning the retry loop against a flapping server.
    this._uploadBreaker = b.circuitBreaker.create({
      name:             'upload',
      failureThreshold: UPLOAD_CB_FAILURES,
      cooldownMs:       UPLOAD_CB_COOLDOWN_MS,
      successThreshold: UPLOAD_CB_SUCCESSES,
      onStateChange: (e) => {
        log.warn('Upload circuit breaker state change', { from: e.from, to: e.to });
        metrics.setCircuitState('upload', e.to);
        if (e.to === 'open') metrics.record.circuitOpen('upload');
      },
    });

    // Bounded-concurrency pool gates every _uploadFile invocation —
    // both the initial-scan fan-out and watcher-driven changes route
    // through here. The HTTP agent's maxSockets cap is the hard wall;
    // this pool keeps the JS-side promise queue bounded so a bulk
    // `cp -r 10000 files` doesn't materialize 10000 in-flight promises
    // queueing for the agent's socket pool. Defaults to 4; operators
    // override via config.uploadConcurrency (clamped 1..16).
    const cc = Math.max(1, Math.min(16, (config.uploadConcurrency | 0) || UPLOAD_DEFAULT_CONCURRENCY)); // allow:raw-byte-literal — concurrency clamp upper bound (count, not bytes)
    this._uploadPool = b.promisePool.create({ concurrency: cc });
    metrics.registerPoolStatsProvider(() => ({
      inflight:   this._uploadPool.inFlight(),
      queueDepth: this._uploadPool.queued(),
    }));
  }

  get state() { return this._state; }

  /**
   * Check mTLS certificate expiry and auto-renew if within 60 days.
   * Called from start() after this._http is created. Uses the API key +
   * the CURRENT mTLS cert to authenticate to POST /sync/renew-cert —
   * no admin intervention needed. On successful renewal, writes the
   * new PEMs to disk and tells the HTTP client to reload them so the
   * next outgoing request picks up the new identity.
   */
  async _checkCertExpiry() {
    if (!this._config.mtls || !this._config.mtls.cert) return;
    if (!this._http) return; // called before HttpClient was created — bug, skip
    try {
      var certPath = this._config.mtls.cert;
      if (!nodeFs.existsSync(certPath)) return;

      // Extract expiry from PEM using openssl (cross-platform)
      var { execFileSync } = require('node:child_process');
      var endDate;
      try {
        var output = execFileSync('openssl', ['x509', '-enddate', '-noout', '-in', certPath], { encoding: 'utf8', timeout: OPENSSL_PROBE_TIMEOUT_MS });
        var match = output.match(/notAfter=(.+)/);
        if (match) endDate = new Date(match[1]);
      } catch (_e) {
        return; // OpenSSL not available — skip silently
      }
      if (!endDate || isNaN(endDate.getTime())) return;

      var secondsLeft = Math.floor((endDate.getTime() - Date.now()) / C.TIME.seconds(1));
      var daysLeft = Math.floor(secondsLeft / (C.TIME.days(1) / C.TIME.seconds(1)));
      metrics.setCertExpiresInSeconds(secondsLeft);
      log.info('Certificate expiry check', { expiresAt: endDate.toISOString(), daysLeft: daysLeft });
      // Operator-visible early warnings so an expired cert isn't the
      // first signal something's wrong. < 7 days = error level so the
      // log line stands out in dashboards / alert rules; 7-30 days =
      // warn. Renewal still only fires under the threshold below.
      if (daysLeft < 7) {                                                       // allow:raw-byte-literal — 7-day operator-warning threshold (count, not bytes)
        log.error('mTLS certificate expires in less than 7 days — renewal will run automatically if the threshold trips before then', { daysLeft });
      } else if (daysLeft < 30) {                                               // allow:raw-byte-literal — 30-day operator-warning threshold (count, not bytes)
        log.warn('mTLS certificate expires within 30 days', { daysLeft });
      }
      if (daysLeft > CERT_RENEWAL_THRESHOLD_DAYS) return;

      log.info('Certificate expiring soon — requesting renewal', { daysLeft: daysLeft });
      var renewed;
      try {
        renewed = await this._http.renewCert();
      } catch (err) {
        log.error('Certificate renewal failed', { error: err.message });
        return;
      }

      nodeFs.writeFileSync(this._config.mtls.cert, renewed.clientCert, { mode: 0o644 });
      nodeFs.writeFileSync(this._config.mtls.key,  renewed.clientKey,  { mode: 0o600 });
      if (this._config.mtls.ca && renewed.caCert) {
        nodeFs.writeFileSync(this._config.mtls.ca, renewed.caCert, { mode: 0o644 });
      }

      // Rebuild the HTTP client's TLS agent so the next request uses the
      // new cert. WsClient reads certs fresh in its own constructor (below
      // in start()), so as long as WsClient is created after this point
      // it'll pick up the renewed files on its first connect.
      this._http.reloadMtlsCerts();

      log.info('Certificate renewed successfully', { newExpiresAt: renewed.expiresAt, daysLeft: daysLeft });
    } catch (err) {
      log.error('Certificate expiry check failed', { error: err.message });
    }
  }

  async start(ignorePatterns, includePatterns) {
    log.info('Sync engine starting');
    this._ignorePatterns = ignorePatterns || [];
    this._includePatterns = includePatterns || [];
    if (this._includePatterns.length > 0) {
      log.info('Selective sync enabled', { includeCount: this._includePatterns.length });
    }

    // Open state database
    stateDb.open();

    // PRAGMA integrity_check the state DB at boot — a corrupted DB
    // would otherwise surface mid-sync with a cryptic SQL error.
    // Pre-v0.8.13 the result was computed but never logged; now it's
    // either a clean info line or an error that an operator can act
    // on (run `repair`, or back up + drop state.db and re-sync).
    try {
      const ok = stateDb.integrityCheck();
      if (ok) log.info('State DB integrity check passed');
      else log.error('State DB integrity check FAILED — state.db is corrupt; back it up and re-sync to recover');
    } catch (err) {
      log.warn('State DB integrity check could not run', { error: err.message });
    }

    // Seed metrics gauges from the on-disk state. The cli.cmdStart path
    // calls metrics.init() before constructing the engine, so the
    // counters/gauges are already registered; we just publish the initial
    // values so a fresh `stats` call before the first sync event still
    // shows accurate file counts.
    metrics.setFileCount(stateDb.getAllFiles().length);
    metrics.setLastSeq(stateDb.getLastSeq());
    metrics.setSyncState(this._state);
    metrics.setCircuitState('upload', 'closed');

    // Create HTTP client FIRST — _checkCertExpiry uses it for renewal, and
    // the WebSocket client (created later) caches certs at construction so
    // it'll pick up any renewed files on its first connect.
    this._http = new HttpClient(this._config, this._apiKey);

    // Auto-rotate mTLS certificate if expiring within 60 days.
    await this._checkCertExpiry();

    // Re-check daily. Pre-v0.8.13 the check ran only at engine start —
    // a daemon up for months hit cert expiry silently and the first
    // signal was a failed upload after the cert died. The interval
    // updates the cert_expires_in_seconds gauge each tick, warns at
    // 30 / 7 day boundaries, and triggers renewal at the 60-day floor.
    this._certCheckTimer = setInterval(() => {
      this._checkCertExpiry().catch(err => log.warn('Periodic cert-expiry check failed', { error: err.message }));
    }, C.TIME.hours(24));                                                       // allow:raw-byte-literal — daily cadence; sub-day granularity not meaningful for cert expiry
    this._certCheckTimer.unref();

    // Create file watcher — propagates both ignore + include so the
    // watcher emits change events only for in-scope paths.
    this._watcher = new Watcher(this._config.syncFolder, ignorePatterns, includePatterns);
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

    this._ws.on('auth_error', ({ status }) => {
      log.error(`Authentication failed (HTTP ${status}). Check your API key.`);
      this._setState(SYNC_STATE.ERROR);
      this.emit('auth_error');
    });

    this._ws.on('reconnecting', () => {
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

  _clearCertCheckTimer() {
    if (this._certCheckTimer) {
      try { clearInterval(this._certCheckTimer); } catch { /* allow:silent-catch — idempotent timer teardown */ }
      this._certCheckTimer = null;
    }
  }

  async stop() {
    log.info('Sync engine stopping');
    this._setState(SYNC_STATE.DISCONNECTED);
    this._clearCertCheckTimer();

    if (this._watcher) {
      this._watcher.stop();
      this._watcher = null;
    }

    // Drain in-flight uploads before tearing down the HTTP client so
    // we don't kill mid-stream POSTs. The daemon's outer shutdown
    // budget caps how long we wait; pool.drain() resolves promptly
    // when all slots free.
    if (this._uploadPool) {
      try { await this._uploadPool.drain(); }
      catch (err) { log.warn('Upload pool drain failed', { error: err.message }); }
    }

    if (this._ws) {
      this._ws.close();
      this._ws = null;
    }

    if (this._http) {
      this._http.destroy();
      this._http = null;
    }

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

  // Runtime pattern reload — pushes new ignore/include arrays to the
  // engine + the watcher. Used by the SIGHUP handler so operators can
  // edit config.ignore / config.include and reload without bouncing
  // the daemon. The patterns take effect on the next watcher event +
  // the next server message; existing in-flight transfers complete
  // under whichever patterns were in force when they started.
  updatePatterns(ignorePatterns, includePatterns) {
    this._ignorePatterns = ignorePatterns || [];
    this._includePatterns = includePatterns || [];
    if (this._watcher) {
      this._watcher.updatePatterns(this._ignorePatterns, this._includePatterns);
    }
    log.info('Patterns reloaded', {
      ignoreCount:  this._ignorePatterns.length,
      includeCount: this._includePatterns.length,
    });
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
    metrics.setSyncState(newState);
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
      case MSG.FILE_RENAMED:
        this._handleFileRenamed(msg);
        break;
      case MSG.HEARTBEAT:
        this._handleHeartbeat(msg);
        break;
      case MSG.CA_ROTATION:
        this._handleCaRotation(msg);
        break;
      default:
        log.debug('Unknown server message type', { type });
    }
  }

  /**
   * Server regenerated the mTLS CA and sent us new credentials. Persist the
   * three PEMs atomically (temp + fsync + rename so a crash can't leave us
   * half-rotated), refresh the in-memory cert caches in both clients, then
   * ack. The server restarts shortly after; our next reconnect will use the
   * new cert against the new CA.
   *
   * See hermitstash-private/routes/admin.js → /admin/api/mtls-ca/regenerate
   * for the orchestration flow.
   */
  _handleCaRotation(msg) {
    const { newCaPem, newCertPem, newKeyPem, restartInMs, dryRun } = msg;
    if (!newCaPem || !newCertPem || !newKeyPem) {
      log.error('ca:rotation missing required fields', { hasCa: !!newCaPem, hasCert: !!newCertPem, hasKey: !!newKeyPem });
      return;
    }
    // dryRun mode: the server set { skipRestart: true } — ack the rotation
    // but don't touch any files. Used by E2E tests that validate the
    // rotation protocol without destroying the client's cert state.
    if (dryRun) {
      log.info('ca:rotation dry-run received — acking without file writes');
      try { this._ws.send({ type: MSG.CA_ROTATION_ACK }); } catch (_e) {} // allow:silent-catch — ack on a dry-run rotation; if the socket is gone the server timeouts on its own
      return;
    }
    const mtls = this._config.mtls;
    if (!mtls || !mtls.cert || !mtls.key || !mtls.ca) {
      log.error('ca:rotation received but no mTLS paths configured — ignoring');
      return;
    }
    try {
      // Atomic write: temp file + fsync + rename. Order: cert, key, CA.
      const writeAtomic = (targetPath, data, mode) => {
        const tmp = targetPath + '.tmp';
        const fd = nodeFs.openSync(tmp, 'w', mode || 0o600);
        try {
          nodeFs.writeSync(fd, data);
          nodeFs.fsyncSync(fd);
        } finally {
          nodeFs.closeSync(fd);
        }
        nodeFs.renameSync(tmp, targetPath);
      };
      writeAtomic(mtls.cert, newCertPem, 0o644);
      writeAtomic(mtls.key,  newKeyPem,  0o600);
      writeAtomic(mtls.ca,   newCaPem,   0o644);

      // Refresh cached TLS buffers in both clients so reconnects + the next
      // HTTP request pick up the new credentials.
      if (this._ws && typeof this._ws.reloadMtlsCerts === 'function') this._ws.reloadMtlsCerts();
      if (this._http && typeof this._http.reloadMtlsCerts === 'function') this._http.reloadMtlsCerts();

      // Ack the rotation so the server knows we're ready for its restart.
      this._ws.send({ type: MSG.CA_ROTATION_ACK });

      log.info('CA rotated — new cert/key/CA persisted, waiting for server restart', {
        restartInMs: restartInMs || null,
        certPath: mtls.cert,
      });
    } catch (err) {
      log.error('CA rotation failed to persist', err);
    }
  }

  // Selective-sync gate for server-driven events. Returns true if the
  // path is in scope (include empty OR matches an include pattern) AND
  // not ignored. Server events for out-of-scope paths are no-ops aside
  // from the seq update — the daemon still advances `lastSeq` so the
  // next reconnect doesn't replay them.
  _shouldSync(relativePath) {
    return pathFilter.shouldSync(relativePath, {
      include: this._includePatterns,
      ignore:  this._ignorePatterns,
    });
  }

  // Last-write-wins protection. When a server-driven download is about
  // to overwrite a local file that the user modified independently,
  // rename the local copy aside so the user's bytes aren't lost. Skip
  // if local doesn't exist or already matches the incoming checksum.
  // Best-effort: any failure here logs and lets the download proceed
  // (refusing to download would block forward progress on a single
  // file forever).
  async _maybeSaveConflictCopy(relativePath, fullPath, incomingChecksum) {
    try {
      if (!nodeFs.existsSync(longPath(fullPath))) return;
      const actualLocal = await hashFile(fullPath);
      if (!actualLocal || actualLocal === incomingChecksum) return;
      const conflict = b.atomicFile.conflictPath(fullPath);
      nodeFs.renameSync(longPath(fullPath), longPath(conflict));
      metrics.record.conflict();
      log.warn('Saved conflict copy before remote overwrite', {
        relativePath,
        conflict: nodePath.relative(this._config.syncFolder, conflict).split(nodePath.sep).join('/'),
      });
    } catch (err) {
      log.error('Could not save conflict copy; download will overwrite local', {
        relativePath, error: err.message,
      });
    }
  }

  async _handleFileAdded(msg) {
    const { fileId, relativePath, checksum, size, seq } = msg;

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_added', { relativePath });
      return;
    }

    // Selective-sync: skip out-of-scope paths but still advance seq so
    // we don't replay them on reconnect.
    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
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

    // Name collision: server is adding a file we never tracked, but a
    // local file with the same path already exists. If its content
    // differs, rename it to a conflict copy before the download lands.
    await this._maybeSaveConflictCopy(relativePath, fullPath, checksum);

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

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_replaced', { relativePath });
      return;
    }

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
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

    // Detect local-side unsynced changes BEFORE the download overwrites
    // them. If the local file's actual content differs from the last
    // value we synced AND differs from the incoming server checksum,
    // the user modified locally while a remote replacement happened —
    // rename the local copy to <name>.conflict-<UTC>.<ext> before the
    // download lands. Best-effort: a hash failure logs and proceeds.
    await this._maybeSaveConflictCopy(relativePath, fullPath, checksum);

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

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file removed', { relativePath });
    try {
      if (nodeFs.existsSync(longPath(fullPath))) {
        nodeFs.unlinkSync(longPath(fullPath));
        log.info('Deleted local file', { relativePath });
      }
    } catch (err) {
      log.error('Failed to delete local file', { relativePath, error: err.message });
    }

    stateDb.removeFile(relativePath);
    this._updateSeq(seq);
  }

  async _handleFileRenamed(msg) {
    const { oldRelativePath, relativePath, fileId, checksum, size, seq } = msg;

    if (!this._safePath(oldRelativePath) || !this._safePath(relativePath)) {
      log.error('Path traversal attempt blocked in file_renamed', { oldRelativePath, relativePath });
      return;
    }

    // Selective-sync edge cases when the rename crosses the scope
    // boundary. Both in scope → normal rename below. Both out of
    // scope → no-op, just advance seq. Old in / new out → treat as a
    // remove (file left our window). Old out / new in → treat as an
    // add (file entered our window — download it fresh).
    const oldInScope = this._shouldSync(oldRelativePath);
    const newInScope = this._shouldSync(relativePath);
    if (!oldInScope && !newInScope) {
      this._updateSeq(seq);
      return;
    }
    if (oldInScope && !newInScope) {
      log.info('Server rename moves file out of selective-sync scope; removing local copy',
        { from: oldRelativePath, to: relativePath });
      await this._handleFileRemoved({ relativePath: oldRelativePath, seq });
      return;
    }
    if (!oldInScope && newInScope) {
      log.info('Server rename brings file into selective-sync scope; downloading',
        { from: oldRelativePath, to: relativePath });
      await this._handleFileAdded({ fileId, relativePath, checksum, size, seq });
      return;
    }

    log.info('Server: file renamed', { from: oldRelativePath, to: relativePath });

    const oldFullPath = this._safePath(oldRelativePath);
    const newFullPath = this._safePath(relativePath);

    // Suppress watcher events for both paths during the move
    this._downloadingPaths.add(oldRelativePath);
    this._downloadingPaths.add(relativePath);

    try {
      // Create destination directory if needed
      const newDir = nodePath.dirname(newFullPath);
      if (!nodeFs.existsSync(longPath(newDir))) nodeFs.mkdirSync(longPath(newDir), { recursive: true });

      // Move the file locally
      if (oldFullPath && nodeFs.existsSync(longPath(oldFullPath))) {
        nodeFs.renameSync(longPath(oldFullPath), longPath(newFullPath));
      }

      // Update state DB: remove old, add new
      const existing = stateDb.getFile(oldRelativePath);
      stateDb.removeFile(oldRelativePath);
      stateDb.upsertFile({
        relativePath,
        serverFileId: fileId || (existing && existing.serverFileId),
        localChecksum: checksum || (existing && existing.localChecksum),
        serverChecksum: checksum || (existing && existing.serverChecksum),
        localMtime: Date.now(),
        size: size || (existing && existing.size),
        serverSeq: seq,
        status: FILE_STATUS.SYNCED,
      });

      log.info('Renamed local file', { from: oldRelativePath, to: relativePath });
    } catch (err) {
      log.error('Failed to rename local file', { from: oldRelativePath, to: relativePath, error: err.message });
    }

    this._downloadingPaths.delete(oldRelativePath);
    this._downloadingPaths.delete(relativePath);
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
      // Server may return null / no body / non-object on 404 or auth-
      // redirect responses (e.g. a stash with sync disabled, or a wrong
      // shareId). Treat any non-object response as "empty bundle"
      // rather than NPE'ing on meta.files — the WS catch-up path will
      // surface any later events for files we haven't seen yet.
      const allFiles = (meta && Array.isArray(meta.files)) ? meta.files : [];
      // Selective sync: filter the server's file list down to the
      // in-scope subset before any local I/O. Out-of-scope files are
      // ignored on the server side as well (no download, no scan).
      const files = this._includePatterns.length === 0 && this._ignorePatterns.length === 0
        ? allFiles
        : allFiles.filter(f => this._shouldSync(f.relativePath));
      const skipped = allFiles.length - files.length;
      log.info('Initial sync', { fileCount: files.length, skippedOutOfScope: skipped, totalSize: meta.totalSize });

      // Pre-hash existing local files in parallel to avoid serial I/O
      const existingLocalPaths = [];
      for (const file of files) {
        const fullPath = this._safePath(file.relativePath);
        if (fullPath && nodeFs.existsSync(longPath(fullPath))) {
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
      const relativePath = nodePath.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/');
      // Selective-sync gate — applies both include allowlist + ignore
      // denylist. shouldSync() returns false for out-of-scope paths so
      // we never upload files outside the user's selected scope.
      if (this._watcher && !this._watcher.shouldSync(relativePath)) continue;
      if (serverPaths.has(relativePath)) continue;

      try {
        const stat = nodeFs.statSync(longPath(fullPath));
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
    // Fan out through the upload pool — `cc` tasks run concurrently,
    // the rest queue with back-pressure. Promise.all waits for every
    // task to settle (failures are logged inside _uploadFile; one
    // failure doesn't abort the others).
    const uploadPromises = [];
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

      uploadPromises.push(this._uploadPool.run(() => this._uploadFile(relativePath, fullPath)));
    }
    await Promise.all(uploadPromises);
  }

  /**
   * Recursively walk a directory, returning file paths.
   * H2: Skips symlinks. L5: Checks ignore patterns during traversal.
   */
  _walkDir(dir) {
    const results = [];
    const entries = nodeFs.readdirSync(longPath(dir), { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = nodePath.join(dir, entry.name);

      // H2: Skip symlinks entirely
      try {
        const lstat = nodeFs.lstatSync(longPath(fullPath));
        if (lstat.isSymbolicLink()) continue;
      } catch { continue; }

      if (entry.isDirectory()) {
        // L5: Check ignore patterns before recursing into subdirectories
        const relDir = nodePath.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/');
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
    metrics.setLastSeq(stateDb.getLastSeq());
    metrics.setFileCount(stateDb.getAllFiles().length);
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
    metrics.setActiveOps(this._activeOps);
    this._setState(SYNC_STATE.DOWNLOADING);

    const downloadStart = Date.now();
    const stuckTimer = setTimeout(() => {
      log.warn('Download still in flight after 10 minutes (no per-call timeout — possible hung peer or very large file)',
        { relativePath, elapsedSec: Math.floor((Date.now() - downloadStart) / C.TIME.seconds(1)) });
    }, C.TIME.minutes(10));
    stuckTimer.unref();
    let ok = false;
    try {
      // Check disk space
      const freeSpace = this._getFreeDiskSpace();
      if (freeSpace < MIN_FREE_DISK_BYTES) {
        log.warn('Low disk space, pausing download', { freeSpace, relativePath });
        stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
        this._downloadingPaths.delete(relativePath);
        this._activeOps--;
        metrics.setActiveOps(this._activeOps);
        metrics.record.download(false);
        if (this._activeOps <= 0) { this._activeOps = 0; this._setState(SYNC_STATE.SYNCED); }
        return;
      }

      // M11: Checksum verification is done inside downloadFile before rename
      await this._http.downloadFile(fileId, fullPath, expectedChecksum);

      const localChecksum = expectedChecksum;
      const stat = nodeFs.statSync(longPath(fullPath));
      const fileRecord = stateDb.getFile(relativePath);
      stateDb.upsertFile({
        ...fileRecord,
        relativePath,
        localChecksum,
        localMtime: stat.mtimeMs,
        size: stat.size,
        status: FILE_STATUS.SYNCED,
      });
      ok = true;

      log.info('Downloaded', { relativePath });
    } catch (err) {
      log.error('Download failed', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }

    clearTimeout(stuckTimer);
    metrics.record.download(ok);
    metrics.record.downloadDuration((Date.now() - downloadStart) / C.TIME.seconds(1));
    this._downloadingPaths.delete(relativePath);
    this._activeOps--;
    metrics.setActiveOps(this._activeOps);
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
    // Compute checksum (streaming SHA3-512 on the main thread —
    // benchmarks show worker threads add no benefit for the file
    // sizes we deal with here, see lib/checksum.js docstring).
    let localChecksum;
    try {
      localChecksum = await hashFile(fullPath);
    } catch (err) {
      if (err.code === 'ENOENT') return;
      log.error('Failed to hash file', { relativePath, error: err.message });
      return;
    }

    // Check if this is actually a change
    const existing = stateDb.getFile(relativePath);
    if (existing && existing.localChecksum === localChecksum) {
      return; // No actual change
    }

    // Rename detection: if a recently deleted file has the same checksum, it's a rename
    for (const [oldPath, pending] of this._pendingDeletes) {
      if (pending.checksum === localChecksum) {
        // Match! This is a rename, not delete + add
        clearTimeout(pending.timer);
        this._pendingDeletes.delete(oldPath);
        log.info('Rename detected (checksum match)', { from: oldPath, to: relativePath });
        await this._handleLocalRename(oldPath, relativePath, pending, localChecksum, size, mtime);
        return;
      }
    }

    // Check for conflict: pending download for this file?
    if (existing && existing.status === FILE_STATUS.PENDING_DOWNLOAD) {
      log.warn('Conflict: local change during pending download', { relativePath });
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

    // Route through the upload pool — concurrent watcher events run
    // up to `concurrency` uploads at a time; excess back-pressures the
    // event handler so we don't materialize an unbounded promise queue.
    await this._uploadPool.run(() => this._uploadFile(relativePath, fullPath));
  }

  async _handleLocalDelete(relativePath) {
    const existing = stateDb.getFile(relativePath);
    if (!existing || !existing.serverFileId) {
      stateDb.removeFile(relativePath);
      return;
    }

    // Buffer the delete for rename detection — wait 1 second for a matching add
    log.debug('Buffering delete for rename detection', { relativePath });
    const self = this;
    const timer = setTimeout(function () {
      // No matching add arrived — this is a real delete
      self._pendingDeletes.delete(relativePath);
      self._executeDelete(relativePath, existing);
    }, C.TIME.seconds(1));

    this._pendingDeletes.set(relativePath, {
      checksum: existing.localChecksum || existing.serverChecksum,
      fileId: existing.serverFileId,
      existing: existing,
      timer: timer,
    });
  }

  async _executeDelete(relativePath, existing) {
    log.info('Local delete confirmed', { relativePath });
    try {
      await this._http.deleteFile(existing.serverFileId);
      stateDb.removeFile(relativePath);
      log.info('Deleted from server', { relativePath });
    } catch (err) {
      log.error('Failed to delete from server', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }
  }

  async _handleLocalRename(oldPath, newPath, pending, checksum, size, mtime) {
    this._activeOps++;
    this._setState(SYNC_STATE.UPLOADING);

    try {
      // Call server rename endpoint
      var result = await this._http.renameFile(this._config.bundleId, oldPath, newPath);
      log.info('Renamed on server', { from: oldPath, to: newPath, seq: result.seq });

      // Update local state
      stateDb.removeFile(oldPath);
      stateDb.upsertFile({
        relativePath: newPath,
        serverFileId: pending.fileId,
        localChecksum: checksum,
        serverChecksum: checksum,
        localMtime: mtime,
        size: size,
        serverSeq: result.seq || 0,
        status: FILE_STATUS.SYNCED,
      });
    } catch (err) {
      log.warn('Server rename failed, falling back to delete + upload', { from: oldPath, to: newPath, error: err.message });
      // Fallback: delete old, upload new
      await this._executeDelete(oldPath, pending.existing);
      var fullPath = this._safePath(newPath);
      if (fullPath) await this._handleLocalModify(newPath, fullPath, size, mtime);
    }

    this._activeOps--;
    if (this._activeOps <= 0) { this._activeOps = 0; this._setState(SYNC_STATE.SYNCED); }
  }

  async _uploadFile(relativePath, fullPath) {
    // _activeOps tracks distinct uploads, not attempts — increment once
    // before the retry loop. Retries are bounded inside b.retry.withRetry
    // and don't widen the active-ops gauge.
    this._activeOps++;
    metrics.setActiveOps(this._activeOps);
    this._setState(SYNC_STATE.UPLOADING);

    const uploadStart = Date.now();
    // Watchdog: if a single upload (including retries) takes longer
    // than 10 minutes, log a visible warning so operators don't have
    // to spelunk `active_ops` for a stuck file. We don't kill the
    // upload — could be a legit multi-GB push on a slow link — but
    // a 10-minute single-file upload past a 4-slot pool will burn
    // through the whole queue, so the operator wants to know.
    const stuckTimer = setTimeout(() => {
      log.warn('Upload still in flight after 10 minutes (no per-call timeout — possible hung peer or very large file)',
        { relativePath, elapsedSec: Math.floor((Date.now() - uploadStart) / C.TIME.seconds(1)) });
    }, C.TIME.minutes(10));
    stuckTimer.unref();
    let ok = false;
    try {
      // b.retry.withBreaker composes the breaker around b.retry.withRetry —
      // one retry-loop invocation = one breaker call so the breaker counts
      // a fully-exhausted retry as a single failure (not three). When the
      // breaker is open the inner retry doesn't fire at all and the call
      // fast-fails with code `CIRCUIT_OPEN`.
      //
      // Retry shape: full-jitter exponential backoff with crypto-strength
      // jitter (b.retry.withRetry), classifier refuses to retry obvious
      // bugs (TypeError, ReferenceError) by default — we widen it here
      // because application-shaped HTTP errors don't carry node net codes.
      const result = await b.retry.withBreaker(
        async (attempt) => {
          if (attempt > 1) {
            log.warn(`Upload retrying (attempt ${attempt}/${UPLOAD_MAX_RETRIES})`, { relativePath });
            metrics.record.uploadAttempt();
          }
          return this._http.uploadFile(this._config.bundleId, relativePath, fullPath);
        },
        {
          breaker: this._uploadBreaker,
          retry: {
            maxAttempts:  UPLOAD_MAX_RETRIES,
            baseDelayMs:  UPLOAD_RETRY_DELAY_MS,
            maxDelayMs:   UPLOAD_RETRY_DELAY_MS * 6,
            jitterFactor: 0.5,
            isRetryable:  () => true,
          },
        },
      );
      log.info('Uploaded', { relativePath, fileId: result.fileId || result.id });

      const localChecksum = await hashFile(fullPath);
      const stat = nodeFs.statSync(longPath(fullPath));

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
      ok = true;
    } catch (err) {
      // The breaker throws Error with code `CIRCUIT_OPEN` when it's
      // tripped; distinguish that from a real upload exhaustion so the
      // log line names the right failure mode.
      if (err && err.code === 'CIRCUIT_OPEN') {
        log.warn('Upload skipped — circuit breaker open', { relativePath });
      } else {
        log.error('Upload failed after retries', { relativePath, error: err.message });
      }
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
    }

    clearTimeout(stuckTimer);
    metrics.record.upload(ok);
    metrics.record.uploadDuration((Date.now() - uploadStart) / C.TIME.seconds(1));
    this._activeOps--;
    metrics.setActiveOps(this._activeOps);
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
      const files = nodeFs.readdirSync(longPath(this._config.syncFolder));
      for (const f of files) {
        if (f.includes('.tmp.')) {
          try { nodeFs.unlinkSync(longPath(nodePath.join(this._config.syncFolder, f))); } catch {}
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
    const fullPath = nodePath.resolve(this._config.syncFolder, relativePath);
    const resolvedBase = nodePath.resolve(this._config.syncFolder);
    if (!fullPath.startsWith(resolvedBase + nodePath.sep) && fullPath !== resolvedBase) {
      return null; // traversal attempt
    }
    return fullPath;
  }

  // --- Utilities ---

  _getFreeDiskSpace() {
    try {
      const stat = nodeFs.statfsSync(this._config.syncFolder);
      return stat.bfree * stat.bsize;
    } catch {
      return Infinity; // Can't check — assume OK
    }
  }

}

module.exports = SyncEngine;
