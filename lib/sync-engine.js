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

// How often the engine re-drives stranded transfers (PENDING_DOWNLOAD /
// ERROR rows) independent of the seq cursor, so a transfer that failed
// while the cursor scrolled past it still recovers.
const RECONCILE_INTERVAL_MS = C.TIME.minutes(5);

// Windows rename-lock mitigation for data-path renames (conflict copy,
// server-driven file move). A Dropbox / antivirus / Search-indexer handle
// on the source inode surfaces as EPERM / EACCES / EBUSY; the open handle
// usually clears within a few hundred ms. Matches the delay table
// b.atomicFile uses internally for its atomic-write commit rename.
const RENAME_RETRY_DELAYS_MS = [0, 5, 15, 40, 100]; // allow:raw-byte-literal — backoff delay table in ms, not a byte count
const RENAME_RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

// PEM files must end in a newline — without it, a trust anchor appended
// via `cat extra.pem >> ca.crt` begins on the same line as the prior
// `-----END CERTIFICATE-----` and OpenSSL / Node TLS reject the bundle.
function ensureNewline(pem) {
  return (pem && !pem.endsWith('\n')) ? pem + '\n' : pem;
}

// Synchronous rename with bounded retry on transient Windows lock errors.
// Sleeps via Atomics.wait on a throwaway buffer so the bounded backoff
// doesn't require an async context (these calls sit inside synchronous
// apply sequences). Rethrows immediately on a non-transient code or once
// the delay table is exhausted, so a genuine failure still surfaces.
function _renameWithRetry(from, to) {
  for (let i = 0; i < RENAME_RETRY_DELAYS_MS.length; i++) {
    try {
      nodeFs.renameSync(from, to);
      return;
    } catch (err) {
      const last = i === RENAME_RETRY_DELAYS_MS.length - 1;
      if (last || !RENAME_RETRY_CODES.has(err.code)) throw err;
      const ms = RENAME_RETRY_DELAYS_MS[i + 1];
      if (ms > 0) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); // allow:raw-byte-literal — 4-byte control buffer for the bounded sleep
      }
    }
  }
}

class SyncEngine extends EventEmitter {
  constructor(config, apiKey) {
    super();
    this._config = config;
    this._apiKey = apiKey;
    this._state = SYNC_STATE.DISCONNECTED;
    this._ws = null;
    this._http = null;
    this._watcher = null;
    // path -> active-op count. A path stays watcher-suppressed until the
    // LAST overlapping op releases it, so two ops on the same path (e.g. a
    // conflict-copy window overlapping a download) can't reopen the
    // re-upload window for each other prematurely.
    this._downloadingPaths = new Map();
    this._activeOps = 0; // retained only for the legacy active_ops gauge + getStatus()
    this._activeDownloads = 0; // downloads aren't pool-routed; count them explicitly
    this._catchUpPending = 0; // server-event handlers in flight during catch-up
    this._pendingDeletes = new Map(); // Rename detection: { relativePath -> { checksum, fileId, timer } }
    this._stopped = false;

    // Single tail promise that serializes server-event application. Each
    // inbound message chains onto it so events apply in strict arrival
    // (== seq) order and same-path downloads never overlap. lastSeq stays
    // monotone with applied state because _updateSeq runs at the tail of an
    // awaited handler, never ahead of the file op it gates.
    this._applyChain = Promise.resolve();

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
    // registerPoolStatsProvider keeps a single provider slot (last writer
    // wins); stop() clears it so the metrics module drops its reference to
    // this engine + pool rather than sampling a drained pool.
    metrics.registerPoolStatsProvider(() => ({
      inflight:   this._uploadPool.inFlight(),
      queueDepth: this._uploadPool.queued(),
    }));
  }

  get state() { return this._state; }

  // --- Watcher-suppression refcount ---
  // Every _suppressPath must be paired with exactly one _releasePath on
  // every exit path; the count survives overlapping ops on the same path.
  _suppressPath(p) {
    this._downloadingPaths.set(p, (this._downloadingPaths.get(p) || 0) + 1);
  }

  _releasePath(p) {
    const n = (this._downloadingPaths.get(p) || 0) - 1;
    if (n > 0) this._downloadingPaths.set(p, n);
    else this._downloadingPaths.delete(p);
  }

  _isSuppressed(p) {
    return this._downloadingPaths.has(p);
  }

  // Persist a renewed/rotated mTLS trio atomically. b.atomicFile.writeSync
  // does temp + fsync + rename + parent-dir-fsync per file, with the
  // Windows EPERM/EACCES/EBUSY rename retry and an O_EXCL|O_NOFOLLOW
  // CSPRNG-token temp — so write ordering no longer matters and a crash
  // can't leave a torn key paired with the old cert. fileMode is the
  // honoured option (opts.mode is ignored by the primitive).
  _persistMtlsTrio(paths, pems) {
    b.atomicFile.writeSync(paths.cert, ensureNewline(pems.cert), { fileMode: 0o644 });
    b.atomicFile.writeSync(paths.key,  ensureNewline(pems.key),  { fileMode: 0o600 });
    if (paths.ca && pems.ca) {
      b.atomicFile.writeSync(paths.ca, ensureNewline(pems.ca), { fileMode: 0o644 });
    }
  }

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

      // Atomic, crash-safe trio replacement. A partial write previously
      // risked a torn cert/key/CA that failed the next handshake; each
      // file is now all-or-nothing and the rename ordering is immaterial.
      try {
        this._persistMtlsTrio(
          { cert: this._config.mtls.cert, key: this._config.mtls.key, ca: this._config.mtls.ca },
          { cert: renewed.clientCert, key: renewed.clientKey, ca: renewed.caCert },
        );
      } catch (err) {
        log.error('mTLS certificate files may be inconsistent after a failed renewal write — run `hermitstash-sync repair` with a fresh enrollment code to re-provision the cert/key/CA', { error: err.message });
        return;
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
    this._stopped = false;
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

    // Re-drive stranded transfers periodically, independent of the seq
    // cursor. A download that failed while the cursor advanced past it
    // would otherwise sit ERROR forever; this sweep keys off persisted row
    // state so it recovers regardless of where lastSeq landed.
    this._reconcileTimer = setInterval(() => {
      this._recoverPending().catch(err => log.warn('Pending-transfer reconcile failed', { error: err.message }));
    }, RECONCILE_INTERVAL_MS);
    this._reconcileTimer.unref();

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

      // Re-drive any transfer left PENDING_DOWNLOAD / ERROR by a previous
      // session or a download that failed below the cursor. Chained onto
      // the apply chain so it can't race a catch-up event for the same path.
      this._enqueueRecover();
    });

    // Serialize every inbound server message onto the apply chain. A throw
    // inside an awaited handler is caught here so a single bad event never
    // escapes as an unhandledRejection or stalls later events.
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

    // Re-drive transfers a previous run left mid-flight (crash before the
    // SYNCED upsert). Keyed off persisted row state, independent of the
    // seq replay window, so a crash-interrupted transfer self-heals.
    this._enqueueRecover();

    // Start file watcher
    this._watcher.start();
  }

  _clearCertCheckTimer() {
    if (this._certCheckTimer) {
      try { clearInterval(this._certCheckTimer); } catch { /* allow:silent-catch — idempotent timer teardown */ }
      this._certCheckTimer = null;
    }
    if (this._reconcileTimer) {
      try { clearInterval(this._reconcileTimer); } catch { /* allow:silent-catch — idempotent timer teardown */ }
      this._reconcileTimer = null;
    }
  }

  async stop() {
    log.info('Sync engine stopping');
    this._stopped = true;
    this._setState(SYNC_STATE.DISCONNECTED);
    this._clearCertCheckTimer();

    // Drop any buffered server events so a still-pending apply can't run
    // against a torn-down HTTP client / closed state DB. New messages are
    // ignored once _stopped is set; resetting the chain to a resolved
    // promise abandons the tail of work already queued behind the guard.
    this._applyChain = Promise.resolve();

    // Cancel buffered rename-detection deletes so their 1s timer can't fire
    // _executeDelete against a torn-down HTTP client / closed state DB.
    for (const pending of this._pendingDeletes.values()) {
      clearTimeout(pending.timer);
    }
    this._pendingDeletes.clear();

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

    // Release the metrics provider closure so the snapshot writer stops
    // sampling a drained pool and the metrics module drops its strong
    // reference to this engine. registerPoolStatsProvider keeps a single
    // slot, so passing null clears it.
    try { metrics.registerPoolStatsProvider(null); }
    catch (err) { log.debug('Pool-stats provider clear failed', { error: err.message }); }

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

  // Transition to SYNCED only when no transfer is queued OR in flight.
  // Derives "busy" from authoritative sources — the upload pool's
  // inFlight + queued depth and the explicit download counter — instead
  // of the per-op _activeOps, so SYNCED can't flap to true in the gap
  // between a finishing op and a not-yet-started queued op.
  _maybeMarkSynced() {
    if (this._state === SYNC_STATE.DISCONNECTED) return;
    const uploadsBusy = this._uploadPool.inFlight() > 0 || this._uploadPool.queued() > 0;
    const downloadsBusy = this._activeDownloads > 0;
    if (!uploadsBusy && !downloadsBusy) this._setState(SYNC_STATE.SYNCED);
  }

  // --- Server message handling ---

  // Append each message to the apply chain so handlers run one at a time in
  // arrival (== seq) order. A handler throw is logged here and deliberately
  // does NOT advance the cursor — leaving lastSeq below N lets the server
  // replay the event on the next reconnect; the reconcile sweep recovers a
  // download that scrolled past the cursor.
  _onServerMessage(msg) {
    if (this._stopped) return;
    this._applyChain = this._applyChain
      .then(() => this._applyServerMessage(msg))
      .catch((err) => log.error('Server event apply failed — will retry on next catch-up', {
        type: msg && msg.type, relativePath: msg && msg.relativePath, seq: msg && msg.seq, error: err.message,
      }));
  }

  async _applyServerMessage(msg) {
    if (this._stopped) return;
    const { type } = msg;

    switch (type) {
      case MSG.FILE_ADDED:
        await this._handleFileAdded(msg);
        break;
      case MSG.FILE_REPLACED:
        await this._handleFileReplaced(msg);
        break;
      case MSG.FILE_REMOVED:
        await this._handleFileRemoved(msg);
        break;
      case MSG.FILE_RENAMED:
        await this._handleFileRenamed(msg);
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
      // Atomic write per file: temp + fsync + rename + parent-dir-fsync,
      // with Windows EPERM/EACCES/EBUSY rename retry and an O_EXCL|O_NOFOLLOW
      // CSPRNG-token temp. Cert → key → CA order.
      this._persistMtlsTrio(
        { cert: mtls.cert, key: mtls.key, ca: mtls.ca },
        { cert: newCertPem, key: newKeyPem, ca: newCaPem },
      );

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
      log.error('CA rotation failed to persist — re-enrollment may be required', err);
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
      _renameWithRetry(longPath(fullPath), longPath(conflict));
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
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    // Selective-sync: skip out-of-scope paths but still advance seq so
    // we don't replay them on reconnect.
    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file added', { relativePath, size });

    // Track outstanding catch-up work synchronously BEFORE the first await
    // so a heartbeat processed mid-batch sees this handler as still pending.
    this._catchUpPending++;
    // Bracket the whole apply window — including the pre-download conflict
    // copy — so a concurrent local edit can't be re-uploaded mid-apply.
    this._suppressPath(relativePath);
    try {
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

      // Only advance the cursor once the download commits. A failure leaves
      // the row PENDING_DOWNLOAD/ERROR and the cursor below N, so reconnect
      // catch-up redelivers the event (idempotent on the localChecksum
      // short-circuit above) and the reconcile sweep re-drives the row.
      const ok = await this._downloadFile(relativePath, fileId, checksum);
      if (ok) this._updateSeq(seq);
    } finally {
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }
  }

  async _handleFileReplaced(msg) {
    const { fileId, relativePath, checksum, size, seq } = msg;

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_replaced', { relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file replaced', { relativePath, size });

    this._catchUpPending++;
    this._suppressPath(relativePath);
    try {
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

      const ok = await this._downloadFile(relativePath, fileId, checksum);
      if (ok) this._updateSeq(seq);
    } finally {
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }
  }

  async _handleFileRemoved(msg) {
    const { relativePath, seq } = msg;

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_removed', { relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file removed', { relativePath });

    this._catchUpPending++;
    this._suppressPath(relativePath);
    try {
      const existing = stateDb.getFile(relativePath);
      const lastSynced = existing && (existing.localChecksum || existing.serverChecksum);
      let applied = true;

      if (nodeFs.existsSync(longPath(fullPath))) {
        // Preserve locally-modified bytes against a remote delete. If the
        // file on disk still matches the last value we synced, the delete
        // is uncontested — remove it. If it diverged, the user changed it
        // independently; keep their copy as a conflict file rather than
        // destroying it.
        let actualLocal = null;
        try { actualLocal = await hashFile(fullPath); }
        catch (err) { log.warn('Could not hash local file before remote delete', { relativePath, error: err.message }); }

        if (lastSynced && actualLocal && actualLocal !== lastSynced) {
          try {
            const conflict = b.atomicFile.conflictPath(fullPath);
            _renameWithRetry(longPath(fullPath), longPath(conflict));
            metrics.record.conflict();
            log.warn('Kept conflict copy before honoring remote delete', {
              relativePath,
              conflict: nodePath.relative(this._config.syncFolder, conflict).split(nodePath.sep).join('/'),
            });
          } catch (err) {
            applied = false;
            log.error('Could not preserve locally-modified file before remote delete — keeping the local file and the DB row; close any app holding the file and the next reconnect retries', { relativePath, error: err.message });
          }
        } else {
          // Uncontested delete — bounded retry on a Windows/Dropbox lock.
          applied = this._unlinkWithRetry(relativePath, fullPath);
        }
      }

      if (applied) {
        stateDb.removeFile(relativePath);
        this._updateSeq(seq);
      }
      // If not applied: keep the DB row (the path stays watcher-suppressed
      // for this apply, and the row is left intact) and do NOT advance the
      // cursor, so the next reconnect re-delivers the delete.
    } finally {
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }
  }

  // Delete a local file with bounded retry on transient Windows lock
  // errors. Treats ENOENT / already-absent as success. Returns true if the
  // file is gone (or was never there), false if it stayed locked after the
  // retry budget — in which case the caller keeps the DB row and the seq
  // cursor so the delete is re-driven on reconnect rather than silently
  // resurrecting the file.
  _unlinkWithRetry(relativePath, fullPath) {
    const target = longPath(fullPath);
    for (let i = 0; i < RENAME_RETRY_DELAYS_MS.length; i++) {
      try {
        nodeFs.unlinkSync(target);
        log.info('Deleted local file', { relativePath });
        return true;
      } catch (err) {
        if (err.code === 'ENOENT') return true; // already gone
        const last = i === RENAME_RETRY_DELAYS_MS.length - 1;
        if (last || !RENAME_RETRY_CODES.has(err.code)) {
          log.error('Failed to delete local file — keeping it and the DB row; the delete retries on the next reconnect', { relativePath, error: err.message });
          return false;
        }
        const ms = RENAME_RETRY_DELAYS_MS[i + 1];
        if (ms > 0) {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); // allow:raw-byte-literal — 4-byte control buffer for the bounded sleep
        }
      }
    }
    return false;
  }

  async _handleFileRenamed(msg) {
    const { oldRelativePath, relativePath, fileId, checksum, size, seq } = msg;

    if (!this._safePath(oldRelativePath) || !this._safePath(relativePath)) {
      log.error('Path traversal attempt blocked in file_renamed', { oldRelativePath, relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
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

    this._catchUpPending++;
    // Suppress watcher events for both paths during the move
    this._suppressPath(oldRelativePath);
    this._suppressPath(relativePath);

    let applied = false;
    try {
      // Create destination directory if needed
      const newDir = nodePath.dirname(newFullPath);
      if (!nodeFs.existsSync(longPath(newDir))) nodeFs.mkdirSync(longPath(newDir), { recursive: true });

      // Move the file locally. Bounded Windows rename-lock retry so a
      // transient Dropbox/AV handle doesn't abort the move.
      if (oldFullPath && nodeFs.existsSync(longPath(oldFullPath))) {
        _renameWithRetry(longPath(oldFullPath), longPath(newFullPath));
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

      // Both the filesystem move and the DB swap landed.
      applied = true;
      log.info('Renamed local file', { from: oldRelativePath, to: relativePath });
    } catch (err) {
      log.error('Failed to rename local file', { from: oldRelativePath, to: relativePath, error: err.message });
    } finally {
      this._releasePath(oldRelativePath);
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }

    if (applied) {
      this._updateSeq(seq);
      return;
    }

    // The local move did not land. Never advance the cursor past an event
    // whose side effect failed — fall back to delete-old + re-download-new
    // so the new path lands fresh. _handleFileAdded owns the seq advance
    // once its download to the new path commits; it upserts
    // PENDING_DOWNLOAD first, so a further failure leaves a recoverable
    // marker rather than a SYNCED row at the wrong path. The delete of the
    // old path is best-effort and must not advance the cursor here.
    log.warn('Local rename failed — recovering via delete-old + re-download-new', { from: oldRelativePath, to: relativePath });
    await this._handleFileRemovedNoSeq(oldRelativePath);
    await this._handleFileAdded({ fileId, relativePath, checksum, size, seq });
  }

  // Local-only delete of a path with no seq advance. Used by the rename
  // recovery fallback to clear the stale source without touching the
  // cursor (the companion _handleFileAdded owns the advance).
  async _handleFileRemovedNoSeq(relativePath) {
    const fullPath = this._safePath(relativePath);
    if (!fullPath) return;
    this._suppressPath(relativePath);
    try {
      if (nodeFs.existsSync(longPath(fullPath))) {
        this._unlinkWithRetry(relativePath, fullPath);
      }
      stateDb.removeFile(relativePath);
    } finally {
      this._releasePath(relativePath);
    }
  }

  /**
   * Re-drive transfers that persisted state says are unfinished —
   * PENDING_DOWNLOAD rows (queued but not yet committed) and ERROR rows (a
   * prior download failed). Independent of the seq cursor, so a transfer
   * that failed below lastSeq still recovers. Chained onto the apply chain
   * by _enqueueRecover so it can't race a live catch-up event for the same
   * path. Skips rows whose local content already matches serverChecksum to
   * avoid redundant transfers, and rows without a serverFileId to download.
   */
  async _recoverPending() {
    if (this._stopped || !this._http) return;
    let rows;
    try {
      rows = stateDb.getFilesByStatus(FILE_STATUS.PENDING_DOWNLOAD)
        .concat(stateDb.getFilesByStatus(FILE_STATUS.ERROR));
    } catch (err) {
      log.warn('Could not enumerate pending transfers for reconcile', { error: err.message });
      return;
    }
    if (!rows.length) return;

    let recovered = 0;
    for (const row of rows) {
      if (this._stopped) break;
      const relativePath = row.relativePath;
      const fileId = row.serverFileId;
      const checksum = row.serverChecksum;
      if (!fileId || !checksum) continue; // nothing to download against

      const fullPath = this._safePath(relativePath);
      if (!fullPath) continue;

      // Skip if local already matches the server checksum (a download that
      // landed but whose status update was interrupted, or a watcher-driven
      // upload that converged).
      try {
        if (nodeFs.existsSync(longPath(fullPath))) {
          const local = await hashFile(fullPath);
          if (local === checksum) {
            const existing = stateDb.getFile(relativePath);
            stateDb.upsertFile({ ...existing, relativePath, localChecksum: local, serverChecksum: checksum, serverFileId: fileId, status: FILE_STATUS.SYNCED });
            continue;
          }
        }
      } catch { /* allow:silent-catch — hash probe is best-effort; fall through to re-download */ }

      this._suppressPath(relativePath);
      try {
        await this._downloadFile(relativePath, fileId, checksum);
        recovered++;
      } finally {
        this._releasePath(relativePath);
      }
    }
    if (recovered > 0) log.info('Reconcile pass re-drove stranded transfers', { count: recovered });
  }

  // Chain a reconcile pass onto the apply chain so it serializes with live
  // server events rather than racing them on the same path.
  _enqueueRecover() {
    if (this._stopped) return;
    this._applyChain = this._applyChain
      .then(() => this._recoverPending())
      .catch((err) => log.warn('Pending-transfer reconcile failed', { error: err.message }));
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

    // The seq===0 "connection live" heartbeat is a liveness ping only — it
    // does NOT by itself declare catch-up complete. A genuine "caught up at
    // seq N" heartbeat (seq <= lastSeq) only completes catch-up once the
    // event apply queue has actually drained (no handler still pending and
    // no transfer in flight). _maybeFinishCatchUp owns the transition.
    if (this._state === SYNC_STATE.CATCHING_UP) {
      const lastSeq = stateDb.getLastSeq();
      if (seq !== 0 && seq <= lastSeq) {
        this._caughtUpAtSeq = true;
      }
      this._maybeFinishCatchUp();
    }

    // Send ack
    if (this._ws) {
      this._ws.send({ type: MSG.ACK, seq });
    }
  }

  // Complete the catch-up transition only when a genuine caught-up-at-seq-N
  // heartbeat has arrived AND no catch-up handler is still outstanding AND
  // no download is in flight. Re-evaluated at the tail of every handler and
  // every download so the transition fires the moment the queue drains.
  _maybeFinishCatchUp() {
    if (this._state !== SYNC_STATE.CATCHING_UP) return;
    if (!this._caughtUpAtSeq) return;
    if (this._catchUpPending > 0 || this._activeDownloads > 0) return;
    this._caughtUpAtSeq = false;
    this._setState(SYNC_STATE.SYNCED);
    stateDb.setMeta('last_sync_time', new Date().toISOString());
    log.info('Catch-up complete, now synced');
  }

  _updateSeq(seq) {
    try {
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
    } catch (err) {
      // A transient lock / closed DB must not silently drop the cursor
      // advance. Re-throw so the apply chain's catch leaves lastSeq below N
      // and the server replays the event on reconnect.
      log.error('Failed to persist sync cursor — event will replay on reconnect', { seq, error: err.message });
      throw err;
    }
  }

  // --- File downloads ---

  // Returns true if the file landed SYNCED, false on any failure path
  // (low-disk pause, download/checksum error). Callers gate _updateSeq on
  // the boolean so a failed transfer never advances the cursor.
  async _downloadFile(relativePath, fileId, expectedChecksum) {
    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in download', { relativePath });
      return false;
    }

    this._suppressPath(relativePath);
    this._activeDownloads++;
    this._activeOps++;
    metrics.setActiveOps(this._activeOps);
    this._setState(SYNC_STATE.DOWNLOADING);

    let ok = false;
    const downloadStart = Date.now();
    let stuckTimer = null;
    try {
      // Check disk space BEFORE arming the stuck-timer, so a low-disk pause
      // doesn't leave a 10-minute timer dangling (and firing a misleading
      // "still in flight" warning long after the early return).
      const freeSpace = this._getFreeDiskSpace();
      if (freeSpace < MIN_FREE_DISK_BYTES) {
        log.warn('Low disk space, pausing download', { freeSpace, relativePath });
        stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
        return false;
      }

      // The timer only exists once a real network download is in flight, so
      // the warning is semantically accurate and there's nothing to leak on
      // the disk-check early return above.
      stuckTimer = setTimeout(() => {
        log.warn('Download still in flight after 10 minutes (no per-call timeout — possible hung peer or very large file)',
          { relativePath, elapsedSec: Math.floor((Date.now() - downloadStart) / C.TIME.seconds(1)) });
      }, C.TIME.minutes(10));
      stuckTimer.unref();

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
    } finally {
      if (stuckTimer) clearTimeout(stuckTimer);
      metrics.record.download(ok);
      metrics.record.downloadDuration((Date.now() - downloadStart) / C.TIME.seconds(1));
      this._releasePath(relativePath);
      this._activeDownloads = Math.max(0, this._activeDownloads - 1);
      this._activeOps = Math.max(0, this._activeOps - 1);
      metrics.setActiveOps(this._activeOps);
      this._maybeMarkSynced();
      this._maybeFinishCatchUp();
    }
    return ok;
  }

  // --- Local change handling ---

  async _onLocalChange(ev) {
    try {
      if (this._state === SYNC_STATE.DISCONNECTED || this._state === SYNC_STATE.ERROR) return;

      const { type, relativePath, fullPath, size, mtime } = ev;

      // H1: Skip changes for files currently being downloaded to avoid re-upload race
      if (this._isSuppressed(relativePath)) {
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
    // unref so a buffered delete never holds the foreground event loop open;
    // stop() cancels it explicitly during teardown.
    if (typeof timer.unref === 'function') timer.unref();

    this._pendingDeletes.set(relativePath, {
      checksum: existing.localChecksum || existing.serverChecksum,
      fileId: existing.serverFileId,
      existing: existing,
      timer: timer,
    });
  }

  async _executeDelete(relativePath, existing) {
    // A buffered delete can fire just as stop() tears things down. Bail if the
    // engine is disconnected or the HTTP client is gone, rather than throwing
    // an unhandled rejection against a null client / closed state DB.
    if (this._state === SYNC_STATE.DISCONNECTED || !this._http) return;
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
    } finally {
      this._activeOps = Math.max(0, this._activeOps - 1);
      this._maybeMarkSynced();
    }
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
      // jitter (b.retry.withRetry). A permanent server rejection (a 4xx the
      // upload carries as err.permanent) is caught inside the wrapped call and
      // returned as a sentinel: that stops the retry loop AND lets the breaker
      // count a success, so a handful of un-uploadable files can't open the
      // per-target breaker and stall every other file's upload. Transient
      // failures still throw through to the retry + breaker as before.
      const result = await b.retry.withBreaker(
        async (attempt) => {
          if (attempt > 1) {
            log.warn(`Upload retrying (attempt ${attempt}/${UPLOAD_MAX_RETRIES})`, { relativePath });
            metrics.record.uploadAttempt();
          }
          try {
            return await this._http.uploadFile(this._config.bundleId, relativePath, fullPath);
          } catch (uploadErr) {
            if (uploadErr && uploadErr.permanent) return { _permanentUploadError: uploadErr };
            throw uploadErr;
          }
        },
        {
          breaker: this._uploadBreaker,
          retry: {
            maxAttempts:  UPLOAD_MAX_RETRIES,
            baseDelayMs:  UPLOAD_RETRY_DELAY_MS,
            maxDelayMs:   UPLOAD_RETRY_DELAY_MS * 6,
            jitterFactor: 0.5,
            isRetryable:  (err) => !(err && err.permanent),
          },
        },
      );

      if (result && result._permanentUploadError) {
        const perr = result._permanentUploadError;
        log.error('Upload rejected by server — not retried (fix the file or its permissions, then resync)',
          { relativePath, status: perr.statusCode, error: perr.message });
        stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
      } else {
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
      }
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
    this._activeOps = Math.max(0, this._activeOps - 1);
    metrics.setActiveOps(this._activeOps);
    // Derive SYNCED from the pool's queued + inflight depth, not the per-op
    // counter, so state doesn't flap to SYNCED between two serial transfers.
    this._maybeMarkSynced();
  }

  // --- Temp file cleanup ---

  /**
   * Remove leftover temp files from interrupted downloads on startup.
   * downloadFile() writes its temp beside the destination at any depth, so the
   * scan must recurse — a flat read of the sync-folder root leaks temps left
   * inside subdirectories. Matches only the exact ".tmp.<hex>" suffix that
   * downloadFile() generates (b.crypto.generateToken(4) → 8 hex chars) so a
   * user file that merely contains ".tmp." is never removed. Recurses real
   * directories only (skips symlinks to avoid following links out of the tree
   * or cycling) and deliberately ignores include/exclude patterns, since an
   * orphaned temp can sit inside an ignored directory too.
   */
  _cleanupTempFiles() {
    const TEMP_RE = /\.tmp\.[0-9a-f]{8,}$/;
    const walk = (dir) => {
      let entries;
      try { entries = nodeFs.readdirSync(longPath(dir), { withFileTypes: true }); }
      catch { return; }
      for (const ent of entries) {
        if (ent.isSymbolicLink()) continue;
        const full = nodePath.join(dir, ent.name);
        if (ent.isDirectory()) { walk(full); continue; }
        // allow:regex-no-length-cap — ent.name is one filesystem path component (NAME_MAX-bounded); the suffix pattern is linear with no backtracking surface
        if (ent.isFile() && TEMP_RE.test(ent.name)) {
          try { nodeFs.unlinkSync(longPath(full)); } catch {}
        }
      }
    };
    walk(this._config.syncFolder);
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
