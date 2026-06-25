'use strict';

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const {
  MSG, FILE_STATUS, SYNC_STATE,
  UPLOAD_MAX_RETRIES, UPLOAD_RETRY_DELAY_MS, MIN_FREE_DISK_BYTES,
  UPLOAD_CB_FAILURES, UPLOAD_CB_COOLDOWN_MS, UPLOAD_CB_SUCCESSES,
  UPLOAD_DEFAULT_CONCURRENCY, MAX_SYNC_FILE_BYTES,
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

// The `.tmp.<8hex>` suffix every daemon-private scratch file carries —
// the download temp, the case-fold probe, and the two-step case-rename
// temp. The boot sweep (_cleanupTempFiles) collects crashed-run orphans
// matching this, and the local upload scan (_walkDir) refuses to enqueue a
// live in-flight temp for upload regardless of sweep timing. Anchored,
// linear, NAME_MAX-bounded — tested against one path component only.
const TEMP_FILE_RE = /\.tmp\.[0-9a-f]{8,}$/;

// PEM files must end in a newline — without it, a trust anchor appended
// via `cat extra.pem >> ca.crt` begins on the same line as the prior
// `-----END CERTIFICATE-----` and OpenSSL / Node TLS reject the bundle.
function ensureNewline(pem) {
  return (pem && !pem.endsWith('\n')) ? pem + '\n' : pem;
}

// Canonical Unicode form for a relativePath. macOS (and any NFD-surfacing
// volume) hands back decomposed forms from readdir while the server stores
// the composed form the file was uploaded under; without normalization the
// two render as distinct keys and the same file churns as a phantom
// remove + add on every reconnect. NFC is the form the server and most
// other platforms use, so the daemon normalizes every relativePath to NFC
// at each boundary — inbound server handlers, the state-db key, and the
// watcher emission — so a single byte-stable identity flows through the
// whole pipeline.
function canonRelPath(relativePath) {
  return typeof relativePath === 'string' ? relativePath.normalize('NFC') : relativePath;
}

// Final temp->dest renames route through b.atomicFile.renameWithRetry,
// which rides out the same transient Windows / Dropbox lock codes
// (EPERM / EACCES / EBUSY) on the same bounded backoff this module used
// to hand-roll. (RENAME_RETRY_* above still back the local unlink retry,
// for which the framework exposes no primitive.)

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
    // Per-path serialization. A local upload and a same-path server download
    // must run in a strict total order — the single pre-await _isSuppressed
    // check is a TOCTOU window: a local edit can pass the check, await its
    // hash, and then upsert/upload while a concurrent download for the same
    // path is mid-flight. A per-path mutex (keyed on _suppKey, so case-
    // variants of one inode share a slot) held across the hash + upsert +
    // transfer span closes that window. Keyed so unrelated paths still run
    // in parallel. The slot is dropped when its mutex is idle so the map
    // can't grow unbounded over a long-running daemon.
    this._pathLocks = new Map();
    this._activeOps = 0; // retained only for the legacy active_ops gauge + getStatus()
    this._activeDownloads = 0; // downloads aren't pool-routed; count them explicitly
    // Live download promises, so resync()/stop() can await in-flight
    // transfers before wiping the DB (downloads have no pool to drain).
    this._activeDownloadPromises = new Set();
    this._catchUpPending = 0; // server-event handlers in flight during catch-up
    this._pendingDeletes = new Map(); // Rename detection: { relativePath -> { checksum, size, fileId, timer } }
    this._stopped = false;

    // True once the boot probe confirms the sync folder lives on a
    // case-folding filesystem (NTFS, HFS+, exFAT/FAT, a case-folding
    // Dropbox mount on Linux). Detected empirically — os.platform() lies
    // both ways (a FAT mount on Linux folds; a case-sensitive volume on
    // macOS does not). Drives the fold-aware identity resolver so a
    // differently-cased server event reuses the one tracked row instead
    // of spawning a byte-distinct duplicate the FS can't represent.
    this._fsCaseFolds = false;

    // Set across the resync() teardown window. Post-await write paths
    // (download/upload upsert, seq advance, buffered-delete fire) check it
    // and no-op so a suspended handler that resumes after clearAll() can't
    // re-populate the just-cleared DB.
    this._resyncing = false;

    // Memoized in-flight resync promise. resync() coalesces onto it so the
    // teardown body runs exactly once per logical resync — a second caller
    // (an un-awaited SIGHUP arriving mid-drain) awaits the same promise
    // instead of starting a parallel teardown that would double-clearAll
    // and double-close/connect the socket.
    this._resyncInFlight = null;

    // Sticky guard set when the server permanently rejects the WebSocket
    // upgrade with a non-auth status (404/409/426/400/...). It pins the
    // engine in ERROR so the close-driven RECONNECTING flip can't mask a
    // permanent rejection the daemon will never recover from on its own.
    // Cleared at every connect entry point (start()/resync()) so a later
    // successful dial isn't held down by a stale flag.
    this._terminalUpgradeReject = false;

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
  // The suppression key is fold-normalized on a case-folding host so a
  // case-variant local watcher event (which the FS surfaces under whatever
  // casing the inode carries) shares the same suppression slot as the
  // server-driven op — otherwise a "Foo.txt" download wouldn't suppress a
  // "foo.txt" watcher event for the same inode and the file would re-upload
  // mid-download.
  _suppKey(p) {
    return this._fsCaseFolds && typeof p === 'string' ? p.toLowerCase() : p;
  }

  _suppressPath(p) {
    const k = this._suppKey(p);
    this._downloadingPaths.set(k, (this._downloadingPaths.get(k) || 0) + 1);
  }

  _releasePath(p) {
    const k = this._suppKey(p);
    const n = (this._downloadingPaths.get(k) || 0) - 1;
    if (n > 0) this._downloadingPaths.set(k, n);
    else this._downloadingPaths.delete(k);
  }

  _isSuppressed(p) {
    return this._downloadingPaths.has(this._suppKey(p));
  }

  // Run `fn` while holding the per-path mutex for `p`, so a local upload and
  // a same-path server download are strictly serialized rather than racing.
  // Keyed on _suppKey so a case-variant of one inode shares the slot. The
  // map entry is reclaimed once the mutex is idle (no holder, no waiters) so
  // it can't grow unbounded across a long-running daemon. b.safeAsync.Mutex
  // is a FIFO async lock from the vendored framework.
  async _withPathLock(p, fn) {
    const k = this._suppKey(p);
    let mtx = this._pathLocks.get(k);
    if (!mtx) {
      mtx = new b.safeAsync.Mutex();
      this._pathLocks.set(k, mtx);
    }
    try {
      return await mtx.runExclusive(fn);
    } finally {
      // Drop the slot only when nothing else holds or is waiting on it, so a
      // queued waiter keeps the same mutex instance (and its FIFO order).
      if (!mtx.isHeld() && mtx.pendingCount() === 0 && this._pathLocks.get(k) === mtx) {
        this._pathLocks.delete(k);
      }
    }
  }

  // Persist a renewed/rotated mTLS trio. b.atomicFile.writeSync does temp +
  // fsync + rename + parent-dir-fsync PER FILE, with the Windows
  // EPERM/EACCES/EBUSY rename retry and an O_EXCL|O_NOFOLLOW CSPRNG-token
  // temp. Per-file atomicity does NOT make the three-file SET atomic: a
  // crash partway through can land the new cert/key while the CA is still
  // the old one (or any other torn combination). The CA-rotation handler
  // compensates with staging + chain validation + a .prev backup + a
  // boot-time recovery from that backup — this helper only guarantees each
  // individual write is all-or-nothing. fileMode is the honoured option
  // (opts.mode is ignored by the primitive).
  _persistMtlsTrio(paths, pems) {
    b.atomicFile.writeSync(paths.cert, ensureNewline(pems.cert), { fileMode: 0o644 });
    b.atomicFile.writeSync(paths.key,  ensureNewline(pems.key),  { fileMode: 0o600 });
    if (paths.ca && pems.ca) {
      b.atomicFile.writeSync(paths.ca, ensureNewline(pems.ca), { fileMode: 0o644 });
    }
  }

  // Validate a candidate mTLS trio before it touches the live identity.
  // Throws on any failure (unparseable PEM, key/cert mismatch, or a leaf
  // that doesn't chain to the supplied CA) so the caller can reject the
  // rotation and leave the working identity intact. All primitives are
  // node:crypto built-ins.
  _validateMtlsTrio(certPem, keyPem, caPem) {
    const leaf = new nodeCrypto.X509Certificate(certPem);   // throws on unparseable cert
    const caCert = new nodeCrypto.X509Certificate(caPem);   // throws on unparseable CA
    const key = nodeCrypto.createPrivateKey(keyPem);        // throws on unparseable key
    if (!leaf.checkPrivateKey(key)) {
      throw new Error('rotated key does not match rotated cert');
    }
    // The supplied CA must both validly issue the leaf (issuer/subject DN +
    // AKI/SKI linkage AND signature) AND assert basicConstraints cA:TRUE.
    // node's X509Certificate.verify()/checkIssued() validate the signature and
    // DN linkage but NOT the cA bit, so a non-CA end-entity certificate whose
    // key happened to sign the leaf would otherwise be accepted here as the
    // trust anchor for a swapped-in identity (the classic basicConstraints
    // bypass, CVE-2002-0862 class). b.x509Chain.issuerValidlyIssued is the
    // framework's fail-closed issuer test — cA-bit first, then checkIssued,
    // then signature — and returns false (never throws) on any malformed input.
    if (!b.x509Chain.issuerValidlyIssued(caCert, leaf)) {
      throw new Error('rotated leaf does not chain to a valid CA — the issuer must assert basicConstraints cA:TRUE and have signed the leaf');
    }
  }

  // Restore the mTLS identity from a pre-rotation .prev backup when the
  // live trio on disk is torn (a CA rotation crashed mid-swap) or a
  // leftover .next stage file is present. Runs at boot before the HTTP
  // client caches the certs. Detects a torn live trio by parsing the
  // cert/key and checking they still match; on a mismatch (or a present
  // .next) it copies the .prev trio back over the live paths. Best-effort
  // — a missing/partial backup leaves the live files untouched and logs an
  // actionable message.
  _recoverMtlsFromBackup() {
    const mtls = this._config && this._config.mtls;
    if (!mtls || !mtls.cert || !mtls.key || !mtls.ca) return;
    const cert = mtls.cert, key = mtls.key, ca = mtls.ca;
    const next = (p) => p + '.next';
    const prev = (p) => p + '.prev';

    let torn = false;
    const leftoverNext = nodeFs.existsSync(longPath(next(cert))) ||
      nodeFs.existsSync(longPath(next(key))) || nodeFs.existsSync(longPath(next(ca)));

    try {
      if (nodeFs.existsSync(longPath(cert)) && nodeFs.existsSync(longPath(key))) {
        // Read the live cert/key TOCTOU-safe: refuse a symlink at either path
        // and bind the read to the opened inode. client.key is a 0o600 secret
        // written only by b.atomicFile.writeSync, so a symlink there is an
        // attacker-planted swap — refuse it (treated as torn below) rather
        // than following the link and judging trio consistency off the link
        // target. A swapped-for-symlink path makes fdSafeReadSync throw, which
        // the catch turns into torn — exactly the safe outcome.
        const certPem = b.atomicFile.fdSafeReadSync(longPath(cert), {
          refuseSymlink: true, inodeCheck: true, maxBytes: C.BYTES.mib(1), encoding: 'utf8',
        });
        const keyPem = b.atomicFile.fdSafeReadSync(longPath(key), {
          refuseSymlink: true, inodeCheck: true, maxBytes: C.BYTES.mib(1), encoding: 'utf8',
        });
        const leaf = new nodeCrypto.X509Certificate(certPem);
        const pk = nodeCrypto.createPrivateKey(keyPem);
        if (!leaf.checkPrivateKey(pk)) torn = true;
      }
    } catch {
      // Unparseable / symlink-swapped / TOCTOU live cert/key — treat as torn
      // so the backup is tried instead of trusting a swapped file.
      torn = true;
    }

    if (!torn && !leftoverNext) return;

    const haveBackup = nodeFs.existsSync(longPath(prev(cert))) &&
      nodeFs.existsSync(longPath(prev(key))) && nodeFs.existsSync(longPath(prev(ca)));
    if (!haveBackup) {
      if (torn) {
        log.error('mTLS identity on disk is inconsistent and no pre-rotation backup is present — re-run enrollment with a fresh code to re-provision the cert/key/CA');
      }
      // Clean up a stray .next so the next rotation starts from a known state.
      for (const p of [cert, key, ca]) {
        try { nodeFs.unlinkSync(longPath(next(p))); } catch { /* allow:silent-catch — stray-stage cleanup is best-effort */ }
      }
      return;
    }

    try {
      nodeFs.copyFileSync(longPath(prev(cert)), longPath(cert));
      nodeFs.copyFileSync(longPath(prev(key)), longPath(key));
      nodeFs.copyFileSync(longPath(prev(ca)), longPath(ca));
      for (const p of [cert, key, ca]) {
        try { nodeFs.unlinkSync(longPath(next(p))); } catch { /* allow:silent-catch — stray-stage cleanup is best-effort */ }
      }
      log.warn('mTLS identity restored from pre-rotation backup; re-run enrollment if reconnect still fails');
    } catch (err) {
      log.error('Could not restore mTLS identity from pre-rotation backup — re-run enrollment with a fresh code', { error: err.message });
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

      // Read the cert's notAfter via node:crypto's X509Certificate — no
      // external binary, so expiry detection + auto-renew work uniformly on
      // SEA binaries and minimal (distroless / wolfi) containers that ship
      // no `openssl` on PATH. validToDate is a Date on current Node; the
      // validTo string is parsed as a fallback for resilience.
      var endDate;
      try {
        // Read the cert TOCTOU-safe (refuse a symlink, bind the read to the
        // opened inode) before parsing notAfter, so a path swapped between the
        // existsSync above and this read can't redirect the expiry check at a
        // foreign file. The cert is client-owned and only b.atomicFile-written.
        var certBytes = b.atomicFile.fdSafeReadSync(longPath(certPath), {
          refuseSymlink: true, inodeCheck: true, maxBytes: C.BYTES.mib(1),
        });
        var x509 = new nodeCrypto.X509Certificate(certBytes);
        endDate = x509.validToDate || new Date(x509.validTo);
      } catch (err) {
        log.error('Could not read mTLS certificate expiry — the cert file may be corrupt; run `hermitstash-sync repair` with a fresh enrollment code to re-provision the cert/key/CA', { error: err.message, cert: nodePath.basename(certPath) });
        return;
      }
      if (!endDate || isNaN(endDate.getTime())) {
        log.error('mTLS certificate has an unparseable expiry date — re-run enrollment to re-provision the cert/key/CA', { cert: nodePath.basename(certPath) });
        return;
      }

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

    // Probe the sync folder's filesystem once so the identity resolver
    // knows whether to fold case for differently-cased server events.
    this._detectCaseFolding();

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

    // Recover the mTLS identity from a pre-rotation backup if a prior CA
    // rotation was interrupted mid-swap (torn trio, or a cert/key mismatch
    // on disk). Runs BEFORE the HTTP client caches the certs so the
    // restored identity is the one the first request uses.
    this._recoverMtlsFromBackup();

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
    // Thread the probed case-fold decision so the watcher's ignore/include
    // matching folds case identically to the state-DB identity layer on a
    // case-insensitive volume. _detectCaseFolding() ran above, so
    // _fsCaseFolds is resolved before the Watcher is constructed.
    this._watcher = new Watcher(this._config.syncFolder, ignorePatterns, includePatterns, this._fsCaseFolds);
    this._watcher.on('change', ev => this._onLocalChange(ev));
    this._watcher.on('error', err => log.error('Watcher error', err));

    // The watcher self-recovers from a fatal stop (event-storm overflow,
    // start failure) by re-creating its handle, but a fresh handle starts
    // from a clean baseline — it does not replay events that fired during
    // the dead window. On 'rescan' (emitted after a successful restart),
    // re-walk the synced folder so changes made while detection was off get
    // re-detected and uploaded.
    this._watcher.on('rescan', () => this._enqueueLocalRescan());
    // 'fatal' precedes each restart attempt; 'degraded' means the watcher
    // gave up after exhausting its retry budget. Surface both as an
    // operator-actionable state — local change detection is impaired.
    this._watcher.on('fatal', err => {
      log.error('File watcher hit a fatal error and is restarting — local changes may be briefly undetected until it recovers', { code: err && err.code });
    });
    this._watcher.on('degraded', () => {
      this._setState(SYNC_STATE.ERROR);
      log.error('File watcher could not be restarted — local change detection is OFF. Restart the daemon, narrow your ignore patterns, or raise HERMITSTASH_WATCHER_MAX_PENDING.');
    });

    // Create WebSocket client
    this._ws = new WsClient(this._config, this._apiKey);

    this._ws.on('open', () => {
      // Capture the pre-open state: a local change that fired while the engine
      // was ERROR (or RECONNECTING) is dropped by _onLocalChange's early
      // return, and nothing re-detects it because the WS-reconnect path had no
      // local-folder reconcile (only the watcher's own 'rescan' did). Recover
      // it below with a _localRescan once the connection is back up.
      const wasDownControlChannel =
        this._state === SYNC_STATE.ERROR || this._state === SYNC_STATE.RECONNECTING;

      this._setState(SYNC_STATE.CATCHING_UP);

      // Reset the catch-up-complete latch for this fresh session. _caughtUpAtSeq
      // is the "a real caught-up heartbeat arrived" gate _maybeFinishCatchUp
      // checks before flipping to SYNCED. It is only otherwise cleared on a
      // successful catch-up completion and in _resyncOnce — NOT on reconnect. If
      // a prior session set it true (caught-up heartbeat received) but dropped
      // before the apply queue drained, a stale true latch would let this new
      // session flip to SYNCED the instant _catchUpPending momentarily hits 0,
      // while later catch-up events are still queued — a false "done" signal.
      // 'open' is the sole CATCHING_UP entry on reconnect, so clearing it here
      // makes every catch-up entry start from a clean latch.
      this._caughtUpAtSeq = false;

      // On first connection with no local state, do initial sync from
      // bundle metadata — chained onto the apply chain AHEAD of the
      // reconcile sweep so it is the single ordering authority. Catch-up
      // file_added events and the reconcile pass then see the SYNCED (or
      // quarantined PENDING_DOWNLOAD/ERROR) rows initial sync wrote, and
      // the localChecksum short-circuit suppresses a duplicate download
      // for the same path. _onServerMessage appends to the same tail, so
      // an event that arrives mid-initial-sync still applies after it.
      const lastSeq = stateDb.getLastSeq();
      if (lastSeq === 0 && this._config.shareId) {
        this._applyChain = this._applyChain
          .then(() => this._initialSync())
          .catch(err => log.error('Initial sync failed', { error: err.message }));
      }

      // Re-drive any transfer left PENDING_DOWNLOAD / ERROR by a previous
      // session or a download that failed below the cursor. Chained onto
      // the apply chain so it can't race a catch-up event for the same path.
      this._enqueueRecover();

      // If the control channel had gone ERROR/RECONNECTING, any local
      // modify/delete that fired during that window was dropped (the watcher
      // still ran, but _onLocalChange returns early in ERROR). Re-walk the
      // synced folder against real disk state so those missed changes are
      // re-detected and uploaded — mirroring the watcher's own 'rescan'
      // recovery, which only covers a watcher restart, not a WS reconnect.
      // Skipped on a fresh lastSeq===0 initial sync, which already reconciles
      // the whole folder via _scanLocalForUpload.
      if (wasDownControlChannel && !(lastSeq === 0 && this._config.shareId)) {
        this._enqueueLocalRescan();
      }
    });

    // Serialize every inbound server message onto the apply chain. A throw
    // inside an awaited handler is caught here so a single bad event never
    // escapes as an unhandledRejection or stalls later events.
    this._ws.on('message', msg => this._onServerMessage(msg));

    this._ws.on('close', () => {
      // A permanent upgrade rejection (handled below) already set a sticky
      // ERROR — the ws-client emits 'error' (-> upgrade_rejected) BEFORE
      // 'close', so guard here so the close-driven RECONNECTING flip can't
      // mask a rejection the daemon will never recover from on its own.
      if (this._terminalUpgradeReject) return;
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

    // A non-auth handshake rejection (404/409/426/400/...) permanently
    // closes the socket inside ws-client without scheduling a reconnect.
    // Without this listener the close handler would flip the engine to
    // RECONNECTING and it would sit there forever — no error state, no
    // metric, no operator signal. Surface it as a sticky ERROR with an
    // actionable, restart-pointing message instead.
    this._ws.on('upgrade_rejected', ({ status }) => this._onUpgradeRejected(status));

    this._ws.on('reconnecting', () => {
      this._setState(SYNC_STATE.RECONNECTING);
    });

    // Connect WebSocket. Clear any sticky permanent-upgrade-reject flag at
    // this connect entry point so a fresh start isn't pinned by a prior
    // run's rejection.
    this._terminalUpgradeReject = false;
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

  // Coalesce overlapping resync requests onto a single in-flight promise so
  // the teardown body runs exactly once per logical resync. SIGHUP fires
  // resync() and a second signal (or a `resync` CLI command) arriving mid-
  // drain would otherwise start a parallel teardown — double clearAll(),
  // double WS close/connect, _resyncing stomped back to false by whichever
  // body finishes first. The second caller now awaits the first's promise
  // and returns its result.
  resync() {
    if (this._resyncInFlight) {
      log.info('Resync already in progress; coalescing onto the in-flight run');
      return this._resyncInFlight;
    }
    this._resyncInFlight = this._resyncOnce();
    // Clear the memo once the run settles (success or failure) so the NEXT
    // resync starts a fresh teardown rather than returning a resolved stale
    // promise. finally runs after the body fully settles.
    const done = this._resyncInFlight.finally(() => { this._resyncInFlight = null; });
    // Swallow on the memo-clearing handle so a rejected resync can't surface
    // as an unhandledRejection here; the original promise still rejects for
    // the caller that awaited resync().
    done.catch(() => {});
    return this._resyncInFlight;
  }

  async _resyncOnce() {
    log.info('Full resync requested');

    // A successful redial below clears any sticky permanent-upgrade-reject
    // ERROR — a fresh connect must not be pinned by a prior rejection.
    this._terminalUpgradeReject = false;

    // Quiesce every in-flight writer BEFORE wiping the DB, mirroring
    // stop()'s drain discipline but transiently — resync reconnects, so
    // the HTTP client and state DB stay live. Without this, an in-flight
    // download/upload upsert (or a still-armed rename-detection delete
    // timer) lands after clearAll() and re-populates the just-cleared DB,
    // or issues a server DELETE for a file this resync is about to re-pull.

    // Gate post-await write paths so any suspended handler that resumes
    // after the wipe no-ops instead of writing.
    this._resyncing = true;

    // Abandon the tail of queued apply handlers (same as stop():392).
    this._applyChain = Promise.resolve();

    // Cancel every buffered rename-detection delete so no 1s timer fires
    // _executeDelete against the cleared DB. After resync the state is
    // CONNECTING with _http live, so the timer's DISCONNECTED/!_http guard
    // would NOT stop it — the explicit cancel here is what protects the
    // re-pull.
    for (const pending of this._pendingDeletes.values()) {
      clearTimeout(pending.timer);
    }
    this._pendingDeletes.clear();

    // Drain in-flight uploads so no _uploadFile upsert lands after the wipe.
    if (this._uploadPool) {
      try { await this._uploadPool.drain(); }
      catch (err) { log.warn('Upload pool drain failed during resync', { error: err.message }); }
    }

    // Await every in-flight download too — they have no pool to drain, so
    // resync tracks their promises explicitly. Their post-await upsert
    // no-ops on the _resyncing guard (still set here), and awaiting them
    // guarantees clearAll runs strictly after the last one settles rather
    // than racing a download that resumes after the flag is cleared.
    if (this._activeDownloadPromises.size > 0) {
      try { await Promise.allSettled([...this._activeDownloadPromises]); }
      catch { /* allow:silent-catch — individual download failures are already logged inside _downloadFileImpl */ }
    }

    // Reset the in-memory counters + suppression map now that no writer is
    // still in flight.
    this._activeDownloads = 0;
    this._catchUpPending = 0;
    this._caughtUpAtSeq = false;
    this._downloadingPaths.clear();

    // Every awaited drain has resolved — now the synchronous clearAll
    // runs with no writer able to race it.
    stateDb.clearAll();

    // Belt-and-suspenders: re-reset the chain in case a message arrived
    // and re-armed the tail during the await above.
    this._applyChain = Promise.resolve();
    this._resyncing = false;

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

  // Handle a permanent (non-auth) WebSocket upgrade rejection. ws-client
  // tears the socket down without scheduling a reconnect on a 4xx handshake
  // rejection, so the engine must surface a sticky ERROR rather than let the
  // close-driven RECONNECTING flip mask a failure the daemon will never
  // recover from on its own. 401/403 are owned by the auth_error handler
  // (which exits via cli.js); skip them here to avoid double-handling. The
  // process is deliberately NOT exited — a 404/409/426 is often operator-
  // fixable (wrong URL, stale bundle, server too old) without re-init, so
  // ERROR + an actionable log is the right altitude.
  _onUpgradeRejected(status) {
    if (status === 401 || status === 403) return;                                // allow:raw-byte-literal — HTTP 401/403 already handled by auth_error
    metrics.record.upgradeRejected(status);
    this._terminalUpgradeReject = true;
    this._setState(SYNC_STATE.ERROR);
    if (status === 404 || status === 426) {                                      // allow:raw-byte-literal — HTTP 404/426 upgrade-route/protocol rejections
      log.error(`Server did not accept the WebSocket upgrade (HTTP ${status}). The server URL may not expose /sync/ws, a reverse proxy may be stripping the Upgrade header, or the server is older than the protocol this client speaks. Verify the server URL/proxy and upgrade the server, then restart the daemon — it will NOT reconnect on its own.`);
    } else if (status === 409 || status === 400) {                               // allow:raw-byte-literal — HTTP 409/400 stale-bundle/bad-handshake rejections
      log.error(`Server rejected the sync handshake (HTTP ${status}). The bundleId may be stale or the bundle may no longer exist. Re-run "hermitstash-sync init" or verify the bundle, then restart the daemon — it will NOT reconnect on its own.`);
    } else {
      log.error(`Server rejected the WebSocket upgrade (HTTP ${status}). The connection is permanently closed; check the server and restart the daemon.`);
    }
  }

  // Transition to SYNCED only when no transfer is queued OR in flight.
  // Derives "busy" from authoritative sources — the upload pool's
  // inFlight + queued depth and the explicit download counter — instead
  // of the per-op _activeOps, so SYNCED can't flap to true in the gap
  // between a finishing op and a not-yet-started queued op.
  _maybeMarkSynced() {
    if (this._state === SYNC_STATE.DISCONNECTED) return;
    // Never pre-empt the catch-up -> SYNCED transition. While CATCHING_UP, a
    // transfer finishing must not flip state to SYNCED: _maybeFinishCatchUp
    // (driven by the trailing heartbeat once the apply queue and transfers
    // drain) is the sole owner of that transition. Flipping early here defeats
    // the heartbeat's CATCHING_UP guard (so _caughtUpAtSeq never gets set) and
    // reports SYNCED while catch-up events are still queued.
    if (this._state === SYNC_STATE.CATCHING_UP) return;
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
   * Server regenerated the mTLS CA and sent us new credentials. The three
   * files (cert / key / CA) are not a single atomic unit on disk, so the
   * rotation runs stage -> validate -> backup -> swap -> ack:
   *   1. STAGE the new PEMs to .next siblings.
   *   2. VALIDATE the candidate trio (parse + key/cert match + leaf chains
   *      to the new CA) BEFORE touching the live identity — on any failure
   *      the live trio is untouched and the server times out its own
   *      rotation.
   *   3. BACKUP the current trio to .prev siblings so a torn swap is
   *      recoverable at boot.
   *   4. SWAP the .next stages over the live paths.
   *   5. Only after a validated, committed swap: reload the in-memory cert
   *      caches and ACK so the server knows we're ready for its restart.
   * A crash between any of these steps is recovered at boot by
   * _recoverMtlsFromBackup (restores the .prev trio).
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
      this._sendCaRotationAck(msg);
      return;
    }
    const mtls = this._config.mtls;
    if (!mtls || !mtls.cert || !mtls.key || !mtls.ca) {
      log.error('ca:rotation received but no mTLS paths configured — ignoring');
      return;
    }

    const certNext = mtls.cert + '.next';
    const keyNext = mtls.key + '.next';
    const caNext = mtls.ca + '.next';

    // 2. VALIDATE first — reject a bad trio before any live file is touched.
    try {
      this._validateMtlsTrio(newCertPem, newKeyPem, newCaPem);
    } catch (err) {
      log.error('CA rotation rejected — the server-supplied cert/key/CA failed validation; keeping the current identity. Re-run enrollment if the server forces a re-provision', { error: err.message });
      return;
    }

    try {
      // 1. STAGE the validated PEMs to .next siblings (atomic per file).
      b.atomicFile.writeSync(certNext, ensureNewline(newCertPem), { fileMode: 0o644 });
      b.atomicFile.writeSync(keyNext,  ensureNewline(newKeyPem),  { fileMode: 0o600 });
      b.atomicFile.writeSync(caNext,   ensureNewline(newCaPem),   { fileMode: 0o644 });

      // 3. BACKUP the current live trio to .prev so a torn swap is
      // recoverable at boot.
      nodeFs.copyFileSync(longPath(mtls.cert), longPath(mtls.cert + '.prev'));
      nodeFs.copyFileSync(longPath(mtls.key),  longPath(mtls.key + '.prev'));
      nodeFs.copyFileSync(longPath(mtls.ca),   longPath(mtls.ca + '.prev'));

      // 4. SWAP each .next over the live path. On a crash between renames
      // the .prev copies remain for boot recovery.
      b.atomicFile.renameWithRetry(longPath(certNext), longPath(mtls.cert));
      b.atomicFile.renameWithRetry(longPath(keyNext),  longPath(mtls.key));
      b.atomicFile.renameWithRetry(longPath(caNext),   longPath(mtls.ca));
    } catch (err) {
      // The swap did not complete. Restore the live identity from the .prev
      // backup rather than only logging, so a half-swapped trio doesn't
      // brick the next handshake.
      log.error('CA rotation failed mid-swap — restoring the previous mTLS identity', { error: err.message });
      this._recoverMtlsFromBackup();
      return;
    }

    // 5. Validated swap succeeded — refresh cached TLS buffers in both
    // clients so reconnects + the next HTTP request pick up the new
    // credentials, then ack.
    if (this._ws && typeof this._ws.reloadMtlsCerts === 'function') this._ws.reloadMtlsCerts();
    if (this._http && typeof this._http.reloadMtlsCerts === 'function') this._http.reloadMtlsCerts();

    this._sendCaRotationAck(msg);

    log.info('CA rotated — new cert/key/CA validated and persisted, waiting for server restart', {
      restartInMs: restartInMs || null,
      certPath: mtls.cert,
    });
  }

  // Send the CA-rotation ACK with a null-guard on the socket and a WARN on
  // a dropped ACK. The certs are already committed at this point, so the
  // rotation itself succeeded; the warning just makes the server-side
  // timeout path observable rather than silent. send() never throws, so no
  // try/catch is needed — wrapping it would only re-hide a dropped ACK.
  _sendCaRotationAck() {
    if (!this._ws || typeof this._ws.send !== 'function') {
      log.warn('CA rotation persisted, but the WebSocket is gone — ACK not sent; the server may time out and force re-enrollment on next connect');
      return;
    }
    const acked = this._ws.send({ type: MSG.CA_ROTATION_ACK });
    if (acked === false) {
      log.warn('CA rotation persisted, but the ACK could not be sent (socket closed) — the server may time out and force re-enrollment on next connect');
    }
  }

  // Selective-sync gate for server-driven events. Returns true if the
  // path is in scope (include empty OR matches an include pattern) AND
  // not ignored. Server events for out-of-scope paths are no-ops aside
  // from the seq update — the daemon still advances `lastSeq` so the
  // next reconnect doesn't replay them.
  _shouldSync(relativePath) {
    return pathFilter.shouldSync(relativePath, {
      include:  this._includePatterns,
      ignore:   this._ignorePatterns,
      caseFold: this._fsCaseFolds,
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
      b.atomicFile.renameWithRetry(longPath(fullPath), longPath(conflict));
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
    const { fileId, checksum, size, seq } = msg;
    // Canonicalize to the byte-stable identity (NFC) before any lookup,
    // suppression, or DB write so the same file resolves to one key
    // regardless of the Unicode form the volume surfaced.
    const relativePath = this._identityKey(msg.relativePath);

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_added', { relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    // Reject names this OS can't represent (reserved device, trailing
    // dot/space, ADS). Advances seq + skips so a hostile tip event can't
    // wedge catch-up.
    if (!this._validateServerPath(relativePath, seq)) return;

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
      // Fold-aware lookup: on a case-folding host a server "Foo.txt" event
      // reuses a row tracked as "foo.txt" rather than spawning a duplicate.
      const existing = this._lookupTracked(relativePath);

      // A fold-match under a different casing means the file is already
      // tracked; reconcile the local name to the server's authoritative
      // casing and reuse the single row instead of conflict-copying.
      if (existing && existing.relativePath !== relativePath) {
        await this._reconcileCaseRename(existing, relativePath, fullPath, fileId, checksum, size, seq);
        return;
      }

      // Check if we already have this file with the same checksum
      if (existing && existing.localChecksum === checksum) {
        // Already in sync — just update seq
        stateDb.upsertFile({ ...existing, relativePath, serverSeq: seq, serverChecksum: checksum, serverFileId: fileId });
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
      const ok = await this._downloadFile(relativePath, fileId, checksum, size);
      if (ok) this._updateSeq(seq);
    } finally {
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }
  }

  // Reconcile a fold-matched row to the server's authoritative casing. On a
  // case-folding FS the on-disk inode is shared between the old and new
  // names, so a direct case-only rename is a no-op on some volumes — the
  // move goes through a unique temp first. After the disk move the DB row
  // is moved atomically (renameFile) so exactly one row survives under the
  // server's key. If the bytes already match the server's checksum no
  // download is needed; otherwise the row is left PENDING_DOWNLOAD and the
  // normal download path runs.
  async _reconcileCaseRename(existing, relativePath, fullPath, fileId, checksum, size, seq) {
    const oldKey = existing.relativePath;
    log.info('Case-variant server event matches a tracked file — reconciling local name to server casing', { from: oldKey, to: relativePath });

    // oldKey is the tracked-row key (the name the file currently carries on
    // THIS host); resolve it host-platform so a locally-legal name on a
    // non-Windows volume still resolves for the on-disk move.
    const oldFullPath = this._safeLocalPath(oldKey);
    try {
      if (oldFullPath && oldFullPath !== fullPath && nodeFs.existsSync(longPath(oldFullPath))) {
        // Two-step rename so a case-only change lands even on volumes where
        // a direct same-name rename is a no-op.
        // Use the `.tmp.<8hex>` convention the download path uses so a crash
        // between the two renames leaves an orphan the boot sweep collects.
        const tmp = fullPath + '.tmp.' + nodeCrypto.randomBytes(4).toString('hex'); // allow:raw-randombytes-token — local temp suffix for the two-step case rename, not a security token
        b.atomicFile.renameWithRetry(longPath(oldFullPath), longPath(tmp));
        b.atomicFile.renameWithRetry(longPath(tmp), longPath(fullPath));
      }
    } catch (err) {
      log.error('Could not reconcile local file to server casing — keeping existing row', { from: oldKey, to: relativePath, error: err.message });
      // Don't advance seq; the next reconnect re-delivers and retries.
      return;
    }

    // Only SYNCED when the LOCAL bytes match the server AND the file is
    // actually on disk. Falling back to serverChecksum marked a row whose
    // download never landed as SYNCED with no bytes — an unrecoverable phantom
    // row (the reconcile sweep only re-drives PENDING_DOWNLOAD/ERROR, and the
    // local rescan only walks files that exist). A false result falls through
    // to the PENDING_DOWNLOAD + _downloadFile path below.
    const bytesMatch = existing.localChecksum === checksum && nodeFs.existsSync(longPath(fullPath));
    stateDb.renameFile(oldKey, {
      ...existing,
      relativePath,
      serverFileId: fileId || existing.serverFileId,
      serverChecksum: checksum,
      localChecksum: bytesMatch ? checksum : existing.localChecksum,
      size: size || existing.size,
      serverSeq: seq,
      status: bytesMatch ? FILE_STATUS.SYNCED : FILE_STATUS.PENDING_DOWNLOAD,
    });

    if (bytesMatch) {
      this._updateSeq(seq);
      return;
    }
    const ok = await this._downloadFile(relativePath, fileId, checksum, size);
    if (ok) this._updateSeq(seq);
  }

  async _handleFileReplaced(msg) {
    const { fileId, checksum, size, seq } = msg;
    const relativePath = this._identityKey(msg.relativePath);

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_replaced', { relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    if (!this._validateServerPath(relativePath, seq)) return;

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file replaced', { relativePath, size });

    this._catchUpPending++;
    this._suppressPath(relativePath);
    try {
      // Check if we're the one who uploaded this change (fold-aware so a
      // case-variant event reuses the tracked row).
      const existing = this._lookupTracked(relativePath);
      if (existing && existing.relativePath !== relativePath) {
        await this._reconcileCaseRename(existing, relativePath, fullPath, fileId, checksum, size, seq);
        return;
      }
      if (existing && existing.localChecksum === checksum) {
        stateDb.upsertFile({ ...existing, relativePath, serverSeq: seq, serverChecksum: checksum, serverFileId: fileId });
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

      const ok = await this._downloadFile(relativePath, fileId, checksum, size);
      if (ok) this._updateSeq(seq);
    } finally {
      this._releasePath(relativePath);
      this._catchUpPending--;
      this._maybeFinishCatchUp();
    }
  }

  async _handleFileRemoved(msg) {
    const seq = msg.seq;
    const relativePath = this._identityKey(msg.relativePath);

    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in file_removed', { relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    if (!this._validateServerPath(relativePath, seq)) return;

    if (!this._shouldSync(relativePath)) {
      this._updateSeq(seq);
      return;
    }

    log.info('Server: file removed', { relativePath });

    this._catchUpPending++;
    this._suppressPath(relativePath);
    try {
      const existing = this._lookupTracked(relativePath);
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
            b.atomicFile.renameWithRetry(longPath(fullPath), longPath(conflict));
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
          applied = await this._unlinkWithRetry(relativePath, fullPath);
        }
      }

      if (applied) {
        // Remove the row under its actual tracked key (which may differ in
        // casing from the canonical key on a case-folding host).
        stateDb.removeFile(existing ? existing.relativePath : relativePath);
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
  async _unlinkWithRetry(relativePath, fullPath) {
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
        // Non-blocking backoff — yields the event loop so WS frame
        // processing / heartbeats / concurrent transfers keep running while a
        // Windows/Dropbox lock on the source inode clears.
        const ms = RENAME_RETRY_DELAYS_MS[i + 1];
        if (ms > 0) {
          await b.safeAsync.sleep(ms);
        }
      }
    }
    return false;
  }

  async _handleFileRenamed(msg) {
    const { fileId, checksum, size, seq } = msg;
    const oldRelativePath = this._identityKey(msg.oldRelativePath);
    const relativePath = this._identityKey(msg.relativePath);

    if (!this._safePath(oldRelativePath) || !this._safePath(relativePath)) {
      log.error('Path traversal attempt blocked in file_renamed', { oldRelativePath, relativePath });
      // Advance seq even on a blocked event; otherwise a traversal-shaped event
      // at the change-log tip pins lastSeq and wedges catch-up on every reconnect.
      this._updateSeq(seq);
      return;
    }

    // Validate BOTH the source and destination names — a rename that lands
    // on an OS-hostile destination (or moves from one) is skipped with seq
    // advanced, same contract as the other inbound entry points.
    if (!this._validateServerPath(oldRelativePath, seq)) return;
    if (!this._validateServerPath(relativePath, seq)) return;

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
      // Move the file locally. Bounded Windows rename-lock retry so a
      // transient Dropbox/AV handle doesn't abort the move. `moved` records
      // whether WE actually relocated the source — it must gate the SYNCED
      // decision below, because a bare existsSync(newFullPath) is true even
      // when an UNRELATED local file already occupies the destination.
      // The destination directory is created only on the branch that actually
      // moves bytes into it: a rename whose source is absent (an earlier
      // download left an ERROR/PENDING_DOWNLOAD row, say) skips the move and
      // falls through to the re-download recovery below, which creates the
      // directory when it writes — so we don't materialize an empty
      // destination tree the user never had on a no-op rename event.
      let moved = false;
      if (oldFullPath && nodeFs.existsSync(longPath(oldFullPath))) {
        const newDir = nodePath.dirname(newFullPath);
        if (!nodeFs.existsSync(longPath(newDir))) nodeFs.mkdirSync(longPath(newDir), { recursive: true });
        b.atomicFile.renameWithRetry(longPath(oldFullPath), longPath(newFullPath));
        moved = true;
      }

      // Fold-aware lookup so the old key resolves on a case-folding host.
      const existing = this._lookupTracked(oldRelativePath);
      const oldKey = existing ? existing.relativePath : oldRelativePath;

      // A SYNCED row is only honest when WE moved the source bytes to the new
      // path AND they match the server's content. `landed` is gated on `moved`,
      // not a bare existsSync: if the source was absent (an earlier download
      // left an ERROR/PENDING_DOWNLOAD row, say) the move was skipped, and any
      // bytes sitting at newFullPath are NOT ours — an unrelated/stale local
      // file. Marking that SYNCED strands a phantom row the reconcile sweep
      // never re-downloads (it only re-drives PENDING_DOWNLOAD/ERROR, and the
      // local rescan only walks files that exist) AND would later upload the
      // unrelated bytes to the server under the renamed path. A rename event
      // may omit checksum (pure rename, content unchanged) — the moved bytes
      // keep their known checksum; a checksum that differs from our last-synced
      // value means the rename also changed content. In every not-SYNCED case
      // fall through to the delete-old + re-download-new recovery below, which
      // upserts PENDING_DOWNLOAD and owns the seq advance only once the bytes
      // land.
      const landed = moved && nodeFs.existsSync(longPath(newFullPath));
      const movedChecksum = existing && (existing.localChecksum || existing.serverChecksum);
      const bytesMatch = !checksum || movedChecksum === checksum;
      if (landed && bytesMatch) {
        // Update state DB as ONE transaction: remove old + add new commit or
        // roll back together, so a crash between them can't strand the file
        // tracked at neither path (the old key stays intact for the server's
        // replay to re-apply cleanly).
        stateDb.renameFile(oldKey, {
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
      }
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

    // The rename did not produce a verified SYNCED file at the new path —
    // either the move failed, the source bytes were absent, or the rename also
    // changed content. Never advance the cursor past an event whose side effect
    // didn't land — fall back to delete-old + re-download-new so the new path
    // lands fresh. _handleFileAdded owns the seq advance once its download to
    // the new path commits; it upserts PENDING_DOWNLOAD first, so a further
    // failure leaves a recoverable marker rather than a SYNCED row at the wrong
    // path. The delete of the old path is best-effort and must not advance the
    // cursor here.
    log.warn('Local rename did not produce a synced file — recovering via delete-old + re-download-new', { from: oldRelativePath, to: relativePath });
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
        await this._unlinkWithRetry(relativePath, fullPath);
      }
      // Remove the row under its actual tracked key (which may differ in
      // casing from the canonical key on a case-folding host). The on-disk
      // delete above correctly targets the raw relativePath (the server's
      // old-cased name); only the DB delete must use the fold-resolved key.
      const existing = this._lookupTracked(relativePath);
      stateDb.removeFile(existing ? existing.relativePath : relativePath);
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
   *
   * Also re-drives PENDING_UPLOAD rows whose on-disk bytes haven't reached
   * the server (a local-rename fallback whose old-path delete failed leaves
   * exactly such a marker — see _handleLocalRename — and without this the
   * renamed file would sit un-uploaded indefinitely because no further
   * watcher event fires for it).
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
    await this._recoverPendingUploads();
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
            stateDb.upsertFile({ ...existing, relativePath, localChecksum: local, serverChecksum: checksum, serverFileId: fileId, status: FILE_STATUS.SYNCED, needsBytes: 0 });
            continue;
          }
        }
      } catch { /* allow:silent-catch — hash probe is best-effort; fall through to re-download */ }

      // A row flagged too-large-for-disk: don't re-fetch it until enough
      // space has actually recovered, so the sweep can't re-exhaust the
      // disk (and re-pull over the network) every tick. Re-driven only once
      // the shortfall clears.
      if (row.needsBytes && row.needsBytes > 0) {
        const freeSpace = this._getFreeDiskSpace();
        if (Number.isFinite(freeSpace) && freeSpace < row.needsBytes) {
          continue;
        }
      }

      this._suppressPath(relativePath);
      try {
        await this._downloadFile(relativePath, fileId, checksum, row.size);
        recovered++;
      } finally {
        this._releasePath(relativePath);
      }
    }
    if (recovered > 0) log.info('Reconcile pass re-drove stranded transfers', { count: recovered });
  }

  /**
   * Re-drive PENDING_UPLOAD rows whose bytes never reached the server. The
   * common stranding case is the local-rename fallback whose old-path delete
   * failed: it upserts a PENDING_UPLOAD marker for the new path but cannot
   * upload it then (uploading would duplicate the still-present old path on
   * the server). Once the next sweep runs — by which point a server-driven
   * delete may have cleared the duplicate, or the operator deleted it — re-
   * route the file through _handleLocalModify so the new bytes propagate.
   * Skips rows whose on-disk content already matches serverChecksum (a row
   * that converged) and rows whose local file is gone (a transient marker
   * for a file the user removed before it ever uploaded).
   */
  async _recoverPendingUploads() {
    if (this._stopped || !this._http) return;
    let rows;
    try {
      rows = stateDb.getFilesByStatus(FILE_STATUS.PENDING_UPLOAD);
    } catch (err) {
      log.warn('Could not enumerate pending uploads for reconcile', { error: err.message });
      return;
    }
    if (!rows.length) return;

    let redriven = 0;
    for (const row of rows) {
      if (this._stopped) break;
      const relativePath = row.relativePath;
      const fullPath = this._safeLocalPath(relativePath);
      if (!fullPath) continue;
      // A live transfer owns the path — leave it to that op.
      if (this._isSuppressed(relativePath)) continue;

      let stat;
      try { stat = nodeFs.statSync(longPath(fullPath)); }
      catch { continue; } // local file gone — nothing to upload
      if (stat.isDirectory()) continue;

      // Already converged: on-disk bytes match what the server has.
      if (row.serverChecksum) {
        try {
          const local = await hashFile(fullPath);
          if (local === row.serverChecksum) continue;
        } catch { /* allow:silent-catch — hash probe is best-effort; fall through to re-drive the upload */ }
      }

      await this._handleLocalModify(relativePath, fullPath, stat.size, stat.mtimeMs);
      redriven++;
    }
    if (redriven > 0) log.info('Reconcile pass re-drove stranded uploads', { count: redriven });
  }

  // Chain a reconcile pass onto the apply chain so it serializes with live
  // server events rather than racing them on the same path.
  _enqueueRecover() {
    if (this._stopped) return;
    this._applyChain = this._applyChain
      .then(() => this._recoverPending())
      .catch((err) => log.warn('Pending-transfer reconcile failed', { error: err.message }));
  }

  // Chain a local-folder reconcile onto the apply chain. Driven by the
  // watcher's 'rescan' event after it self-recovers from a fatal stop: the
  // restarted watcher starts from a clean baseline and never replays the
  // changes that fired during the dead window, so the daemon re-walks the
  // synced folder and re-detects any on-disk file whose bytes diverged from
  // its tracked row. Serialized on the apply chain so it can't race a live
  // server event for the same path.
  _enqueueLocalRescan() {
    if (this._stopped) return;
    log.info('Watcher recovered — re-scanning synced folder for changes missed while detection was off');
    this._applyChain = this._applyChain
      .then(() => this._localRescan())
      .catch((err) => log.warn('Local rescan after watcher recovery failed', { error: err.message }));
  }

  // Re-walk the synced folder and re-detect any in-scope file whose on-disk
  // content differs from its tracked row (or is untracked). Each divergent
  // file is routed through the same _handleLocalModify the watcher would
  // have driven, so it lands PENDING_UPLOAD and uploads through the pool.
  // Keyed off real disk state, independent of the seq cursor, so a change
  // made during the watcher's dead window still converges.
  async _localRescan() {
    if (this._stopped || this._resyncing || !this._http) return;
    let localFiles;
    try { localFiles = this._walkDir(this._config.syncFolder); }
    catch (err) { log.warn('Local rescan walk failed', { error: err.message }); return; }

    let requeued = 0;
    const onDisk = new Set();
    for (const fullPath of localFiles) {
      if (this._stopped || this._resyncing) break;
      const relativePath = this._identityKey(
        nodePath.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/'));
      if (this._watcher && !this._watcher.shouldSync(relativePath)) continue;
      // Skip paths with an op in flight — a live download/upload owns the
      // row and a rescan must not fight it.
      if (this._isSuppressed(relativePath)) continue;

      let stat;
      try {
        stat = nodeFs.statSync(longPath(fullPath));
        if (stat.isDirectory()) continue;
      } catch { continue; }
      // Record every in-scope file present on disk so the delete-detection
      // pass below can distinguish a missed local delete (a tracked SYNCED row
      // with no file here) from a file that is still present.
      onDisk.add(relativePath);

      let localChecksum;
      try { localChecksum = await hashFile(fullPath); }
      catch { continue; }

      const existing = this._lookupTracked(relativePath);
      if (existing && existing.localChecksum === localChecksum) continue; // converged

      log.info('Rescan re-detected a local change missed during the watcher dead window', { relativePath });
      await this._handleLocalModify(relativePath, fullPath, stat.size, stat.mtimeMs);
      requeued++;
    }
    if (requeued > 0) log.info('Local rescan re-queued changes for upload', { count: requeued });

    // Recover local DELETES missed while detection was off (the watcher dead
    // window, or a WS-reconnect window where _onLocalChange returned early). A
    // SYNCED row whose file is no longer on disk is a deletion the watcher
    // never saw. Route it through the same _handleLocalDelete an unlink event
    // would: it buffers for one second and cancels on a matching add, so an
    // atomic-save (delete+recreate) still resolves as a rename, not a delete.
    // Only SYNCED rows count — a PENDING_DOWNLOAD row has no local file yet,
    // and PENDING_UPLOAD/ERROR rows are mid-flight.
    let tracked;
    try { tracked = stateDb.getFilesByStatus(FILE_STATUS.SYNCED); }
    catch (err) { log.warn('Local rescan delete-detection skipped — state read failed', { error: err.message }); tracked = []; }
    let deleted = 0;
    for (const row of tracked) {
      if (this._stopped || this._resyncing) break;
      const rel = this._identityKey(row.relativePath);
      if (onDisk.has(rel)) continue;                              // still present
      if (this._watcher && !this._watcher.shouldSync(rel)) continue;
      if (this._isSuppressed(rel)) continue;                      // a live op owns it
      // The disk walk is a snapshot; re-stat before propagating a server-side
      // delete so a file created between the walk and here is never deleted.
      try { nodeFs.statSync(longPath(nodePath.join(this._config.syncFolder, rel))); continue; }
      catch { /* truly absent — fall through to propagate the delete */ }
      log.info('Rescan detected a local delete missed while detection was off', { relativePath: rel });
      await this._handleLocalDelete(rel);
      deleted++;
    }
    if (deleted > 0) log.info('Local rescan propagated local deletes', { count: deleted });
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
      // meta may be a 200 with a null / non-object body (a legitimately empty
      // bundle answers 200 { files: [] }, but a tolerant server could answer
      // 200 null) — guard totalSize so the log line never NPEs into the catch.
      log.info('Initial sync', { fileCount: files.length, skippedOutOfScope: skipped, totalSize: meta && meta.totalSize });

      // Pre-hash existing local files in parallel to avoid serial I/O
      const existingLocalPaths = [];
      for (const file of files) {
        const relPath = this._identityKey(file.relativePath);
        const fullPath = this._safePath(relPath);
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
        const relPath = this._identityKey(file.relativePath);
        const fullPath = this._safePath(relPath);
        if (!fullPath) {
          log.error('Path traversal attempt blocked in initial sync', { relativePath: relPath });
          continue;
        }
        // Refuse OS-unrepresentable server names here too (no seq advance:
        // initial sync doesn't own the cursor, the WS catch-up + reconcile
        // path does — and validateServerPath without a seq just skips).
        if (!this._validateServerPath(relPath)) continue;

        const localChecksum = localHashes.get(fullPath) || null;

        if (localChecksum && localChecksum === file.checksum) {
          // File exists locally with matching checksum — mark synced, skip download
          const existing = stateDb.getFile(relPath);
          stateDb.upsertFile({
            ...existing,
            relativePath: relPath,
            serverFileId: file.id,
            localChecksum,
            serverChecksum: file.checksum,
            size: file.size,
            serverSeq: file.seq || 0,
            status: FILE_STATUS.SYNCED,
          });
          continue;
        }

        // A local file exists here with content that differs from the
        // server's version. Initial sync runs whenever lastSeq===0 — not only
        // on a true first run but after `resync` and after the daemon's
        // rename-and-recreate recovery of a corrupt state.db — so this path is
        // reachable for a user who edited files offline. Preserve their bytes
        // as a conflict copy before the download overwrites them, the same
        // last-write-wins protection the file_added/file_replaced handlers
        // apply. _maybeSaveConflictCopy is a no-op when the local file is
        // absent or already matches the incoming checksum.
        if (localChecksum && localChecksum !== file.checksum) {
          await this._maybeSaveConflictCopy(relPath, fullPath, file.checksum);
        }

        stateDb.upsertFile({
          relativePath: relPath,
          serverFileId: file.id,
          serverChecksum: file.checksum,
          size: file.size,
          serverSeq: file.seq || 0,
          status: FILE_STATUS.PENDING_DOWNLOAD,
        });

        await this._downloadFile(relPath, file.id, file.checksum, file.size);
      }

      // Also scan local folder for files not on server — queue them for upload
      await this._scanLocalForUpload(files);

      log.info('Initial sync complete');
    } catch (err) {
      // getBundleMetadata now fails closed on a non-2xx (it previously masked a
      // 401/403/404/5xx as an empty bundle). An auth-class denial is not a
      // transient blip the WS catch-up can paper over — the API key or mTLS
      // cert was rejected for this bundle — so surface it as a sticky ERROR
      // with the same operator signal the WS auth path emits, rather than the
      // bland "will rely on WebSocket catch-up" log that buries it.
      if (/\(HTTP 40[13]\)/.test(err && err.message || '')) {
        log.error('Initial sync denied — the API key or mTLS cert was rejected for this bundle; re-enroll with "hermitstash-sync init"', { error: err.message });
        this._setState(SYNC_STATE.ERROR);
        this.emit('auth_error');
        return;
      }
      log.error('Initial sync failed — will rely on WebSocket catch-up', err);
    }
  }

  /**
   * Scan local sync folder for files that aren't on the server yet.
   * Uses worker pool for parallel checksum computation on new files.
   */
  async _scanLocalForUpload(serverFiles) {
    const serverPaths = new Set(serverFiles.map(f => this._identityKey(f.relativePath)));
    const localFiles = this._walkDir(this._config.syncFolder);

    // Collect files that need uploading
    const toUpload = [];
    for (const fullPath of localFiles) {
      const relativePath = this._identityKey(
        nodePath.relative(this._config.syncFolder, fullPath).replace(/\\/g, '/'));
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

      // Pass the checksum we just hashed so the post-upload state records the
      // uploaded bytes rather than a post-upload disk re-read that could have
      // drifted between the hash above and stream completion.
      uploadPromises.push(this._uploadPool.run(() => this._uploadFile(relativePath, fullPath, localChecksum)));
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
        // Never enqueue a daemon-private scratch file for upload. The boot
        // sweep collects crashed-run orphans, but a same-tick scan racing a
        // live case-rename/download temp could still pick one up in the
        // sub-ms window before the sweep — skip it here so an in-flight temp
        // is never uploaded regardless of sweep timing.
        // allow:regex-no-length-cap — entry.name is one path component (NAME_MAX-bounded); anchored suffix, no backtracking
        if (TEMP_FILE_RE.test(entry.name)) continue;
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
      // seq===0 is normally the liveness ping; but on a fresh client
      // (lastSeq===0) syncing a truly empty bundle, the server's catch-up-
      // complete heartbeat also carries seq 0 (server sends `bundle.seq || 0`,
      // and an empty bundle's tip is 0), and it IS a legitimate caught-up
      // signal. Accept seq===0 only when lastSeq===0 so an established client
      // still ignores a stray seq-0 liveness heartbeat. _maybeFinishCatchUp
      // still gates the transition on a drained apply queue + no active
      // downloads, so this can't flip the state while events are draining.
      if (seq <= lastSeq && (seq !== 0 || lastSeq === 0)) {
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
    // A resync is wiping the cursor; a suspended handler resuming mid-wipe
    // must not re-advance lastSeq past the cleared (=0) state.
    if (this._resyncing) return;
    try {
      if (seq > stateDb.getLastSeq()) {
        stateDb.setLastSeq(seq);
      }
      stateDb.setMeta('last_sync_time', new Date().toISOString());
      metrics.setLastSeq(stateDb.getLastSeq());
      metrics.setFileCount(stateDb.getAllFiles().length);
      // Keep the WebSocket client's reconnect `since` in sync. Feed the
      // persisted monotone cursor (lastSeq), NOT the raw event seq: a replayed
      // or out-of-order event with a seq below the applied cursor would
      // otherwise regress `since` (which the reconnect dial uses verbatim,
      // without re-reading lastSeq) below lastSeq, making the server re-send
      // events we've already applied. lastSeq only moves forward (guarded above).
      if (this._ws) {
        this._ws.updateSince(stateDb.getLastSeq());
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
  // (low-disk pause, too-large-for-disk, download/checksum error). Callers
  // gate _updateSeq on the boolean so a failed transfer never advances the
  // cursor. expectedSize is the server-declared byte length used for the
  // disk preflight; pass 0/undefined when unknown. The returned promise is
  // tracked so resync()/stop() can await every in-flight download before
  // wiping the DB (downloads have no pool to drain).
  _downloadFile(relativePath, fileId, expectedChecksum, expectedSize) {
    const p = this._downloadFileImpl(relativePath, fileId, expectedChecksum, expectedSize);
    this._activeDownloadPromises.add(p);
    p.finally(() => this._activeDownloadPromises.delete(p)).catch(() => {});
    return p;
  }

  async _downloadFileImpl(relativePath, fileId, expectedChecksum, expectedSize) {
    const fullPath = this._safePath(relativePath);
    if (!fullPath) {
      log.error('Path traversal attempt blocked in download', { relativePath });
      return false;
    }
    // Hold the per-path lock across the whole transfer so a concurrent
    // same-path local upload can't interleave its hash + upsert + stream
    // against this download. Unrelated paths keep their own locks and run
    // in parallel.
    return this._withPathLock(relativePath, () =>
      this._downloadFileLocked(relativePath, fileId, expectedChecksum, expectedSize, fullPath));
  }

  async _downloadFileLocked(relativePath, fileId, expectedChecksum, expectedSize, fullPath) {
    this._suppressPath(relativePath);
    this._activeDownloads++;
    this._activeOps++;
    metrics.setActiveOps(this._activeOps);
    // Keep CATCHING_UP intact during a catch-up download. A transient
    // DOWNLOADING state here would clobber the state the trailing heartbeat's
    // catch-up-complete guard depends on (so _caughtUpAtSeq never gets set);
    // _maybeFinishCatchUp is the sole owner of the catch-up -> SYNCED exit.
    if (this._state !== SYNC_STATE.CATCHING_UP) this._setState(SYNC_STATE.DOWNLOADING);

    let ok = false;
    const downloadStart = Date.now();
    let stuckTimer = null;
    try {
      // Check disk space BEFORE arming the stuck-timer, so a low-disk pause
      // doesn't leave a 10-minute timer dangling (and firing a misleading
      // "still in flight" warning long after the early return).
      const freeSpace = this._getFreeDiskSpace();

      // Expected-size preflight: when the server told us how big the file
      // is, refuse to start a download that cannot fit (size + the absolute
      // free-space floor we keep as headroom). Stamp the shortfall on the
      // row (needsBytes) so the reconcile sweep skips re-fetching it every
      // tick and re-exhausting the disk; the row self-clears once space
      // recovers. This is a terminal-until-space-returns state, distinct
      // from a transient ERROR.
      const wanted = (typeof expectedSize === 'number' && expectedSize > 0) ? expectedSize : 0;

      // Per-file size ceiling — runs from MAX_SYNC_FILE_BYTES regardless of
      // whether free space is known. _getFreeDiskSpace returns Infinity when
      // statfs throws (an unsupported mount, a permissions error), so the
      // disk-fit preflight below silently passes there; this check keeps a
      // ceiling on a statfs-failing mount so a server that declares an
      // enormous size can't drive an unbounded download. The wire layer
      // (downloadFile) enforces the same cap mid-stream against a server
      // that lies about its size; this is the cheap up-front refusal.
      if (wanted > MAX_SYNC_FILE_BYTES) {
        log.error('File ' + relativePath + ' (' + wanted + ' bytes) exceeds the per-file size limit (' + MAX_SYNC_FILE_BYTES + ' bytes) — refusing. Raise HERMITSTASH_MAX_FILE_BYTES if this file is legitimately that large, then run `hermitstash-sync resync`', { relativePath, size: wanted, limit: MAX_SYNC_FILE_BYTES });
        stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
        return false;
      }

      if (wanted > 0 && Number.isFinite(freeSpace) && freeSpace < wanted + MIN_FREE_DISK_BYTES) {
        const need = wanted + MIN_FREE_DISK_BYTES;
        log.error('File ' + relativePath + ' (' + wanted + ' bytes) needs more free space than is available (' + freeSpace + ' bytes) — free up disk or move the sync folder, then run `hermitstash-sync resync`', { relativePath, size: wanted, freeSpace });
        const existing = stateDb.getFile(relativePath);
        stateDb.upsertFile({ ...existing, relativePath, status: FILE_STATUS.ERROR, needsBytes: need });
        return false;
      }

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

      // Checksum verification is done inside downloadFile before rename.
      // Thread the server-declared size so the wire layer can bound the
      // inbound body to min(MAX_SYNC_FILE_BYTES, size) and abort the instant
      // a hostile server streams past it, rather than only catching an
      // oversized body after it has fully landed.
      await this._http.downloadFile(fileId, fullPath, expectedChecksum, wanted);

      // A stop() or resync() flipped mid-download; do NOT write the SYNCED
      // row — resync's clearAll has already run (or is about to) and this
      // upsert would re-populate the cleared DB. The bytes are on disk; the
      // post-resync re-pull / next session's reconcile re-derives the row.
      if (this._resyncing || this._stopped) {
        return false;
      }

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
        needsBytes: 0, // cleared on success — the file fit
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
    // No local mutation may begin once stop()/resync() has flipped — a
    // mutation started here would race the teardown / DB wipe.
    if (this._stopped || this._state === SYNC_STATE.DISCONNECTED || this._resyncing || !this._http) return;
    relativePath = this._identityKey(relativePath);
    // Serialize against a same-path download under the per-path lock. The
    // suppression re-check happens INSIDE the locked body (after the hash),
    // so a download that started while this was queued is honored rather
    // than raced. Key on the normalized relativePath so it matches the
    // suppression / download lock slot.
    return this._withPathLock(relativePath, () =>
      this._handleLocalModifyLocked(relativePath, fullPath, size, mtime));
  }

  async _handleLocalModifyLocked(relativePath, fullPath, size, mtime) {
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

    // Recover a missing/non-numeric event size by stat'ing the file. Some
    // watcher backends deliver a change event without a numeric `ev.size`;
    // `undefined > 0` is false, so the rename-detection predicate below would
    // skip silently (degrading a move to a server delete + fresh re-upload)
    // AND the persisted row would store size=null, which then mismatches every
    // future buffered-delete size comparison for the path. Stat'ing here makes
    // both the rename predicate and the stored size independent of whether the
    // backend populated ev.size. Best-effort: if the stat fails the path falls
    // through with the original (possibly missing) size — the file still
    // uploads, it just may not be recognized as a rename.
    if (!Number.isFinite(size)) {
      try {
        const st = nodeFs.statSync(longPath(fullPath));
        size = st.size;
      } catch { /* allow:silent-catch — size recovery is best-effort; upload still proceeds */ }
    }

    // Re-evaluate teardown + suppression AFTER the hash await. Holding the
    // per-path lock keeps a same-path download mutually exclusive with this
    // body, but a stop()/resync() could have flipped while the hash ran, and
    // _isSuppressed is the authoritative "a transfer owns this path" signal —
    // bail rather than upsert/upload over an op that just took the path.
    if (this._stopped || this._resyncing || !this._http) return;
    if (this._isSuppressed(relativePath)) {
      log.debug('Skipping local upload — path became suppressed after hashing (a server download took it)', { relativePath });
      return;
    }

    // Check if this is actually a change
    const existing = this._lookupTracked(relativePath);
    if (existing && existing.localChecksum === localChecksum) {
      return; // No actual change
    }

    // Rename detection. A bare checksum match mis-moves the wrong fileId
    // when two files share content (the classic case: multiple empty
    // files). Require structural agreement — same checksum AND same size
    // AND a locality signal (same basename or same parent directory) — and
    // disambiguate: if more than one buffered delete satisfies the full
    // predicate, refuse to guess and fall through to an independent delete
    // + fresh upload. Zero-byte files skip rename detection entirely (an
    // empty delete + empty add is genuinely ambiguous; treat it as a real
    // delete + a fresh upload).
    if (size > 0) {
      const newBase = nodePath.basename(relativePath);
      const newDir = nodePath.dirname(relativePath);
      const matches = [];
      for (const [oldPath, pending] of this._pendingDeletes) {
        if (pending.checksum !== localChecksum) continue;
        if (pending.size !== size) continue;
        const sameBase = nodePath.basename(oldPath) === newBase;
        const sameDir = nodePath.dirname(oldPath) === newDir;
        if (!sameBase && !sameDir) continue;
        matches.push({ oldPath, pending });
      }
      if (matches.length === 1) {
        const { oldPath, pending } = matches[0];
        clearTimeout(pending.timer);
        this._pendingDeletes.delete(oldPath);
        log.info('Rename detected (checksum + size + locality match)', { from: oldPath, to: relativePath });
        await this._handleLocalRename(oldPath, relativePath, pending, localChecksum, size, mtime);
        return;
      }
      if (matches.length > 1) {
        // Ambiguous (duplicate content) — don't guess. The buffered deletes
        // resolve to real deletes on their own timers; this file uploads
        // independently below.
        log.info('Multiple buffered deletes match this content — treating as independent delete + upload, not a rename', { to: relativePath, candidates: matches.length });
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
    // Thread the checksum of the bytes we hashed (localChecksum) so the
    // post-upload state records what the server received, not a re-read of a
    // disk that may have drifted mid-stream.
    await this._uploadPool.run(() => this._uploadFile(relativePath, fullPath, localChecksum));
  }

  async _handleLocalDelete(relativePath) {
    relativePath = this._identityKey(relativePath);
    const existing = this._lookupTracked(relativePath);
    if (!existing || !existing.serverFileId) {
      stateDb.removeFile(existing ? existing.relativePath : relativePath);
      return;
    }

    // Clear any timer already buffered for this path before replacing it.
    // A delete -> recreate -> delete within the 1s rename-detection window
    // would otherwise orphan the first timer, which then fires against the
    // newer buffered entry and double-deletes. One live timer per path,
    // carrying the freshest snapshot.
    const prior = this._pendingDeletes.get(relativePath);
    if (prior) clearTimeout(prior.timer);

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

    // Carry size + the source basename alongside the checksum so rename
    // detection can require structural agreement (not checksum alone),
    // which mis-moves the wrong fileId on duplicate / empty-file content.
    this._pendingDeletes.set(relativePath, {
      checksum: existing.localChecksum || existing.serverChecksum,
      size: existing.size,
      fileId: existing.serverFileId,
      existing: existing,
      timer: timer,
    });
  }

  // Issue the server-side DELETE for a buffered local delete. Returns a
  // tri-state so the rename fallback can distinguish:
  //   'deleted' — the DELETE committed (no server-side copy remains).
  //   'skipped' — suppression / teardown bailed; a live server op owns this
  //               path, so WE left no stale server-side duplicate.
  //   'failed'  — a genuine server DELETE error; oldPath may still exist on
  //               the server.
  // The buffered-delete timer caller ignores the return, so widening it from
  // boolean to tri-state is non-breaking there.
  async _executeDelete(relativePath, existing) {
    // A same-path download owns this path right now — never issue a server
    // DELETE against a file a download is mid-stream on (it would delete the
    // bytes the server is delivering). Check suppression BEFORE taking the
    // lock so the delete refuses immediately rather than queuing behind the
    // download and then deleting the freshly-pulled file. Server events are
    // authoritative for sync bundles, so a delete that loses this race is
    // correctly dropped.
    if (this._isSuppressed(relativePath)) {
      log.debug('Skipping buffered delete — a same-path transfer is in flight', { relativePath });
      return 'skipped';
    }
    // Serialize the server DELETE against a same-path local upload under the
    // per-path lock. The lock key matches the upload's; oldPath in a rename
    // fallback differs from the new path the caller's lock holds, so there
    // is no self-deadlock.
    return this._withPathLock(relativePath, () =>
      this._executeDeleteLocked(relativePath, existing));
  }

  async _executeDeleteLocked(relativePath, existing) {
    // A buffered delete can fire just as stop()/resync() tears things down.
    // Bail if the engine is disconnected, mid-resync, or the HTTP client is
    // gone, rather than throwing an unhandled rejection against a null
    // client / closed state DB or deleting server state a resync re-pulls.
    if (this._state === SYNC_STATE.DISCONNECTED || this._resyncing || !this._http) return 'skipped';
    // Re-check suppression under the lock: a download could have taken the
    // path between the pre-lock check and acquiring the lock.
    if (this._isSuppressed(relativePath)) {
      log.debug('Skipping buffered delete — a same-path transfer took the path under the lock', { relativePath });
      return 'skipped';
    }
    // Re-read the row at fire time. The `existing` snapshot was captured when
    // the delete was buffered (~1s ago); prefer the CURRENT serverFileId so a
    // server-driven event that re-upserted the row with a DIFFERENT id in that
    // window is honored rather than the stale closed-over id. Suppression
    // (checked above) already covers an in-flight server op; this removes the
    // residual staleness dependency on the snapshot. Fall back to the snapshot
    // only if the row is no longer readable; if neither carries a serverFileId
    // the delete intent is stale — skip rather than target a wrong/absent id.
    // Use the fold-aware lookup (matching how the row was located at buffer time
    // in _handleLocalDelete) so the fresh read still hits the row on a
    // case-folding volume (NTFS / Dropbox mount) where a plain exact-match
    // getFile would miss it.
    const target = this._lookupTracked(relativePath) || existing;
    if (!target || !target.serverFileId) {
      log.debug('Skipping buffered delete — the tracked row is gone under the buffer window', { relativePath });
      return 'skipped';
    }
    log.info('Local delete confirmed', { relativePath });
    try {
      await this._http.deleteFile(target.serverFileId);
      stateDb.removeFile(relativePath);
      log.info('Deleted from server', { relativePath });
      return 'deleted';
    } catch (err) {
      log.error('Failed to delete from server', { relativePath, error: err.message });
      stateDb.updateFileStatus(relativePath, FILE_STATUS.ERROR);
      return 'failed';
    }
  }

  async _handleLocalRename(oldPath, newPath, pending, checksum, size, mtime) {
    this._activeOps++;
    // Don't drop out of CATCHING_UP for a concurrent local rename during
    // catch-up; _maybeFinishCatchUp owns the catch-up -> SYNCED transition.
    if (this._state !== SYNC_STATE.CATCHING_UP) this._setState(SYNC_STATE.UPLOADING);

    try {
      // Call server rename endpoint
      var result = await this._http.renameFile(this._config.bundleId, oldPath, newPath);
      log.info('Renamed on server', { from: oldPath, to: newPath, seq: result.seq });

      // Update local state as ONE transaction so a crash between the delete
      // and the insert can't strand the file tracked at neither path.
      stateDb.renameFile(oldPath, {
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
      // Under teardown the delete-then-upload fallback would leave a
      // server-side duplicate (the delete bails on the DISCONNECTED guard
      // while the upload proceeds, or vice versa). Short-circuit so neither
      // leg runs in the window; the next start()/initial-sync re-derives a
      // consistent state.
      if (this._stopped || this._state === SYNC_STATE.DISCONNECTED || this._resyncing || !this._http) {
        log.warn('Server rename failed during teardown — deferring recovery to next start/initial-sync', { from: oldPath, to: newPath, error: err.message });
        stateDb.updateFileStatus(oldPath, FILE_STATUS.ERROR);
        return;
      }
      log.warn('Server rename failed, falling back to delete + upload', { from: oldPath, to: newPath, error: err.message });
      // Fallback: delete old, then upload new ONLY if the delete committed,
      // so the two legs can't diverge into a server-side duplicate.
      const outcome = await this._executeDelete(oldPath, pending.existing);
      // 'deleted' (committed) or 'skipped' (oldPath owned by a live server op
      // — no stale duplicate left by us) both mean the new local bytes are
      // genuinely unsynced and safe to upload. 'failed' means oldPath may
      // still be on the server, so uploading newPath would create a server-
      // side duplicate; leave a recoverable PENDING_UPLOAD marker instead.
      // newPath is a LOCAL-origin name, so use _safeLocalPath (host platform)
      // — a Linux-legal "foo:bar" rename target must still upload.
      var fullPath = this._safeLocalPath(newPath);
      if (outcome === 'failed') {
        if (fullPath) {
          stateDb.upsertFile({
            relativePath: newPath,
            serverFileId: null,
            localChecksum: checksum,
            serverChecksum: null,
            localMtime: mtime,
            size: size,
            serverSeq: 0,
            status: FILE_STATUS.PENDING_UPLOAD,
          });
          log.warn('Server rename fallback could not delete the old path — left the renamed file PENDING_UPLOAD for the reconcile sweep to re-drive', { from: oldPath, to: newPath });
        }
        return;
      }
      // Call the locked upload body directly — this rename path already runs
      // under newPath's per-path lock (acquired by _handleLocalModify before
      // it dispatched into rename detection), so re-acquiring it here would
      // self-deadlock. oldPath's delete above used a distinct lock key.
      if (fullPath) await this._handleLocalModifyLocked(newPath, fullPath, size, mtime);
    } finally {
      this._activeOps = Math.max(0, this._activeOps - 1);
      this._maybeMarkSynced();
    }
  }

  // `uploadedChecksum` is the SHA3-512 of the exact bytes the caller decided
  // to upload (hashed before the stream opened). It is the row's localChecksum
  // on success — NOT a post-upload disk re-read. The stream sends bytes lazily
  // from disk, so a concurrent writer can mutate the file between the
  // caller's hash and stream completion; re-hashing the disk afterward and
  // storing THAT as localChecksum would record a SYNCED row whose checksum
  // matches the post-upload (v2) bytes while the server holds the uploaded
  // (v1) bytes — the next watcher event would see v2 == localChecksum and
  // never re-upload, silently stranding the server at v1 (a lost update). By
  // recording the uploaded bytes' checksum and re-detecting any post-upload
  // disk drift below, a divergent v2 stays PENDING_UPLOAD and re-uploads.
  async _uploadFile(relativePath, fullPath, uploadedChecksum) {
    // Stream-start suppression gate. The upload pool may have queued this
    // task; by the time a slot frees, a same-path server download could have
    // taken the path. _uploadFile streams disk bytes lazily (createReadStream
    // inside http-client.uploadFile), so bail here rather than push bytes the
    // server is about to overwrite from the download. The watcher-driven path
    // also holds the per-path lock across this call, but the initial-scan
    // fan-out (_scanLocalForUpload) does not — this gate covers both.
    if (this._isSuppressed(relativePath)) {
      log.debug('Skipping upload — a same-path transfer took the path before the stream started', { relativePath });
      return;
    }
    // _activeOps tracks distinct uploads, not attempts — increment once
    // before the retry loop. Retries are bounded inside b.retry.withRetry
    // and don't widen the active-ops gauge.
    this._activeOps++;
    metrics.setActiveOps(this._activeOps);
    // Don't drop out of CATCHING_UP for a concurrent local upload during
    // catch-up; _maybeFinishCatchUp owns the catch-up -> SYNCED transition.
    if (this._state !== SYNC_STATE.CATCHING_UP) this._setState(SYNC_STATE.UPLOADING);

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
      } else if (this._resyncing || this._stopped) {
        // A resync()/stop() landed while this upload was in flight. The
        // server has the bytes, but writing the SYNCED row now would
        // re-populate a DB that clearAll() just emptied; let the post-resync
        // re-pull / next session's reconcile re-derive the row instead.
        log.debug('Upload finished during resync/stop — skipping state write', { relativePath });
      } else {
        log.info('Uploaded', { relativePath, fileId: result.fileId || result.id });

        // The checksum the server recorded for what it actually received.
        // Falls back to the caller's pre-upload hash for an older server that
        // omits it. This is the authoritative "what landed on the server"
        // value — the row's localChecksum tracks it, never a post-upload disk
        // re-read.
        const uploaded = result.checksum || uploadedChecksum;

        // Re-hash the disk AFTER the upload to detect a concurrent local edit
        // that mutated the file during or right after the stream read. If the
        // disk no longer matches the bytes the server received, the file
        // diverged mid-upload (v2): record localChecksum = the uploaded bytes
        // (so the next compare sees disk-v2 != localChecksum-v1 and re-uploads)
        // and leave the row PENDING_UPLOAD instead of SYNCED. A SYNCED row with
        // localChecksum = hash(v2) would mask the drift and strand the server
        // at v1 forever. On a torn read the re-hash itself may fail (file
        // removed) — treat that as drift too. Last-write-wins is preserved:
        // v2 still converges, it just isn't silently dropped.
        let diskNow = null;
        try { diskNow = await hashFile(fullPath); }
        catch (err) { log.warn('Could not re-hash file after upload to confirm no concurrent edit', { relativePath, error: err.message }); }

        let stat = null;
        try { stat = nodeFs.statSync(longPath(fullPath)); }
        catch { /* file vanished after upload — handled as drift below */ }

        // Fail-safe: a missing `uploaded` value (a future caller that forgets
        // the checksum arg AND a server that omits result.checksum) is treated
        // as divergence — re-drive rather than silently declare SYNCED against
        // bytes we can't confirm. Today both call sites pass localChecksum, so
        // this only hardens against a future regression.
        const diverged = !diskNow || !stat || diskNow !== uploaded;
        if (diverged) {
          // The local file changed (or vanished) between the caller's hash and
          // upload completion. Keep it PENDING_UPLOAD so the watcher/reconcile
          // re-uploads the current disk bytes rather than declaring SYNCED
          // against the now-stale server copy. Record the uploaded checksum as
          // localChecksum so the next compare reliably detects the divergence.
          const existing = stateDb.getFile(relativePath);
          stateDb.upsertFile({
            ...existing,
            relativePath,
            serverFileId: result.fileId || result.id,
            localChecksum: uploaded,
            serverChecksum: uploaded,
            localMtime: stat ? stat.mtimeMs : (existing ? existing.localMtime : null),
            size: stat ? stat.size : (existing ? existing.size : null),
            serverSeq: result.seq || 0,
            status: FILE_STATUS.PENDING_UPLOAD,
          });
          log.warn('Local file changed during upload — re-queuing the newer content so the server does not stay on stale bytes', { relativePath });
          // Re-drive immediately so the divergence converges without waiting
          // for the next watcher event or the reconcile sweep. The path is not
          // suppressed here (uploads aren't suppression-gated), and the pool
          // bounds the concurrency.
          this._enqueueLocalRescan();
          // The upload itself succeeded server-side (v1 landed); only a newer
          // local v2 still needs sending. Count it as a successful upload so the
          // success-rate metric reflects the server write rather than a failure —
          // the re-drive above accounts for v2 on its own pass.
          ok = true;
        } else {
          stateDb.upsertFile({
            relativePath,
            serverFileId: result.fileId || result.id,
            localChecksum: uploaded,
            serverChecksum: uploaded,
            localMtime: stat.mtimeMs,
            size: stat.size,
            serverSeq: result.seq || 0,
            status: FILE_STATUS.SYNCED,
          });
          ok = true;
        }
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
    const TEMP_RE = TEMP_FILE_RE;
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
   * Resolve a SERVER-provided relativePath and verify it stays within the
   * sync folder. Returns the full path, or null on refusal. Delegates to
   * b.safePath.resolveOrNull, which adds NUL / C0-control / bidi-override /
   * encoded-separator / absolute-rel / Windows-reserved-name / trailing-dot
   * or -space / NTFS-ADS-marker refusals on top of the traversal check the
   * hand-rolled lexical guard did alone.
   *
   * platform:'windows' is forced for server-origin names so a POSIX peer
   * cannot push a name a Windows peer later can't materialize — the same
   * cross-platform posture _validateServerPath / b.guardFilename already
   * enforce on intake, consolidated into one fail-closed pass.
   */
  _safePath(relativePath) {
    return b.safePath.resolveOrNull(this._config.syncFolder, relativePath, { platform: 'windows' });
  }

  /**
   * Resolve a LOCAL-origin relativePath (a name that originated on THIS
   * host — the watcher rename-fallback destination, or a tracked-row key
   * that may represent a locally-created file). Same traversal + refusal
   * classes as _safePath but WITHOUT the Windows-platform override, so a
   * Linux/macOS user's legitimately-named "foo:bar" / "aux" file still
   * resolves and syncs on its native filesystem.
   */
  _safeLocalPath(relativePath) {
    return b.safePath.resolveOrNull(this._config.syncFolder, relativePath);
  }

  // Empirically detect whether the sync folder lives on a case-folding
  // filesystem. os.platform() is unreliable in both directions (a FAT /
  // exFAT mount on Linux folds; a case-sensitive APFS volume on macOS does
  // not), so the only honest signal is to ask the actual volume. Drop a
  // temp probe file under a known mixed-case name and check whether the
  // opposite-cased variant resolves to it. Best-effort: a probe failure
  // leaves _fsCaseFolds at its safe default (false — exact-byte identity).
  _detectCaseFolding() {
    let probe = null;
    try {
      // Name the probe with the same `.tmp.<8hex>` tail the download path
      // uses (4 random bytes = 8 hex) so a crashed-run orphan is collected by
      // the boot sweep's TEMP_RE; the `.hs-case-probe` infix keeps it
      // human-identifiable.
      const token = nodeCrypto.randomBytes(4).toString('hex'); // allow:raw-randombytes-token — local FS-probe filename, not a security token
      const lower = nodePath.join(this._config.syncFolder, '.hs-case-probe.tmp.' + token);
      const upper = nodePath.join(this._config.syncFolder, '.HS-CASE-PROBE.tmp.' + token);
      nodeFs.mkdirSync(longPath(this._config.syncFolder), { recursive: true });
      nodeFs.writeFileSync(longPath(lower), '');
      probe = lower;
      // If the upper-cased path resolves to the file we just wrote under
      // the lower-cased name, the volume folds case.
      this._fsCaseFolds = nodeFs.existsSync(longPath(upper));
    } catch (err) {
      this._fsCaseFolds = false;
      log.debug('Case-fold probe could not run — assuming case-sensitive', { error: err.message });
    } finally {
      if (probe) { try { nodeFs.unlinkSync(longPath(probe)); } catch { /* allow:silent-catch — probe cleanup is best-effort */ } }
    }
    log.info('Filesystem case-fold detection', { caseFolds: this._fsCaseFolds });
  }

  // The byte-stable identity key for a relativePath: NFC-normalized so an
  // NFD-surfacing volume and the server's composed form resolve to one
  // key. Case is preserved — folding is handled at lookup time via
  // getFileFolded so the server's authoritative casing is never lost.
  _identityKey(relativePath) {
    return canonRelPath(relativePath);
  }

  // Fold-aware tracked-row lookup. On a case-folding host a server event
  // for "Foo.txt" resolves to a row tracked as "foo.txt" so the daemon
  // reuses it instead of conflict-copying against a phantom collision.
  _lookupTracked(relativePath) {
    return stateDb.getFileFolded(this._identityKey(relativePath), this._fsCaseFolds);
  }

  // Name-level validation for a server-supplied relativePath. _safePath
  // only blocks traversal; this additionally refuses names the operating
  // system can't represent (Windows reserved devices like CON/NUL,
  // trailing dot / space, NTFS alternate-data-stream `name:stream`) via
  // b.guardFilename.verifyExtractionPath, which is platform-unconditional
  // — a Linux/Docker peer refuses the same names so a Windows peer sharing
  // the bundle never sees a file it can't materialize. Returns true if the
  // path is safe to write; on rejection it advances seq (so a hostile tip
  // event can't pin lastSeq and re-wedge catch-up on every reconnect) and
  // returns false. The correct fix for a genuinely OS-hostile name is
  // server-side rename, so the policy is strict reject, never sanitize
  // (which would diverge the local leaf from the server's authoritative
  // relativePath and reintroduce DB-vs-disk drift).
  _validateServerPath(relativePath, seq) {
    if (typeof relativePath !== 'string' || relativePath.length === 0) {
      log.error('Server sent an empty relativePath — skipping', { seq });
      if (seq !== undefined) this._updateSeq(seq);
      return false;
    }
    try {
      b.guardFilename.verifyExtractionPath(relativePath, this._config.syncFolder);
      return true;
    } catch (err) {
      if (err instanceof b.guardFilename.GuardFilenameError) {
        log.error('Server sent a path that is unrepresentable on this filesystem — skipping; the server-side name must be renamed', {
          relativePath, reason: err.code, detail: err.message,
        });
        if (seq !== undefined) this._updateSeq(seq);
        return false;
      }
      throw err;
    }
  }

  // --- Utilities ---

  _getFreeDiskSpace() {
    try {
      const stat = nodeFs.statfsSync(this._config.syncFolder);
      // bavail is the space available to an unprivileged process — bfree
      // counts root-reserved blocks the non-root daemon user cannot write
      // into, which would over-report headroom and let a download fill the
      // writable space then loop. Matches blamejs's own free-space probe.
      //
      // frsize is the fragment (allocation) unit block counts are reported
      // in — the correct multiplier for bavail per POSIX statvfs. bsize is
      // the preferred-I/O block size, which can differ on some filesystems
      // and would mis-size free space there. Fall back to bsize on a kernel
      // that doesn't report frsize.
      const unit = (typeof stat.frsize === 'number' && stat.frsize > 0) ? stat.frsize : stat.bsize;
      return stat.bavail * unit;
    } catch {
      return Infinity; // Can't check — assume OK
    }
  }

}

module.exports = SyncEngine;
