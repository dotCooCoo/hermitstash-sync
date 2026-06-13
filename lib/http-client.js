'use strict';

const nodeHttps = require('node:https');
const nodeHttp = require('node:http');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const nodeTls = require('node:tls');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION, MAX_SYNC_FILE_BYTES } = require('./constants');
const { longPath } = require('./long-path');
const log = require('./logger');
const b = require('../vendor/blamejs');
const { PassThrough, Transform } = require('node:stream');

const C = b.constants;
const DOWNLOAD_ERR_BODY_CAP = C.BYTES.kib(64);

// Error class with `withStatusCode: true` so the HTTP status survives as
// `err.statusCode` on 4xx/5xx instead of forcing us to string-parse the
// "HTTP <N>" message. Without an `errorClass` opt, blamejs returns a bare
// FrameworkError that drops statusCode (see vendor/.../http-client.js
// `_makeError`).
const HermitStashHttpError = b.frameworkError.defineClass('HermitStashHttpError', { withStatusCode: true });

// Cap on JSON response bodies parsed via safeJson. Server responses are
// bounded by application logic; this is a defence-in-depth ceiling against
// a hostile or compromised server returning a giant or deeply-nested doc.
const RESPONSE_JSON_MAX_BYTES = C.BYTES.mib(16);

// Grace window before a replaced HTTP agent is destroyed. reloadMtlsCerts()
// swaps the keepAlive agent on CA rotation; deferring the old agent's destroy
// by the per-request timeout ceiling lets in-flight transfers finish on their
// existing sockets instead of being aborted mid-stream.
const AGENT_DRAIN_GRACE_MS = C.TIME.seconds(30);

function _safeParseJson(body) {
  try {
    return b.safeJson.parse(body, { maxBytes: RESPONSE_JSON_MAX_BYTES });
  } catch (_e) {
    return null;
  }
}

// Deliberate opt-out for operators who must reach a non-PQC HermitStash
// endpoint (legacy server behind a TLS-terminating proxy, an air-gapped
// box without OpenSSL 3.5+). When truthy, a classical negotiated group is
// logged as a WARN instead of failing the connection. Default OFF — the
// post-quantum hybrid is the floor unless the operator explicitly relaxes
// it. Read once at module load; a daemon restart picks up a changed value.
function _allowClassicalTls() {
  // Accept the unambiguous truthy spellings only — anything else (unset,
  // empty, '0', 'false') keeps enforcement ON.
  const raw = b.safeEnv.readVar('HERMITSTASH_ALLOW_CLASSICAL_TLS', { type: 'string', default: '' });
  return raw === '1' || raw === 'true' || raw === 'yes';
}
const ALLOW_CLASSICAL_TLS = _allowClassicalTls();

// Inspect a freshly-handshaked TLS socket's negotiated key-exchange group
// and enforce the post-quantum floor. node:tls reports getEphemeralKeyInfo()
// as a non-empty `{ name: 'X25519', type: 'ECDH', ... }` for a CLASSICAL
// group and as `{}` (no name) for an ML-KEM hybrid — it doesn't model the
// hybrid as ECDH. So a non-empty name that does NOT carry "MLKEM" means the
// peer offered no hybrid and the handshake fell back to classical: a
// downgrade. (Same detection shape blamejs uses in b.pqcAgent's
// auditClassicalDowngrade.)
//
// The negotiated group is always surfaced to the logger so a classical
// negotiation is visible. On the enforced path (the HermitStash mTLS sync
// transport + the WebSocket control channel) a classical group destroys the
// socket with an actionable error naming the group and host, so a downgraded
// or MITM'd connection can't proceed — unless HERMITSTASH_ALLOW_CLASSICAL_TLS
// is set, which downgrades the hard-fail to the same WARN the observe-only
// path emits. The auto-update GitHub-release downloader runs observe-only
// (enforce: false): its CDN legitimately speaks no ML-KEM, and failing there
// would brick self-update.
function assertNegotiatedGroupPqc(socket, host, opts) {
  opts = opts || {};
  const enforce = opts.enforce !== false;
  if (!socket || typeof socket.getEphemeralKeyInfo !== 'function') return;
  let info;
  try { info = socket.getEphemeralKeyInfo() || {}; }
  catch { return; }   // best-effort — a closed socket can't report; nothing to assert
  const group = info.name;
  if (!group || /MLKEM/i.test(group)) return;   // hybrid (or unreported) — at the floor

  // Classical fallback observed. Always log so the downgrade is visible on
  // both the enforced and observe-only transports.
  log.warn(
    'TLS negotiated classical group ' + group + ' against ' + host +
    ' — server is not PQC-ready; post-quantum (store-now-decrypt-later) ' +
    'protection is not in effect for this connection',
    { group: group, host: host }
  );

  if (enforce && !ALLOW_CLASSICAL_TLS) {
    socket.destroy(new Error(
      'server negotiated classical TLS group ' + group + ' for ' + host +
      ' — this build requires a post-quantum key exchange. Upgrade the ' +
      'HermitStash server to a PQC-capable build (OpenSSL 3.5+ with ML-KEM ' +
      'hybrid groups), or set HERMITSTASH_ALLOW_CLASSICAL_TLS=1 to allow a ' +
      'classical fallback deliberately.'
    ));
  }
}

/**
 * Build TLS options for any https/tls consumer in this project. Always sets
 * the PQC ecdhCurve + groups + TLS 1.3 minimum — callers cannot opt out
 * (that's the point of centralizing this). Accepts mTLS cert/key/ca as
 * either file paths (string) or pre-loaded Buffers; ws-client passes
 * cached buffers to avoid re-reading on reconnect.
 *
 * @param {?{cert?:string|Buffer, key?:string|Buffer, ca?:string|Buffer}} mtls
 * @param {?object} extras — additional tls options merged last (e.g.
 *                           rejectUnauthorized for self-signed test CAs)
 * @returns {object} tls options ready to spread into https.request / tls.connect
 */
// Build the CA bundle for outbound TLS. When opts.ca is set on a TLS
// connection, Node REPLACES its default trust store with just that
// value — so naively passing the mTLS CA file we got at enrollment
// silently breaks server-cert validation for any server-cert chain
// not anchored by that CA (Let's Encrypt-served deployments, the
// system trust store, NODE_EXTRA_CA_CERTS). We additively combine:
//   1. node:tls.rootCertificates (the system / Mozilla CA bundle)
//   2. NODE_EXTRA_CA_CERTS file contents, when the env var is set
//   3. the mTLS CA the server issued at enrollment
// so the operator's existing trust chain keeps working AND any
// self-hosted server whose TLS cert is signed by the enrollment-time
// mTLS CA validates without further config.
function _buildCaBundle(mtlsCaBuf) {
  const out = nodeTls.rootCertificates ? nodeTls.rootCertificates.slice() : [];
  // codebase-patterns:allow raw-process-env — NODE_EXTRA_CA_CERTS is the
  // documented Node mechanism for appending trust roots; reading it here
  // restores the behaviour Node provides when `ca` is unset.
  const extra = process.env.NODE_EXTRA_CA_CERTS;                                // allow:raw-process-env
  if (extra) {
    try { out.push(nodeFs.readFileSync(extra, 'utf8')); }
    catch { /* allow:silent-catch — env-var points at a missing file; the user explicitly chose this path, surfacing is the operator's job */ }
  }
  if (mtlsCaBuf) out.push(Buffer.isBuffer(mtlsCaBuf) ? mtlsCaBuf.toString('utf8') : mtlsCaBuf);
  return out;
}

function buildTlsOptions(mtls, extras) {
  const opts = {
    ecdhCurve: TLS_GROUPS,
    groups: TLS_GROUPS,
    minVersion: TLS_MIN_VERSION,
  };
  if (mtls) {
    const load = v => (typeof v === 'string' ? nodeFs.readFileSync(v) : v);
    if (mtls.cert) opts.cert = load(mtls.cert);
    if (mtls.key)  opts.key  = load(mtls.key);
    if (mtls.ca)   opts.ca   = _buildCaBundle(load(mtls.ca));
  }
  if (extras) Object.assign(opts, extras);
  return opts;
}

// Compute the SHA-256 hash of a cert's SubjectPublicKeyInfo, in the
// `sha256/<base64>` pin format used by HPKP / Apple TrustEvaluation /
// most TLS pin tooling. The pin binds to the public-key DER bytes
// (not the cert), so cert rotation that re-uses the same keypair
// keeps the pin valid — the deliberate "key continuity" property the
// pin defends against. `cert.raw` is the DER of the leaf cert that
// Node hands to checkServerIdentity.
function _spkiPinForCert(cert) {
  if (!cert || !cert.raw) return null;
  try {
    const x509 = new nodeCrypto.X509Certificate(cert.raw);
    const spkiDer = x509.publicKey.export({ format: 'der', type: 'spki' });
    return 'sha256/' + nodeCrypto.createHash('sha256').update(spkiDer).digest('base64');
  } catch {
    return null;
  }
}

// Build a `checkServerIdentity` override that enforces SPKI pinning
// on top of Node's default chain + hostname checks. Returns
// `undefined` (passes) when no pins are configured.
function _buildCheckServerIdentity(pinList) {
  if (!Array.isArray(pinList) || pinList.length === 0) return undefined;
  const pins = pinList.slice();
  return function (hostname, cert) {
    const defaultErr = nodeTls.checkServerIdentity(hostname, cert);
    if (defaultErr) return defaultErr;
    const observed = _spkiPinForCert(cert);
    if (!observed) {
      return new Error('SPKI pin enforcement: could not extract SPKI from server cert');
    }
    if (pins.indexOf(observed) === -1) {
      return new Error(
        'SPKI pin mismatch for ' + hostname + ': observed ' + observed +
        ', expected one of [' + pins.join(', ') + ']'
      );
    }
    return undefined;
  };
}

/**
 * Accumulate an HTTP response body as a text string, capped at maxBytes to
 * avoid unbounded growth on hostile servers. Resolves with the collected
 * string on 'end', rejects on stream error. Use only for JSON/text endpoints
 * — binary downloads must stream (see downloadFile).
 */
function collectTextBody(res, maxBytes = DOWNLOAD_ERR_BODY_CAP) {
  return new Promise((resolve, reject) => {
    let body = '';
    res.on('data', chunk => {
      if (body.length < maxBytes) body += chunk;
    });
    res.on('end', () => resolve(body));
    res.on('error', reject);
  });
}

// Errno codes a Windows file lock surfaces when another process (Dropbox /
// OneDrive sync agent, indexer, anti-virus on-access scanner) holds the
// destination open while we try to swap the freshly-downloaded temp into
// place. On POSIX these are rare and the loop simply succeeds first try.
const RENAME_LOCK_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

// Backed-off retry schedule (milliseconds) for the temp→final rename when a
// transient Windows lock blocks it. Mirrors the framework's atomic-write
// retry contract: a short escalating wait gives the lock holder time to
// release before we give up. The first attempt fires immediately (0ms).
const RENAME_RETRY_DELAYS_MS = [0, 5, 15, 40, 100];                              // allow:raw-byte-literal — backoff steps in ms, not byte sizes

/**
 * Rename a freshly-written download temp onto its final destination,
 * retrying on transient Windows lock contention (EPERM/EACCES/EBUSY).
 *
 * The destination commonly lives inside a Dropbox/OneDrive-synced folder
 * where a sync agent can momentarily lock the target; a bare renameSync
 * fails the whole download on a lock that would clear milliseconds later.
 * Non-transient errors (a real ENOENT, ENOSPC, cross-device EXDEV) rethrow
 * immediately — only the lock codes are worth waiting on. The verified temp
 * bytes are left in place on the final failure so the caller can decide
 * whether to unlink or leave it for the startup orphan sweep.
 */
async function renameWithLockRetry(tmpPath, dstPath) {
  let lastErr;
  for (let i = 0; i < RENAME_RETRY_DELAYS_MS.length; i++) {
    const delay = RENAME_RETRY_DELAYS_MS[i];
    if (delay > 0) await b.safeAsync.sleep(delay);
    try {
      nodeFs.renameSync(tmpPath, dstPath);
      return;
    } catch (err) {
      lastErr = err;
      if (!err || !RENAME_LOCK_CODES.has(err.code)) throw err;
    }
  }
  throw lastErr;
}

class HttpClient {
  constructor(config, apiKey) {
    this._config = config;
    // Validate the configured server URL once at construction with
    // `b.safeUrl.parse`. Catches malformed URLs, disallowed schemes
    // (only http: / https:), and credentials embedded in the authority
    // before any request fires. Operators see a deterministic config-
    // time error instead of a FrameworkError on the first request.
    this._serverUrl = b.safeUrl.parse(config.server, {
      allowedProtocols: ['http:', 'https:'],
    });
    this._apiKey = apiKey;
    this._isHttps = this._serverUrl.protocol === 'https:';
    this._sessionCookie = null;

    // Lazy blamejs apiEncrypt client — instantiated on first protocol-
    // scoped request (currently POST /sync/rename, POST /drop/init,
    // POST /drop/finalize/:bundleId per server v1.9.15). Caches the
    // server's published pubkey + a per-session keying counter for
    // replay defence.
    //
    // `_encClientPromise` memoizes the in-flight bootstrap so concurrent
    // first-time callers share one pubkey fetch and one client instead of
    // racing two independent sessions. `_encChain` serializes encrypted
    // requests against a single per-session client so its strict-monotonic
    // request/response counters stay in lockstep — out-of-order responses
    // would otherwise trip the replay check.
    this._encClient = null;
    this._encClientPromise = null;
    this._encPubkey = null;
    this._encChain = Promise.resolve();

    this._tlsOpts = this._isHttps ? buildTlsOptions(config.mtls) : {};
    this._rebuildAgent();

    // Shared bandwidth limiters — one bucket per direction so N
    // concurrent uploads (or downloads) share the configured budget
    // instead of each getting the full rate. `0` = unlimited (passes
    // through via PassThrough). Operators set uploadBytesPerSec /
    // downloadBytesPerSec in config.json. b.streamThrottle rejects
    // bytesPerSec <= 0, so guard at construction.
    const ulRate = config.uploadBytesPerSec | 0;
    const dlRate = config.downloadBytesPerSec | 0;
    this._uploadLimiter   = ulRate > 0 ? b.streamThrottle.create({ bytesPerSec: ulRate }) : null;
    this._downloadLimiter = dlRate > 0 ? b.streamThrottle.create({ bytesPerSec: dlRate }) : null;
  }

  _throttleTransform(limiter) {
    // b.streamThrottle's Transform refuses chunks larger than the
    // 1-second burst budget by default — we always pass through bulk
    // file bodies in single-MB chunks, so `allowOversize: true`
    // splits oversize chunks across wait windows.
    if (!limiter) return new PassThrough();
    return limiter.transform({ allowOversize: true });
  }

  _rebuildAgent() {
    // Capture the previous agent and destroy it on a grace delay rather than
    // synchronously. reloadMtlsCerts() rebuilds the agent on CA rotation, and a
    // synchronous destroy() aborts any upload/download still streaming through
    // the old keepAlive sockets. New requests bind to the agent built below; the
    // old one drains for AGENT_DRAIN_GRACE_MS (the per-request timeout ceiling),
    // then closes.
    const _oldAgent = this._agent;
    if (this._isHttps) {
      // b.pqcAgent.create() pins TLSv1.3 + the framework's PQC group
      // preference + applies blamejs's network-tls posture; our mTLS
      // cert/key/ca pass through to the underlying https.Agent options.
      this._agent = b.pqcAgent.create({
        cert: this._tlsOpts.cert,
        key:  this._tlsOpts.key,
        ca:   this._tlsOpts.ca,
        keepAlive: true,
        maxSockets: 6,
      });
      // blamejs's pqcAgent forces its own ecdhCurve string ("SecP384r1MLKEM1024:
      // X25519MLKEM768"). HermitStash server's PQC gate currently expects the
      // 3-group string that includes SecP256r1MLKEM768 — restore it here until
      // hermitstash-private's TLS posture migrates to the 2-group preference.
      this._agent.options.ecdhCurve = TLS_GROUPS;
      this._agent.options.groups    = TLS_GROUPS;
      this._agent.options.minVersion = TLS_MIN_VERSION;
      // Optional SPKI pinning — when config.pinnedServerSpki is set,
      // every TLS handshake must produce a leaf cert whose SPKI hash
      // matches one of the configured pins. Layered ON TOP of the
      // default chain + hostname checks; we don't bypass them.
      const pin = _buildCheckServerIdentity(this._config.pinnedServerSpki);
      if (pin) this._agent.options.checkServerIdentity = pin;

      // Post-handshake post-quantum floor enforcement. blamejs's pqcAgent
      // already wraps createConnection for its own (non-fatal) downgrade
      // audit; HermitStash mutates agent.options AFTER construction, so we
      // wrap independently at this layer to HARD-FAIL a classical
      // negotiation on the sync transport. createConnection runs once per
      // fresh socket (not per keep-alive reuse), so the assertion binds to
      // every new handshake the agent opens. Covers _jsonRequest, the
      // encrypted path, and the multipart upload / binary download — they
      // all share this agent.
      const host = this._serverUrl.hostname;
      const _origCreateConnection = this._agent.createConnection.bind(this._agent);
      this._agent.createConnection = function (options, cb) {
        const socket = _origCreateConnection(options, cb);
        if (socket && typeof socket.once === 'function') {
          socket.once('secureConnect', function () {
            assertNegotiatedGroupPqc(socket, host, { enforce: true });
          });
        }
        return socket;
      };
    } else {
      this._agent = new nodeHttp.Agent({ keepAlive: true, maxSockets: 6 });
    }
    if (_oldAgent) {
      const drainTimer = setTimeout(() => {
        // allow:silent-catch — best-effort close of the now-drained prior agent
        try { _oldAgent.destroy(); } catch (_e) {}
      }, AGENT_DRAIN_GRACE_MS);
      if (typeof drainTimer.unref === 'function') drainTimer.unref();
    }
  }

  /**
   * Re-read mTLS cert/key/CA files from disk, rebuild _tlsOpts, and replace
   * the keepAlive agent. Called by sync-engine after a CA rotation so the
   * next HTTP request uses the new credentials instead of the pre-rotation
   * buffers baked into the old agent.
   */
  reloadMtlsCerts() {
    if (!this._isHttps || !this._config.mtls) return;
    try {
      this._tlsOpts = buildTlsOptions(this._config.mtls);
      this._rebuildAgent();
      // allow:silent-catch — cert-reload from disk after CA rotation; an absent file path here means the rotation hand-off lost a race, the next request rebuilds against the persisted trio
    } catch (_e) {}
  }

  /**
   * GET bundle metadata (JSON).
   *
   * Server v1.9.15+ bypasses the legacy api-encrypt envelope for Bearer-
   * authed sync clients (mTLS + API key) — the response body is plain
   * JSON. Older servers wrapped this in `{ _e, _t }` and required an
   * ECIES handshake the sync client never performed in production. The
   * envelope path was always dead-end ciphertext for sync; we now read
   * the body directly.
   */
  async getBundleMetadata(shareId) {
    const resp = await this._jsonRequest('GET', `/b/${shareId}`, null, {
      'Accept': 'application/json',
    });
    return resp.json;
  }

  /**
   * Upload a file to a sync bundle.
   * Multipart uploads are NOT encrypted by api-encrypt (only JSON responses are).
   * The response IS encrypted — we decrypt it.
   */
  async uploadFile(bundleId, relativePath, filePath) {
    // Windows long-path: deep node_modules-style trees blow past
    // MAX_PATH=260. longPath() returns the path unchanged on POSIX
    // and on short Windows paths; only long Windows absolutes get
    // the `\\?\` prefix that bypasses the Win32 API path cap.
    const fsPath = longPath(filePath);
    const stat = nodeFs.statSync(fsPath);
    const safeFilename = nodePath.basename(relativePath).replace(/["\\]/g, '_');
    const boundary = `----HermitStash${b.crypto.generateToken(16)}`;

    const relPathPart = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="relativePath"\r\n\r\n` +
      `${relativePath}\r\n`
    );
    const fileHeader = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${safeFilename}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    );
    const fileFooter = Buffer.from(`\r\n--${boundary}--\r\n`);
    const contentLength = relPathPart.length + fileHeader.length + stat.size + fileFooter.length;

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('POST', `/drop/file/${bundleId}`, {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': contentLength,
      });

      const mod = this._isHttps ? nodeHttps : nodeHttp;

      // Source read stream + throttle transform. Created up front so the
      // shared cleanup() closure below can tear them down on any failure
      // path. When uploadBytesPerSec is 0 (default) the Transform is a
      // pass-through and adds no overhead.
      const fileStream = nodeFs.createReadStream(fsPath);
      const throttled = fileStream.pipe(this._throttleTransform(this._uploadLimiter));

      // Idempotent source teardown. Without it, a request error or timeout
      // leaves the read stream's file descriptor open — on a long-running
      // daemon that accumulates toward EMFILE, and on Windows it keeps the
      // source file handle live. destroy() is a no-op once a stream is
      // already destroyed, so re-entry (req.destroy re-emits 'error') is safe.
      const cleanupSrc = () => {
        try { fileStream.destroy(); } catch {}
        try { throttled.destroy(); } catch {}
      };

      const req = mod.request(reqOpts, res => {
        this._extractCookie(res.headers);
        let body = '';
        res.on('data', chunk => { if (body.length < DOWNLOAD_ERR_BODY_CAP) body += chunk; });
        // res does not forward source errors, so a mid-response socket reset
        // (TLS teardown / peer RST during the response phase) would otherwise
        // escape as an uncaughtException and crash the daemon. Reject instead
        // and release the source fd.
        res.on('error', err => {
          cleanupSrc();
          reject(new Error(`Upload response read failed: ${err.message}`));
        });
        res.on('end', () => {
          if (res.statusCode !== 200 && res.statusCode !== 201) {
            const upErr = new Error(`Upload failed: HTTP ${res.statusCode} — ${body}`);
            upErr.statusCode = res.statusCode;
            // A 4xx (other than 408 Request Timeout / 429 Too Many Requests)
            // is a caller error the server will reject again on every retry —
            // mark it permanent so the sync engine refuses the retry and does
            // not spend circuit-breaker budget on a file that can never land.
            // 5xx and 408/429 stay retryable (transient server-side pressure).
            upErr.permanent = res.statusCode >= 400 && res.statusCode < 500 &&
              res.statusCode !== 408 && res.statusCode !== 429;                   // allow:raw-byte-literal — HTTP 408/429 status codes
            reject(upErr);
            return;
          }
          var parsed;
          try {
            parsed = b.safeJson.parse(body, { maxBytes: RESPONSE_JSON_MAX_BYTES });
          } catch (err) {
            reject(new Error(`Upload response parse error: ${err.message}`));
            return;
          }
          resolve(parsed);
        });
      });

      req.on('error', err => { cleanupSrc(); reject(err); });
      req.setTimeout(C.TIME.seconds(30), () => {
        cleanupSrc();
        req.destroy(new Error('Request timeout'));
      });

      req.write(relPathPart);
      req.write(fileHeader);

      fileStream.on('error', err => { cleanupSrc(); req.destroy(err); });
      throttled.on('error', err => { cleanupSrc(); req.destroy(err); });
      throttled.on('end', () => {
        req.write(fileFooter);
        req.end();
      });
      throttled.pipe(req, { end: false });
    });
  }

  /**
   * Download a file by server file ID.
   * Downloads are NOT encrypted by api-encrypt (streamed binary, not JSON).
   *
   * The inbound body is bounded two ways so a hostile or misbehaving server
   * can't fill the disk before the post-download checksum runs:
   *   1. A Content-Length preflight refuses to open the temp fd when the
   *      server declares a body larger than the ceiling.
   *   2. A counting Transform aborts the request + write stream the instant
   *      the cumulative byte count crosses the ceiling, then unlinks the
   *      partial temp — bytes never accumulate past the cap on disk.
   * The ceiling is min(MAX_SYNC_FILE_BYTES, expectedSize) when the server
   * declared a size, else MAX_SYNC_FILE_BYTES — the same per-file constant
   * the upload/checksum path uses, so one limit bounds both directions.
   */
  async downloadFile(fileId, destPath, expectedChecksum, expectedSize) {
    // longPath() is a no-op on POSIX + short paths; only long Windows
    // absolutes get the `\\?\` prefix.
    const dir = longPath(nodePath.dirname(destPath));
    nodeFs.mkdirSync(dir, { recursive: true });
    const tmpPath = longPath(destPath + '.tmp.' + b.crypto.generateToken(4));
    const dstPath = longPath(destPath);

    // Total-byte ceiling for this transfer. When the server told us the
    // size, clamp to it so a server that under-declares can't stream more
    // than it promised; otherwise fall back to the per-file cap.
    const wantedSize = (typeof expectedSize === 'number' && expectedSize > 0) ? expectedSize : 0;
    const byteCeiling = wantedSize > 0 ? Math.min(MAX_SYNC_FILE_BYTES, wantedSize) : MAX_SYNC_FILE_BYTES;

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('GET', `/files/${fileId}/download`);

      // Set when the in-stream counter trips the byte ceiling. Lifted to the
      // executor scope so the req/ws error handlers below (which fire after
      // the abort) reject with the real cap message rather than the generic
      // socket-abort error the destroy() produces.
      let overflowErr = null;

      const mod = this._isHttps ? nodeHttps : nodeHttp;
      const req = mod.request(reqOpts, res => {
        if (res.statusCode !== 200) {
          let body = '';
          res.on('data', c => { if (body.length < DOWNLOAD_ERR_BODY_CAP) body += c; });
          res.on('end', () => reject(new Error(`Download failed: HTTP ${res.statusCode} — ${body}`)));
          // res does not forward source errors, so a socket reset while
          // collecting the error body would otherwise escape as an
          // uncaughtException. No write stream is open in this branch yet —
          // the tmpPath unlink is defensive and harmless if absent.
          res.on('error', err => {
            try { nodeFs.unlinkSync(tmpPath); } catch {}
            reject(err);
          });
          return;
        }

        // Content-Length preflight: if the server declares a body larger
        // than the ceiling, refuse BEFORE opening the temp fd — no partial
        // bytes ever touch disk for an over-sized declared body. A server
        // that lies (declares small, streams large) is still stopped by the
        // counting Transform below.
        const declared = parseInt(res.headers['content-length'], 10);
        if (Number.isFinite(declared) && declared > byteCeiling) {
          req.destroy();
          reject(new Error(
            `Server declared ${declared} bytes for ${destPath}, over the ${byteCeiling}-byte size limit — refusing. ` +
            `Raise HERMITSTASH_MAX_FILE_BYTES if this file is legitimately that large.`
          ));
          return;
        }

        // O_EXCL refuses to open an existing sibling at the predictable
        // tmpPath, turning an attacker pre-plant into an EEXIST failure
        // (the 32-bit random suffix makes a benign collision practically
        // impossible). O_NOFOLLOW rejects a symlink final component on
        // POSIX; it is a no-op on Windows via `|| 0`.
        const ws = nodeFs.createWriteStream(tmpPath, {
          mode: 0o600,
          flags: nodeFs.constants.O_WRONLY | nodeFs.constants.O_CREAT |
                 nodeFs.constants.O_EXCL | (nodeFs.constants.O_NOFOLLOW || 0),
        });
        const hash = nodeCrypto.createHash('sha3-512');

        // Counting gate between the response and the write stream. It hashes
        // every chunk in flight and aborts the moment the cumulative count
        // crosses the ceiling — tearing down the request socket and the
        // write stream and unlinking the partial temp so an over-long body
        // can't keep landing on disk while the post-download checksum waits
        // for an 'end' that a hostile server never sends.
        let received = 0;
        // overflowErr (declared in the executor scope above) is set here when
        // the counter trips the ceiling. Aborting the request makes the
        // socket emit a generic 'aborted'/'ECONNRESET' that would otherwise
        // win the reject race and mask the real cause, so every error handler
        // prefers this captured error when present.
        const counter = new Transform({
          transform(chunk, _enc, cb) {
            if (overflowErr) { cb(); return; }
            received += chunk.length;
            if (received > byteCeiling) {
              overflowErr = new Error(
                `Server sent more than the ${byteCeiling}-byte size limit for ${destPath} — refusing. ` +
                `Raise HERMITSTASH_MAX_FILE_BYTES if this file is legitimately that large.`
              );
              // Abort the source request so the server stops sending, then
              // fail the write stream so its 'error' branch unlinks the temp.
              try { req.destroy(); } catch {}
              cb(overflowErr);
              return;
            }
            hash.update(chunk);
            cb(null, chunk);
          },
        });

        const throttled = counter.pipe(this._throttleTransform(this._downloadLimiter));
        res.pipe(counter);
        throttled.pipe(ws);
        // A counter overflow surfaces as an 'error' on the counter — destroy
        // the write stream (its 'error' handler unlinks the temp) and reject
        // with the actionable cap message.
        counter.on('error', err => { ws.destroy(overflowErr || err); });
        throttled.on('error', err => { ws.destroy(overflowErr || err); });
        // res.pipe() does not forward source errors downstream, so a mid-stream
        // response abort (socket reset / TLS teardown) would otherwise leave the
        // write stream + fd open, the partial temp file unremoved, and this
        // Promise unsettled. Handle it explicitly.
        res.on('error', err => {
          try { ws.destroy(); } catch {}
          try { nodeFs.unlinkSync(tmpPath); } catch {}
          reject(overflowErr || err);
        });

        ws.on('finish', async () => {
          try {
            if (expectedChecksum) {
              const downloadedChecksum = hash.digest('hex');
              if (downloadedChecksum !== expectedChecksum) {
                try { nodeFs.unlinkSync(tmpPath); } catch {}
                reject(new Error(
                  `Checksum mismatch: expected ${expectedChecksum.slice(0, 16)}... got ${downloadedChecksum.slice(0, 16)}...`
                ));
                return;
              }
            }
            // Flush the verified bytes to disk before the rename, then flush
            // the directory entry after it, so a crash can't leave the final
            // path pointing at an unsynced inode. All fsync calls are best-
            // effort (Windows rejects directory fsync, some FUSE mounts no-op
            // file fsync) and never fail an otherwise-good download.
            try {
              const fd = nodeFs.openSync(tmpPath, 'r+');
              try { b.atomicFile.fsync(fd); } finally { try { nodeFs.closeSync(fd); } catch {} }
            } catch {}
            // The destination often lives in a Dropbox/OneDrive-synced folder
            // where a sync agent can briefly lock the target; retry the swap
            // on transient Windows lock codes before giving up.
            await renameWithLockRetry(tmpPath, dstPath);
            try { b.atomicFile.fsyncDir(dir); } catch {}
            resolve(destPath);
          } catch (err) {
            // Rename never landed — drop the temp so a failed download doesn't
            // leave an orphan, matching the other failure branches. The error
            // names the path and points at the recovery command.
            try { nodeFs.unlinkSync(tmpPath); } catch {}
            if (err && RENAME_LOCK_CODES.has(err.code)) {
              reject(new Error(
                `Could not write ${destPath}: ${err.code} (file locked by another process). ` +
                `Close any app holding it open and run \`hermitstash-sync resync\` if it persists.`
              ));
              return;
            }
            reject(err);
          }
        });

        ws.on('error', err => {
          try { nodeFs.unlinkSync(tmpPath); } catch {}
          reject(overflowErr || err);
        });
      });

      req.on('error', err => {
        try { nodeFs.unlinkSync(tmpPath); } catch {}
        reject(overflowErr || err);
      });

      req.setTimeout(C.TIME.seconds(30), () => { req.destroy(new Error('Request timeout')); });
      req.end();
    });
  }

  /**
   * Delete a file from a sync bundle.
   */
  async deleteFile(fileId) {
    const resp = await this._jsonRequest('DELETE', `/files/${fileId}`);
    if (resp.statusCode !== 200 && resp.statusCode !== 204) {
      throw new Error(`Delete failed: HTTP ${resp.statusCode}`);
    }
  }

  /**
   * Rename/move a file within a sync bundle (metadata-only, no re-upload).
   *
   * Server v1.9.15+ routes POST /sync/rename through blamejs apiEncrypt
   * (per-session PQC envelope with strict-monotonic counter for replay
   * defence). Body + response are wrapped/decrypted by `b.httpClient.
   * encrypted` against the server's published hybrid keypair.
   */
  async renameFile(bundleId, oldRelativePath, newRelativePath) {
    const resp = await this._encryptedRequest('POST', '/sync/rename', {
      bundleId, oldRelativePath, newRelativePath,
    });
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      // In passthrough mode a non-2xx response resolves with its decrypted
      // body. Read the RFC 9457 problem-details `.detail`, falling back to the
      // pre-v1.10.1 `.error` shape for older servers.
      const detail = resp.body && (resp.body.detail || resp.body.error);
      throw new Error(detail || `Rename failed: HTTP ${resp.statusCode}`);
    }
    return resp.body || {};
  }

  /**
   * Health check (before api-encrypt middleware — plain JSON).
   */
  async healthCheck() {
    const resp = await this._rawRequest('GET', '/health');
    return resp.statusCode === 200;
  }

  /**
   * Request a new mTLS client certificate from the server. Authenticated via
   * Bearer API key + the CURRENT mTLS cert (presented at TLS handshake). The
   * route is registered before api-encrypt in the server, so the response is
   * plain JSON — no ECIES session required.
   *
   * Caller is expected to persist the returned PEMs to disk and call
   * reloadMtlsCerts() on this client so the next request uses the fresh cert.
   *
   * @returns {Promise<{clientCert: string, clientKey: string, caCert: string, expiresAt: string, issuedAt: string}>}
   */
  async renewCert() {
    const resp = await this._rawRequest('POST', '/sync/renew-cert', '{}', {
      'Content-Type': 'application/json',
      'Content-Length': '2',
    });
    let data;
    try { data = b.safeJson.parse(resp.body, { maxBytes: RESPONSE_JSON_MAX_BYTES }); }
    catch (_e) { throw new Error(`Invalid JSON from /sync/renew-cert (HTTP ${resp.statusCode})`); }
    if (resp.statusCode !== 200 || !data.success) {
      throw new Error(data.detail || data.error || `Renewal failed with HTTP ${resp.statusCode}`);
    }
    return data;
  }

  /**
   * Lazily fetch the server's published blamejs hybrid keypair from
   * `/.well-known/blamejs-pubkey` and build a `b.httpClient.encrypted`
   * instance bound to it. Cached on the HttpClient — pubkey + per-
   * session counter survive across multiple encrypted requests so the
   * server can apply strict-monotonic replay defence.
   *
   * The bootstrap promise is memoized (`_encClientPromise`) so concurrent
   * first-time callers share one pubkey fetch and one client instead of
   * racing two sessions. A failed bootstrap clears the memo so the next
   * call retries rather than re-throwing a cached rejection forever.
   *
   * The wrapper returned by `b.httpClient.encrypted(...)` exposes only
   * `request()` — it does NOT surface a session-reset method. To recover
   * from server-side session loss (a `401 session-expired` after a server
   * restart, or a client-side counter mismatch), null `this._encClient`
   * (and `this._encClientPromise`) so the next call rebuilds a fresh
   * session with a new key and a reset counter. `_encryptedRequest` does
   * this transparently and retries once.
   */
  _getEncClient() {
    if (this._encClient) return Promise.resolve(this._encClient);
    if (this._encClientPromise) return this._encClientPromise;

    this._encClientPromise = (async () => {
      const pubResp = await this._jsonRequest('GET', '/.well-known/blamejs-pubkey', null, {
        'Accept': 'application/json',
      });
      if (pubResp.statusCode !== 200 || !pubResp.json) {
        throw new Error('Failed to fetch /.well-known/blamejs-pubkey: HTTP ' + pubResp.statusCode);
      }
      this._encPubkey = pubResp.json;

      const baseUrl = this._serverUrl.protocol + '//' + this._serverUrl.host;
      this._encClient = b.httpClient.encrypted({
        pubkey:  this._encPubkey,
        baseUrl: baseUrl,
        headers: { Authorization: 'Bearer ' + this._apiKey },
        keying:  'per-session',
      });
      return this._encClient;
    })();

    // On failure, clear the memo so a later request rebuilds rather than
    // re-throwing the cached rejection for the daemon's lifetime.
    this._encClientPromise.catch(() => { this._encClientPromise = null; });
    return this._encClientPromise;
  }

  // Drop the cached encrypted client so the next _getEncClient() re-fetches
  // the pubkey and opens a fresh per-session counter. Nulls the in-flight
  // bootstrap memo too — clearing only _encClient would leave a stale
  // promise that resolves to the dead client.
  _resetEncClient() {
    this._encClient = null;
    this._encClientPromise = null;
  }

  /**
   * Encrypted JSON request via blamejs apiEncrypt. Body is wrapped in
   * the per-session envelope (`_ek/_ct/_ts/_nonce` on first call,
   * `_sid/_ctr/_ct` thereafter); response is auto-decrypted. Used for
   * server routes opted into blamejs scope (POST /drop/init, POST
   * /drop/finalize/:bundleId, POST /sync/rename as of v1.9.15).
   *
   * Requests are serialized through a single-slot promise chain so at most
   * one is in flight against the shared per-session client at a time. The
   * per-session protocol uses strictly-monotonic request/response counters;
   * concurrent callers would interleave and trip the client-side replay
   * check (`CLIENT_RESPONSE_REPLAY`). These are low-volume metadata ops, so
   * serializing costs nothing and keeps the counters in lockstep.
   *
   * If the server lost the session (expiry / max-responses / restart) it
   * answers `401` with a `session-*` body, or the client surfaces a sid/ctr
   * mismatch — in either case the cached client holds a dead session and
   * every future request would fail. Detect that, rebuild a fresh session,
   * and retry once.
   */
  _encryptedRequest(method, urlPath, bodyData) {
    const run = () => this._encryptedRequestOnce(method, urlPath, bodyData, false);
    // Tail-promise lock: chain off the previous request's settlement (success
    // or failure) so only one encrypted request touches the session at once.
    const result = this._encChain.then(run, run);
    this._encChain = result.then(() => {}, () => {});
    return result;
  }

  async _encryptedRequestOnce(method, urlPath, bodyData, retried) {
    const enc = await this._getEncClient();
    let resp;
    try {
      resp = await enc.request({
        method:        method,
        path:          urlPath,
        body:          bodyData,
        agent:         this._agent,
        allowInternal: true,
        timeoutMs:     C.TIME.seconds(30),
        maxResponseBytes: RESPONSE_JSON_MAX_BYTES,
        // Resolve on non-2xx so the encrypted problem-details body can be
        // decrypted and read. Server v1.11.28+ encrypts error responses on
        // this per-session route; without passthrough the wrapper would reject
        // on the raw ciphertext before the decrypt step and the detail is lost.
        responseMode:  'passthrough',
      });
    } catch (err) {
      // A server that silently re-keyed surfaces as a client-side sid/ctr
      // mismatch rather than a 401. Treat those as session loss: rebuild and
      // retry once. Any other throw (network, decrypt, malformed) propagates.
      if (!retried && err &&
          (err.code === 'CLIENT_RESPONSE_SID' || err.code === 'CLIENT_RESPONSE_REPLAY')) {
        this._resetEncClient();
        return this._encryptedRequestOnce(method, urlPath, bodyData, true);
      }
      throw err;
    }

    // Session torn down server-side (expiry / max-responses / restart). The
    // cached client still holds the dead _sid plus a bumped counter, so every
    // future request would fail the same way. Rebuild and retry once.
    if (!retried && resp.statusCode === 401) {                                   // allow:raw-byte-literal — HTTP 401 status code
      const code = resp.body && (resp.body.error || resp.body.detail);
      if (code === 'session-unknown' || code === 'session-expired' ||
          code === 'session-rotation-required') {
        this._resetEncClient();
        return this._encryptedRequestOnce(method, urlPath, bodyData, true);
      }
    }
    return resp;
  }

  /**
   * JSON request. Sends body as plain JSON, parses response as plain JSON.
   *
   * Server v1.9.15+ short-circuits the legacy `_e/_t` payload-encryption
   * envelope for Bearer-authed sync clients (`if (req.apiKey) return next()`
   * in `middleware/api-encrypt.js`). Application-layer encryption was
   * always dead-end ciphertext for the sync client — production never
   * performed the ECIES handshake on `/drop/init`, so every prior
   * encrypted response was undecryptable. Transport security comes from
   * the PQC TLS 1.3 + mTLS posture pinned in `lib/pqc-agent.js`; the
   * Bearer API key + client cert are the application-auth surface.
   *
   * Returns { statusCode, headers, body, json } where `json` is the
   * parsed body or null if not valid JSON.
   */
  async _jsonRequest(method, urlPath, bodyData, extraHeaders) {
    var headers = extraHeaders || {};
    var bodyStr;
    if (bodyData !== undefined && bodyData !== null) {
      headers['Content-Type'] = 'application/json';
      bodyStr = JSON.stringify(bodyData);
    }

    var resp = await this._rawRequest(method, urlPath, bodyStr, headers);
    resp.json = _safeParseJson(resp.body);
    return resp;
  }

  // --- Transport internals ---

  _extractCookie(headers) {
    if (!headers || !headers['set-cookie']) return;
    var cookies = Array.isArray(headers['set-cookie'])
      ? headers['set-cookie'] : [headers['set-cookie']];
    for (var c of cookies) {
      if (c.startsWith('hs_sid=')) {
        this._sessionCookie = c.split(';')[0];
      }
    }
  }

  _reqOpts(method, urlPath, extraHeaders = {}) {
    var headers = {
      'Authorization':   `Bearer ${this._apiKey}`,
      'User-Agent':      `hermitstash-sync/${VERSION}`,
      // Content-negotiation + Fetch-metadata hints. These are accurate
      // descriptions of what the sync client is doing (CORS-style API
      // requests, no preferred locale), not browser fingerprint lies.
      // HermitStash's bot-guard middleware checks both for GETs —
      // without them, page-shaped routes (e.g. /b/:shareId with Accept
      // JSON) get classified as scraper traffic and 403'd.
      'Accept-Language': 'en-US,en;q=0.9',
      'Sec-Fetch-Mode':  'cors',
      'Sec-Fetch-Dest':  'empty',
      ...extraHeaders,
    };
    if (this._sessionCookie) headers['Cookie'] = this._sessionCookie;
    return {
      hostname: this._serverUrl.hostname,
      port: this._serverUrl.port || (this._isHttps ? 443 : 80), // allow:raw-byte-literal — IANA HTTPS/HTTP default ports
      path: urlPath,
      method,
      agent: this._agent,
      headers,
    };
  }

  /**
   * Small-body JSON / control-plane HTTP request — routed through
   * blamejs `b.httpClient.request()` so it inherits the framework's
   * SSRF guard with DNS pinning (closes the resolution-vs-connect
   * TOCTOU window), AbortSignal-aware cancellation, idle vs wall-clock
   * timeout split, permanent-vs-transient error classification, and
   * safeUrl scheme validation. Streaming bodies (multipart upload,
   * binary download) keep the raw `https.request` path because
   * b.httpClient builds multipart fully in memory.
   */
  async _rawRequest(method, urlPath, body, extraHeaders) {
    var headers = Object.assign({
      'Authorization':   `Bearer ${this._apiKey}`,
      'User-Agent':      `hermitstash-sync/${VERSION}`,
      'Accept-Language': 'en-US,en;q=0.9',
      'Sec-Fetch-Mode':  'cors',
      'Sec-Fetch-Dest':  'empty',
    }, extraHeaders || {});
    if (this._sessionCookie) headers['Cookie'] = this._sessionCookie;

    var url = `${this._serverUrl.protocol}//${this._serverUrl.host}${urlPath}`;

    try {
      var resp = await b.httpClient.request({
        url:           url,
        method:        method,
        headers:       headers,
        body:          body ? Buffer.from(body) : undefined,
        agent:         this._agent,            // mTLS + PQC + keepAlive
        // Allow loopback / private IPs — the user explicitly configured this
        // server URL, so blamejs's default SSRF gate (which would block
        // 127.0.0.1, 10.x, etc.) doesn't apply. The gate's value here is
        // closing the DNS-rebinding TOCTOU window on the resolved host.
        allowInternal: true,
        timeoutMs:     C.TIME.seconds(30),
        // 16 MiB cap on response body — sized for the largest envelope a
        // sync bundle metadata response could plausibly carry.
        maxResponseBytes: RESPONSE_JSON_MAX_BYTES,
        // Pass an errorClass so 4xx/5xx surface as `err.statusCode` directly.
        // Without this opt blamejs returns a bare FrameworkError that drops
        // the status code on the floor.
        errorClass:    HermitStashHttpError,
      });
      this._extractCookie(resp.headers);
      return {
        statusCode: resp.statusCode,
        headers:    resp.headers,
        body:       Buffer.isBuffer(resp.body) ? resp.body.toString('utf8') : String(resp.body || ''),
      };
    } catch (err) {
      // 4xx/5xx now arrive as HermitStashHttpError with a structured
      // statusCode property — translate to the legacy { statusCode, body }
      // contract so callers can keep asserting on resp.statusCode. The
      // message tail is "HTTP <N>: <body slice>" (vendor http-client
      // line 1164).
      if (err && err instanceof HermitStashHttpError && err.statusCode) {
        const msg = err.message || '';
        const headerPrefix = 'HTTP ' + err.statusCode + ': ';
        const body = msg.startsWith(headerPrefix) ? msg.slice(headerPrefix.length) : '';
        return { statusCode: err.statusCode, headers: {}, body: body };
      }
      throw err;
    }
  }

  destroy() {
    this._agent.destroy();
  }
}

module.exports = HttpClient;
module.exports.buildTlsOptions = buildTlsOptions;
module.exports.buildCaBundle = _buildCaBundle;
module.exports.buildCheckServerIdentity = _buildCheckServerIdentity;
module.exports.collectTextBody = collectTextBody;
module.exports.assertNegotiatedGroupPqc = assertNegotiatedGroupPqc;
