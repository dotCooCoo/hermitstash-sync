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
// Hostname-level loopback classification is shared with config.validate()'s
// plaintext-http refusal gate (single home in lib/config.js) so the plaintext
// WARN in the constructor and the config-load refusal can never drift on
// which hosts count as loopback. No require cycle: config depends only on
// constants/path-filter/blamejs.
const { isLoopbackHost: _isLoopbackHost } = require('./config');
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

// Timeouts for the per-session encrypted metadata routes (/sync/rename,
// /drop/init, /drop/finalize). The encrypted wrapper forwards BOTH idleTimeoutMs
// (a zero-progress cap) AND timeoutMs (the overall wall-clock cap) to the base
// request, which turns timeoutMs into an AbortSignal that tears the socket down
// on expiry — so a trickling peer can neither hang the call past the ceiling nor
// leave an orphaned socket holding a slot in the keepAlive pool while the
// serialized _encChain queue waits behind it. These are low-volume metadata ops,
// so a tight wall-clock ceiling is fine.
const ENC_IDLE_TIMEOUT_MS = C.TIME.seconds(30);
const ENC_WALL_CLOCK_TIMEOUT_MS = C.TIME.seconds(60);

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
//
// Returns `true` when it destroyed/blocked the socket (an enforced classical
// downgrade with the opt-out unset) and `false` otherwise (at-floor, allowed-
// classical, observe-only, or an unreadable socket). The WebSocket control
// channel branches on this return value so it never emits 'open' on a socket
// this function just tore down — and so it does not have to read b.wsClient's
// private `_socket.destroyed` field to detect the hard-fail.
function assertNegotiatedGroupPqc(socket, host, opts) {
  opts = opts || {};
  const enforce = opts.enforce !== false;
  if (!socket || typeof socket.getEphemeralKeyInfo !== 'function') return false;
  let info;
  try { info = socket.getEphemeralKeyInfo() || {}; }
  catch { return false; }   // best-effort — a closed socket can't report; nothing to assert
  const group = info.name;
  if (!group || /MLKEM/i.test(group)) return false;   // hybrid (or unreported) — at the floor

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
    return true;
  }
  return false;
}


// Coerce a configured byte-rate to a safe non-negative integer. Deliberately
// NOT bitwise `| 0` (ToInt32 truncation wraps values >= 2^31 to negative and
// silently voids a large validated throttle). 0 / undefined / non-finite => 0
// (unlimited), matching the prior default behaviour for the common case.
function _coerceRate(v) {
  const n = Math.trunc(Number(v));
  return Number.isFinite(n) && n > 0 ? n : 0;
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
    // Refuse a symlink at the operator-pointed CA-bundle path so an attacker
    // who can write the parent dir can't redirect the trust-root read at an
    // attacker-chosen file. No inodeCheck — NODE_EXTRA_CA_CERTS is an arbitrary
    // operator-supplied path, not a CONFIG_DIR-owned secret, so symlink refusal
    // plus the inode-bound fd is the right posture without demanding a prior lstat
    // inode match. A missing file or a refused symlink is non-fatal here: the
    // operator chose this path and a broken value just means no extra roots get
    // appended (same outcome as before, surfacing is the operator's job).
    try {
      out.push(b.atomicFile.fdSafeReadSync(extra, {
        refuseSymlink: true,
        maxBytes:      b.constants.BYTES.mib(1),
        encoding:      'utf8',
      }));
    } catch { /* allow:silent-catch — env-var points at a missing file or a symlink; the user explicitly chose this path, surfacing is the operator's job */ }
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
    // The mTLS trio (cert, the 0o600 private key, CA) lives in CONFIG_DIR's
    // certs/ dir and is written exclusively via b.atomicFile.writeSync, so a
    // symlink at any of these paths is never legitimate — it is exactly the
    // swap an attacker with parent-dir write plants to point the secret read
    // at a victim file. Read each through fdSafeReadSync with refuseSymlink +
    // inodeCheck so the bytes bind to the inode the lstat saw (no TOCTOU re-
    // stat, no symlink follow), matching the keychain credentials-file read.
    // No encoding → returns a Buffer, byte-compatible with the TLS layer.
    const load = v => (typeof v === 'string'
      ? b.atomicFile.fdSafeReadSync(v, {
          refuseSymlink: true,
          inodeCheck:    true,
          maxBytes:      b.constants.BYTES.mib(1),
          errorFor: (kind) => new Error(
            'mTLS material at ' + v + ' could not be read safely (' + kind + ') — ' +
            'remove it and re-enroll with "hermitstash-sync init"'
          ),
        })
      : v);
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
// pin defends against. Accepts a node:crypto X509Certificate, a DER
// Buffer, or the `{raw}` cert object Node hands to checkServerIdentity.
// Single home for the pin derivation: the config.pinnedServerSpki
// verification below and the diagnose bundle's cert-info both depend on
// it, and a drift in either copy (digest, export type, encoding) would
// mint pins the other side never matches — per the README workflow the
// operator copies one side's output into the other side's config.
function spkiPin(certLike) {
  try {
    // Normalize to the DER bytes b.crypto.spkiPin accepts (a DER Buffer or PEM
    // string). Node's X509Certificate and the `{raw}` cert object Node hands
    // checkServerIdentity both expose the certificate DER on `.raw`.
    let der;
    if (certLike instanceof nodeCrypto.X509Certificate) der = certLike.raw;
    else if (Buffer.isBuffer(certLike)) der = certLike;
    else if (certLike && certLike.raw) der = certLike.raw;
    else return null;
    // b.crypto.spkiPin (blamejs v0.17.13+) derives the identical RFC 7469 pin —
    // base64(SHA-256(SubjectPublicKeyInfo DER)) with the 'sha256/' prefix — and
    // returns { sha256, b64, hex }. Return the bare .sha256 string the
    // pin-verify + diagnose call sites expect (byte-identical to the previous
    // hand-rolled derivation, so a configured pinnedServerSpki still matches).
    // The primitive THROWS on a cert it can't parse where the old hand-roll
    // returned null, so the surrounding try preserves the null-on-failure contract.
    return b.crypto.spkiPin(der).sha256;
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
    const observed = spkiPin(cert);
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
 * string on 'end', rejects (and destroys the stream) the moment a chunk would
 * overflow the BYTE cap. Use only for JSON/text endpoints — binary downloads
 * must stream (see downloadFile).
 *
 * Thin wrapper around b.safeBuffer.collectStream so the cap is a true UTF-8
 * byte ceiling: a hand-rolled `body.length` cap counts UTF-16 code units (the
 * real ceiling inflates to ~4x for multibyte content) and overshoots by one
 * chunk because the guard runs before the append. collectStream enforces the
 * cap at every chunk and destroys the stream on overflow.
 */
function collectTextBody(res, maxBytes = DOWNLOAD_ERR_BODY_CAP) {
  return b.safeBuffer.collectStream(res, { maxBytes }).then(buf => buf.toString('utf8'));
}

// Errno codes a Windows file lock surfaces when another process (Dropbox /
// OneDrive sync agent, indexer, anti-virus on-access scanner) holds the
// destination open while we try to swap the freshly-downloaded temp into
// place. On POSIX these are rare and the loop simply succeeds first try.
const RENAME_LOCK_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

// The temp→final download rename routes through b.atomicFile.renameWithRetry,
// which rides out the same transient Windows / Dropbox lock codes on the same
// bounded backoff this module used to hand-roll. RENAME_LOCK_CODES (above) is
// still used to classify the final error for the operator-facing
// "file locked by another process" message.

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

    // Defense-in-depth on the "no plaintext on the wire" floor. config.validate()
    // fails the daemon closed on a non-loopback http:// server, but a direct
    // HttpClient caller (enrollment tooling, tests) can bypass that gate. Surface
    // a loud WARN whenever a plaintext transport is selected against a
    // non-loopback host so the absent TLS/mTLS + post-quantum protection is never
    // silent. Loopback (sidecar/dev/test) stays quiet; this does NOT throw, so a
    // deliberate cleartext caller still works while being told what it gave up.
    if (!this._isHttps && !_isLoopbackHost(this._serverUrl.hostname)) {
      log.warn(
        'server URL uses plaintext http://' + this._serverUrl.hostname +
        ' — the API key and all sync traffic are UNENCRYPTED and the post-quantum ' +
        'TLS floor (mTLS + ML-KEM hybrid groups) is not in effect. Use https:// unless ' +
        'you deliberately terminate TLS at a trusted loopback proxy.',
        { host: this._serverUrl.hostname }
      );
    }

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

    // Effective per-file byte ceiling. config.maxFileSize (0 = unlimited) lets an
    // operator LOWER the cap below the process-wide MAX_SYNC_FILE_BYTES memory-
    // safety ceiling; it can only tighten, never raise it (Math.min). 0 / unset /
    // invalid falls back to MAX_SYNC_FILE_BYTES so the env-driven default
    // (HERMITSTASH_MAX_FILE_BYTES) stays authoritative when config.json sets no
    // cap. Enforced at the wire boundary in uploadFile()/downloadFile().
    const cfgMax = Math.trunc(Number(config.maxFileSize));
    this._maxFileBytes = (Number.isFinite(cfgMax) && cfgMax > 0)
      ? Math.min(cfgMax, MAX_SYNC_FILE_BYTES)
      : MAX_SYNC_FILE_BYTES;

    // Shared bandwidth limiters — one bucket per direction so N
    // concurrent uploads (or downloads) share the configured budget
    // instead of each getting the full rate. `0` = unlimited (passes
    // through via PassThrough). Operators set uploadBytesPerSec /
    // downloadBytesPerSec in config.json. b.streamThrottle rejects
    // bytesPerSec <= 0, so guard at construction.
    //
    // NOT bitwise `| 0`: ToInt32 wraps any value >= 2^31 to a negative number,
    // so a large operator-validated cap (e.g. a 3 GB/s LAN limit that validate()
    // accepts across the full 2^53 integer domain) would wrap negative and
    // silently DISABLE the throttle. Math.trunc(Number(v)) keeps the full domain;
    // the `> 0` guard below maps 0 / unset / non-finite to unlimited unchanged.
    const ulRate = _coerceRate(config.uploadBytesPerSec);
    const dlRate = _coerceRate(config.downloadBytesPerSec);
    this._uploadLimiter   = ulRate > 0 ? b.streamThrottle.create({ bytesPerSec: ulRate }) : null;
    this._downloadLimiter = dlRate > 0 ? b.streamThrottle.create({ bytesPerSec: dlRate }) : null;
    // Remember the per-direction throttle rates so the transfer sites can
    // scale their socket-inactivity timeout when a throttle is configured —
    // a slow-but-progressing throttled transfer must not be aborted while a
    // single chunk's throttle-wait legitimately exceeds the base 30s idle
    // window. 0 = unlimited (no scaling).
    this._uploadBytesPerSec   = ulRate > 0 ? ulRate : 0;
    this._downloadBytesPerSec = dlRate > 0 ? dlRate : 0;
  }

  // Socket-inactivity timeout for a throttled transfer. With no throttle the
  // base 30s idle window applies unchanged. With a throttle configured, the
  // wait the limiter imposes on a single ~64 KiB read chunk can exceed 30s at
  // low rates; scale the window to that worst-case single-chunk wait plus the
  // base, so a genuinely stalled socket is still caught but a progressing
  // slow transfer is not killed mid-wait.
  _throttledIdleTimeout(bytesPerSec) {
    const base = C.TIME.seconds(30);
    if (!bytesPerSec || bytesPerSec <= 0) return base;
    const chunkBytes = C.BYTES.kib(64); // fs.createReadStream default highWaterMark
    // chunkBytes / bytesPerSec is the worst-case single-chunk throttle-wait in
    // seconds; C.TIME.seconds() lifts it to ms (accepts fractional seconds).
    const chunkWaitMs = Math.ceil(C.TIME.seconds(chunkBytes / bytesPerSec));
    return Math.max(base, chunkWaitMs + base);
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
      // NOTE: this `ca` bundle (system roots + NODE_EXTRA_CA_CERTS + the
      // enrollment mTLS CA) survives only because blamejs system-trust stays
      // OFF by default — if b.network.tls system-trust (STATE.cas /
      // setSystemTrust) were ever enabled, applyToContext would OVERWRITE
      // options.ca with its own set and drop the enrollment CA, breaking
      // validation for self-hosted servers whose leaf that CA signed. This
      // client never enables it; keep it that way (or pin the CA post-create).
      this._agent = b.pqcAgent.create({
        cert: this._tlsOpts.cert,
        key:  this._tlsOpts.key,
        ca:   this._tlsOpts.ca,
        keepAlive: true,
        maxSockets: 6,
        // ecdhCurve through create() so every group is validated against the
        // framework's known-groups table — a typo'd group throws a typed
        // pqc-agent error at construction instead of silently producing a
        // broken ClientHello. allowOperatorGroups keeps the trailing classical
        // X25519 accepted even if a future vendor bump re-narrows the default
        // preference to hybrids-only (without it that bump would throw here
        // and refuse to boot). minVersion TLSv1.3 is pinned by create().
        ecdhCurve: TLS_GROUPS,
        allowOperatorGroups: true,
      });
      // Belt-and-suspenders, do NOT remove: b.pqcAgent.create() now mirrors our
      // ecdhCurve into options.groups verbatim (blamejs v0.17.13+ — same string,
      // same order), so groups already equals TLS_GROUPS. We still re-assert it
      // explicitly because BOTH keys must be set (Node versions differ on which
      // one OpenSSL honours) and this keeps the advertised order byte-identical
      // to the server's group string even if a future vendor bump changes
      // create()'s mirroring.
      this._agent.options.groups = TLS_GROUPS;
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
      // Don't destroy the old agent on a FIXED timer while it still owns in-use
      // sockets. Streaming uploads/downloads run with NO wall-clock cap (only a
      // per-chunk idle timeout), and encrypted metadata calls can run up to 60s,
      // so a fixed 30s destroy would abort a healthy, still-progressing transfer
      // riding a pre-swap socket after a cert-renewal / CA-rotation rebuild.
      // Poll instead: close the old agent as soon as it has drained its in-use
      // sockets + queued requests, and unconditionally at a hard 10-minute cap
      // (the transfer stuck ceiling) so an idle old agent still closes promptly
      // and nothing leaks. Tick-counted (not wall-clock) so a clock jump can't
      // skew the cap.
      let ticks = 0;
      const maxTicks = Math.ceil(C.TIME.minutes(10) / AGENT_DRAIN_GRACE_MS);
      const drainOldAgent = () => {
        ticks += 1;
        let busy = false;
        try {
          const active = _oldAgent.sockets || {};
          const queued = _oldAgent.requests || {};
          busy = Object.keys(active).length > 0 || Object.keys(queued).length > 0;
        } catch (_e) { busy = false; }
        if (!busy || ticks >= maxTicks) {
          clearInterval(drainTimer);
          // allow:silent-catch — best-effort close of the drained prior agent
          try { _oldAgent.destroy(); } catch (_e2) {}
        }
      };
      const drainTimer = setInterval(drainOldAgent, AGENT_DRAIN_GRACE_MS);
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
    // Fail closed on a non-2xx. Returning resp.json blind would mask a 403
    // (bot-guard / wrong cert), a 404 (wrong shareId), a 409 (sync disabled),
    // or a 5xx as a successful empty bundle, because the caller collapses any
    // body lacking a `.files` array to "0 files." Mirror deleteFile /
    // renameFile / renewCert, which all throw on non-2xx. A legitimately
    // empty bundle still answers 200 with `files: []`, so this never trips on
    // a real empty bundle.
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      if (resp.statusCode === 401 || resp.statusCode === 403) {                  // allow:raw-byte-literal — HTTP 401/403 status codes
        throw new Error(
          `Bundle metadata request denied (HTTP ${resp.statusCode}) — the API key or mTLS cert was ` +
          `rejected for this bundle. Re-enroll with "hermitstash-sync init", and confirm the shareId ` +
          `matches a sync bundle you own.`);
      }
      // RFC 9457 problem-details `.detail`, falling back to the pre-v1.10.1
      // `.error` shape; resp.json may be null on a non-JSON error body.
      const detail = resp.json && (resp.json.detail || resp.json.error);
      throw new Error(detail || `Bundle metadata fetch failed: HTTP ${resp.statusCode}`);
    }
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
    // Open the source once and derive the size from THIS fd's fstat, then
    // stream the body from the same fd. Binding the declared Content-Length and
    // the streamed bytes to one inode snapshot closes the stat-vs-stream race:
    // the watcher path holds the per-path lock, but the initial-scan fan-out
    // does not, so a file still being written during the boot scan could
    // otherwise be framed with a stale length (a grown file overruns the
    // declared length and corrupts the next keepAlive request; a shrunk file
    // under-delivers and stalls until the idle timeout). A counting guard below
    // still aborts if the bytes actually streamed diverge from the fstat size.
    const srcFd = nodeFs.openSync(fsPath, 'r');
    let stat;
    try {
      stat = nodeFs.fstatSync(srcFd);
    } catch (err) {
      try { nodeFs.closeSync(srcFd); } catch {}
      throw err;
    }
    // Enforce the effective per-file ceiling at the wire boundary, from THIS
    // fd's fstat (bound to the same inode that streams below). config.maxFileSize
    // can lower this below the process default; 0 leaves the env/default
    // MAX_SYNC_FILE_BYTES in force. Marked permanent so the sync engine records
    // ERROR once instead of retrying a file that can never shrink under the cap.
    if (stat.size > this._maxFileBytes) {
      try { nodeFs.closeSync(srcFd); } catch {}
      const err = new Error(
        `Refusing to upload "${relativePath}": ${stat.size} bytes exceeds the ` +
        `${this._maxFileBytes}-byte per-file size limit. Raise maxFileSize in ` +
        `config.json (or HERMITSTASH_MAX_FILE_BYTES) if this file is legitimately that large.`
      );
      err.permanent = true;
      throw err;
    }
    // Refuse a path carrying a C0 control character (NUL / CR / LF / other byte
    // below 0x20). They are legal in POSIX filenames, but the raw relativePath
    // value and the derived filename are interpolated into the CRLF-delimited
    // multipart body below; an embedded CR/LF would let the value break out of
    // its part and reframe the structure the server parses (multipart-part
    // injection). Refused at this sink so no control-char path from any code
    // path can reach the framing. Marked permanent so the sync engine doesn't
    // retry a file that can never be framed safely; mirrors the server-path
    // control-character refusal.
    for (let ci = 0; ci < relativePath.length; ci++) {
      if (relativePath.charCodeAt(ci) < 0x20) {                                   // allow:raw-byte-literal — C0 control-character ceiling (0x20 = space), not a size
        try { nodeFs.closeSync(srcFd); } catch {}
        const err = new Error(`Refusing to upload "${relativePath}": path contains control characters`);
        err.permanent = true;
        throw err;
      }
    }
    const safeFilename = nodePath.basename(relativePath).replace(/["\\]/g, '_');
    const boundary = `----HermitStash${b.crypto.generateToken(16)}`;

    // Pin the connect to the SSRF-guard-validated address before building the
    // request — closes the DNS-rebind TOCTOU window the control-plane path
    // already closes. Resolved here (await) rather than inside _reqOpts because
    // the gate is async; servername stays the hostname so SNI + cert hostname
    // validation are unchanged. A guard refusal throws and fails the upload
    // closed (before the source fd is committed to a request).
    let pinnedLookup;
    try {
      pinnedLookup = await this._pinnedServerLookup();
    } catch (err) {
      try { nodeFs.closeSync(srcFd); } catch {}
      throw err;
    }

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
      if (pinnedLookup) reqOpts.lookup = pinnedLookup;

      const mod = this._isHttps ? nodeHttps : nodeHttp;

      // Declared body size came from this fd's fstat; the bytes streamed below
      // must match it exactly or the Content-Length is a lie. Track the running
      // count so a concurrent writer that grows or shrinks the file mid-stream
      // (possible on the unlocked initial-scan path) is caught instead of
      // overrunning the declared length (corrupting the next keepAlive request)
      // or under-delivering (stalling the peer until the idle timeout).
      const declaredBodySize = stat.size;
      let streamedBytes = 0;
      let lengthMismatchErr = null;

      // Source read stream bound to the already-open fd. autoClose is OFF so
      // cleanupSrc is the SOLE owner of srcFd: a stream's autoClose schedules an
      // async fs.close, and a synchronous closeSync in the same tick would race
      // it — the deferred close could land on a since-reused fd number and shut
      // an unrelated transfer's descriptor (spurious EBADF / corrupt transfer)
      // on a daemon running concurrent uploads/downloads. With autoClose off,
      // srcFd is closed exactly once, explicitly, on every terminal path.
      // Created up front so the shared cleanupSrc() closure below can tear them
      // down on any failure path. When uploadBytesPerSec is 0 (default) the
      // throttle Transform is a pass-through and adds no overhead.
      const fileStream = nodeFs.createReadStream(null, { fd: srcFd, autoClose: false });
      const lengthGuard = new Transform({
        transform(chunk, _enc, cb) {
          streamedBytes += chunk.length;
          if (streamedBytes > declaredBodySize) {
            // The file grew after the fstat. Stop before the extra bytes reach
            // the socket and poison the next pipelined request.
            lengthMismatchErr = new Error(
              `Upload aborted for "${relativePath}": file grew during upload ` +
              `(declared ${declaredBodySize} bytes, already read ${streamedBytes}) — ` +
              `it is still being written. The sync engine will retry once it settles.`
            );
            cb(lengthMismatchErr);
            return;
          }
          cb(null, chunk);
        },
      });
      const throttled = fileStream.pipe(lengthGuard).pipe(this._throttleTransform(this._uploadLimiter));

      // Idempotent source teardown. Without it, a request error or timeout
      // leaves the read stream's file descriptor open — on a long-running
      // daemon that accumulates toward EMFILE, and on Windows it keeps the
      // source file handle live. destroy() is a no-op once a stream is
      // already destroyed, so re-entry (req.destroy re-emits 'error') is safe.
      // srcFd is closed EXACTLY ONCE, guarded by this flag. cleanupSrc is
      // re-entrant — a fileStream/throttled 'error' calls it, then req.destroy
      // re-emits 'error' which calls it again — and several handlers can fire
      // on one teardown. Without the guard, a second closeSync would target the
      // raw fd number, which the event loop may have REUSED for another
      // transfer's source / a socket between the two calls, silently closing an
      // unrelated descriptor (EBADF / corrupt transfers across the daemon).
      let srcClosed = false;
      const cleanupSrc = () => {
        try { fileStream.destroy(); } catch {}
        try { lengthGuard.destroy(); } catch {}
        try { throttled.destroy(); } catch {}
        if (!srcClosed) {
          srcClosed = true;
          try { nodeFs.closeSync(srcFd); } catch {}
        }
      };

      const req = mod.request(reqOpts, res => {
        // Collect the response body with a true BYTE cap (collectStream
        // destroys the stream on overflow), instead of a hand-rolled string
        // collector whose `.length` counts UTF-16 code units and overshoots by
        // one chunk. A success body is parsed as JSON at the 16 MiB ceiling; an
        // error body only feeds the thrown/logged message, so cap it at the same
        // 64 KiB DOWNLOAD_ERR_BODY_CAP the download error path uses — a hostile
        // server returning a large body on a failed upload then can't amplify a
        // 16 MiB string into the daemon's logs. res.statusCode is known before
        // the body is read, so the cap is chosen up front. The body finished
        // streaming before the server responded, so srcFd is done being read —
        // cleanupSrc runs on BOTH outcomes (it is the sole srcFd owner; autoClose
        // is off and the resolve/reject paths below do not call it themselves).
        const ok2xx = res.statusCode === 200 || res.statusCode === 201;           // allow:raw-byte-literal — HTTP 200/201 success status codes
        const bodyCap = ok2xx ? RESPONSE_JSON_MAX_BYTES : DOWNLOAD_ERR_BODY_CAP;
        b.safeBuffer.collectStream(res, { maxBytes: bodyCap }).then(buf => {
          cleanupSrc();
          const body = buf.toString('utf8');
          if (!ok2xx) {
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
        }).catch(err => {
          // collectStream rejects on a mid-response socket reset (TLS teardown
          // / peer RST during the response phase) or an over-cap body — without
          // this the source error would escape as an uncaughtException and crash
          // the daemon. Release the source fd and reject.
          cleanupSrc();
          reject(new Error(`Upload response read failed: ${err.message}`));
        });
      });

      req.on('error', err => { cleanupSrc(); reject(err); });
      // Scale the socket-inactivity window when an upload throttle is
      // configured so a single chunk's throttle-wait can't trip the timeout
      // on a slow-but-progressing transfer; unthrottled uploads keep the 30s
      // base.
      req.setTimeout(this._throttledIdleTimeout(this._uploadBytesPerSec), () => {
        cleanupSrc();
        req.destroy(new Error('Request timeout'));
      });

      req.write(relPathPart);
      req.write(fileHeader);

      fileStream.on('error', err => { cleanupSrc(); req.destroy(err); });
      throttled.on('error', err => { cleanupSrc(); req.destroy(err); });
      throttled.on('end', () => {
        if (streamedBytes !== declaredBodySize) {
          // The file shrank after the fstat (a concurrent writer truncated it on
          // the unlocked initial-scan path). The declared Content-Length promised
          // declaredBodySize bytes; writing the footer + req.end() now would leave
          // the body short and stall the socket until the idle timeout. Abort with
          // a transient error so the sync engine retries once the file settles —
          // the mirror of the grew-during-upload guard in lengthGuard above.
          const shortErr = new Error(
            `Upload aborted for "${relativePath}": file shrank during upload ` +
            `(declared ${declaredBodySize} bytes, streamed ${streamedBytes}) — ` +
            `it is still being written. The sync engine will retry once it settles.`
          );
          cleanupSrc();
          req.destroy(shortErr);
          return;
        }
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
   * The ceiling is min(this._maxFileBytes, expectedSize) when the server
   * declared a size, else this._maxFileBytes — the same effective per-file cap
   * the upload path enforces (config.maxFileSize lowered onto MAX_SYNC_FILE_BYTES),
   * so one limit bounds both directions.
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
    const byteCeiling = wantedSize > 0 ? Math.min(this._maxFileBytes, wantedSize) : this._maxFileBytes;

    // Pin the connect to the SSRF-guard-validated address (DNS-rebind TOCTOU
    // close), matching the control-plane path. servername stays the hostname so
    // SNI + cert hostname validation are unchanged; a guard refusal fails the
    // download closed.
    const pinnedLookup = await this._pinnedServerLookup();

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('GET', `/files/${fileId}/download`);
      if (pinnedLookup) reqOpts.lookup = pinnedLookup;

      // Set when the in-stream counter trips the byte ceiling. Lifted to the
      // executor scope so the req/ws error handlers below (which fire after
      // the abort) reject with the real cap message rather than the generic
      // socket-abort error the destroy() produces.
      let overflowErr = null;

      const mod = this._isHttps ? nodeHttps : nodeHttp;
      const req = mod.request(reqOpts, res => {
        if (res.statusCode !== 200) {
          // Collect the error body with a true BYTE cap (collectStream
          // destroys the stream on overflow), instead of a hand-rolled string
          // collector whose `.length` counts UTF-16 code units and overshoots
          // by one chunk. No write stream is open in this branch yet — the
          // tmpPath unlink is defensive and harmless if absent.
          b.safeBuffer.collectStream(res, { maxBytes: DOWNLOAD_ERR_BODY_CAP }).then(buf => {
            reject(new Error(`Download failed: HTTP ${res.statusCode} — ${buf.toString('utf8')}`));
          }).catch(err => {
            // A socket reset while collecting the error body (or an over-cap
            // body) would otherwise escape as an uncaughtException.
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
          // Permanent: the file is over the effective per-file cap and can't
          // shrink, so the sync engine records ERROR once instead of re-fetching
          // (and re-refusing) it on every reconcile cycle. Mirrors the upload
          // path's permanent size-cap refusal.
          const e = new Error(
            `Server declared ${declared} bytes for ${destPath}, over the ${byteCeiling}-byte size limit — refusing. ` +
            `Raise maxFileSize in config.json (or HERMITSTASH_MAX_FILE_BYTES) if this file is legitimately that large.`
          );
          e.permanent = true;
          reject(e);
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
                `Raise maxFileSize in config.json (or HERMITSTASH_MAX_FILE_BYTES) if this file is legitimately that large.`
              );
              // Permanent: over the effective per-file cap, won't shrink on
              // retry — the sync engine records ERROR once instead of re-fetching
              // it every reconcile cycle (mirrors the upload size-cap refusal).
              overflowErr.permanent = true;
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
            } else if (wantedSize > 0 && received !== wantedSize) {
              // No reference checksum to verify against — e.g. a content-unchanged
              // rename moved this file into selective-sync scope, so the server
              // omitted the checksum. The exact byte count is then the only
              // application-layer integrity guard: a body that doesn't match the
              // server-declared size is truncated or corrupt. (TLS 1.3 + mTLS
              // covers an active MITM; this catches a half-failed / truncated
              // response body that the upper byte-ceiling alone would let land
              // marked SYNCED.) A checksum, when present, already covers this.
              try { nodeFs.unlinkSync(tmpPath); } catch {}
              reject(new Error(
                `Download size mismatch for ${destPath}: expected ${wantedSize} bytes, got ${received} — refusing (truncated or corrupt response).`
              ));
              return;
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
            b.atomicFile.renameWithRetry(tmpPath, dstPath);
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

      // Scale the socket-inactivity window when a download throttle is
      // configured so a single chunk's throttle-wait can't trip the timeout
      // on a slow-but-progressing transfer; unthrottled downloads keep the
      // 30s base.
      req.setTimeout(this._throttledIdleTimeout(this._downloadBytesPerSec), () => { req.destroy(new Error('Request timeout')); });
      req.end();
    });
  }

  /**
   * Delete a file from a sync bundle.
   */
  async deleteFile(fileId) {
    const resp = await this._jsonRequest('DELETE', `/files/${fileId}`);
    // DELETE is idempotent: a 404 means the server-side file is already gone
    // (a prior DELETE whose response was lost, or another device's delete
    // won the race), which satisfies the caller's intent — treat it as
    // success so a failed-delete retry isn't pinned re-attempting a file that
    // no longer exists.
    if (resp.statusCode !== 200 && resp.statusCode !== 204 && resp.statusCode !== 404) {
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
      // Forward the idle (zero-progress) bound via idleTimeoutMs AND the overall
      // wall-clock ceiling via timeoutMs. The encrypted wrapper passes both to
      // the base request, which converts timeoutMs into an AbortSignal that tears
      // the socket down on expiry — so a server that keeps a connection trickling
      // forward progress on the encrypted route can't hang a rename/init/finalize
      // past the cap, and no orphaned socket is left holding a keepAlive slot
      // while the serialized _encChain queue waits behind it.
      resp = await enc.request({
        method:        method,
        path:          urlPath,
        body:          bodyData,
        agent:         this._agent,
        allowInternal: true,
        idleTimeoutMs: ENC_IDLE_TIMEOUT_MS,
        timeoutMs:     ENC_WALL_CLOCK_TIMEOUT_MS,
        maxResponseBytes: RESPONSE_JSON_MAX_BYTES,
        // Resolve on non-2xx so the encrypted problem-details body can be
        // decrypted and read. Server v1.11.28+ encrypts error responses on
        // this per-session route; without passthrough the wrapper would reject
        // on the raw ciphertext before the decrypt step and the detail is lost.
        responseMode:  'passthrough',
      });
    } catch (err) {
      // The base request surfaces both the overall-wall-clock abort and an
      // idle (zero-progress) stall as ETIMEDOUT; this branch can't distinguish
      // them, so the message names both bounds. Translate either into the
      // actionable, transient timeout error the caller (and the sync engine's
      // retry) expect, preserving the prior contract.
      if (err && err.code === 'ETIMEDOUT') {
        const timeoutErr = new Error(
          'Encrypted request ' + method + ' ' + urlPath + ' timed out (idle or ' +
          ENC_WALL_CLOCK_TIMEOUT_MS + 'ms wall-clock cap) — the server accepted the ' +
          'connection but did not return a complete response in time. Retry; if it ' +
          'persists the server may be overloaded or a network path is dropping bytes.'
        );
        timeoutErr.code = 'ENC_WALL_CLOCK_TIMEOUT';
        timeoutErr.permanent = false;   // transient: a retry can succeed
        throw timeoutErr;
      }
      // A server that silently re-keyed surfaces as a client-side sid/ctr
      // mismatch rather than a 401. Treat those as session loss: rebuild and
      // retry once. Any other throw (network, decrypt, malformed) propagates.
      //
      // NOTE: this retry re-submits the identical request body, and the sole
      // production caller (renameFile -> POST /sync/rename) is non-idempotent, so
      // a response-integrity trip AFTER the server already applied the rename
      // re-sends it and the retry may see 404/409. That does not corrupt state:
      // the trip requires a genuine server-side counter/store fault (the envelope
      // rides inside TLS 1.3 + mTLS, so an on-wire replay cannot reach it), and
      // the sync engine's _handleLocalRename falls back to delete-old + upload-new
      // (same content, metadata-only server rename) on a rename failure. Do NOT
      // map 404/409 to success here — a 404 can also mean the source genuinely
      // never existed, and masking that would write a false SYNCED row.
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

    // Bootstrap _ek failed to decapsulate against a rotated server keypair —
    // the cached enc client sealed the session key to a stale pubkey. Rebuild
    // (which re-fetches /.well-known/blamejs-pubkey) and retry once.
    if (!retried && resp.statusCode === 400) {                                   // allow:raw-byte-literal — HTTP 400 status code
      const code = resp.body && (resp.body.error || resp.body.detail);
      if (code === 'encrypted-payload-rejected') {
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

  // Resolve the configured server host once through the SAME SSRF gate the
  // control-plane path uses (b.httpClient.request runs it internally) and
  // return a `lookup` function pinned to the guard-validated address set. The
  // streaming transfer paths (multipart upload / binary download) build a raw
  // https.request and would otherwise resolve the hostname again at connect
  // time with the default OS resolver, leaving a resolve-vs-connect DNS-rebind
  // TOCTOU window that the control plane closes. allowInternal:true matches the
  // posture of those paths (the user explicitly configured this server URL);
  // the gate still hard-denies cloud-metadata unconditionally. Returns
  // undefined when the gate can't resolve, in which case the caller falls back
  // to default resolution rather than failing the transfer.
  async _pinnedServerLookup() {
    const url = `${this._serverUrl.protocol}//${this._serverUrl.host}`;
    let result;
    try {
      // No errorClass override: the native SsrfError carries the
      // `ssrf-guard/*` code on `.code` (HermitStashHttpError's (code, message)
      // constructor would swap them), which the refusal check below depends on.
      result = await b.ssrfGuard.checkUrl(url, { allowInternal: true });
    } catch (err) {
      // A genuine guard refusal (e.g. the host resolves to a cloud-metadata IP)
      // must surface — do not silently fall through to an unpinned connect that
      // the guard would have blocked. Re-throw so the transfer fails closed.
      if (err && typeof err.code === 'string' && err.code.startsWith('ssrf-guard/')) throw err;
      return undefined;
    }
    const ips = result && result.ips;
    if (!Array.isArray(ips) || ips.length === 0) return undefined;
    const families = ips.map(i => ({ address: i.address, family: i.family || 4 }));   // allow:raw-byte-literal — 4 = IPv4 address family, default when unreported
    return function pinnedLookup(hostname, options, callback) {
      if (typeof options === 'function') { callback = options; options = {}; }
      options = options || {};
      if (options.all) callback(null, families);
      else callback(null, families[0].address, families[0].family);
    };
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
   * safeUrl scheme validation. The streaming transfer paths (multipart
   * upload, binary download) keep their own raw `https.request` shape.
   * The load-bearing deltas that keep them hand-rolled (verified against
   * blamejs v0.17.9 — re-verify on each vendor refresh):
   *   - Throttling: request() now ships maxBytesPerSec, but as a
   *     PER-REQUEST token bucket built fresh per attempt; these paths
   *     need the ONE shared b.streamThrottle bucket per direction so N
   *     concurrent transfers split the configured budget instead of
   *     each taking the full rate. downloadStream/uploadMultipartStream
   *     forward neither maxBytesPerSec nor the transform hooks.
   *   - Upload framing: uploadMultipartStream stats by path (not our
   *     pre-opened-fd fstat) and has no grew-or-shrank Content-Length
   *     guard, so a file mutated mid-upload could desync the framing.
   *   - Download: downloadStream has no exact-declared-size assertion
   *     for the no-checksum case (only a maxBytes ceiling).
   * They still close the same DNS-rebind TOCTOU window by resolving
   * through the SSRF gate (_pinnedServerLookup) and pinning the connect
   * `lookup` to the validated address set, so the SSRF/DNS-pin posture
   * matches this path.
   */
  async _rawRequest(method, urlPath, body, extraHeaders) {
    var headers = Object.assign({
      'Authorization':   `Bearer ${this._apiKey}`,
      'User-Agent':      `hermitstash-sync/${VERSION}`,
      'Accept-Language': 'en-US,en;q=0.9',
      'Sec-Fetch-Mode':  'cors',
      'Sec-Fetch-Dest':  'empty',
    }, extraHeaders || {});

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
module.exports.spkiPin = spkiPin;
