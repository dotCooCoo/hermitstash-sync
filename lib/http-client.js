'use strict';

const nodeHttps = require('node:https');
const nodeHttp = require('node:http');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const nodeTls = require('node:tls');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const { longPath } = require('./long-path');
const b = require('../vendor/blamejs');
const { PassThrough } = require('node:stream');

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
    this._encClient = null;
    this._encPubkey = null;

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
      const req = mod.request(reqOpts, res => {
        this._extractCookie(res.headers);
        let body = '';
        res.on('data', chunk => { if (body.length < DOWNLOAD_ERR_BODY_CAP) body += chunk; });
        res.on('end', () => {
          if (res.statusCode !== 200 && res.statusCode !== 201) {
            reject(new Error(`Upload failed: HTTP ${res.statusCode} — ${body}`));
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

      req.on('error', reject);
      req.setTimeout(C.TIME.seconds(30), () => { req.destroy(new Error('Request timeout')); });

      req.write(relPathPart);
      req.write(fileHeader);

      const fileStream = nodeFs.createReadStream(fsPath);
      // Bandwidth limit: route the body bytes through the shared
      // upload limiter before they hit the request socket. When
      // uploadBytesPerSec is 0 (default) the Transform is a pass-
      // through and adds no overhead.
      const throttled = fileStream.pipe(this._throttleTransform(this._uploadLimiter));
      fileStream.on('error', err => { req.destroy(err); });
      throttled.on('error', err => { req.destroy(err); });
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
   */
  async downloadFile(fileId, destPath, expectedChecksum) {
    // longPath() is a no-op on POSIX + short paths; only long Windows
    // absolutes get the `\\?\` prefix.
    const dir = longPath(nodePath.dirname(destPath));
    nodeFs.mkdirSync(dir, { recursive: true });
    const tmpPath = longPath(destPath + '.tmp.' + b.crypto.generateToken(4));
    const dstPath = longPath(destPath);

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('GET', `/files/${fileId}/download`);

      const mod = this._isHttps ? nodeHttps : nodeHttp;
      const req = mod.request(reqOpts, res => {
        if (res.statusCode !== 200) {
          let body = '';
          res.on('data', c => { if (body.length < DOWNLOAD_ERR_BODY_CAP) body += c; });
          res.on('end', () => reject(new Error(`Download failed: HTTP ${res.statusCode} — ${body}`)));
          return;
        }

        const ws = nodeFs.createWriteStream(tmpPath);
        const hash = nodeCrypto.createHash('sha3-512');
        // Hash from the raw response (pre-throttle) — the bytes are
        // identical and we want the digest to settle as fast as the
        // network delivers it, not at throttle pace. The throttle only
        // gates how fast we drain to disk.
        res.on('data', chunk => hash.update(chunk));
        const throttled = res.pipe(this._throttleTransform(this._downloadLimiter));
        throttled.pipe(ws);
        throttled.on('error', err => { ws.destroy(err); });
        // res.pipe() does not forward source errors downstream, so a mid-stream
        // response abort (socket reset / TLS teardown) would otherwise leave the
        // write stream + fd open, the partial temp file unremoved, and this
        // Promise unsettled. Handle it explicitly.
        res.on('error', err => {
          try { ws.destroy(); } catch {}
          try { nodeFs.unlinkSync(tmpPath); } catch {}
          reject(err);
        });

        ws.on('finish', () => {
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
            nodeFs.renameSync(tmpPath, dstPath);
            resolve(destPath);
          } catch (err) {
            reject(err);
          }
        });

        ws.on('error', err => {
          try { nodeFs.unlinkSync(tmpPath); } catch {}
          reject(err);
        });
      });

      req.on('error', err => {
        try { nodeFs.unlinkSync(tmpPath); } catch {}
        reject(err);
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
    if (resp.statusCode !== 200) {
      throw new Error(`Rename failed: HTTP ${resp.statusCode}`);
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
   * Reset (e.g. on server-side session expiry) by calling
   * `enc.resetSession()` on the returned client.
   */
  async _getEncClient() {
    if (this._encClient) return this._encClient;

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
  }

  /**
   * Encrypted JSON request via blamejs apiEncrypt. Body is wrapped in
   * the per-session envelope (`_ek/_ct/_ts/_nonce` on first call,
   * `_sid/_ctr/_ct` thereafter); response is auto-decrypted. Used for
   * server routes opted into blamejs scope (POST /drop/init, POST
   * /drop/finalize/:bundleId, POST /sync/rename as of v1.9.15).
   */
  async _encryptedRequest(method, urlPath, bodyData) {
    const enc = await this._getEncClient();
    return enc.request({
      method:        method,
      path:          urlPath,
      body:          bodyData,
      agent:         this._agent,
      allowInternal: true,
      timeoutMs:     C.TIME.seconds(30),
      maxResponseBytes: RESPONSE_JSON_MAX_BYTES,
    });
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
