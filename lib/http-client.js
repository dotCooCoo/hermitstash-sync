'use strict';

const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const b = require('../vendor/blamejs');

// Error class with `withStatusCode: true` so the HTTP status survives as
// `err.statusCode` on 4xx/5xx instead of forcing us to string-parse the
// "HTTP <N>" message. Without an `errorClass` opt, blamejs returns a bare
// FrameworkError that drops statusCode (see vendor/.../http-client.js
// `_makeError`).
const HermitStashHttpError = b.frameworkError.defineClass('HermitStashHttpError', { withStatusCode: true });

// Cap on JSON response bodies parsed via safeJson. Server responses are
// bounded by application logic; this is a defence-in-depth ceiling against
// a hostile or compromised server returning a giant or deeply-nested doc.
const RESPONSE_JSON_MAX_BYTES = 16 * 1024 * 1024;

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
function buildTlsOptions(mtls, extras) {
  const opts = {
    ecdhCurve: TLS_GROUPS,
    groups: TLS_GROUPS,
    minVersion: TLS_MIN_VERSION,
  };
  if (mtls) {
    const load = v => (typeof v === 'string' ? fs.readFileSync(v) : v);
    if (mtls.cert) opts.cert = load(mtls.cert);
    if (mtls.key)  opts.key  = load(mtls.key);
    if (mtls.ca)   opts.ca   = load(mtls.ca);
  }
  if (extras) Object.assign(opts, extras);
  return opts;
}

/**
 * Accumulate an HTTP response body as a text string, capped at maxBytes to
 * avoid unbounded growth on hostile servers. Resolves with the collected
 * string on 'end', rejects on stream error. Use only for JSON/text endpoints
 * — binary downloads must stream (see downloadFile).
 */
function collectTextBody(res, maxBytes = 65536) {
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
  }

  _rebuildAgent() {
    try { if (this._agent) this._agent.destroy(); } catch (_e) {}
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
    } else {
      this._agent = new http.Agent({ keepAlive: true, maxSockets: 6 });
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
    const stat = fs.statSync(filePath);
    const safeFilename = path.basename(relativePath).replace(/["\\]/g, '_');
    const boundary = `----HermitStash${crypto.randomBytes(16).toString('hex')}`;

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

      const mod = this._isHttps ? https : http;
      const req = mod.request(reqOpts, res => {
        this._extractCookie(res.headers);
        let body = '';
        res.on('data', chunk => { if (body.length < 65536) body += chunk; });
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
      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });

      req.write(relPathPart);
      req.write(fileHeader);

      const fileStream = fs.createReadStream(filePath);
      fileStream.on('error', err => { req.destroy(err); });
      fileStream.on('end', () => {
        req.write(fileFooter);
        req.end();
      });
      fileStream.pipe(req, { end: false });
    });
  }

  /**
   * Download a file by server file ID.
   * Downloads are NOT encrypted by api-encrypt (streamed binary, not JSON).
   */
  async downloadFile(fileId, destPath, expectedChecksum) {
    const dir = path.dirname(destPath);
    fs.mkdirSync(dir, { recursive: true });
    const tmpPath = destPath + '.tmp.' + crypto.randomBytes(4).toString('hex');

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('GET', `/files/${fileId}/download`);

      const mod = this._isHttps ? https : http;
      const req = mod.request(reqOpts, res => {
        if (res.statusCode !== 200) {
          let body = '';
          res.on('data', c => { if (body.length < 65536) body += c; });
          res.on('end', () => reject(new Error(`Download failed: HTTP ${res.statusCode} — ${body}`)));
          return;
        }

        const ws = fs.createWriteStream(tmpPath);
        const hash = crypto.createHash('sha3-512');
        res.on('data', chunk => hash.update(chunk));
        res.pipe(ws);

        ws.on('finish', () => {
          try {
            if (expectedChecksum) {
              const downloadedChecksum = hash.digest('hex');
              if (downloadedChecksum !== expectedChecksum) {
                try { fs.unlinkSync(tmpPath); } catch {}
                reject(new Error(
                  `Checksum mismatch: expected ${expectedChecksum.slice(0, 16)}... got ${downloadedChecksum.slice(0, 16)}...`
                ));
                return;
              }
            }
            fs.renameSync(tmpPath, destPath);
            resolve(destPath);
          } catch (err) {
            reject(err);
          }
        });

        ws.on('error', err => {
          try { fs.unlinkSync(tmpPath); } catch {}
          reject(err);
        });
      });

      req.on('error', err => {
        try { fs.unlinkSync(tmpPath); } catch {}
        reject(err);
      });

      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });
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
      throw new Error(data.error || `Renewal failed with HTTP ${resp.statusCode}`);
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
      timeoutMs:     30000,
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
      'Authorization': `Bearer ${this._apiKey}`,
      'User-Agent': `hermitstash-sync/${VERSION}`,
      ...extraHeaders,
    };
    if (this._sessionCookie) headers['Cookie'] = this._sessionCookie;
    return {
      hostname: this._serverUrl.hostname,
      port: this._serverUrl.port || (this._isHttps ? 443 : 80),
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
      'Authorization': `Bearer ${this._apiKey}`,
      'User-Agent':    `hermitstash-sync/${VERSION}`,
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
        timeoutMs:     30000,
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
module.exports.collectTextBody = collectTextBody;
