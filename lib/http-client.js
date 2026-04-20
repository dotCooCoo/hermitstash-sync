'use strict';

const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const log = require('./logger');
const { ml_kem1024 } = require('../vendor/noble-pq.cjs');
const { xchacha20poly1305 } = require('../vendor/noble-ciphers.cjs');

const HYBRID_HKDF_INFO = 'hermitstash-hybrid-ecies-v1';

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
    this._serverUrl = new URL(config.server);
    this._apiKey = apiKey;
    this._isHttps = this._serverUrl.protocol === 'https:';
    this._sessionCookie = null;
    this._sessionKey = null; // XChaCha20-Poly1305 session key (base64url)
    this._keyExchangeDone = false;

    // ML-KEM-1024 keypair for hybrid ECIES key exchange
    this._kemKeypair = ml_kem1024.keygen();

    this._tlsOpts = this._isHttps ? buildTlsOptions(config.mtls) : {};

    // P-384 private key for ECDH leg of hybrid ECIES
    if (this._isHttps && config.mtls && config.mtls.key) {
      this._ecdhPrivateKey = crypto.createPrivateKey({
        key: fs.readFileSync(config.mtls.key),
        format: 'pem',
      });
    }

    this._rebuildAgent();
  }

  _rebuildAgent() {
    try { if (this._agent) this._agent.destroy(); } catch (_e) {}
    const Agent = this._isHttps ? https.Agent : http.Agent;
    this._agent = new Agent({
      ...this._tlsOpts,
      keepAlive: true,
      maxSockets: 6,
    });
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
      if (this._config.mtls.key) {
        this._ecdhPrivateKey = crypto.createPrivateKey({
          key: fs.readFileSync(this._config.mtls.key),
          format: 'pem',
        });
      }
      this._rebuildAgent();
    } catch (_e) {}
  }

  /**
   * Perform the hybrid ECIES key exchange with the server.
   * Sends ML-KEM public key, receives encrypted session key, decrypts it.
   * Must be called before any encrypted API requests.
   */
  async initSession() {
    const body = JSON.stringify({
      uploaderName: 'session-init',
      fileCount: 0,
      bundleType: 'sync',
    });
    const resp = await this._rawRequest('POST', '/drop/init', body, true, {
      'Content-Type': 'application/json',
    }); // includeKemHeader=true adds X-KEM-Public-Key

    // Extract session cookie
    this._extractCookie(resp.headers);

    // Perform hybrid ECIES key exchange
    var json;
    try { json = JSON.parse(resp.body); } catch (_e) { json = null; }

    if (json && json._ek && json._epk && json._kem && this._ecdhPrivateKey) {
      this._sessionKey = this._hybridDecrypt(json._ek, json._epk, json._kem);
      this._keyExchangeDone = true;
      log.info('Hybrid ECIES key exchange completed');
    }

    return resp;
  }

  /**
   * GET bundle metadata (JSON). Decrypts the encrypted response.
   */
  async getBundleMetadata(shareId) {
    const resp = await this._encryptedRequest('GET', `/b/${shareId}`, null, {
      'Accept': 'application/json',
    });
    return resp.decrypted;
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
          try {
            var parsed = JSON.parse(body);
            // Decrypt encrypted response if we have the session key
            if (this._sessionKey && parsed && parsed._e) {
              resolve(this._decryptPayload(parsed._e));
            } else {
              resolve(parsed);
            }
          } catch (err) {
            reject(new Error(`Upload response parse error: ${err.message}`));
          }
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
    const resp = await this._encryptedRequest('DELETE', `/files/${fileId}`);
    if (resp.statusCode !== 200 && resp.statusCode !== 204) {
      throw new Error(`Delete failed: HTTP ${resp.statusCode}`);
    }
  }

  /**
   * Rename/move a file within a sync bundle (metadata-only, no re-upload).
   */
  async renameFile(bundleId, oldRelativePath, newRelativePath) {
    // We need the bundle's shareId — for now, POST to a known route pattern
    // The server route is POST /bundles/:shareId/file/rename
    // Since we have bundleId not shareId, use an alternate approach via the API
    const resp = await this._encryptedRequest('POST', `/sync/rename`, {
      bundleId, oldRelativePath, newRelativePath,
    });
    if (resp.statusCode !== 200) {
      throw new Error(`Rename failed: HTTP ${resp.statusCode}`);
    }
    return resp.json || {};
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
    const resp = await this._rawRequest('POST', '/sync/renew-cert', '{}', false, {
      'Content-Type': 'application/json',
      'Content-Length': '2',
    });
    let data;
    try { data = JSON.parse(resp.body); }
    catch (_e) { throw new Error(`Invalid JSON from /sync/renew-cert (HTTP ${resp.statusCode})`); }
    if (resp.statusCode !== 200 || !data.success) {
      throw new Error(data.error || `Renewal failed with HTTP ${resp.statusCode}`);
    }
    return data;
  }

  // --- Encryption internals ---

  /**
   * Hybrid ECIES decrypt: recover session key from _ek, _epk, _kem.
   * _ek is prefixed with a 1-byte protocol version for algorithm agility.
   * 0x01 = ML-KEM-1024 + ECDH P-384 + HKDF-SHA3-512 + XChaCha20-Poly1305
   */
  _hybridDecrypt(ekBase64url, epkBase64url, kemBase64url) {
    var packed = Buffer.from(ekBase64url, 'base64url');

    // Read and validate protocol version byte
    var version = packed[0];
    if (version !== 0x01) {
      throw new Error('Unsupported ECIES protocol version: 0x' + version.toString(16));
    }

    // ML-KEM-1024 leg: decapsulate
    var kemCt = Buffer.from(kemBase64url, 'base64url');
    var ssKem = ml_kem1024.decapsulate(new Uint8Array(kemCt), this._kemKeypair.secretKey);

    // ECDH P-384 leg
    var epkDer = Buffer.from(epkBase64url, 'base64url');
    var serverEpk = crypto.createPublicKey({ key: epkDer, format: 'der', type: 'spki' });
    var ssEcdh = crypto.diffieHellman({ privateKey: this._ecdhPrivateKey, publicKey: serverEpk });

    // Combine + HKDF-SHA3-512
    var combined = Buffer.concat([Buffer.from(ssKem), ssEcdh]);
    var wrappingKey = crypto.hkdfSync('sha3-512', combined, '', HYBRID_HKDF_INFO, 32);

    // Decrypt session key: skip version byte(1), then nonce(24) + ciphertext
    var nonce = packed.subarray(1, 25);
    var ct = packed.subarray(25);
    var sessionKeyBytes = xchacha20poly1305(new Uint8Array(Buffer.from(wrappingKey)), nonce).decrypt(ct);
    return Buffer.from(sessionKeyBytes).toString('base64url');
  }

  _encryptPayload(data) {
    var key = Buffer.from(this._sessionKey, 'base64url');
    var nonce = crypto.randomBytes(24);
    var plaintext = Buffer.from(JSON.stringify({ _d: data, _t: Date.now() }), 'utf8');
    var ct = xchacha20poly1305(new Uint8Array(key), nonce).encrypt(new Uint8Array(plaintext));
    return Buffer.concat([Buffer.from(nonce), Buffer.from(ct)]).toString('base64url');
  }

  _decryptPayload(sealed) {
    var key = Buffer.from(this._sessionKey, 'base64url');
    var packed = Buffer.from(sealed, 'base64url');
    if (packed.length < 41) return null;
    var nonce = packed.subarray(0, 24);
    var ct = packed.subarray(24);
    var plaintext = Buffer.from(xchacha20poly1305(new Uint8Array(key), nonce).decrypt(ct)).toString('utf8');
    var parsed = JSON.parse(plaintext);
    return parsed._d !== undefined ? parsed._d : parsed;
  }

  /**
   * Make an encrypted JSON request. Encrypts body, decrypts response.
   */
  async _encryptedRequest(method, urlPath, bodyData, extraHeaders) {
    if (bodyData !== undefined && bodyData !== null && !this._sessionKey) {
      throw new Error('Encrypted request requires a session key. Call initSession() first.');
    }
    var headers = extraHeaders || {};
    var bodyStr;
    if (bodyData !== undefined && bodyData !== null) {
      headers['Content-Type'] = 'application/json';
      bodyStr = JSON.stringify({ _e: this._encryptPayload(bodyData) });
    }

    var resp = await this._rawRequest(method, urlPath, bodyStr, false, headers);

    // Decrypt response
    resp.decrypted = null;
    try {
      var json = JSON.parse(resp.body);
      if (this._sessionKey && json && json._e) {
        resp.decrypted = this._decryptPayload(json._e);
      }
    } catch (_e) {}

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
   * Raw HTTP request. If includeKemHeader is true, sends X-KEM-Public-Key.
   */
  _rawRequest(method, urlPath, body, includeKemHeader, extraHeaders) {
    return new Promise((resolve, reject) => {
      var headers = extraHeaders || {};
      if (includeKemHeader && !this._keyExchangeDone) {
        headers['X-KEM-Public-Key'] = Buffer.from(this._kemKeypair.publicKey).toString('base64url');
      }
      var reqOpts = this._reqOpts(method, urlPath, headers);

      var mod = this._isHttps ? https : http;
      var req = mod.request(reqOpts, res => {
        this._extractCookie(res.headers);
        collectTextBody(res)
          .then(respBody => resolve({ statusCode: res.statusCode, headers: res.headers, body: respBody }))
          .catch(reject);
      });

      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });

      if (body) req.write(body);
      req.end();
    });
  }

  destroy() {
    this._agent.destroy();
  }
}

module.exports = HttpClient;
module.exports.buildTlsOptions = buildTlsOptions;
module.exports.collectTextBody = collectTextBody;
