'use strict';

const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const log = require('./logger');

class HttpClient {
  constructor(config, apiKey) {
    this._serverUrl = new URL(config.server);
    this._apiKey = apiKey;
    this._isHttps = this._serverUrl.protocol === 'https:';

    // Build TLS options
    this._tlsOpts = {};
    if (this._isHttps) {
      // M2: Set both ecdhCurve and groups for PQC TLS compatibility
      this._tlsOpts.ecdhCurve = TLS_GROUPS;
      this._tlsOpts.groups = TLS_GROUPS;
      this._tlsOpts.minVersion = TLS_MIN_VERSION;

      if (config.mtls) {
        if (config.mtls.cert) this._tlsOpts.cert = fs.readFileSync(config.mtls.cert);
        if (config.mtls.key) this._tlsOpts.key = fs.readFileSync(config.mtls.key);
        if (config.mtls.ca) this._tlsOpts.ca = fs.readFileSync(config.mtls.ca);
      }
    }

    // Create a reusable agent
    const Agent = this._isHttps ? https.Agent : http.Agent;
    this._agent = new Agent({
      ...this._tlsOpts,
      keepAlive: true,
      maxSockets: 6,
    });
  }

  /**
   * GET bundle metadata (JSON)
   */
  async getBundleMetadata(shareId) {
    const resp = await this._request('GET', `/b/${shareId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (resp.statusCode !== 200) {
      throw new Error(`Failed to get bundle metadata: HTTP ${resp.statusCode}`);
    }
    return JSON.parse(resp.body);
  }

  /**
   * Upload a file to a sync bundle
   * Uses multipart/form-data matching server's /drop/file/:bundleId
   * Streams the file content to avoid loading the entire file into memory (C4).
   */
  async uploadFile(bundleId, relativePath, filePath) {
    const stat = fs.statSync(filePath);
    // C3: Sanitize filename to prevent header injection via " and \ characters
    const safeFilename = path.basename(relativePath).replace(/["\\]/g, '_');
    const boundary = `----HermitStash${crypto.randomBytes(16).toString('hex')}`;

    // Build multipart parts (headers only — file content is streamed)
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

    // Pre-compute Content-Length: multipart overhead + file size
    const contentLength = relPathPart.length + fileHeader.length + stat.size + fileFooter.length;

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('POST', `/drop/file/${bundleId}`, {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': contentLength,
      });

      const mod = this._isHttps ? https : http;
      const req = mod.request(reqOpts, res => {
        let body = '';
        res.on('data', chunk => { if (body.length < 65536) body += chunk; });
        res.on('end', () => {
          if (res.statusCode !== 200 && res.statusCode !== 201) {
            reject(new Error(`Upload failed: HTTP ${res.statusCode} — ${body}`));
            return;
          }
          try {
            resolve(JSON.parse(body));
          } catch (err) {
            reject(new Error(`Upload response parse error: ${err.message}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });

      // Write multipart preamble
      req.write(relPathPart);
      req.write(fileHeader);

      // Stream file content
      const fileStream = fs.createReadStream(filePath);
      fileStream.on('error', err => { req.destroy(err); });
      fileStream.on('end', () => {
        // Write multipart footer and finish
        req.write(fileFooter);
        req.end();
      });
      fileStream.pipe(req, { end: false });
    });
  }

  /**
   * Download a file by server file ID.
   * M11: Computes checksum of temp file and verifies before rename.
   * If expectedChecksum is provided and mismatches, temp file is deleted and an error is thrown.
   */
  async downloadFile(fileId, destPath, expectedChecksum) {
    const dir = path.dirname(destPath);
    fs.mkdirSync(dir, { recursive: true });

    // Write to temp file then rename atomically
    const tmpPath = destPath + '.tmp.' + crypto.randomBytes(4).toString('hex');

    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts('GET', `/files/${fileId}/download`);

      const mod = this._isHttps ? https : http;
      const req = mod.request(reqOpts, res => {
        if (res.statusCode !== 200) {
          let body = '';
          // L3: Limit accumulated error body to 64 KB
          res.on('data', c => { if (body.length < 65536) body += c; });
          res.on('end', () => reject(new Error(`Download failed: HTTP ${res.statusCode} — ${body}`)));
          return;
        }

        const ws = fs.createWriteStream(tmpPath);
        // M11: Hash file content during download for checksum verification
        const hash = crypto.createHash('sha3-512');
        res.on('data', chunk => hash.update(chunk));
        res.pipe(ws);

        ws.on('finish', () => {
          try {
            // M11: Verify checksum before rename
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

      // M4: Request timeout
      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });

      req.end();
    });
  }

  /**
   * Delete a file from a sync bundle
   */
  async deleteFile(fileId) {
    const resp = await this._request('DELETE', `/files/${fileId}`);
    if (resp.statusCode !== 200 && resp.statusCode !== 204) {
      throw new Error(`Delete failed: HTTP ${resp.statusCode} — ${resp.body}`);
    }
  }

  /**
   * Health check
   */
  async healthCheck() {
    const resp = await this._request('GET', '/health');
    return resp.statusCode === 200;
  }

  // --- internals ---

  _reqOpts(method, urlPath, extraHeaders = {}) {
    return {
      hostname: this._serverUrl.hostname,
      port: this._serverUrl.port || (this._isHttps ? 443 : 80),
      path: urlPath,
      method,
      agent: this._agent,
      headers: {
        'Authorization': `Bearer ${this._apiKey}`,
        'User-Agent': `hermitstash-sync/${VERSION}`,
        ...extraHeaders,
      },
    };
  }

  _request(method, urlPath, opts = {}) {
    return new Promise((resolve, reject) => {
      const reqOpts = this._reqOpts(method, urlPath, opts.headers || {});

      const mod = this._isHttps ? https : http;
      const req = mod.request(reqOpts, res => {
        let body = '';
        // L3/L6: Limit accumulated response body to 64 KB
        res.on('data', chunk => { if (body.length < 65536) body += chunk; });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      });

      req.on('error', reject);
      // M4: Request timeout
      req.setTimeout(30000, () => { req.destroy(new Error('Request timeout')); });

      if (opts.body) {
        req.write(opts.body);
      }
      req.end();
    });
  }

  destroy() {
    this._agent.destroy();
  }
}

module.exports = HttpClient;
