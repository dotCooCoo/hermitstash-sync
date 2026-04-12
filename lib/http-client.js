'use strict';

const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const log = require('./logger');

class HttpClient {
  constructor(config, apiKey) {
    this._serverUrl = new URL(config.server);
    this._apiKey = apiKey;
    this._isHttps = this._serverUrl.protocol === 'https:';

    // Build TLS options
    this._tlsOpts = {};
    if (this._isHttps) {
      this._tlsOpts.ecdhCurve = TLS_GROUPS;
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
   */
  async uploadFile(bundleId, relativePath, filePath) {
    const stat = fs.statSync(filePath);
    const filename = path.basename(relativePath);
    const boundary = `----HermitStash${crypto.randomBytes(16).toString('hex')}`;

    // Build multipart body
    const fileContent = fs.readFileSync(filePath);

    // relativePath field
    const relPathPart = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="relativePath"\r\n\r\n` +
      `${relativePath}\r\n`
    );

    // file field
    const fileHeader = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    );

    const fileFooter = Buffer.from(`\r\n--${boundary}--\r\n`);

    const body = Buffer.concat([relPathPart, fileHeader, fileContent, fileFooter]);

    const resp = await this._request('POST', `/drop/file/${bundleId}`, {
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length,
      },
      body,
    });

    if (resp.statusCode !== 200 && resp.statusCode !== 201) {
      throw new Error(`Upload failed: HTTP ${resp.statusCode} — ${resp.body}`);
    }

    return JSON.parse(resp.body);
  }

  /**
   * Download a file by server file ID
   * Streams to disk, returns the local path
   */
  async downloadFile(fileId, destPath) {
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
          res.on('data', c => body += c);
          res.on('end', () => reject(new Error(`Download failed: HTTP ${res.statusCode} — ${body}`)));
          return;
        }

        const ws = fs.createWriteStream(tmpPath);
        res.pipe(ws);

        ws.on('finish', () => {
          try {
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
        'User-Agent': 'hermitstash-sync/0.1.0',
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
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      });

      req.on('error', reject);

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
