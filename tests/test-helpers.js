'use strict';

/**
 * Test helpers for HermitStash E2E tests.
 *
 * Uses the sync client's own libraries (lib/) wherever possible so that
 * tests exercise the same code paths as the real CLI:
 *   - lib/checksum.js  for SHA3-512 hashing
 *   - lib/http-client.js  for authenticated uploads with ECIES + mTLS
 *   - lib/ws-client.js  for WebSocket sync connections
 *   - lib/constants.js  for message types and TLS config
 *
 * Raw httpRequest is kept for edge-case tests that intentionally bypass
 * normal auth (bot guard, bad tokens, public endpoints).
 */

const { spawn, execFileSync } = require('node:child_process');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');

// ---- Sync client libraries ----
const { hashBuffer } = require('../lib/checksum');
const { MSG } = require('../lib/constants');
const HttpClient = require('../lib/http-client');
const WsClient = require('../lib/ws-client');

// Suppress client library logging in test processes to avoid noise
var _logSuppressed = false;
function _suppressLog() {
  if (_logSuppressed) return;
  _logSuppressed = true;
  try {
    var logger = require('../lib/logger');
    var logFile = path.join(os.tmpdir(), 'hermitstash-sync-test-' + process.pid + '.log');
    logger.init({ level: 'error', stdout: false, file: logFile });
  } catch (_e) { /* logger init is best-effort */ }
}

// Absolute path to the HermitStash server repo. Defaults to a sibling
// checkout of `dotCooCoo/hermitstash` (i.e. `../hermitstash/` relative
// to this repo's root). Override via `HERMITSTASH_SERVER_DIR=…` when
// the server source lives elsewhere (private fork, monorepo layout).
const SERVER_DIR = process.env.HERMITSTASH_SERVER_DIR
  || path.resolve(__dirname, '..', '..', 'hermitstash');

/**
 * Find a random available TCP port.
 */
function getRandomPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create a unique temporary directory for test isolation.
 */
function createTempDir(label) {
  const dir = path.join(os.tmpdir(), `hermitstash-test-${label || 'data'}-${b.crypto.generateToken(6)}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Recursively remove a directory.
 */
function rmrf(dir) {
  if (!dir || !fs.existsSync(dir)) return;
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Run a Node.js script against the server's DB using execFileSync.
 * The script is passed as a single -e argument (no shell interpolation).
 * Returns stdout as a string.
 */
function runDbScript(serverDbPath, scriptBody) {
  // Match the server's PRAGMAs so this ad-hoc connection joins WAL readers/writers
  // instead of hitting SQLITE_BUSY against the live server. Without this,
  // parallel test workers collide on INSERT.
  // Wrap the body in an async IIFE so scripts that need vault.init() before
  // calling b.cryptoField.sealDoc can await without racing against db.close().
  // Pure-sync bodies still work — they just don't use `await`.
  const PRAGMAS = [
    'PRAGMA journal_mode=WAL',
    'PRAGMA busy_timeout=10000',
    'PRAGMA synchronous=NORMAL',
  ];
  const fullScript = [
    `var { DatabaseSync } = require('node:sqlite');`,
    `var db = new DatabaseSync(${JSON.stringify(serverDbPath)});`,
    `${JSON.stringify(PRAGMAS)}.forEach(function (p) { db.exec(p); });`,
    `(async function () {`,
    scriptBody,
    `})().then(function () { db.close(); }, function (err) {`,
    `  try { db.close(); } catch (_e) {}`,
    `  process.stderr.write(String(err && err.stack || err));`,
    `  process.exit(1);`,
    `});`,
  ].join('\n');

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return execFileSync(process.execPath, ['-e', fullScript], {
        cwd: SERVER_DIR,
        encoding: 'utf8',
        timeout: 15000,
      }).trim();
    } catch (err) {
      const msg = (err.stderr || '') + ' ' + (err.message || '');
      if (attempt < 2 && /SQLITE_BUSY|database is locked/i.test(msg)) {
        // Synchronous backoff — callers are sync. 50ms then 200ms.
        const until = Date.now() + (50 * Math.pow(4, attempt));
        while (Date.now() < until) { /* spin */ }
        continue;
      }
      throw err;
    }
  }
  throw new Error('runDbScript: exhausted retries');
}

/**
 * Raw HTTP request for test infrastructure (auth failures, bot guard, etc.).
 * Returns { statusCode, headers, body, json }.
 *
 * For normal authenticated uploads, use uploadFile() which routes through
 * the sync client's HttpClient.
 */
/**
 * Send an encrypted JSON request to a server route handled by blamejs
 * apiEncrypt (e.g. POST /sync/rename, POST /drop/init in v1.9.15).
 *
 * Wraps `b.httpClient.encrypted` and shapes the result as { statusCode,
 * headers, body, json } so call sites can mostly drop in for httpRequest
 * on the migrated routes. The pubkey is fetched once per ctx and cached.
 *
 * @param {object} ctx test context (url, apiKey, mTLS cert/key/CA)
 * @param {string} urlPath e.g. '/sync/rename'
 * @param {object} [opts] { method?, body?, headers? }
 *   - method defaults to 'POST'; body is the plaintext JSON object;
 *     omit body for an empty-body request
 */
async function encryptedRequest(ctx, urlPath, opts = {}) {
  const apiKey = opts.apiKey || ctx.apiKey;

  // Cache pubkey + agent per ctx (server boot), encrypted-client per
  // bearer token. Different tokens get separate per-session counters
  // so the IDOR tests can mix bound and unbound keys cleanly. The
  // pubkey route requires Bearer + mTLS (it's behind api-auth on the
  // server), so the helper fetches it via the same HttpClient that
  // routes the encrypted requests.
  if (!ctx._encAgent || !ctx._encHttpClient) {
    const HttpClient = require('../lib/http-client');
    var mtls;
    if (ctx.clientCert && ctx.clientKey && ctx.caCert) {
      mtls = { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert };
    }
    const httpClient = new HttpClient({ server: ctx.url, mtls: mtls }, ctx.apiKey);
    httpClient._agent.options.rejectUnauthorized = false;
    ctx._encAgent = httpClient._agent;
    ctx._encHttpClient = httpClient;
  }
  if (!ctx._encPubkey) {
    const pubResp = await ctx._encHttpClient._jsonRequest('GET', '/.well-known/blamejs-pubkey', null, {
      'Accept': 'application/json',
    });
    if (pubResp.statusCode !== 200 || !pubResp.json) {
      throw new Error('Failed to fetch /.well-known/blamejs-pubkey: HTTP ' + pubResp.statusCode);
    }
    ctx._encPubkey = pubResp.json;
  }
  if (!ctx._encClients) ctx._encClients = new Map();
  let enc = ctx._encClients.get(apiKey);
  if (!enc) {
    const bHttpClientEncrypted = require('../vendor/blamejs/lib/middleware/api-encrypt').httpClient;
    enc = bHttpClientEncrypted({
      pubkey:  ctx._encPubkey,
      baseUrl: ctx.url,
      headers: Object.assign({}, TEST_BROWSER_HEADERS, { Authorization: 'Bearer ' + apiKey }),
      keying:  'per-session',
    });
    ctx._encClients.set(apiKey, enc);
  }

  try {
    const resp = await enc.request({
      method:        opts.method || 'POST',
      path:          urlPath,
      body:          opts.body !== undefined ? opts.body : null,
      headers:       opts.headers || {},
      agent:         ctx._encAgent,
      allowInternal: true,
      timeoutMs:     30000,
    });
    return {
      statusCode: resp.statusCode,
      headers:    resp.headers,
      body:       typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body),
      json:       resp.body && typeof resp.body === 'object' ? resp.body : null,
    };
  } catch (err) {
    // Surface 4xx/5xx as a plain { statusCode, body } so test code can
    // assert on resp.statusCode the same way it does with httpRequest.
    // b.httpClient.encrypted's underlying request comes back as a generic
    // FrameworkError("HTTP_ERROR", "HTTP <N> <msg>") since we don't pass an
    // errorClass here — extract the status from the message tail.
    if (err && err.code === 'HTTP_ERROR' && typeof err.message === 'string') {
      // Vendor format: "HTTP <N>: <body slice>"
      const m = err.message.match(/^HTTP (\d{3}):\s?(.*)$/s);
      if (m) {
        return { statusCode: parseInt(m[1], 10), headers: {}, body: m[2] || '', json: null };
      }
    }
    throw err;
  }
}

// Realistic-browser headers — sent unless the caller overrides. The framework
// bot-guard fingerprints accept-language + sec-fetch-mode + user-agent on
// non-exempt paths; tests get blocked otherwise. Per project memory: send
// realistic headers, never weaken the default.
var TEST_BROWSER_HEADERS = {
  'accept-language':    'en-US,en;q=0.9',
  'sec-fetch-mode':     'cors',
  'sec-fetch-dest':     'empty',
  'sec-fetch-site':     'same-origin',
  'user-agent':         'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) hermitstash-test/0.1',
};

function httpRequest(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const method = opts.method || 'GET';

    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method,
      // `bare: true` opts out of the browser-shape defaults — the bot-guard
      // suite needs an unfingerprinted request to verify the default block path.
      headers: opts.bare ? (opts.headers || {}) : Object.assign({}, TEST_BROWSER_HEADERS, opts.headers || {}),
      rejectUnauthorized: false,
      cert: opts.cert || undefined,
      key: opts.key || undefined,
      ca: opts.ca || undefined,
    };

    const req = mod.request(reqOpts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        var bodyBuffer = Buffer.concat(chunks);
        var body = bodyBuffer.toString('utf8');
        let json = null;
        try { json = JSON.parse(body); } catch {}
        resolve({ statusCode: res.statusCode, headers: res.headers, body, bodyBuffer, json });
      });
    });

    req.on('error', reject);
    req.setTimeout(opts.timeout || 1000, () => {
      req.destroy(new Error('Request timeout'));
    });

    if (opts.body) req.write(opts.body);
    req.end();
  });
}

/**
 * Thin wrapper around lib/http-client.js HttpClient for test use.
 *
 * Server v1.9.15+ short-circuits the legacy api-encrypt envelope for
 * Bearer-authed clients (`if (req.apiKey) return next()`), so the
 * client posts plain JSON and reads plain JSON. The pre-v1.9.15
 * ECIES handshake here is gone — `init()` is kept as a no-op for
 * call-site compatibility with older test files that still call it.
 */
class ApiClient {
  constructor(baseUrl, apiKey, opts = {}) {
    _suppressLog();
    var mtls;
    if (opts.clientCert && opts.clientKey && opts.ca) {
      mtls = { cert: opts.clientCert, key: opts.clientKey, ca: opts.ca };
    }
    this._client = new HttpClient({ server: baseUrl, mtls: mtls }, apiKey);
    // Tests use a self-signed CA — allow it at TLS layer.
    if (this._client._agent && this._client._agent.options) {
      this._client._agent.options.rejectUnauthorized = false;
    }
  }

  // Compat shim — pre-v1.9.15 callers performed an ECIES handshake here.
  // The new server short-circuits the envelope for Bearer clients, so this
  // is a no-op. Returns a synthetic 200 to preserve the legacy shape.
  async init() {
    return { statusCode: 200, headers: {}, body: '', json: null };
  }

  async request(urlPath, method, body) {
    var m = (method || 'GET').toUpperCase();
    var payload = (m === 'GET' || m === 'HEAD') ? null : (body === undefined ? {} : body);
    var resp = await this._client._jsonRequest(m, urlPath, payload);
    return {
      statusCode: resp.statusCode,
      headers: resp.headers,
      body: resp.body,
      json: resp.json,
    };
  }
}

/**
 * Upload a file via the sync client's HttpClient (lib/http-client.js).
 * Writes content to a temp file first, then calls HttpClient.uploadFile().
 *
 * Falls back to raw multipart for unauthenticated edge-case tests (no apiKey).
 *
 * Returns { statusCode, headers, body, json } for backward compat.
 */
function uploadFile(baseUrl, bundleId, relativePath, fileContent, apiKey) {
  var certPath = process.env.HERMITSTASH_TEST_CLIENT_CERT;
  var keyPath = process.env.HERMITSTASH_TEST_CLIENT_KEY;
  var caPath = process.env.HERMITSTASH_TEST_CA_CERT;

  if (apiKey && certPath && keyPath && caPath) {
    return _uploadViaClient(baseUrl, bundleId, relativePath, fileContent, apiKey, certPath, keyPath, caPath);
  }
  return _uploadRaw(baseUrl, bundleId, relativePath, fileContent, apiKey);
}

/**
 * Upload via the sync client's HttpClient — exercises the real upload path.
 */
async function _uploadViaClient(baseUrl, bundleId, relativePath, fileContent, apiKey, certPath, keyPath, caPath) {
  _suppressLog();
  var tempDir = createTempDir('upload');
  // Use a short temp filename to avoid Windows PATH_MAX with long relativePaths.
  // The real relativePath is passed to HttpClient.uploadFile() separately.
  var ext = path.extname(relativePath) || '.bin';
  var tempName = 'f-' + b.crypto.generateToken(4) + ext.slice(0, 10);
  var filePath = path.join(tempDir, tempName);
  var data = Buffer.isBuffer(fileContent) ? fileContent : Buffer.from(fileContent, 'utf8');
  fs.writeFileSync(filePath, data);

  var client = new HttpClient({
    server: baseUrl,
    mtls: { cert: certPath, key: keyPath, ca: caPath },
  }, apiKey);

  try {
    var result = await client.uploadFile(bundleId, relativePath, filePath);
    return { statusCode: 200, headers: {}, body: JSON.stringify(result || {}), json: result || {} };
  } catch (err) {
    var match = err.message.match(/HTTP (\d+)/);
    var statusCode = match ? parseInt(match[1]) : 500;
    return { statusCode: statusCode, headers: {}, body: err.message, json: null };
  } finally {
    client.destroy();
    rmrf(tempDir);
  }
}

/**
 * Raw multipart upload — for tests without auth that bypass the normal client flow.
 */
function _uploadRaw(baseUrl, bundleId, relativePath, fileContent, apiKey) {
  return new Promise((resolve, reject) => {
    var parsed = new URL(baseUrl);
    var boundary = '----HermitStashTest' + b.crypto.generateToken(8);
    var filename = path.basename(relativePath);
    var fileData = Buffer.isBuffer(fileContent) ? fileContent : Buffer.from(fileContent, 'utf8');

    var preamble = Buffer.from(
      '--' + boundary + '\r\n' +
      'Content-Disposition: form-data; name="relativePath"\r\n\r\n' +
      relativePath + '\r\n' +
      '--' + boundary + '\r\n' +
      'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n' +
      'Content-Type: application/octet-stream\r\n\r\n',
      'utf8'
    );
    var epilogue = Buffer.from('\r\n--' + boundary + '--\r\n', 'utf8');
    var bodyParts = Buffer.concat([preamble, fileData, epilogue]);

    var reqOpts = {
      hostname: parsed.hostname, port: parsed.port,
      path: '/drop/file/' + bundleId, method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': bodyParts.length,
      },
      rejectUnauthorized: false,
    };
    if (apiKey) reqOpts.headers['Authorization'] = 'Bearer ' + apiKey;

    var mod = parsed.protocol === 'https:' ? https : http;
    var req = mod.request(reqOpts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        var body = Buffer.concat(chunks).toString('utf8');
        var json = null;
        try { json = JSON.parse(body); } catch (_e) {}
        resolve({ statusCode: res.statusCode, headers: res.headers, body: body, json: json });
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, function () { req.destroy(new Error('Upload timeout')); });
    req.write(bodyParts);
    req.end();
  });
}

/**
 * SHA3-512 hash — delegates to the sync client's lib/checksum.js hashBuffer().
 * Accepts string or Buffer, returns hex string matching server's checksum field.
 */
function sha3(data) {
  return hashBuffer(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));
}

/**
 * Create an API key directly in the server's SQLite database.
 * Returns the raw key string (hs_...).
 */
function createApiKey(serverDbPath, permissions) {
  const perms = permissions || 'admin,upload,read,sync,webhook';
  const rawToken = 'hs_' + b.crypto.generateToken(32);
  const keyHash = sha3(rawToken);
  const prefix = rawToken.substring(0, 7);
  const id = b.crypto.generateToken(32);
  const now = new Date().toISOString();
  const dataDir = path.dirname(serverDbPath);

  // Seal via the same b.cryptoField.sealDoc path production uses. Requires
  // initialising vault inside the spawned process so b.vault.seal can run;
  // re-requiring lib/field-crypto registers all HS table schemas with
  // b.cryptoField (including api_keys.{name, prefix, permissions, ...}).
  // Without this, sealed columns sit as plaintext and only work because
  // field-crypto's read path falls back to raw on unseal failure — a
  // fragile contract that masks real schema-drift bugs.
  const script = [
    `process.env.HERMITSTASH_DATA_DIR = ${JSON.stringify(dataDir)};`,
    `process.env.HERMITSTASH_ALLOW_DISK_DB = 'true';`,
    `var vault = require('./lib/vault');`,
    `await vault.init();`,
    `require('./lib/field-crypto');`,
    `var b = require('./lib/vendor/blamejs');`,
    `var sealed = b.cryptoField.sealDoc('api_keys', {`,
    `  name: 'e2e-test',`,
    `  prefix: ${JSON.stringify(prefix)},`,
    `  permissions: ${JSON.stringify(perms)},`,
    `});`,
    `var users = db.prepare("SELECT _id FROM users ORDER BY createdAt ASC LIMIT 1").all();`,
    `var userId = users.length > 0 ? users[0]._id : 'system';`,
    `db.prepare("INSERT INTO api_keys (_id, name, keyHash, prefix, permissions, userId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)")`,
    `  .run(${JSON.stringify(id)}, sealed.name, ${JSON.stringify(keyHash)}, sealed.prefix, sealed.permissions, userId, ${JSON.stringify(now)});`,
    `process.stdout.write('OK');`,
  ].join('\n');

  const result = runDbScript(serverDbPath, script);
  if (result !== 'OK') throw new Error('Failed to create API key: ' + result);
  return rawToken;
}

/**
 * Wait for the server's health check to return 200.
 */
async function waitForHealth(port, maxWaitMs = 30000, useTls = false) {
  const start = Date.now();
  const protocol = useTls ? 'https' : 'http';
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await httpRequest(`${protocol}://127.0.0.1:${port}/health`);
      if (res.statusCode === 200) return true;
    } catch {}
    await sleep(300);
  }
  throw new Error(`Server did not become healthy within ${maxWaitMs}ms`);
}

/**
 * Generate a full PKI for testing: CA + server cert + client cert.
 *
 * Routes through `b.mtlsCa` instead of openssl shell-out — removes the
 * runtime dependency on the openssl binary (the test harness no longer
 * fails on minimal Windows / container hosts that lack it) and exercises
 * the same cert-issuance path the production server uses for sync-token
 * enrollment + browser cert issuance.
 *
 * caKeySealedMode: 'disabled' keeps the CA key as plaintext PEM on disk —
 * test-fixture only, the production CA is always sealed.
 *
 * Each call gets its OWN unique certs directory under the OS temp dir.
 * A shared path would let a secondary startServer() (e.g. the fresh-install
 * test spawning a second server) wipe + regenerate the CA, invalidating
 * every existing client cert against the still-running primary server —
 * which manifests as 403 on every subsequent WS upgrade because the new
 * client cert no longer chains to the primary's still-loaded CA.
 */
async function generateTestCerts() {
  const certsDir = createTempDir('test-certs');
  fs.mkdirSync(certsDir, { recursive: true });

  try {
    const ca = b.mtlsCa.create({
      dataDir:         certsDir,
      caKeySealedMode: 'disabled',
      generation:      1,
    });
    await ca.initCA();  // writes ca.crt + ca.key under certsDir

    // Server cert: serverAuth EKU + SANs for localhost loopback +
    // host.docker.internal (Docker Desktop's host-gateway DNS, used by
    // test-docker-e2e on Win/Mac where --network=host isn't available).
    const server = await ca.generateClientCert({
      cn:           'localhost',
      usage:        'server',
      sans:         ['DNS:localhost', 'DNS:host.docker.internal', 'IP:127.0.0.1'],
      validityDays: 3650,
    });
    const serverCertPath = path.join(certsDir, 'server.crt');
    const serverKeyPath  = path.join(certsDir, 'server.key');
    fs.writeFileSync(serverCertPath, server.cert);
    fs.writeFileSync(serverKeyPath, server.key);

    // Client cert for tests that exercise mTLS-authenticated paths.
    const client = await ca.generateClientCert({
      cn:           'hs_test_client',
      usage:        'client',
      validityDays: 3650,
    });
    const clientCertPath = path.join(certsDir, 'client.crt');
    const clientKeyPath  = path.join(certsDir, 'client.key');
    fs.writeFileSync(clientCertPath, client.cert);
    fs.writeFileSync(clientKeyPath, client.key);

    return {
      caCertPath:     path.join(certsDir, 'ca.crt'),
      serverCertPath,
      serverKeyPath,
      clientCertPath,
      clientKeyPath,
    };
  } catch (e) {
    console.error('[test-helpers] Failed to generate test certificates:', e.message);
    return null;
  }
}

/**
 * Start the HermitStash server for testing.
 *
 * opts.extraEnv  — object whose keys overlay the default env passed to the
 *                  server child process. Useful for tests that need to flip
 *                  defaults like SETUP_COMPLETE to exercise first-run flows.
 *                  Passing `null` clears the default (handy for SETUP_COMPLETE
 *                  which is `'true'` in the harness defaults).
 */
async function startServer(opts) {
  opts = opts || {};
  // Fail fast with an actionable message if the server source isn't
  // where we expected. The test suite spawns the real HermitStash
  // server out-of-process; it can't bootstrap without the source.
  if (!fs.existsSync(path.join(SERVER_DIR, 'server.js'))) {
    throw new Error(
      'HermitStash server source not found at ' + SERVER_DIR + '. ' +
      'Clone https://github.com/dotCooCoo/hermitstash next to this repo, ' +
      'or set HERMITSTASH_SERVER_DIR=/path/to/server before running tests.',
    );
  }

  const port = await getRandomPort();
  const dataDir = createTempDir('server-data');
  const uploadsDir = path.join(dataDir, 'uploads');
  fs.mkdirSync(uploadsDir, { recursive: true });

  const certs = await generateTestCerts();
  if (!certs) throw new Error('Cannot generate test certificates');

  const dbPath = path.join(dataDir, 'test.db');

  const env = {
    ...process.env,
    PORT: String(port),
    HERMITSTASH_DB_PATH: dbPath,
    // Isolate HERMITSTASH_DATA_DIR to this test's temp dir so the server's
    // vault.key / vault.key.sealed / db.key.enc don't clash with other
    // concurrent test runs or the developer's dev-state data/ directory.
    // Without this, setting VAULT_PASSPHRASE_MODE=required in the caller's
    // env would collide with a pre-existing plaintext vault.key in the
    // project's main data/ dir.
    HERMITSTASH_DATA_DIR: dataDir,
    HERMITSTASH_TMPDIR: dataDir,
    HERMITSTASH_ALLOW_DISK_DB: 'true',
    UPLOAD_DIR: uploadsDir,
    SETUP_COMPLETE: 'true',
    EMAIL_VERIFICATION: 'false',
    SESSION_SECRET: 'test-secret-' + b.crypto.generateToken(8),
    ARGON2_FAST: '1',
    PQC_ENFORCE: 'false',
    TLS_CERT: certs.serverCertPath,
    TLS_KEY: certs.serverKeyPath,
    MTLS_CA_CERT: certs.caCertPath,
    MTLS_CA_KEY: path.join(path.dirname(certs.caCertPath), 'ca.key'),
    // The shared E2E server is hammered by host tests + the docker
    // container, all NAT'd to 127.0.0.1 from the server's TCP view.
    // Production default (5/5min) burns through during a single run.
    // Codes are 64-bit one-time-use 1h-expiry — bumping the cap doesn't
    // change the brute-force floor in any meaningful way.
    SYNC_ENROLL_MAX: '500',
  };

  if (opts.extraEnv) {
    for (var k in opts.extraEnv) {
      if (opts.extraEnv[k] === null) delete env[k];
      else env[k] = opts.extraEnv[k];
    }
  }

  if (process.env.S3_TEST_BUCKET && process.env.S3_TEST_ACCESS_KEY && process.env.S3_TEST_SECRET_KEY) {
    env.STORAGE_BACKEND = 's3';
    env.S3_BUCKET = process.env.S3_TEST_BUCKET;
    env.S3_REGION = process.env.S3_TEST_REGION || 'us-west-1';
    env.S3_ACCESS_KEY = process.env.S3_TEST_ACCESS_KEY;
    env.S3_SECRET_KEY = process.env.S3_TEST_SECRET_KEY;
    if (process.env.S3_TEST_ENDPOINT) env.S3_ENDPOINT = process.env.S3_TEST_ENDPOINT;
  }
  if (process.env.BACKUP_TEST_BUCKET) {
    env.BACKUP_ENABLED = 'true';
    env.BACKUP_S3_BUCKET = process.env.BACKUP_TEST_BUCKET;
    env.BACKUP_S3_REGION = process.env.S3_TEST_REGION || 'us-west-1';
    env.BACKUP_S3_ACCESS_KEY = process.env.S3_TEST_ACCESS_KEY;
    env.BACKUP_S3_SECRET_KEY = process.env.S3_TEST_SECRET_KEY;
    if (process.env.S3_TEST_ENDPOINT) env.BACKUP_S3_ENDPOINT = process.env.S3_TEST_ENDPOINT;
  }

  const serverProcess = spawn(process.execPath, ['server.js'], {
    cwd: SERVER_DIR, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  });

  let stdout = '';
  let stderr = '';
  serverProcess.stdout.on('data', d => { stdout += d.toString(); });
  serverProcess.stderr.on('data', d => { stderr += d.toString(); });
  serverProcess.on('error', err => { console.error('[test-helpers] Server process error:', err.message); });

  try {
    await waitForHealth(port, 30000, true);
  } catch (err) {
    console.error('[test-helpers] Server stdout:', stdout);
    console.error('[test-helpers] Server stderr:', stderr);
    try { serverProcess.kill('SIGTERM'); } catch {}
    throw err;
  }

  // Wait for the default admin user to be created — the server inserts it
  // asynchronously after startup (hashPassword is async), so it may not
  // exist immediately after the health check passes.
  var userWaitStart = Date.now();
  while (Date.now() - userWaitStart < 10000) {
    try {
      var userCheck = runDbScript(dbPath, [
        'var row = db.prepare("SELECT COUNT(*) as cnt FROM users").get();',
        'process.stdout.write(String(row ? row.cnt : 0));',
      ].join('\n'));
      if (parseInt(userCheck, 10) > 0) break;
    } catch (_e) { /* DB may not be ready yet */ }
    await sleep(200);
  }

  const apiKey = createApiKey(dbPath, 'admin,upload,read,sync,webhook');
  const syncDir = createTempDir('sync-folder');

  const baseUrl = `https://127.0.0.1:${port}`;
  const client = new ApiClient(baseUrl, apiKey, {
    clientCert: certs.clientCertPath,
    clientKey: certs.clientKeyPath,
    ca: certs.caCertPath,
  });
  await client.init();

  // Production HttpClient — exercises the real client code path (PQC TLS, connection pooling, ECIES)
  const HttpClient = require(path.join(__dirname, '..', 'lib', 'http-client'));
  const prodClient = new HttpClient({
    server: baseUrl,
    mtls: {
      cert: certs.clientCertPath,
      key: certs.clientKeyPath,
      ca: certs.caCertPath,
    },
  }, apiKey);
  // Allow self-signed test certs
  prodClient._agent.options.rejectUnauthorized = false;

  return {
    url: baseUrl, port, apiKey, client, prodClient, certs, serverProcess,
    dataDir, uploadsDir, dbPath, syncDir,
    stdout: () => stdout, stderr: () => stderr,
  };
}

/**
 * Stop the server and clean up temp directories.
 */
async function stopServer(ctx) {
  if (!ctx) return;
  if (ctx.serverProcess) {
    try { ctx.serverProcess.kill('SIGTERM'); } catch {}
    await new Promise(resolve => {
      const timeout = setTimeout(() => {
        try { ctx.serverProcess.kill('SIGKILL'); } catch {}
        resolve();
      }, 5000);
      ctx.serverProcess.on('exit', () => { clearTimeout(timeout); resolve(); });
    });
  }
  await sleep(200);
  rmrf(ctx.dataDir);
  rmrf(ctx.syncDir);
}

// ---- Bundle helpers (DB infrastructure — not client library code) ----

async function createBundleViaApi(baseUrl, apiKey, dbPath, opts = {}) {
  if (!opts._client) throw new Error('createBundleViaApi requires opts._client (initialized ApiClient)');
  const bundleType = opts.bundleType || 'sync';

  // Server v1.9.15+ routes /drop/init through blamejs apiEncrypt (per-session
  // PQC envelope). Fetch the server's published pubkey, then post via
  // b.httpClient.encrypted so the body is wrapped in `{ _ek, _ct, _ts,
  // _nonce }` (first call) and the response is auto-decrypted.
  const pubkeyResp = await opts._client.request('/.well-known/blamejs-pubkey', 'GET');
  if (pubkeyResp.statusCode !== 200 || !pubkeyResp.json) {
    throw new Error('Failed to fetch /.well-known/blamejs-pubkey: HTTP ' + pubkeyResp.statusCode);
  }

  const bHttpClientEncrypted = require('../vendor/blamejs/lib/middleware/api-encrypt').httpClient;
  const enc = bHttpClientEncrypted({
    pubkey:  pubkeyResp.json,
    baseUrl: baseUrl,
    headers: Object.assign({}, TEST_BROWSER_HEADERS, { Authorization: 'Bearer ' + apiKey }),
    keying:  'per-session',
  });

  const resp = await enc.request({
    method: 'POST',
    path:   '/drop/init',
    body:   { uploaderName: 'E2E Test', bundleType: bundleType, fileCount: 0 },
    agent:  opts._client._client._agent,    // mTLS + PQC + self-signed CA accept
    allowInternal: true,
  });
  if (resp.statusCode !== 200) throw new Error('Failed to create bundle via API: HTTP ' + resp.statusCode);
  const data = resp.body;
  if (!data || !data.bundleId) throw new Error('Failed to parse bundle init response');
  return { bundleId: data.bundleId, shareId: data.shareId, finalizeToken: data.finalizeToken };
}

function createBundleViaDb(dbPath, opts = {}) {
  const bundleType = opts.bundleType || 'sync';
  const shareId = b.crypto.generateToken(32);
  const bundleId = b.crypto.generateToken(32);
  const finalizeToken = b.crypto.generateToken(32);
  const finalizeTokenHash = sha3(finalizeToken);
  const shareIdHash = sha3('hs-share:' + shareId);
  const now = new Date().toISOString();
  const dataDir = path.dirname(dbPath);

  // Seal via the same b.cryptoField.sealDoc path production uses — see
  // createApiKey for the same pattern + rationale (vault.init + require
  // lib/field-crypto to register schemas, then sealDoc the doc and INSERT
  // the sealed values).
  const script = [
    `process.env.HERMITSTASH_DATA_DIR = ${JSON.stringify(dataDir)};`,
    `process.env.HERMITSTASH_ALLOW_DISK_DB = 'true';`,
    `var vault = require('./lib/vault');`,
    `await vault.init();`,
    `require('./lib/field-crypto');`,
    `var b = require('./lib/vendor/blamejs');`,
    `var sealed = b.cryptoField.sealDoc('bundles', {`,
    `  uploaderName: 'E2E Test',`,
    `  uploaderEmail: 'test@hermitstash.com',`,
    `});`,
    `var users = db.prepare("SELECT _id FROM users ORDER BY createdAt ASC LIMIT 1").all();`,
    `var userId = users.length > 0 ? users[0]._id : null;`,
    `db.prepare("INSERT INTO bundles (_id, shareId, shareIdHash, uploaderName, uploaderEmail, expectedFiles, receivedFiles, skippedCount, totalSize, downloads, status, bundleType, seq, finalizeTokenHash, ownerId, stashId, accessMode, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")`,
    `  .run(`,
    `    ${JSON.stringify(bundleId)}, ${JSON.stringify(shareId)}, ${JSON.stringify(shareIdHash)},`,
    `    sealed.uploaderName, sealed.uploaderEmail, 0, 0, 0, 0, 0,`,
    `    ${JSON.stringify(bundleType === 'sync' ? 'complete' : 'uploading')},`,
    `    ${JSON.stringify(bundleType)}, 0, ${JSON.stringify(finalizeTokenHash)},`,
    `    ${opts.ownerId ? JSON.stringify(opts.ownerId) : 'userId'},`,
    `    ${opts.stashId ? JSON.stringify(opts.stashId) : 'null'}, 'open', ${JSON.stringify(now)}`,
    `  );`,
    `process.stdout.write('OK');`,
  ].join('\n');

  const result = runDbScript(dbPath, script);
  if (result !== 'OK') throw new Error('Failed to create bundle: ' + result);
  return { bundleId, shareId, finalizeToken };
}

function createSnapshotBundleViaDb(dbPath) {
  return createBundleViaDb(dbPath, { bundleType: 'snapshot' });
}

function getBundleFromDb(dbPath, bundleId) {
  const script = [
    `var row = db.prepare("SELECT _id, status, bundleType, seq, receivedFiles, totalSize, downloads, ownerId, createdAt, accessMode, expectedFiles, skippedCount FROM bundles WHERE _id = ?").get(${JSON.stringify(bundleId)});`,
    `process.stdout.write(JSON.stringify(row || null));`,
  ].join('\n');
  return JSON.parse(runDbScript(dbPath, script));
}

function getBundleFilesFromDb(dbPath, bundleId) {
  const script = [
    `var rows = db.prepare("SELECT _id, bundleId, uploadedBy, size, downloads, status, seq, createdAt, updatedAt, deletedAt FROM files WHERE bundleId = ?").all(${JSON.stringify(bundleId)});`,
    `process.stdout.write(JSON.stringify(rows));`,
  ].join('\n');
  return JSON.parse(runDbScript(dbPath, script));
}

function countBundleFiles(dbPath, bundleId) {
  const script = [
    `var row = db.prepare("SELECT COUNT(*) as cnt FROM files WHERE bundleId = ? AND deletedAt IS NULL").get(${JSON.stringify(bundleId)});`,
    `process.stdout.write(String(row ? row.cnt : 0));`,
  ].join('\n');
  return parseInt(runDbScript(dbPath, script), 10);
}

// ---- WebSocket connection for tests ----
// Uses the production lib/ws-client.js with { reconnect: false } so tests
// exercise the same code path the real client daemon runs.

/**
 * Create a WsClient configured for tests (no auto-reconnect, self-signed CA).
 * Does NOT call connect() — the caller should attach 'message'/'open' listeners
 * first, then call wsClient.connect(bundleId, since).
 */
function newTestWsClient(url, apiKey) {
  var certPath = process.env.HERMITSTASH_TEST_CLIENT_CERT;
  var keyPath = process.env.HERMITSTASH_TEST_CLIENT_KEY;
  var caPath = process.env.HERMITSTASH_TEST_CA_CERT;
  // No `tls: { rejectUnauthorized: false }` here: the client ignores
  // config-supplied TLS options (see _configTlsOverrides in lib/ws-client.js), so
  // it would be inert and would only read as still-supported. The harness reaches
  // the test server with verification ON — the test CA below is bundled into the
  // trust anchors additively. If a future harness change breaks the handshake,
  // fix the certificate or the CA path; do NOT reach for
  // HERMITSTASH_ALLOW_INSECURE_TLS, which restores the full passthrough for every
  // dial in the process.
  var config = {
    server: url,
    reconnect: false,
  };
  if (certPath && keyPath && caPath) {
    config.mtls = { cert: certPath, key: keyPath, ca: caPath };
  }
  return new WsClient(config, apiKey);
}

/**
 * Wait for an event on an EventEmitter where the payload satisfies a predicate.
 * Attaches the listener synchronously, so callers should invoke this BEFORE
 * triggering the action that causes the event.
 */
function waitFor(emitter, eventName, predicate, timeoutMs) {
  timeoutMs = timeoutMs || 1000;
  return new Promise(function (resolve, reject) {
    var timer = setTimeout(function () {
      emitter.off(eventName, handler);
      reject(new Error('Timed out waiting for ' + eventName + ' after ' + timeoutMs + 'ms'));
    }, timeoutMs);
    var handler = function (arg) {
      if (predicate(arg)) {
        clearTimeout(timer);
        emitter.off(eventName, handler);
        resolve(arg);
      }
    };
    emitter.on(eventName, handler);
  });
}

/**
 * Connect a WsClient, wait for 'open', rejecting on 'upgrade_rejected' or 'error'.
 * Returns the connected client.
 */
async function connectWsClient(ws, bundleId, since, timeoutMs) {
  timeoutMs = timeoutMs || 2000;
  var openedP = new Promise(function (resolve, reject) {
    var timer = setTimeout(function () { reject(new Error('WS connect timeout')); }, timeoutMs);
    ws.once('open', function () { clearTimeout(timer); resolve(); });
    ws.once('upgrade_rejected', function (info) { clearTimeout(timer); var e = new Error('WS upgrade rejected'); e.status = info.status; e.body = info.body; reject(e); });
    ws.once('error', function (err) { clearTimeout(timer); reject(err); });
  });
  ws.connect(bundleId, since === undefined ? 0 : since);
  await openedP;
  return ws;
}

/**
 * Attempt to connect with bad/missing auth. Resolves with { statusCode, body }
 * when the upgrade is rejected, or rejects if the connection unexpectedly opens.
 */
function expectWsRejectClient(url, apiKey, bundleId, since, timeoutMs) {
  var ws = newTestWsClient(url, apiKey);
  return new Promise(function (resolve, reject) {
    var timer = setTimeout(function () { ws.close(); reject(new Error('Expected rejection, got timeout')); }, timeoutMs || 2000);
    ws.once('upgrade_rejected', function (info) {
      clearTimeout(timer); ws.close();
      resolve({ statusCode: info.status, body: info.body });
    });
    ws.once('open', function () { clearTimeout(timer); ws.close(); reject(new Error('Upgrade succeeded unexpectedly')); });
    ws.once('error', function (err) { clearTimeout(timer); ws.close(); reject(err); });
    ws.connect(bundleId, since === undefined ? 0 : since);
  });
}


/**
 * Compute the cert fingerprint the same way the server does:
 * reconstruct PEM from DER (64-char lines), then SHA3-512 hash.
 */
function computeCertFingerprint(certPemPath) {
  var certPem = fs.readFileSync(certPemPath, 'utf8');
  var b64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');
  var der = Buffer.from(b64, 'base64');
  var derB64 = der.toString('base64');
  var reconstructedPem = '-----BEGIN CERTIFICATE-----\n'
    + derB64.match(/.{1,64}/g).join('\n')
    + '\n-----END CERTIFICATE-----\n';
  return sha3(reconstructedPem);
}

/**
 * Count rows in a table (raw SQL — works even for sealed tables).
 */
function countTableRows(dbPath, tableName, whereClause) {
  var where = whereClause ? ' WHERE ' + whereClause : '';
  var script = [
    'var row = db.prepare("SELECT COUNT(*) as cnt FROM ' + tableName + where + '").get();',
    'process.stdout.write(String(row ? row.cnt : 0));',
  ].join('\n');
  return parseInt(runDbScript(dbPath, script), 10);
}

module.exports = {
  SERVER_DIR,
  MSG,
  ApiClient,
  HttpClient,
  WsClient,
  startServer,
  stopServer,
  sleep,
  createTempDir,
  rmrf,
  httpRequest,
  encryptedRequest,
  uploadFile,
  sha3,
  createApiKey,
  runDbScript,
  createBundleViaApi,
  createBundleViaDb,
  createSnapshotBundleViaDb,
  getBundleFromDb,
  getBundleFilesFromDb,
  countBundleFiles,
  newTestWsClient,
  waitFor,
  connectWsClient,
  expectWsRejectClient,
  computeCertFingerprint,
  countTableRows,
};
