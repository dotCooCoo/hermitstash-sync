'use strict';

/**
 * HttpClient stream-teardown tests.
 *
 * Exercises the production lib/http-client.js transfer paths against a
 * local adversarial HTTPS + mTLS server that deliberately resets the
 * socket mid-response (or mid-error-body). The point is to prove that a
 * peer RST during the response phase:
 *
 *   1. rejects the upload/download promise (so the sync engine's
 *      retry/breaker can mark the file ERROR and recover), and
 *   2. does NOT escape as an uncaughtException that would crash the daemon, and
 *   3. releases the source file descriptor on the upload path (no fd leak that
 *      would accumulate toward EMFILE on a long-running daemon, or keep the
 *      Windows file handle live and block a follow-up rename).
 *
 * These tests stand up their own server rather than reusing the shared
 * HermitStash test server, because they need byte-level control over when
 * the socket is destroyed. They still drive the REAL HttpClient (PQC TLS,
 * mTLS, the production upload/download methods) — no test-only shim.
 *
 * Requires OpenSSL-free PKI via b.mtlsCa (generateTestCerts). If cert
 * generation is unavailable the suite skips itself.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeHttps = require('node:https');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeNet = require('node:net');
const b = require('../vendor/blamejs');
const {
  createTempDir, rmrf, sha3,
} = require('./test-helpers');

const HttpClient = require('../lib/http-client');
const { TLS_GROUPS, TLS_MIN_VERSION } = require('../lib/constants');

// Reuse the OpenSSL-free PKI generator from test-helpers without standing up
// a full HermitStash server. generateTestCerts() is not exported, so build
// the same CA + server + client trio directly via b.mtlsCa here.
async function makeCerts() {
  const certsDir = createTempDir('teardown-certs');
  try {
    const ca = b.mtlsCa.create({ dataDir: certsDir, caKeySealedMode: 'disabled', generation: 1 });
    await ca.initCA();
    const server = await ca.generateClientCert({
      cn: 'localhost', usage: 'server',
      sans: ['DNS:localhost', 'IP:127.0.0.1'], validityDays: 3650,
    });
    const client = await ca.generateClientCert({
      cn: 'hs_test_client', usage: 'client', validityDays: 3650,
    });
    const caCert = nodeFs.readFileSync(nodePath.join(certsDir, 'ca.crt'), 'utf8');
    return {
      dir: certsDir,
      caCert,
      serverCert: server.cert, serverKey: server.key,
      clientCert: client.cert, clientKey: client.key,
    };
  } catch (e) {
    rmrf(certsDir);
    return null;
  }
}

// Start a local HTTPS server whose request handler is supplied per-test. The
// server speaks the same PQC TLS 1.3 + mTLS posture the production client
// dials. requestUnauthorized is allowed (self-signed CA) but a client cert is
// requested so the mTLS path is exercised.
function startServer(certs, onRequest) {
  const server = nodeHttps.createServer({
    cert: certs.serverCert,
    key: certs.serverKey,
    ca: certs.caCert,
    requestCert: true,
    rejectUnauthorized: false,
    minVersion: TLS_MIN_VERSION,
    ecdhCurve: TLS_GROUPS,
    groups: TLS_GROUPS,
  }, onRequest);
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function makeClient(certs, port) {
  // Pass the PEMs as Buffers — buildTlsOptions treats a string as a file path
  // (readFileSync) and only takes a Buffer verbatim, so the in-memory PEMs
  // from b.mtlsCa must be wrapped to avoid an ENOENT on the PEM text.
  const client = new HttpClient({
    server: `https://127.0.0.1:${port}`,
    mtls: {
      cert: Buffer.from(certs.clientCert, 'utf8'),
      key:  Buffer.from(certs.clientKey, 'utf8'),
      ca:   Buffer.from(certs.caCert, 'utf8'),
    },
  }, 'hs_teardown_test_key');
  // Self-signed test CA — accept at the TLS layer, same as the shared harness.
  if (client._agent && client._agent.options) {
    client._agent.options.rejectUnauthorized = false;
  }
  return client;
}

describe('HttpClient stream teardown', { timeout: 30000 }, () => {
  let certs;

  before(async () => {
    certs = await makeCerts();
  });

  after(() => {
    if (certs) rmrf(certs.dir);
  });

  it('upload: socket reset mid-response rejects without crashing the process', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    // Track uncaughtExceptions for the duration of this test — a leaked
    // res.on('error') is exactly the sink that would surface here.
    const uncaught = [];
    const onUncaught = (err) => { uncaught.push(err); };
    process.on('uncaughtException', onUncaught);

    // Server: read the whole upload, then start the response and destroy the
    // socket mid-flight (after headers, before the body completes) so the
    // client sees a reset during the response phase.
    const server = await startServer(certs, (req, res) => {
      req.on('data', () => {});
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '4096' });
        res.write('{"par');
        // Rip the underlying socket out from under the half-written response.
        res.socket.destroy();
      });
      req.on('error', () => {});
    });
    const port = server.address().port;

    const tempDir = createTempDir('teardown-upload');
    const filePath = nodePath.join(tempDir, 'payload.bin');
    nodeFs.writeFileSync(filePath, Buffer.alloc(b.constants.BYTES.kib(64), 0x41));

    const client = makeClient(certs, port);
    try {
      await assert.rejects(
        client.uploadFile('bundle-teardown', 'payload.bin', filePath),
        (err) => err instanceof Error,
        'upload should reject when the response socket is reset mid-stream',
      );

      // Give any stray async error a tick to surface before asserting.
      await new Promise((r) => setImmediate(r));
      assert.equal(uncaught.length, 0,
        'a mid-response socket reset must not escape as uncaughtException: ' +
        uncaught.map((e) => e && e.message).join('; '));
    } finally {
      process.off('uncaughtException', onUncaught);
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });

  it('upload: source fd is released after a failed upload (no fd leak)', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    // Server resets the connection during the request body so the upload
    // fails while the source read stream is still being consumed.
    const server = await startServer(certs, (req, res) => {
      // Destroy on the first body chunk — the source stream is mid-read.
      req.once('data', () => { req.socket.destroy(); });
      req.on('error', () => {});
      res.on('error', () => {});
    });
    const port = server.address().port;

    const tempDir = createTempDir('teardown-fd');
    const filePath = nodePath.join(tempDir, 'leak-check.bin');
    nodeFs.writeFileSync(filePath, Buffer.alloc(b.constants.BYTES.mib(1), 0x42));

    const client = makeClient(certs, port);
    try {
      await assert.rejects(
        client.uploadFile('bundle-teardown', 'leak-check.bin', filePath),
        'upload should reject when the request socket is reset mid-body',
      );

      // Proxy for "the source fd was released": once uploadFile's cleanup has
      // destroyed the read stream, the source file is no longer held open, so
      // renaming it must succeed. On Windows a leaked exclusive handle blocks
      // the rename; on POSIX a leaked fd would eventually exhaust the table.
      // Retry briefly — destroy() completes on the next tick.
      const movedPath = filePath + '.moved';
      let renamed = false;
      for (let i = 0; i < 20 && !renamed; i++) {
        try { nodeFs.renameSync(filePath, movedPath); renamed = true; }
        catch { await b.safeAsync.sleep(10); }
      }
      assert.equal(renamed, true,
        'source file should be renamable after a failed upload — a held fd ' +
        'indicates the read stream was not destroyed on the failure path');
    } finally {
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });

  it('download: non-200 error-body socket reset rejects without crashing', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    const uncaught = [];
    const onUncaught = (err) => { uncaught.push(err); };
    process.on('uncaughtException', onUncaught);

    // Server answers a 500, starts writing the error body, then resets — this
    // exercises the non-200 branch's res.on('error') handler.
    const server = await startServer(certs, (req, res) => {
      res.writeHead(500, { 'Content-Type': 'text/plain', 'Content-Length': '256' });
      res.write('partial error b');
      res.socket.destroy();
      req.on('error', () => {});
    });
    const port = server.address().port;

    const tempDir = createTempDir('teardown-download');
    const destPath = nodePath.join(tempDir, 'sub', 'out.bin');

    const client = makeClient(certs, port);
    try {
      await assert.rejects(
        client.downloadFile('file-teardown', destPath, sha3('never written')),
        'download should reject when the error-body socket is reset mid-stream',
      );

      await new Promise((r) => setImmediate(r));
      assert.equal(uncaught.length, 0,
        'a non-200 error-body socket reset must not escape as uncaughtException: ' +
        uncaught.map((e) => e && e.message).join('; '));

      // No temp file should be left behind.
      const leftover = nodeFs.existsSync(nodePath.dirname(destPath))
        ? nodeFs.readdirSync(nodePath.dirname(destPath)).filter((f) => f.indexOf('.tmp.') !== -1)
        : [];
      assert.deepEqual(leftover, [], 'failed download should not leave a temp file behind');
    } finally {
      process.off('uncaughtException', onUncaught);
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });

  it('download: success commits via the lock-tolerant rename', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    const payload = Buffer.from('hermitstash teardown download body', 'utf8');
    const checksum = sha3(payload);

    const server = await startServer(certs, (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payload.length),
      });
      res.end(payload);
      req.on('error', () => {});
    });
    const port = server.address().port;

    const tempDir = createTempDir('teardown-dl-ok');
    const destPath = nodePath.join(tempDir, 'nested', 'committed.bin');

    const client = makeClient(certs, port);
    try {
      const result = await client.downloadFile('file-ok', destPath, checksum);
      assert.equal(result, destPath);
      assert.equal(nodeFs.readFileSync(destPath).toString('utf8'), payload.toString('utf8'),
        'committed file should match the downloaded bytes');
      // No orphan temp survives a successful commit.
      const leftover = nodeFs.readdirSync(nodePath.dirname(destPath))
        .filter((f) => f.indexOf('.tmp.') !== -1);
      assert.deepEqual(leftover, [], 'successful download should leave no temp file');
    } finally {
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });

  it('download: a truncated body with NO checksum is rejected on the exact-size check', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    // The client expects 64 bytes (from the WS event) but the server delivers
    // only 32. With no reference checksum (a content-unchanged rename into
    // selective-sync scope), the exact-size assertion is the only integrity
    // guard — a short body must be refused, not committed as SYNCED.
    const body = Buffer.alloc(32, 0x43);
    const server = await startServer(certs, (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(body.length) });
      res.end(body);
      req.on('error', () => {});
    });
    const port = server.address().port;
    const tempDir = createTempDir('teardown-dl-trunc');
    const destPath = nodePath.join(tempDir, 'short.bin');
    const client = makeClient(certs, port);
    try {
      await assert.rejects(
        client.downloadFile('file-trunc', destPath, undefined, 64),
        /size mismatch/i,
        'a body shorter than the declared size must be refused when there is no checksum',
      );
      assert.equal(nodeFs.existsSync(destPath), false, 'no truncated file is committed');
      const leftover = nodeFs.readdirSync(tempDir).filter((f) => f.indexOf('.tmp.') !== -1);
      assert.deepEqual(leftover, [], 'the rejected download leaves no temp file');
    } finally {
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });

  it('download: a correctly-sized body with NO checksum still commits', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    // Control: a legitimate checksumless download (exact size) must still land.
    const body = Buffer.from('a content-unchanged rename moved me into scope', 'utf8');
    const server = await startServer(certs, (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(body.length) });
      res.end(body);
      req.on('error', () => {});
    });
    const port = server.address().port;
    const tempDir = createTempDir('teardown-dl-nosum');
    const destPath = nodePath.join(tempDir, 'moved.bin');
    const client = makeClient(certs, port);
    try {
      const result = await client.downloadFile('file-nosum', destPath, undefined, body.length);
      assert.equal(result, destPath);
      assert.equal(nodeFs.readFileSync(destPath).toString('utf8'), body.toString('utf8'),
        'a correctly-sized checksumless download commits unchanged');
    } finally {
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });
});

// Allow standalone invocation (node tests/test-http-teardown.js) without the
// run-all harness — node:test auto-runs the described suite on require.
void nodeNet;
