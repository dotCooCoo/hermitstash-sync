'use strict';

/**
 * Byte-rate throttle wiring tests for lib/http-client.js.
 *
 * b.streamThrottle is unit-tested as a standalone primitive elsewhere; this
 * file covers the HttpClient INTEGRATION the primitive test cannot reach:
 *
 *   1. _throttledIdleTimeout() arithmetic — with no throttle it returns the
 *      base 30s idle window; with a low rate it scales to the worst-case
 *      single-chunk throttle-wait plus the base, so a slow-but-progressing
 *      throttled transfer is NOT aborted while one ~64 KiB chunk's wait
 *      legitimately exceeds 30s. A wrong heuristic either kills legitimate
 *      slow transfers (too low) or never catches a stalled socket (unbounded).
 *   2. A configured downloadBytesPerSec actually limits throughput AND lets a
 *      slow transfer complete — the scaled idle timeout does not abort it
 *      mid-throttle-wait, and the post-download SHA3-512 still verifies.
 *
 * The integration part stands up its own PQC TLS 1.3 + mTLS HTTPS server (the
 * same posture the production client dials) via b.mtlsCa, exactly like
 * test-http-teardown.js, so it drives the REAL download path with no shim.
 * Skips if cert generation is unavailable.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeHttps = require('node:https');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const b = require('../vendor/blamejs');
const { createTempDir, rmrf } = require('./test-helpers');

const HttpClient = require('../lib/http-client');
const { TLS_GROUPS, TLS_MIN_VERSION } = require('../lib/constants');

const C = b.constants;

async function makeCerts() {
  const certsDir = createTempDir('throttle-certs');
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
      dir: certsDir, caCert,
      serverCert: server.cert, serverKey: server.key,
      clientCert: client.cert, clientKey: client.key,
    };
  } catch (_e) {
    rmrf(certsDir);
    return null;
  }
}

function startServer(certs, onRequest) {
  const server = nodeHttps.createServer({
    cert: certs.serverCert, key: certs.serverKey, ca: certs.caCert,
    requestCert: true, rejectUnauthorized: false,
    minVersion: TLS_MIN_VERSION, ecdhCurve: TLS_GROUPS, groups: TLS_GROUPS,
  }, onRequest);
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function makeClient(certs, port, extraCfg) {
  const cfg = Object.assign({
    server: 'https://127.0.0.1:' + port,
    mtls: {
      cert: Buffer.from(certs.clientCert, 'utf8'),
      key:  Buffer.from(certs.clientKey, 'utf8'),
      ca:   Buffer.from(certs.caCert, 'utf8'),
    },
  }, extraCfg || {});
  const client = new HttpClient(cfg, 'hs_throttle_test_key');
  if (client._agent && client._agent.options) {
    client._agent.options.rejectUnauthorized = false;
  }
  return client;
}

describe('_throttledIdleTimeout arithmetic', () => {
  it('returns the base 30s window when unthrottled (0 / negative)', () => {
    const client = new HttpClient({ server: 'http://127.0.0.1:9/' }, 'k');
    const base = C.TIME.seconds(30);
    assert.strictEqual(client._throttledIdleTimeout(0), base);
    assert.strictEqual(client._throttledIdleTimeout(-1), base);
    assert.strictEqual(client._throttledIdleTimeout(undefined), base);
    client.destroy();
  });

  it('scales to the worst-case single-chunk throttle-wait plus the base at a low rate', () => {
    const client = new HttpClient({ server: 'http://127.0.0.1:9/' }, 'k');
    const base = C.TIME.seconds(30);
    const rate = 1024; // 1 KiB/s
    const chunkBytes = C.BYTES.kib(64); // createReadStream default highWaterMark
    const chunkWaitMs = Math.ceil(C.TIME.seconds(chunkBytes / rate)); // 64000ms
    const expected = Math.max(base, chunkWaitMs + base);
    assert.strictEqual(client._throttledIdleTimeout(rate), expected);
    // Sanity: at 1 KiB/s a single 64 KiB chunk's wait (64s) exceeds the base
    // 30s, so the scaled window must be strictly larger than the base.
    assert.ok(client._throttledIdleTimeout(rate) > base);
    client.destroy();
  });

  it('never returns below the base, even at very high rates', () => {
    const client = new HttpClient({ server: 'http://127.0.0.1:9/' }, 'k');
    const base = C.TIME.seconds(30);
    // 100 MiB/s -> a single-chunk wait far under the base. The window stays at
    // (or a rounding-floor 1ms above) the base; never below it.
    const out = client._throttledIdleTimeout(C.BYTES.mib(100));
    assert.ok(out >= base, 'must never drop below the base idle window');
    assert.ok(out <= base + 5, 'a high rate adds at most a sub-millisecond rounding floor, got ' + out);
    client.destroy();
  });

  it('a configured throttle rate is reflected on the constructed client', () => {
    const client = new HttpClient({
      server: 'http://127.0.0.1:9/',
      uploadBytesPerSec: 4096,
      downloadBytesPerSec: 8192,
    }, 'k');
    assert.ok(client._uploadLimiter, 'upload limiter constructed when rate > 0');
    assert.ok(client._downloadLimiter, 'download limiter constructed when rate > 0');
    assert.strictEqual(client._uploadBytesPerSec, 4096);
    assert.strictEqual(client._downloadBytesPerSec, 8192);
    client.destroy();
  });

  it('zero / unset rates build no limiter (pass-through)', () => {
    const client = new HttpClient({ server: 'http://127.0.0.1:9/' }, 'k');
    assert.strictEqual(client._uploadLimiter, null);
    assert.strictEqual(client._downloadLimiter, null);
    assert.strictEqual(client._uploadBytesPerSec, 0);
    assert.strictEqual(client._downloadBytesPerSec, 0);
    client.destroy();
  });
});

describe('throttled download integration', { timeout: 30000 }, () => {
  let certs = null;

  before(async () => { certs = await makeCerts(); });
  after(() => { if (certs) rmrf(certs.dir); });

  it('a configured downloadBytesPerSec limits throughput yet the slow transfer completes and verifies', async (t) => {
    if (!certs) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');

    // The limiter starts with a full bucket (one second of tokens == RATE
    // bytes), so the first RATE bytes pass immediately and only SIZE-RATE
    // bytes are actually throttled. Size the payload to several times the rate
    // so the throttled remainder dominates the wall clock: 256 KiB at 64 KiB/s
    // throttles ~192 KiB -> ~3s, while staying a few-second test.
    const SIZE = C.BYTES.kib(256);
    const RATE = C.BYTES.kib(64);
    const payload = nodeCrypto.randomBytes(SIZE);
    const checksum = nodeCrypto.createHash('sha3-512').update(payload).digest('hex');

    const server = await startServer(certs, (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payload.length),
      });
      res.end(payload);
    });
    const port = server.address().port;

    const tempDir = createTempDir('throttle-dl');
    const destPath = nodePath.join(tempDir, 'throttled.bin');
    const client = makeClient(certs, port, { downloadBytesPerSec: RATE });

    try {
      const start = Date.now();
      const out = await client.downloadFile('file-throttle', destPath, checksum, SIZE);
      const elapsed = Date.now() - start;

      assert.strictEqual(out, destPath);
      // The file landed and its bytes match (checksum already verified inside
      // downloadFile, but assert on disk too).
      const onDisk = nodeFs.readFileSync(destPath);
      assert.strictEqual(onDisk.length, SIZE);
      assert.strictEqual(
        nodeCrypto.createHash('sha3-512').update(onDisk).digest('hex'), checksum);

      // Throttle actually applied: after the initial one-second burst (RATE
      // bytes), the remaining SIZE-RATE bytes drain at RATE bytes/sec. The
      // transfer cannot finish faster than that throttled-remainder floor. Use
      // a conservative fraction to absorb scheduler jitter while still proving
      // the limiter is in-circuit (an un-throttled localhost transfer of this
      // size completes in single-digit milliseconds, far under the floor).
      const floorMs = ((SIZE - RATE) / RATE) * 1000 * 0.5;
      assert.ok(elapsed >= floorMs,
        'throttle should slow the transfer: elapsed=' + elapsed + 'ms floor=' + floorMs + 'ms');
    } finally {
      client.destroy();
      await new Promise((r) => server.close(r));
      rmrf(tempDir);
    }
  });
});
