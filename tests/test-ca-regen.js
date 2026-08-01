'use strict';

/**
 * E2E tests for mTLS CA regeneration + WS rotation protocol.
 *
 * Uses the shared test server with { skipRestart: true } on
 * /admin/api/mtls-ca/regenerate — full orchestration runs (version check →
 * in-memory CA gen → WS broadcast → ack collection → summary response) but
 * the commit + process.exit steps are skipped so the shared server remains
 * usable by downstream tests. The WS rotation message is sent with
 * dryRun: true, which tells sync-engine to ack without writing files.
 *
 * Coverage:
 *   - GET /admin/api/mtls-ca/status reports legacy detection (openssl-
 *     generated test CA is untagged → generation 1 → legacy vs the current generation).
 *   - POST /admin/api/mtls-ca/regenerate rejects missing REGEN confirm.
 *   - Fast path: no live clients → summary returned immediately.
 *   - Full rotation path: connected sync WS client receives ca:rotation
 *     (dryRun=true) with well-formed payload, ack is collected, summary
 *     counts match.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  ApiClient, sleep, createApiKey, createBundleViaDb, sha3,
  computeCertFingerprint, runDbScript,
} = require('./test-helpers');
const WsClient = require('../lib/ws-client');
const { MSG } = require('../lib/constants');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

var hasMtls = !!(ctx.clientCert && ctx.clientKey && ctx.caCert);

// Shared admin client — lazy-init so we pay the ECIES session setup once
// across all tests in this file (the /drop/init endpoint is rate-limited).
var _sharedClient = null;
async function adminClient() {
  if (_sharedClient) return _sharedClient;
  _sharedClient = new ApiClient(ctx.url, ctx.apiKey, {
    clientCert: ctx.clientCert,
    clientKey: ctx.clientKey,
    ca: ctx.caCert,
  });
  await _sharedClient.init();
  return _sharedClient;
}

// Admin endpoints always return encrypted responses (api-encrypt middleware).
// .decrypted is the unwrapped JSON; .json is the raw {_e, _t} envelope.
function body(res) { return res.decrypted || res.json; }

describe('mTLS CA Regeneration', { timeout: 30000 }, function () {

  it('GET /admin/api/mtls-ca/status reports the openssl-generated CA as legacy', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/api/mtls-ca/status', 'GET');
    assert.equal(res.statusCode, 200, 'Status endpoint responds 200');
    var b = body(res);
    assert.ok(b, 'Response body parsed');
    assert.equal(b.exists, true, 'CA exists');
    assert.equal(b.generation, 1, 'Untagged openssl CA is generation 1');
    assert.ok(b.current >= 2, 'Current generation is at least 2');
    assert.equal(b.isLegacy, true, 'Marked as legacy');
  });

  it('POST /admin/api/mtls-ca/regenerate rejects missing confirm phrase', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/api/mtls-ca/regenerate', 'POST', { confirm: 'wrong' });
    assert.equal(res.statusCode, 400, 'Missing/wrong confirm → 400');
    var b = body(res);
    assert.ok(b && /REGEN/.test(b.detail || b.error || ''),
      'Error mentions REGEN: ' + JSON.stringify(b));
  });

  it('POST /admin/api/mtls-ca/regenerate with skipRestart + no live clients returns fast-path summary', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/api/mtls-ca/regenerate', 'POST', { confirm: 'REGEN', skipRestart: true });
    assert.equal(res.statusCode, 200, 'Returns 200');
    var b = body(res);
    assert.equal(b.ok, true, 'ok: true');
    assert.ok(b.summary, 'summary present');
    assert.equal(b.summary.caGenerationBefore, 1, 'Legacy generation before');
    assert.ok(b.summary.caGenerationAfter >= 2, 'Current generation after');
    assert.equal(b.summary.syncClientsConnected, 0, 'No live sync clients in fast path');
  });

  it('with a live sync WS client, rotation is broadcast as dryRun and ack is counted', async function (t) {
    if (!hasMtls) { t.skip('mTLS certs not available'); return; }

    // Set up a sync bundle + sync-scoped key bound to our test client cert.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var syncKey = createApiKey(ctx.dbPath, 'sync');
    var fp = computeCertFingerprint(ctx.clientCert);
    var keyHash = sha3(syncKey);
    runDbScript(ctx.dbPath, [
      'db.prepare("UPDATE api_keys SET certFingerprint = ? WHERE keyHash = ?").run(' + JSON.stringify(fp) + ', ' + JSON.stringify(keyHash) + ');',
      'process.stdout.write("OK");',
    ].join('\n'));
    await sleep(200);

    var ws = new WsClient({
      server: ctx.url,
      reconnect: false,
      tls: { rejectUnauthorized: false },
      mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert },
    }, syncKey);

    var openP = new Promise(function (resolve, reject) {
      var timer = setTimeout(function () { reject(new Error('WS connect timeout')); }, 5000);
      ws.once('open', function () { clearTimeout(timer); resolve(); });
      ws.once('upgrade_rejected', function (info) { clearTimeout(timer); reject(new Error('Upgrade rejected: ' + info.status + ' ' + info.body)); });
    });
    var heartbeatP = new Promise(function (resolve, reject) {
      var timer = setTimeout(function () { reject(new Error('No heartbeat')); }, 5000);
      ws.on('message', function onMsg(m) {
        if (m.type === MSG.HEARTBEAT) { ws.off('message', onMsg); clearTimeout(timer); resolve(); }
      });
    });
    ws.connect(bundle.bundleId, 0);
    await openP;
    await heartbeatP;

    // Listen for ca:rotation BEFORE firing the regen request
    var rotationP = new Promise(function (resolve) {
      ws.on('message', function (m) { if (m.type === MSG.CA_ROTATION) resolve(m); });
    });

    var client = await adminClient();
    var regenP = client.request('/admin/api/mtls-ca/regenerate', 'POST', { confirm: 'REGEN', skipRestart: true });

    var rot = await Promise.race([
      rotationP,
      new Promise(function (_r, rej) { setTimeout(function () { rej(new Error('No ca:rotation within 5s')); }, 5000); }),
    ]);

    // Validate rotation payload
    assert.equal(rot.dryRun, true, 'dryRun: true (since skipRestart was sent)');
    assert.ok(rot.newCaPem && rot.newCaPem.indexOf('BEGIN CERTIFICATE') !== -1, 'newCaPem is a PEM certificate');
    assert.ok(rot.newCertPem && rot.newCertPem.indexOf('BEGIN CERTIFICATE') !== -1, 'newCertPem is a PEM certificate');
    assert.ok(rot.newKeyPem && rot.newKeyPem.indexOf('PRIVATE KEY') !== -1, 'newKeyPem is a PEM private key');
    assert.ok(typeof rot.restartInMs === 'number' && rot.restartInMs > 0, 'restartInMs is positive number');

    // New CA carries the current-generation marker (OU=CAv{N}) in its subject DN
    var { X509Certificate } = require('node:crypto');
    var newCaParsed = new X509Certificate(rot.newCaPem);
    assert.ok(/CAv\d+/.test(newCaParsed.subject), 'New CA subject DN contains a CAv generation marker: ' + newCaParsed.subject);

    // Ack the rotation manually (emulating sync-engine._handleCaRotation's
    // dryRun path: ack without file writes).
    ws.send({ type: MSG.CA_ROTATION_ACK });

    // Await the regen response
    var regenRes = await Promise.race([
      regenP,
      new Promise(function (_r, rej) { setTimeout(function () { rej(new Error('Regen response not received within 20s')); }, 20000); }),
    ]);
    assert.equal(regenRes.statusCode, 200, 'Regen returns 200');
    var b = body(regenRes);
    assert.equal(b.ok, true, 'ok: true');
    var summary = b.summary;
    assert.ok(summary, 'summary present');
    assert.equal(summary.caGenerationBefore, 1, 'Before generation is 1 (legacy untagged)');
    assert.ok(summary.caGenerationAfter >= 2, 'After generation is >= 2');
    assert.ok(summary.syncClientsConnected >= 1, 'At least 1 sync client connected, got ' + summary.syncClientsConnected);
    assert.ok(summary.syncClientsAcked >= 1, 'At least 1 sync client acked, got ' + summary.syncClientsAcked);

    // Verify on-disk CA was NOT swapped (skipRestart), so subsequent tests
    // continue to use the same CA that signed their client certs.
    var statusAfter = await client.request('/admin/api/mtls-ca/status', 'GET');
    var ba = body(statusAfter);
    assert.equal(ba.generation, 1, 'On-disk CA unchanged — still legacy');
    assert.equal(ba.isLegacy, true, 'Still legacy (skipRestart preserves state)');

    try { ws.close(); } catch (_e) {}
  });
});
