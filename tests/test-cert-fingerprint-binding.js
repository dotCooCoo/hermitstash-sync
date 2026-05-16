'use strict';

/**
 * Cert-fingerprint binding enforcement across /sync/* endpoints.
 *
 * When an API key is enrolled with mTLS, its row carries a certFingerprint.
 * Every subsequent request using that key must present a client cert whose
 * SHA3-512 PEM hash matches — otherwise a leaked Bearer token would be
 * usable without the cert, defeating the two-factor sync-client posture.
 *
 * Enforcement is currently scattered across endpoints (no shared middleware).
 * The /sync/rename boundBundleId gap we just fixed had the same shape —
 * this test verifies each /sync/* endpoint independently enforces the
 * certFingerprint gate when one is set on the key.
 *
 * Endpoints under test:
 *   /sync/ws             (WebSocket upgrade)  — expected to enforce
 *   /sync/renew-cert     (cert renewal)       — expected to enforce
 *   /sync/rename         (file rename)        — expected to enforce
 *   /sync/enroll         (enrollment)         — NOT expected (unauthenticated)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const fs = require('node:fs');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');
const {
  sleep, createApiKey, createBundleViaDb, sha3, runDbScript, expectWsRejectClient, encryptedRequest,
} = require('./test-helpers');

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

/**
 * Bind a key to a made-up certFingerprint that CANNOT match anything the
 * test client can present. When the server enforces certFingerprint, the
 * check fails regardless of which cert the caller sent.
 */
function bindBogusFingerprint(rawApiKey) {
  var keyHash = sha3(rawApiKey);
  var bogusFp = sha3('bogus-cert-pem-' + Date.now());
  runDbScript(ctx.dbPath, [
    'db.prepare("UPDATE api_keys SET certFingerprint = ? WHERE keyHash = ?").run(' +
      JSON.stringify(bogusFp) + ', ' + JSON.stringify(keyHash) + ');',
    'process.stdout.write("OK");',
  ].join('\n'));
}

// /sync/rename runs through blamejs apiEncrypt as of server v1.9.15 — the
// body must be wrapped in the per-session envelope. We build a one-shot
// ctx-shaped object so encryptedRequest can attach the right mTLS posture
// per call (mtlsOn=false is the "no client cert" branch the test exercises).
function syncReq(pathname, apiKey, mtlsOn, body) {
  var subCtx = {
    url:    ctx.url,
    apiKey: apiKey,
    dbPath: ctx.dbPath,
  };
  if (mtlsOn) {
    subCtx.clientCert = ctx.clientCert;
    subCtx.clientKey  = ctx.clientKey;
    subCtx.caCert     = ctx.caCert;
  }
  return encryptedRequest(subCtx, pathname, { method: 'POST', body: body, apiKey: apiKey });
}

describe('certFingerprint enforcement across /sync/* endpoints', { timeout: 15000 }, function () {

  it('/sync/ws rejects upgrade when the key has a certFingerprint that does not match', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var key = createApiKey(ctx.dbPath, 'sync');
    bindBogusFingerprint(key);
    await sleep(150);

    // Attempt WS upgrade — the upgrade handler enforces the binding.
    var result = await expectWsRejectClient(ctx.url, key, bundle.bundleId, 0);
    assert.equal(result.statusCode, 403, 'WS upgrade with mismatched cert → 403, got ' + result.statusCode);
  });

  it('/sync/renew-cert rejects a bound-key Bearer without a matching cert', async function () {
    var key = createApiKey(ctx.dbPath, 'sync');
    bindBogusFingerprint(key);
    await sleep(150);

    // With mTLS on — but our client cert does NOT match the bogus fp
    var res = await syncReq('/sync/renew-cert', key, true, {});
    assert.ok(res.statusCode === 403 || res.statusCode === 429,
      'renew with mismatched cert → 403 or 429, got ' + res.statusCode + ' ' + res.body);
  });

  it('/sync/rename rejects a bound-key Bearer without a matching cert', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var key = createApiKey(ctx.dbPath, 'sync');
    bindBogusFingerprint(key);
    await sleep(150);

    // With mTLS on (the transport carries a cert) — but the key's bound
    // fingerprint doesn't match it. Server MUST reject.
    var res = await syncReq('/sync/rename', key, true, {
      bundleId: bundle.bundleId,
      oldRelativePath: 'anything.txt',
      newRelativePath: 'pwned.txt',
    });
    assert.ok(res.statusCode === 403,
      'rename with mismatched cert → 403, got ' + res.statusCode + ' ' + res.body);
  });

  it('/sync/rename rejects a bound-key Bearer when NO cert is presented at all', async function () {
    // Even more egregious: Bearer alone, no mTLS transport. If certFingerprint
    // is set, this must be rejected — otherwise a leaked token fully bypasses
    // the cert-binding defense.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var key = createApiKey(ctx.dbPath, 'sync');
    bindBogusFingerprint(key);
    await sleep(150);

    var res = await syncReq('/sync/rename', key, false, {
      bundleId: bundle.bundleId,
      oldRelativePath: 'anything.txt',
      newRelativePath: 'bearer-only-pwn.txt',
    });
    assert.equal(res.statusCode, 403,
      'rename without cert when key is cert-bound → 403, got ' + res.statusCode + ' ' + res.body);
  });

  it('positive control: cert-bound key can still rename when its cert matches', async function () {
    // Use computeCertFingerprint from test-helpers to match the real test cert.
    var { computeCertFingerprint } = require('./test-helpers');
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var key = createApiKey(ctx.dbPath, 'sync');
    var keyHash = sha3(key);
    var realFp = computeCertFingerprint(ctx.clientCert);
    runDbScript(ctx.dbPath, [
      'db.prepare("UPDATE api_keys SET certFingerprint = ? WHERE keyHash = ?").run(' +
        JSON.stringify(realFp) + ', ' + JSON.stringify(keyHash) + ');',
      'process.stdout.write("OK");',
    ].join('\n'));
    // Seed a file so the rename has a target
    var fileId = b.crypto.generateToken(32);
    var now = new Date().toISOString();
    runDbScript(ctx.dbPath, [
      'db.prepare("INSERT INTO files (_id, bundleId, originalName, relativePath, storagePath, size, mimeType, checksum, encryptionKey, seq, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(',
      '    ' + JSON.stringify(fileId) + ',',
      '    ' + JSON.stringify(bundle.bundleId) + ',',
      '    "real.txt", "real.txt",',
      '    ' + JSON.stringify('nowhere/' + fileId) + ',',
      '    0, "text/plain",',
      '    ' + JSON.stringify('0'.repeat(128)) + ', "", 1, "complete",',
      '    ' + JSON.stringify(now),
      '  );',
      'process.stdout.write("OK");',
    ].join('\n'));
    await sleep(150);

    var res = await syncReq('/sync/rename', key, true, {
      bundleId: bundle.bundleId,
      oldRelativePath: 'real.txt',
      newRelativePath: 'real-renamed.txt',
    });
    assert.equal(res.statusCode, 200,
      'owner + matching cert → 200, got ' + res.statusCode + ' ' + res.body);
  });
});
