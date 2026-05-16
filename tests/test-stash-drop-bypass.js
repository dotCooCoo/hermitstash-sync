'use strict';

/**
 * Stash bundles must reject /drop/* endpoints.
 *
 * Stash-owned bundles (bundle.stashId set) live under /stash/:slug/* routes
 * that apply per-stash upload caps, isStashLocked() access checks, and
 * stash-scoped rate limits. If any /drop/* endpoint were reachable for a
 * stash bundle, those stash-specific guards would be silently bypassed.
 *
 * The gate is a single-line stashId check on each endpoint. Easy to miss
 * if a new drop endpoint is added. Same "is this gate on every
 * endpoint?" pattern as the boundBundleId / certFingerprint audits.
 *
 * Endpoints under test:
 *   POST /drop/file/:bundleId       — regular upload
 *   POST /drop/chunk/:bundleId      — chunked upload
 *   POST /drop/finalize/:bundleId   — finalize
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');
const { sleep, runDbScript, sha3, encryptedRequest } = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey:  process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert:     process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * Create a bundle row with an explicit stashId set. createBundleViaDb
 * doesn't support stashId directly so we inline the insert here.
 */
function createStashBundle() {
  var bundleId = b.crypto.generateToken(32);
  var shareId = b.crypto.generateToken(32);
  var finalizeToken = b.crypto.generateToken(32);
  var finalizeTokenHash = sha3(finalizeToken);
  var shareIdHash = sha3('hs-share:' + shareId);
  var stashId = b.crypto.generateToken(32); // fake stash row ref is fine — we only need stashId != null for the route check
  var now = new Date().toISOString();
  var script = [
    'var users = db.prepare("SELECT _id FROM users ORDER BY createdAt ASC LIMIT 1").all();',
    'var userId = users.length > 0 ? users[0]._id : null;',
    'db.prepare("INSERT INTO bundles (_id, shareId, shareIdHash, uploaderName, uploaderEmail, expectedFiles, receivedFiles, skippedCount, totalSize, downloads, status, bundleType, seq, finalizeTokenHash, ownerId, stashId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(bundleId) + ',',
    '    ' + JSON.stringify(shareId) + ',',
    '    ' + JSON.stringify(shareIdHash) + ',',
    '    "Stash Bypass Test", "stash@hermitstash.com",',
    '    10, 0, 0, 0, 0, "uploading", "default", 0,',
    '    ' + JSON.stringify(finalizeTokenHash) + ',',
    '    userId, ' + JSON.stringify(stashId) + ',',
    '    ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to seed stash bundle: ' + out);
  return { bundleId: bundleId, shareId: shareId, finalizeToken: finalizeToken, stashId: stashId };
}

/**
 * Minimal multipart POST builder — matches the server's parseMultipart
 * expectations. Returns { statusCode, body }.
 */
function multipartPost(pathname, fields, fileFieldName, filename, fileData, apiKey) {
  return new Promise(function (resolve, reject) {
    var parsed = new URL(ctx.url);
    var boundary = '----HSTestStash' + b.crypto.generateToken(8);
    var parts = [];
    Object.keys(fields).forEach(function (k) {
      parts.push(Buffer.from(
        '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="' + k + '"\r\n\r\n' +
        fields[k] + '\r\n', 'utf8'));
    });
    if (fileFieldName) {
      parts.push(Buffer.from(
        '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="' + fileFieldName + '"; filename="' + filename + '"\r\n' +
        'Content-Type: application/octet-stream\r\n\r\n', 'utf8'));
      parts.push(Buffer.isBuffer(fileData) ? fileData : Buffer.from(fileData));
      parts.push(Buffer.from('\r\n', 'utf8'));
    }
    parts.push(Buffer.from('--' + boundary + '--\r\n', 'utf8'));
    var body = Buffer.concat(parts);

    var opts = {
      hostname: parsed.hostname, port: parsed.port, path: pathname, method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': body.length,
        'Authorization': 'Bearer ' + apiKey,
      },
      rejectUnauthorized: false,
    };
    var mod = parsed.protocol === 'https:' ? https : http;
    var req = mod.request(opts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, function () { req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

/**
 * JSON POST for /drop/finalize — takes finalizeToken in body. Server v1.9.15+
 * routes /drop/finalize/:bundleId through blamejs apiEncrypt, so the body has
 * to be wrapped in the per-session envelope.
 */
function jsonPost(pathname, body, apiKey) {
  return encryptedRequest(ctx, pathname, { method: 'POST', body: body || {}, apiKey: apiKey });
}

describe('Stash bundles reject /drop/* endpoints', { timeout: 15000 }, function () {

  it('POST /drop/file/:bundleId rejects a stash-owned bundle with 403', async function () {
    var bundle = createStashBundle();
    await sleep(100);
    var res = await multipartPost(
      '/drop/file/' + bundle.bundleId,
      { relativePath: 'stashed.txt' },
      'file', 'stashed.txt', Buffer.from('x'),
      ctx.apiKey
    );
    assert.equal(res.statusCode, 403,
      '/drop/file on stash bundle → 403, got ' + res.statusCode + ' ' + res.body);
  });

  it('POST /drop/chunk/:bundleId rejects a stash-owned bundle with 403', async function () {
    var bundle = createStashBundle();
    await sleep(100);
    var res = await multipartPost(
      '/drop/chunk/' + bundle.bundleId,
      {
        chunkIndex: '0', totalChunks: '1', fileId: 'f' + b.crypto.generateToken(6),
        filename: 'stashed.txt', relativePath: 'stashed.txt', mimeType: 'text/plain',
      },
      'file', 'stashed.bin', Buffer.from('payload'),
      ctx.apiKey
    );
    assert.equal(res.statusCode, 403,
      '/drop/chunk on stash bundle → 403, got ' + res.statusCode + ' ' + res.body);
  });

  it('POST /drop/finalize/:bundleId rejects a stash-owned bundle with 403', async function () {
    var bundle = createStashBundle();
    await sleep(100);
    var res = await jsonPost('/drop/finalize/' + bundle.bundleId,
      { finalizeToken: bundle.finalizeToken },
      ctx.apiKey
    );
    assert.equal(res.statusCode, 403,
      '/drop/finalize on stash bundle → 403, got ' + res.statusCode + ' ' + res.body);
  });

  it('error message explicitly routes the caller to the stash endpoint', async function () {
    var bundle = createStashBundle();
    await sleep(100);
    var res = await multipartPost(
      '/drop/file/' + bundle.bundleId,
      { relativePath: 'x.txt' },
      'file', 'x.txt', Buffer.from('y'),
      ctx.apiKey
    );
    assert.equal(res.statusCode, 403);
    // Response may be encrypted — tolerate either plain or wrapped
    if (res.body && res.body.indexOf('{"_e"') === -1) {
      assert.match(res.body, /stash/i, 'error mentions "stash" to guide the caller: ' + res.body);
    }
  });
});
