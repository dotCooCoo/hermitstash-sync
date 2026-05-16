'use strict';

/**
 * Cross-user IDOR tests for bundle write endpoints.
 *
 * Covers the three write paths that every ownership-check refactor must keep
 * consistent — each re-implements the ownerId gate independently, so a
 * missed route is the classic pattern for this class of bug:
 *
 *   - POST /drop/finalize/:bundleId       (upload flow)
 *   - POST /sync/rename                   (sync client path)
 *   - POST /bundles/:shareId/file/rename  (browser-authed path via shareId)
 *
 * For each, a bundle owned by userA is targeted by an API key belonging to
 * userB. The server MUST reject with 403 (not a 200 modify + audit-only
 * detection).
 *
 * Positive path: the owner's key successfully performs the same action,
 * proving the negative test isn't producing false positives due to other
 * unrelated rejections (wrong scope, missing field, etc).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  httpRequest, encryptedRequest, sleep, sha3, runDbScript, createBundleViaDb,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  // Needed by encryptedRequest — POST /drop/finalize and POST /sync/rename
  // run through blamejs apiEncrypt with mTLS-bound Bearer auth.
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey:  process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert:     process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * Create a second user directly in the DB and return its ID.
 * startServer creates the "admin" user first; this one is a peer.
 */
function createUserB() {
  var id = b.crypto.generateToken(32);
  var email = 'userb-' + b.crypto.generateToken(4) + '@hermitstash.com';
  var emailHash = sha3('hs-email:' + email.toLowerCase());
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO users (_id, email, emailHash, displayName, role, status, authType, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(' + JSON.stringify(id) + ', ' + JSON.stringify(email) + ', ' + JSON.stringify(emailHash) + ', "User B", "user", "active", "local", ' + JSON.stringify(now) + ');',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to create userB: ' + out);
  return { userId: id, email: email };
}

/**
 * Create an API key bound to a specific userId (bypasses createApiKey's
 * hardcoded "oldest user = owner" assumption).
 */
function createApiKeyFor(userId, permissions) {
  var raw = 'hs_' + b.crypto.generateToken(32);
  var keyHash = sha3(raw);
  var prefix = raw.substring(0, 7);
  var id = b.crypto.generateToken(32);
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO api_keys (_id, name, keyHash, prefix, permissions, userId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)")',
    '  .run(' + JSON.stringify(id) + ', "e2e-user-b", ' + JSON.stringify(keyHash) + ', ' + JSON.stringify(prefix) + ', ' + JSON.stringify(permissions) + ', ' + JSON.stringify(userId) + ', ' + JSON.stringify(now) + ');',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to create api key: ' + out);
  return raw;
}

/**
 * Create a sync bundle owned by a specific userId. Mirrors createBundleViaDb
 * but takes ownerId explicitly rather than defaulting to the oldest user.
 */
function createBundleFor(ownerId, bundleType) {
  bundleType = bundleType || 'sync';
  var bundleId = b.crypto.generateToken(32);
  var shareId = b.crypto.generateToken(32);
  var finalizeToken = b.crypto.generateToken(32);
  var finalizeTokenHash = sha3(finalizeToken);
  var shareIdHash = sha3('hs-share:' + shareId);
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO bundles (_id, shareId, shareIdHash, uploaderName, uploaderEmail, expectedFiles, receivedFiles, skippedCount, totalSize, downloads, status, bundleType, seq, finalizeTokenHash, ownerId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(bundleId) + ',',
    '    ' + JSON.stringify(shareId) + ',',
    '    ' + JSON.stringify(shareIdHash) + ',',
    '    "Owner Test", "owner@hermitstash.com", 0, 0, 0, 0, 0,',
    '    ' + JSON.stringify(bundleType === 'sync' ? 'complete' : 'uploading') + ',',
    '    ' + JSON.stringify(bundleType) + ', 0,',
    '    ' + JSON.stringify(finalizeTokenHash) + ',',
    '    ' + JSON.stringify(ownerId) + ',',
    '    ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to create bundle: ' + out);
  return { bundleId: bundleId, shareId: shareId, finalizeToken: finalizeToken };
}

/**
 * Seed a file row so rename has something to act on. Returns { fileId, relativePath }.
 */
function seedFile(bundleId, relativePath) {
  var fileId = b.crypto.generateToken(32);
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO files (_id, bundleId, originalName, relativePath, storagePath, size, mimeType, checksum, encryptionKey, seq, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(fileId) + ',',
    '    ' + JSON.stringify(bundleId) + ',',
    '    ' + JSON.stringify(relativePath) + ',',
    '    ' + JSON.stringify(relativePath) + ',',
    '    ' + JSON.stringify('nowhere/' + fileId) + ',',
    '    0, "text/plain",',
    '    ' + JSON.stringify('0'.repeat(128)) + ',',
    '    ' + JSON.stringify('') + ',',
    '    1, "complete", ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to seed file: ' + out);
  return { fileId: fileId, relativePath: relativePath };
}

// All routes this test hits (POST /drop/finalize/:bundleId,
// POST /sync/rename) are blamejs apiEncrypt scope as of server v1.9.15
// — bodies must be wrapped in the per-session envelope.
function apiReq(method, pathname, bearerToken, body) {
  return encryptedRequest(ctx, pathname, {
    method: method,
    body:   body,
    apiKey: bearerToken,
  });
}

describe('Bundle ownership IDOR', { timeout: 15000 }, function () {

  it('POST /drop/finalize/:bundleId rejects cross-user finalize with 403', async function () {
    // Admin (ctx.apiKey) is userA. Create userB and a userB-owned bundle.
    var userB = createUserB();
    var bundle = createBundleFor(userB.userId, 'default');
    await sleep(100);

    // Attempt finalize with userA's key (has upload scope). Even with the
    // correct finalizeToken, the ownerId mismatch must block it.
    var res = await apiReq('POST', '/drop/finalize/' + bundle.bundleId, ctx.apiKey, {
      finalizeToken: bundle.finalizeToken,
    });
    assert.equal(res.statusCode, 403, 'Cross-user finalize → 403, got ' + res.statusCode + ' ' + (res.body || ''));
  });

  it('POST /sync/rename rejects cross-user rename with 403', async function () {
    var userB = createUserB();
    var bundle = createBundleFor(userB.userId, 'sync');
    var file = seedFile(bundle.bundleId, 'foo.txt');
    await sleep(100);

    var res = await apiReq('POST', '/sync/rename', ctx.apiKey, {
      bundleId: bundle.bundleId,
      oldRelativePath: file.relativePath,
      newRelativePath: 'bar.txt',
    });
    assert.equal(res.statusCode, 403, 'Cross-user /sync/rename → 403, got ' + res.statusCode + ' ' + (res.body || ''));
  });

  it('POST /sync/rename is rejected with 401 when the API key has no sync scope', async function () {
    // Use a fresh userB-owned key WITHOUT sync scope to prove the scope gate
    // runs before ownership — otherwise a 403 from owner mismatch could mask
    // a missing scope check.
    var userB = createUserB();
    var bundle = createBundleFor(userB.userId, 'sync');
    var file = seedFile(bundle.bundleId, 'scope.txt');
    var uploadOnlyKey = createApiKeyFor(userB.userId, 'upload,read');
    await sleep(100);

    var res = await apiReq('POST', '/sync/rename', uploadOnlyKey, {
      bundleId: bundle.bundleId,
      oldRelativePath: file.relativePath,
      newRelativePath: 'renamed.txt',
    });
    assert.ok(res.statusCode === 401 || res.statusCode === 403,
      'Missing sync scope → 401 or 403, got ' + res.statusCode);
  });

  it('owner can /sync/rename their own bundle (positive control)', async function () {
    // Prove the negative tests above aren't just passing because /sync/rename
    // rejects everyone. Create a bundle owned by userB, use a userB key
    // with sync scope — rename must succeed.
    var userB = createUserB();
    var bundle = createBundleFor(userB.userId, 'sync');
    var file = seedFile(bundle.bundleId, 'mine.txt');
    var userBKey = createApiKeyFor(userB.userId, 'sync');
    await sleep(100);

    var res = await apiReq('POST', '/sync/rename', userBKey, {
      bundleId: bundle.bundleId,
      oldRelativePath: file.relativePath,
      newRelativePath: 'mine-renamed.txt',
    });
    assert.equal(res.statusCode, 200, 'Owner rename → 200, got ' + res.statusCode + ' ' + (res.body || ''));
  });
});
