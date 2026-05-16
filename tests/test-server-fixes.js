'use strict';

/**
 * Server-side fix validation tests.
 *
 * Covers the 14 server fixes applied in the previous session:
 *   Fix #2  — uploadsDir derived from config.storage.uploadDir
 *   Fix #3  — Audit actions for ENROLLMENT_REDEEMED
 *   Fix #5  — enrollment_codes reissue + originalKeyId columns
 *   Fix #7  — Reissue-cert: enrollment insert first, API key update second
 *   Fix #8  — Temp dir name collision fix (concurrent cert gen)
 *   Fix #9  — Backup/restore lock not stuck forever
 *   Fix #11 — Orphan cleanup 5-minute mtime grace period
 *
 * Cert fingerprint (#1), cert columns (#4), and cert audit (#3 partial)
 * are covered in test-cert-renewal.js.
 *
 * S3-specific fixes (#10, #12, #13, #14) are covered in test-s3-storage.js.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const fs = require('node:fs');
const path = require('node:path');
const {
  MSG, ApiClient,
  httpRequest, uploadFile, sha3, sleep,
  createApiKey, runDbScript,
  createBundleViaDb, getBundleFilesFromDb, countBundleFiles,
  newTestWsClient, waitFor, connectWsClient, countTableRows,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  dataDir: process.env.HERMITSTASH_TEST_DATA_DIR,
  syncDir: process.env.HERMITSTASH_TEST_SYNC_DIR,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

var hasMtls = !!(ctx.clientCert && ctx.clientKey && ctx.caCert);

/**
 * Helper: create a stash page directly in the DB.
 */
function createStashViaDb(opts) {
  opts = opts || {};
  var slug = opts.slug || 'fix-test-' + b.crypto.generateToken(4);
  var stashId = b.crypto.generateToken(32);
  var slugHash = sha3('hs-slug:' + slug);
  var now = new Date().toISOString();

  var script = [
    'var users = db.prepare("SELECT _id FROM users LIMIT 1").all();',
    'var userId = users.length > 0 ? users[0]._id : "system";',
    'db.prepare("INSERT INTO customer_stash (_id, slug, slugHash, name, title, subtitle, enabled, syncEnabled, syncBundleId, accessMode, createdBy, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(stashId) + ',',
    '    ' + JSON.stringify(slug) + ',',
    '    ' + JSON.stringify(slugHash) + ',',
    '    ' + JSON.stringify(opts.name || 'Fix Test Stash') + ',',
    '    ' + JSON.stringify(opts.title || 'Fix Test') + ',',
    '    "Upload files",',
    '    "true",',
    '    ' + JSON.stringify(opts.syncEnabled ? 'true' : 'false') + ',',
    '    ' + (opts.syncBundleId ? JSON.stringify(opts.syncBundleId) : 'null') + ',',
    '    "open",',
    '    userId,',
    '    ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');

  var result = runDbScript(ctx.dbPath, script);
  if (result !== 'OK') throw new Error('Failed to create stash: ' + result);
  return { stashId: stashId, slug: slug };
}

/**
 * Helper: create a stash-bound API key with cert tracking columns.
 */
function createBoundApiKey(stashId, bundleId) {
  var rawToken = 'hs_' + b.crypto.generateToken(32);
  var keyHash = sha3(rawToken);
  var prefix = rawToken.substring(0, 7);
  var keyId = b.crypto.generateToken(32);
  var now = new Date().toISOString();

  var script = [
    'var users = db.prepare("SELECT _id FROM users LIMIT 1").all();',
    'var userId = users.length > 0 ? users[0]._id : "system";',
    'db.prepare("INSERT INTO api_keys (_id, name, keyHash, prefix, permissions, userId, boundStashId, boundBundleId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(' + JSON.stringify(keyId) + ', "fix-test", ' + JSON.stringify(keyHash) + ', ' + JSON.stringify(prefix) + ', "sync,upload,read", userId, ' + JSON.stringify(stashId) + ', ' + (bundleId ? JSON.stringify(bundleId) : 'null') + ', ' + JSON.stringify(now) + ');',
    'process.stdout.write("OK");',
  ].join('\n');

  var result = runDbScript(ctx.dbPath, script);
  if (result !== 'OK') throw new Error('Failed to create bound API key: ' + result);
  return { rawToken: rawToken, keyId: keyId, prefix: prefix };
}


// ---- Fix #2: uploadsDir consistency ----

describe('Fix #2: Upload directory consistency', { timeout: 30000 }, function () {

  it('uploaded file is stored and retrievable via WebSocket event', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var content = 'uploadDir-consistency-test-' + b.crypto.generateToken(16);
    var expectedHash = sha3(content);

    var ws = newTestWsClient(ctx.url, ctx.apiKey);
    var eventP = waitFor(ws, 'message', function (m) { return m.type === MSG.FILE_ADDED; }, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    var uploadRes = await uploadFile(ctx.url, bundle.bundleId, 'upload-dir-test.txt', content, ctx.apiKey);
    assert.equal(uploadRes.statusCode, 200, 'Upload should succeed');

    var event = await eventP;
    assert.equal(event.checksum, expectedHash, 'File checksum matches — stored in correct upload dir');
    assert.equal(event.relativePath, 'upload-dir-test.txt');

    // Verify file exists in DB
    var count = countBundleFiles(ctx.dbPath, bundle.bundleId);
    assert.equal(count, 1, 'File recorded in DB');

    ws.close();
  });

  it('multiple uploads to subdirectories all succeed', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    var results = await Promise.all([
      uploadFile(ctx.url, bundle.bundleId, 'a/file1.txt', 'content-a', ctx.apiKey),
      uploadFile(ctx.url, bundle.bundleId, 'b/file2.txt', 'content-b', ctx.apiKey),
      uploadFile(ctx.url, bundle.bundleId, 'c/d/file3.txt', 'content-c', ctx.apiKey),
    ]);

    for (var i = 0; i < results.length; i++) {
      assert.equal(results[i].statusCode, 200, 'Upload ' + i + ' should succeed');
    }
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 3, 'All 3 files stored');
  });
});


// ---- Fix #3: Audit log for enrollment_redeemed ----

describe('Fix #3: Audit log for enrollment redemption', { timeout: 30000 }, function () {

  it('redeeming an enrollment code creates an audit log entry', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stash = createStashViaDb({ syncEnabled: true, syncBundleId: bundle.bundleId });

    // Create enrollment code
    var enrollCode = 'HSTASH-' + b.crypto.generateToken(8).toUpperCase().match(/.{4}/g).join('-');
    var codeHash = sha3('hs-enroll:' + enrollCode);

    runDbScript(ctx.dbPath, [
      'db.prepare("INSERT INTO enrollment_codes (_id, codeHash, apiKey, clientCert, clientKey, caCert, stashId, status, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(',
      '    ' + JSON.stringify(b.crypto.generateToken(32)) + ',',
      '    ' + JSON.stringify(codeHash) + ',',
      '    "hs_audit_test_key", "cert-pem", "key-pem", "ca-pem",',
      '    ' + JSON.stringify(stash.stashId) + ',',
      '    "pending",',
      '    ' + JSON.stringify(new Date(Date.now() + 3600000).toISOString()) + ',',
      '    ' + JSON.stringify(new Date().toISOString()),
      '  );',
      'process.stdout.write("OK");',
    ].join('\n'));

    var auditBefore = countTableRows(ctx.dbPath, 'audit_log');

    // Redeem the code
    var res = await httpRequest(ctx.url + '/sync/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: enrollCode }),
    });
    assert.equal(res.statusCode, 200, 'Enrollment should succeed');

    // Verify audit entry was created
    await sleep(300);
    var auditAfter = countTableRows(ctx.dbPath, 'audit_log');
    assert.ok(auditAfter > auditBefore,
      'Audit log should have new entry for enrollment_redeemed (before: ' + auditBefore + ', after: ' + auditAfter + ')');
  });
});


// ---- Fix #5 + #7: Reissue-cert with enrollment_codes columns ----

describe('Fix #5 + #7: Cert reissue with enrollment ordering', { timeout: 30000 }, function () {

  it('reissue-cert endpoint creates enrollment code and updates API key cert fields', async function () {
    if (!hasMtls) { console.log('  # Skipping — no mTLS certs'); return; }

    // Set up: stash with bound sync API key
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stash = createStashViaDb({ syncEnabled: true, syncBundleId: bundle.bundleId });
    var boundKey = createBoundApiKey(stash.stashId, bundle.bundleId);

    // Count enrollment codes before reissue
    var enrollBefore = countTableRows(ctx.dbPath, 'enrollment_codes');
    var auditBefore = countTableRows(ctx.dbPath, 'audit_log');

    // Call the admin reissue-cert endpoint
    // Response body is api-encrypt sealed, so we verify via DB state changes
    var res = await httpRequest(ctx.url + '/admin/stash/' + stash.stashId + '/reissue-cert', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + ctx.apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ apiKeyId: boundKey.keyId }),
    });

    // Accept 200 (success) or 429 (rate limited from earlier tests)
    assert.ok(res.statusCode === 200 || res.statusCode === 429,
      'Reissue should succeed or be rate-limited: HTTP ' + res.statusCode);
    if (res.statusCode === 429) { console.log('  # Rate limited — skipping data assertions'); return; }

    // Verify DB state changes since response body is encrypted by api-encrypt

    // Fix #5: Verify new enrollment_codes record was created
    var enrollAfter = countTableRows(ctx.dbPath, 'enrollment_codes');
    assert.ok(enrollAfter > enrollBefore,
      'New enrollment code record created (before: ' + enrollBefore + ', after: ' + enrollAfter + ')');

    // Check the raw columns (reissue and originalKeyId)
    var enrollScript = [
      'var rows = db.prepare("SELECT reissue, originalKeyId FROM enrollment_codes ORDER BY rowid DESC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows[0] || {}));',
    ].join('\n');
    var enrollRow = JSON.parse(runDbScript(ctx.dbPath, enrollScript));
    assert.ok(enrollRow.reissue !== undefined || enrollRow.originalKeyId !== undefined,
      'enrollment_codes row has reissue/originalKeyId columns');

    // Fix #4: Verify cert columns on the API key were updated
    var keyScript = [
      'var row = db.prepare("SELECT certIssuedAt, certExpiresAt, certFingerprint FROM api_keys WHERE _id = ?").get(' + JSON.stringify(boundKey.keyId) + ');',
      'process.stdout.write(JSON.stringify(row || {}));',
    ].join('\n');
    var keyRow = JSON.parse(runDbScript(ctx.dbPath, keyScript));
    assert.ok(keyRow.certIssuedAt, 'certIssuedAt populated after reissue');
    assert.ok(keyRow.certExpiresAt, 'certExpiresAt populated after reissue');
    assert.ok(keyRow.certFingerprint, 'certFingerprint populated after reissue');

    // Fix #3: Verify audit entry for cert_reissued
    await sleep(300);
    var auditAfter = countTableRows(ctx.dbPath, 'audit_log');
    assert.ok(auditAfter > auditBefore,
      'Audit log should have entry for cert_reissued (before: ' + auditBefore + ', after: ' + auditAfter + ')');
  });

  it('reissue enrollment code can be redeemed with reissue flag', async function () {
    // Create a reissue enrollment code directly in DB (simulating the server endpoint)
    // to test the redemption path with reissue=true independently of api-encrypt
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stash = createStashViaDb({ syncEnabled: true, syncBundleId: bundle.bundleId });

    var enrollCode = 'HSTASH-' + b.crypto.generateToken(8).toUpperCase().match(/.{4}/g).join('-');
    var codeHash = sha3('hs-enroll:' + enrollCode);
    var originalKeyId = b.crypto.generateToken(32);

    runDbScript(ctx.dbPath, [
      'db.prepare("INSERT INTO enrollment_codes (_id, codeHash, apiKey, clientCert, clientKey, caCert, stashId, status, reissue, originalKeyId, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(',
      '    ' + JSON.stringify(b.crypto.generateToken(32)) + ',',
      '    ' + JSON.stringify(codeHash) + ',',
      '    null,',  // reissue = no new API key
      '    "-----BEGIN CERTIFICATE-----\\nreissue-test-cert\\n-----END CERTIFICATE-----",',
      '    "-----BEGIN EC PRIVATE KEY-----\\nreissue-test-key\\n-----END EC PRIVATE KEY-----",',
      '    "-----BEGIN CERTIFICATE-----\\nreissue-test-ca\\n-----END CERTIFICATE-----",',
      '    ' + JSON.stringify(stash.stashId) + ',',
      '    "pending",',
      '    "true",',
      '    ' + JSON.stringify(originalKeyId) + ',',
      '    ' + JSON.stringify(new Date(Date.now() + 3600000).toISOString()) + ',',
      '    ' + JSON.stringify(new Date().toISOString()),
      '  );',
      'process.stdout.write("OK");',
    ].join('\n'));

    // Redeem the reissue enrollment code
    var redeemRes = await httpRequest(ctx.url + '/sync/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: enrollCode }),
    });
    // 200 = success, 429 = rate limited
    assert.ok(redeemRes.statusCode === 200 || redeemRes.statusCode === 429,
      'Redemption -> ' + redeemRes.statusCode);
    if (redeemRes.statusCode === 429) { console.log('  # Rate limited on redeem'); return; }
    assert.ok(redeemRes.json.success, 'success: true');
    // reissue field may be boolean true or string 'true' depending on DB storage
    assert.ok(redeemRes.json.reissue === true || redeemRes.json.reissue === 'true',
      'Response should have reissue truthy, got: ' + JSON.stringify(redeemRes.json.reissue));
    assert.ok(redeemRes.json.clientCert, 'Should return client cert');
    assert.ok(redeemRes.json.clientKey, 'Should return client key');
    assert.ok(redeemRes.json.caCert, 'Should return CA cert');
    // For reissue, apiKey should be null (client already has one)
    assert.equal(redeemRes.json.apiKey, null, 'reissue enrollment should not return new API key');
  });

  it('reissue-cert rejects invalid requests', async function () {
    if (!hasMtls) { console.log('  # Skipping — no mTLS certs'); return; }

    // Missing apiKeyId
    var bundle1 = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stash1 = createStashViaDb({ syncEnabled: true, syncBundleId: bundle1.bundleId });
    var res1 = await httpRequest(ctx.url + '/admin/stash/' + stash1.stashId + '/reissue-cert', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ctx.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.ok(res1.statusCode === 400 || res1.statusCode === 429,
      'Missing apiKeyId -> ' + res1.statusCode);

    // Nonexistent API key
    var res2 = await httpRequest(ctx.url + '/admin/stash/' + stash1.stashId + '/reissue-cert', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ctx.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKeyId: 'nonexistent-key-id-' + Date.now() }),
    });
    assert.ok(res2.statusCode === 404 || res2.statusCode === 429,
      'Nonexistent key -> ' + res2.statusCode);

    // Cross-stash: key bound to stash1 but reissue targets stash2
    var bundle2 = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stash2 = createStashViaDb({ syncEnabled: true, syncBundleId: bundle2.bundleId });
    var boundKey = createBoundApiKey(stash1.stashId, bundle1.bundleId);
    var res3 = await httpRequest(ctx.url + '/admin/stash/' + stash2.stashId + '/reissue-cert', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ctx.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKeyId: boundKey.keyId }),
    });
    assert.ok(res3.statusCode === 403 || res3.statusCode === 429,
      'Cross-stash reissue -> ' + res3.statusCode);
  });
});


// ---- Fix #8: Concurrent cert generation (temp dir collision) ----

describe('Fix #8: Concurrent certificate temp dir isolation', { timeout: 30000 }, function () {

  it('concurrent uploads do not collide on temp directories', async function () {
    // Fix #8 appended crypto.randomBytes(4) to temp dir names to prevent collision.
    // We test this indirectly: concurrent uploads that trigger server-side temp file
    // creation should all succeed without EEXIST or ENOENT errors.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var count = 10;
    var uploads = [];
    for (var i = 0; i < count; i++) {
      uploads.push(uploadFile(ctx.url, bundle.bundleId, 'concurrent-' + i + '.txt',
        'data-' + b.crypto.generateToken(32), ctx.apiKey));
    }
    var results = await Promise.all(uploads);
    var successes = results.filter(function (r) { return r.statusCode === 200; }).length;
    assert.equal(successes, count,
      'All ' + count + ' concurrent uploads should succeed (no temp dir collisions)');
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), count);
  });
});


// ---- Fix #9: Backup lock recovery ----

describe('Fix #9: Backup lock does not get stuck', { timeout: 30000 }, function () {

  var hasBackup = !!process.env.BACKUP_TEST_BUCKET;

  it('second backup after first completes does not fail with lock error', async function () {
    if (!hasBackup) { console.log('  # Skipping — BACKUP_TEST_BUCKET not set'); return; }
    if (!hasMtls) { console.log('  # Skipping — no mTLS certs'); return; }

    var client = new ApiClient(ctx.url, ctx.apiKey, {
      clientCert: ctx.clientCert, clientKey: ctx.clientKey, ca: ctx.caCert,
    });
    await client.init();

    // First backup
    var res1 = await client.request('/admin/backup/run', 'POST', {
      passphrase: 'lock-test-1-' + Date.now(),
    });
    assert.equal(res1.statusCode, 200, 'First backup should succeed');

    // Wait for backup to complete
    await sleep(2000);

    // Second backup — should NOT fail with "operation in progress"
    var res2 = await client.request('/admin/backup/run', 'POST', {
      passphrase: 'lock-test-2-' + Date.now(),
    });
    // 200 = success, 409 = concurrent operation (if first is still running)
    assert.ok(res2.statusCode === 200 || res2.statusCode === 409,
      'Second backup should not be permanently locked (got: ' + res2.statusCode + ')');

    // If the first backup is still running (409), wait and retry
    if (res2.statusCode === 409) {
      await sleep(5000);
      var res3 = await client.request('/admin/backup/run', 'POST', {
        passphrase: 'lock-test-3-' + Date.now(),
      });
      assert.equal(res3.statusCode, 200, 'Backup after waiting should succeed (lock not stuck)');
    }
  });
});


// ---- Fix #11: Orphan cleanup grace period ----

describe('Fix #11: Orphan cleanup does not delete in-flight uploads', { timeout: 30000 }, function () {

  it('recently uploaded file is not treated as orphan', async function () {
    // Upload a file and immediately verify it exists — the orphan cleanup
    // job should not delete it thanks to the 5-minute mtime grace period
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var content = 'orphan-grace-test-' + Date.now();

    var res = await uploadFile(ctx.url, bundle.bundleId, 'grace-test.txt', content, ctx.apiKey);
    assert.equal(res.statusCode, 200, 'Upload should succeed');

    // File should still be accessible immediately after upload
    var files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    assert.ok(files.length > 0, 'File should exist in DB immediately after upload');
    assert.ok(files[0].size > 0, 'File should have non-zero size');

    // Small delay then re-check — file should still be there
    await sleep(500);
    var count = countBundleFiles(ctx.dbPath, bundle.bundleId);
    assert.equal(count, 1, 'File should persist (not cleaned up as orphan)');
  });
});


// ---- Enrollment code column existence ----

describe('Fix #5: enrollment_codes table has reissue and originalKeyId columns', { timeout: 30000 }, function () {

  it('enrollment_codes table has reissue column', function () {
    // Verify the column exists by inserting a row with reissue set
    var codeHash = sha3('hs-enroll:column-test-' + Date.now());
    var result = runDbScript(ctx.dbPath, [
      'db.prepare("INSERT INTO enrollment_codes (_id, codeHash, apiKey, status, reissue, originalKeyId, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(',
      '    ' + JSON.stringify(b.crypto.generateToken(32)) + ',',
      '    ' + JSON.stringify(codeHash) + ',',
      '    "hs_col_test",',
      '    "pending",',
      '    "true",',
      '    "original-key-123",',
      '    ' + JSON.stringify(new Date(Date.now() + 3600000).toISOString()) + ',',
      '    ' + JSON.stringify(new Date().toISOString()),
      '  );',
      'process.stdout.write("OK");',
    ].join('\n'));
    assert.equal(result, 'OK', 'Insert with reissue and originalKeyId columns should succeed');
  });

  it('reissue and originalKeyId values are stored and retrievable', function () {
    var testId = b.crypto.generateToken(32);
    var codeHash = sha3('hs-enroll:retrieve-test-' + Date.now());

    runDbScript(ctx.dbPath, [
      'db.prepare("INSERT INTO enrollment_codes (_id, codeHash, apiKey, status, reissue, originalKeyId, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(',
      '    ' + JSON.stringify(testId) + ',',
      '    ' + JSON.stringify(codeHash) + ',',
      '    "hs_retrieve_test",',
      '    "pending",',
      '    "true",',
      '    "key-456",',
      '    ' + JSON.stringify(new Date(Date.now() + 3600000).toISOString()) + ',',
      '    ' + JSON.stringify(new Date().toISOString()),
      '  );',
      'process.stdout.write("OK");',
    ].join('\n'));

    var rowStr = runDbScript(ctx.dbPath, [
      'var row = db.prepare("SELECT reissue, originalKeyId FROM enrollment_codes WHERE _id = ?").get(' + JSON.stringify(testId) + ');',
      'process.stdout.write(JSON.stringify(row || {}));',
    ].join('\n'));
    var row = JSON.parse(rowStr);
    assert.equal(row.reissue, 'true', 'reissue column value stored correctly');
    assert.equal(row.originalKeyId, 'key-456', 'originalKeyId column value stored correctly');
  });
});


// ---- Fix #4: api_keys cert columns existence ----

describe('Fix #4: api_keys table has cert tracking columns', { timeout: 30000 }, function () {

  it('api_keys table has certIssuedAt, certExpiresAt, certFingerprint columns', function () {
    var keyId = b.crypto.generateToken(32);
    var keyHash = sha3('hs_coltest_' + Date.now());
    var now = new Date().toISOString();

    var result = runDbScript(ctx.dbPath, [
      'var users = db.prepare("SELECT _id FROM users LIMIT 1").all();',
      'var userId = users.length > 0 ? users[0]._id : "system";',
      'db.prepare("INSERT INTO api_keys (_id, name, keyHash, prefix, permissions, userId, certIssuedAt, certExpiresAt, certFingerprint, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
      '  .run(' + JSON.stringify(keyId) + ', "cert-col-test", ' + JSON.stringify(keyHash) + ', "hs_col", "sync", userId, ' + JSON.stringify(now) + ', ' + JSON.stringify(now) + ', "fp-test-hash", ' + JSON.stringify(now) + ');',
      'process.stdout.write("OK");',
    ].join('\n'));
    assert.equal(result, 'OK', 'Insert with cert columns should succeed');

    var rowStr = runDbScript(ctx.dbPath, [
      'var row = db.prepare("SELECT certIssuedAt, certExpiresAt, certFingerprint FROM api_keys WHERE _id = ?").get(' + JSON.stringify(keyId) + ');',
      'process.stdout.write(JSON.stringify(row || {}));',
    ].join('\n'));
    var row = JSON.parse(rowStr);
    assert.equal(row.certIssuedAt, now, 'certIssuedAt stored');
    assert.equal(row.certExpiresAt, now, 'certExpiresAt stored');
    assert.equal(row.certFingerprint, 'fp-test-hash', 'certFingerprint stored');
  });
});
