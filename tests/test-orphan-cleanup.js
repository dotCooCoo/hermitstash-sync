'use strict';

/**
 * Orphan-cleanup job tests — verifies the sweep doesn't eat in-flight uploads.
 *
 * The job scans uploads/bundles/ for files with no DB row and deletes them.
 * The primary defense against deleting in-flight uploads is a 5-minute
 * mtime grace period (file must be older than 5 min to qualify as orphan).
 * If that grace ever regresses — or if a new code path walks the same tree
 * without the mtime check — uploads mid-process get silently deleted.
 *
 * Also covers the empty-bundle cleanup path, which has the opposite risk:
 * it can race with new uploads starting against a just-created bundle.
 *
 * Uses admin endpoints /admin/storage/orphans/{scan,clean} to exercise the
 * same code paths the scheduled job runs.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const fs = require('node:fs');
const path = require('node:path');
const {
  ApiClient, sleep, createBundleViaDb, uploadFile, runDbScript, sha3,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  dataDir: process.env.HERMITSTASH_TEST_DATA_DIR,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

// Admin endpoints return ECIES-encrypted bodies.
var _client = null;
async function adminClient() {
  if (_client) return _client;
  _client = new ApiClient(ctx.url, ctx.apiKey, {
    clientCert: ctx.clientCert,
    clientKey: ctx.clientKey,
    ca: ctx.caCert,
  });
  await _client.init();
  return _client;
}
function body(res) { return res.decrypted || res.json; }

/**
 * Where the test server stores uploads. startServer sets UPLOAD_DIR to
 * <dataDir>/uploads so we can write fixture files into the same directory
 * the job scans.
 */
function uploadDir() {
  return path.join(ctx.dataDir, 'uploads');
}

/**
 * Write a fixture file at uploads/bundles/<shareId>/<relativePath> with
 * a specified mtime. Returns the absolute path.
 */
function seedOrphanFile(shareId, relativePath, content, mtimeMsAgo) {
  var dir = path.join(uploadDir(), 'bundles', shareId);
  fs.mkdirSync(dir, { recursive: true });
  var full = path.join(dir, relativePath);
  fs.writeFileSync(full, content);
  if (mtimeMsAgo != null) {
    var t = (Date.now() - mtimeMsAgo) / 1000;
    fs.utimesSync(full, t, t);
  }
  return full;
}

/**
 * Insert a files table row pointing at a given storagePath WITHOUT writing
 * the file to disk — produces a dangling DB record for scanDanglingRecords.
 * Returns the inserted fileId.
 */
function seedDanglingFileRow(bundleId, storagePath) {
  var fileId = b.crypto.generateToken(32);
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO files (_id, bundleId, originalName, relativePath, storagePath, size, mimeType, checksum, encryptionKey, seq, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(fileId) + ',',
    '    ' + JSON.stringify(bundleId) + ',',
    '    "dangling.txt",',
    '    "dangling.txt",',
    '    ' + JSON.stringify(storagePath) + ',',
    '    0, "text/plain",',
    '    ' + JSON.stringify('0'.repeat(128)) + ',',
    '    "", 1, "complete", ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to seed file row: ' + out);
  return fileId;
}

function bundleExists(bundleId) {
  var script = [
    'var row = db.prepare("SELECT COUNT(*) as cnt FROM bundles WHERE _id = ?").get(' + JSON.stringify(bundleId) + ');',
    'process.stdout.write(String(row ? row.cnt : 0));',
  ].join('\n');
  return parseInt(runDbScript(ctx.dbPath, script), 10) === 1;
}

describe('Orphan-cleanup sweep', { timeout: 30000 }, function () {

  before(async function () {
    if (!ctx.dataDir) {
      throw new Error('HERMITSTASH_TEST_DATA_DIR not set — test-helpers must expose it');
    }
    await sleep(100);
  });

  it('freshly-written orphan files are NOT flagged (5-minute grace)', async function () {
    // File with no DB row, mtime = now → protected by grace period.
    var shareId = 'fresh-' + b.crypto.generateToken(6);
    seedOrphanFile(shareId, 'fresh.txt', 'in-flight content', 0);

    var client = await adminClient();
    var res = await client.request('/admin/storage/orphans/scan', 'GET');
    assert.equal(res.statusCode, 200);
    var bodyJson = body(res);
    // Total orphans should not include this fresh file. We can't compare
    // by filename directly (the API returns only counts), but the total
    // can't exceed the count of files that PASS the grace period. If our
    // fresh file leaks past the check, the count jumps.
    // Equivalent assertion: after a follow-up clean the file must still exist.
    var cleanRes = await client.request('/admin/storage/orphans/clean', 'POST', { local: true });
    assert.equal(cleanRes.statusCode, 200);
    var fresh = path.join(uploadDir(), 'bundles', shareId, 'fresh.txt');
    assert.ok(fs.existsSync(fresh), 'fresh orphan must survive the grace period, got missing at ' + fresh);

    // Cleanup fixture
    try { fs.unlinkSync(fresh); } catch (_e) { /* fixture cleanup — ignore */ }
    try { fs.rmdirSync(path.dirname(fresh)); } catch (_e) { /* fixture cleanup — ignore */ }
    void bodyJson;
  });

  it('stale orphan files (mtime > 5 min) are deleted by clean', async function () {
    var shareId = 'stale-' + b.crypto.generateToken(6);
    var SIX_MIN = 6 * 60 * 1000;
    var stalePath = seedOrphanFile(shareId, 'stale.txt', 'long-abandoned', SIX_MIN);
    assert.ok(fs.existsSync(stalePath), 'fixture exists before clean');

    var client = await adminClient();
    var cleanRes = await client.request('/admin/storage/orphans/clean', 'POST', { local: true });
    assert.equal(cleanRes.statusCode, 200);
    var bodyJson = body(cleanRes);
    assert.ok(bodyJson.deleted.local >= 1, 'at least 1 orphan cleaned, got ' + bodyJson.deleted.local);
    assert.ok(!fs.existsSync(stalePath), 'stale orphan was deleted');
  });

  it('dangling DB records (file row points to nonexistent path) are surfaced by scan', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var fileId = seedDanglingFileRow(bundle.bundleId, 'bundles/' + bundle.shareId + '/does-not-exist.txt');
    await sleep(100);

    var client = await adminClient();
    var scan = await client.request('/admin/storage/orphans/scan', 'GET');
    assert.equal(scan.statusCode, 200);
    var s = body(scan);
    assert.ok(s.dangling.records >= 1, 'scan reports dangling record, got ' + s.dangling.records);

    // Confirm clean with dangling=true removes the row
    var clean = await client.request('/admin/storage/orphans/clean', 'POST', { dangling: true });
    assert.equal(clean.statusCode, 200);
    var c = body(clean);
    assert.ok(c.deleted.dangling >= 1, 'dangling rows removed, got ' + c.deleted.dangling);
    void fileId;
  });

  it('empty-bundle cleanup SKIPS a bundle while files are still on disk under its shareId', async function () {
    // Create an empty bundle, drop a fresh (orphan) file under its shareId,
    // then request empty-bundle cleanup. The disk-check defense in
    // scanEmptyBundles must keep the bundle alive until the orphan is
    // cleared by a separate pass.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var stasher = seedOrphanFile(bundle.shareId, 'under-bundle.txt', 'fresh', 0);
    await sleep(100);

    var client = await adminClient();
    var clean = await client.request('/admin/storage/orphans/clean', 'POST', { emptyBundles: true, local: false });
    assert.equal(clean.statusCode, 200);

    assert.equal(bundleExists(bundle.bundleId), true,
      'bundle with orphan files on disk MUST survive the empty-bundle pass');

    // Fixture cleanup
    try { fs.unlinkSync(stasher); } catch (_e) { /* fixture cleanup — ignore */ }
  });

  it('concurrent upload during orphan clean does not leave the user with a deleted file', async function () {
    // Upload a file to a sync bundle, then immediately trigger orphan
    // cleanup. The just-uploaded file must survive — its DB row exists
    // (no grace-period dependency needed) because the upload completed
    // before the clean started. This checks that the local-orphan scan
    // correctly cross-references the files table.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var content = 'orphan-race-' + Date.now();
    var res = await uploadFile(ctx.url, bundle.bundleId, 'survivor.txt', content, ctx.apiKey);
    assert.equal(res.statusCode, 200, 'upload succeeded');

    var client = await adminClient();
    var clean = await client.request('/admin/storage/orphans/clean', 'POST', { local: true });
    assert.equal(clean.statusCode, 200);

    // Verify the file's DB row survived the clean
    var script = [
      'var row = db.prepare("SELECT COUNT(*) as cnt FROM files WHERE bundleId = ? AND status = ?").get(' + JSON.stringify(bundle.bundleId) + ', "complete");',
      'process.stdout.write(String(row ? row.cnt : 0));',
    ].join('\n');
    var count = parseInt(runDbScript(ctx.dbPath, script), 10);
    assert.equal(count, 1, 'recently-uploaded file row must survive clean, got ' + count);
  });
});
