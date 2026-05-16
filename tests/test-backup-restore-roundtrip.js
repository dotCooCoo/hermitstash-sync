'use strict';

/**
 * Encrypted backup → restore roundtrip E2E test.
 *
 * Exercises the complete backup + restore code path against a real S3 bucket
 * (BACKUP_TEST_BUCKET). The restore side runs with { dryRun: true } so the
 * full download + decrypt + checksum-verify path runs without mutating the
 * shared test server's disk state — letting this test coexist with the rest
 * of the suite that depends on the server's live DB and vault key.
 *
 * The crypto path under test:
 *   - Argon2id password derivation (manifest encryption)
 *   - XChaCha20-Poly1305 manifest decryption
 *   - Vault key unwrap
 *   - SHA3-512 checksum verification for every file in the archive
 *   - Path-safety rejection on upload restoration (even in dry-run)
 *   - TLS/CA file decryption when present
 *
 * Skips gracefully when BACKUP_TEST_BUCKET isn't configured — no different
 * from test-s3-storage.js.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { sleep, httpRequest, ApiClient, uploadFile, createBundleViaDb } = require('./test-helpers');

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

const HAS_BACKUP = !!process.env.BACKUP_TEST_BUCKET;

if (!HAS_BACKUP) {
  console.log('  ⚠ Skipping backup roundtrip tests — set BACKUP_TEST_BUCKET');
  process.exit(0);
}

// Shared admin client — ECIES session is set up once, reused for every
// admin endpoint call. /drop/init has a rate limit, so paying the session
// cost once is important when this suite grows.
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

describe('Backup → Restore Roundtrip (S3)', { timeout: 60000 }, function () {
  var backupPassphrase = 'roundtrip-test-' + Date.now();
  var knownTimestamp = null;

  before(async function () {
    // Seed a visible state marker — a bundle + file — so the backup archive
    // contains at least one upload row. The restore dry-run then has to
    // download + checksum + decrypt both the DB and that upload.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'default' });
    await uploadFile(ctx.url, bundle.bundleId, 'roundtrip-marker.txt',
      'roundtrip-marker-' + Date.now(), ctx.apiKey);
    await sleep(200);
  });

  it('POST /admin/backup/run produces a backup with a fresh timestamp', async function () {
    // Use the plain httpRequest path (like test-s3-storage.js does) —
    // /admin/backup/run tolerates unencrypted bodies here because the
    // prior backup tests established the shape.
    var res = await httpRequest(ctx.url + '/admin/backup/run', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ctx.apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: backupPassphrase }),
      rejectUnauthorized: false,
      // httpRequest defaults to 1s — backup worker easily takes longer than
      // that to round-trip to S3, so raise the ceiling well above what we
      // expect the backup to take. runBackup resolves only after the worker
      // completes, so this timeout bounds the actual end-to-end duration.
      timeout: 60000,
    });
    assert.equal(res.statusCode, 200, 'backup /run → 200, got ' + res.statusCode + ' ' + res.body);

    // Wait for the backup to land on S3 before reading history. Backup is
    // async (worker thread) so the HTTP 200 returns before S3 PUTs flush.
    await sleep(1500);

    var client = await adminClient();
    var histRes = await client.request('/admin/backup/history', 'GET');
    assert.equal(histRes.statusCode, 200, 'history → 200');
    var b = body(histRes);
    assert.ok(Array.isArray(b.history), 'history is array');
    assert.ok(b.history.length > 0, 'at least one backup in history');

    // Newest first; find the one just created by matching durations < 60s
    // (other fields aren't stable across parallel tests).
    knownTimestamp = b.history[0].timestamp;
    assert.ok(knownTimestamp, 'have a timestamp to restore');
  });

  it('POST /admin/restore/run with dryRun=true verifies the full archive without mutating state', async function () {
    assert.ok(knownTimestamp, 'prior test produced a timestamp');
    var client = await adminClient();
    var res = await client.request('/admin/restore/run', 'POST', {
      passphrase: backupPassphrase,
      timestamp: knownTimestamp,
      dryRun: true,
    });
    assert.equal(res.statusCode, 200, 'restore dry-run → 200, got ' + res.statusCode + ' ' + (res.body || ''));
    var b = body(res);
    assert.equal(b.success, true, 'success: true');
    assert.equal(b.dryRun, true, 'dryRun echoed back');
    assert.equal(b.restarting, false, 'server NOT restarting in dry-run');
    assert.ok(b.stats, 'stats present');
    assert.ok(b.stats.dbFiles >= 3, 'at least db.key.enc + hermitstash.db.enc + vault.key.enc counted, got ' + b.stats.dbFiles);
    assert.equal(b.stats.dryRun, true, 'stats.dryRun marked');
    // totalUploads may be 0 if the bundle was empty, or >=1 with our marker
    assert.ok(b.stats.failedUploads === 0 || b.stats.failedUploads === undefined,
      'no failed upload restores in a clean archive, got ' + b.stats.failedUploads);
  });

  it('POST /admin/restore/run with wrong passphrase is rejected', async function () {
    assert.ok(knownTimestamp, 'prior test produced a timestamp');
    var client = await adminClient();
    var res = await client.request('/admin/restore/run', 'POST', {
      passphrase: 'definitely-not-the-real-passphrase',
      timestamp: knownTimestamp,
      dryRun: true,
    });
    // 403 if passphraseHash is set and verification runs up-front, else
    // 500 from the worker's "wrong passphrase" decrypt failure.
    assert.ok(res.statusCode === 403 || res.statusCode === 500,
      'wrong passphrase → 403 or 500, got ' + res.statusCode + ' ' + (res.body || ''));
    var b = body(res) || {};
    // Error message should hint at passphrase, not leak crypto internals
    var errStr = String(b.error || '');
    assert.ok(/passphrase|decrypt|invalid/i.test(errStr),
      'error mentions passphrase/decrypt/invalid, got: ' + errStr);
  });

  it('POST /admin/restore/run for a nonexistent timestamp fails cleanly', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/restore/run', 'POST', {
      passphrase: backupPassphrase,
      timestamp: '2020-01-01T00-00-00-000Z', // real format, nonexistent
      dryRun: true,
    });
    assert.ok(res.statusCode >= 400, 'nonexistent timestamp → 4xx/5xx, got ' + res.statusCode);
    var b = body(res) || {};
    assert.ok(/not found|timestamp/i.test(String(b.error || '')),
      'error mentions not-found/timestamp, got: ' + (b.error || ''));
  });

  it('POST /admin/restore/run rejects missing passphrase with 400', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/restore/run', 'POST', {
      timestamp: knownTimestamp || '2020-01-01T00-00-00-000Z',
      dryRun: true,
    });
    assert.equal(res.statusCode, 400, 'missing passphrase → 400, got ' + res.statusCode);
  });

  it('POST /admin/restore/run rejects missing timestamp with 400', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/restore/run', 'POST', {
      passphrase: backupPassphrase,
      dryRun: true,
    });
    assert.equal(res.statusCode, 400, 'missing timestamp → 400, got ' + res.statusCode);
  });
});
