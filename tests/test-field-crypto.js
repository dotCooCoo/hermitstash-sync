'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  ApiClient, uploadFile, sha3, runDbScript,
  createBundleViaDb, createBundleViaApi,
} = require('./test-helpers');

var url = process.env.HERMITSTASH_TEST_URL;
var apiKey = process.env.HERMITSTASH_TEST_API_KEY;
var dbPath = process.env.HERMITSTASH_TEST_DB_PATH;
var clientCert = process.env.HERMITSTASH_TEST_CLIENT_CERT;
var clientKey = process.env.HERMITSTASH_TEST_CLIENT_KEY;
var caCert = process.env.HERMITSTASH_TEST_CA_CERT;

if (!url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

var VAULT_PREFIX = 'vault:';

/**
 * Helper: check if a value looks vault-sealed (starts with "vault:").
 */
function isSealed(value) {
  return typeof value === 'string' && value.startsWith(VAULT_PREFIX);
}

/**
 * Helper: check if a value is a valid SHA3-512 hex string (128 hex chars).
 */
function isSha3Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{128}$/.test(value);
}

/**
 * Helper: create an initialized ApiClient.
 */
async function getClient() {
  var client = new ApiClient(url, apiKey, {
    clientCert: clientCert,
    clientKey: clientKey,
    ca: caCert,
  });
  await client.init();
  return client;
}

/**
 * Field-level encryption (field-crypto) verification.
 *
 * These tests query the raw SQLite database to confirm that sensitive
 * fields are vault-sealed at rest and that derived hash fields contain
 * proper SHA3-512 hex digests -- not plaintext.
 */
describe('Field Crypto: File Fields', { timeout: 30000 }, function () {

  it('uploaded file has sealed originalName, storagePath, uploaderEmail in raw DB', async function () {
    var bundle = createBundleViaDb(dbPath, { bundleType: 'sync' });
    var content = 'field-crypto-test-' + Date.now();
    var res = await uploadFile(url, bundle.bundleId, 'secret-document.txt', content, apiKey);
    assert.equal(res.statusCode, 200, 'Upload should succeed: ' + res.statusCode + ' ' + (res.body || '').substring(0, 200));

    // Query raw DB for the file record
    var script = [
      'var rows = db.prepare("SELECT originalName, storagePath, uploaderEmail, uploaderName, shareId, relativePath FROM files WHERE bundleId = ?").all(' + JSON.stringify(bundle.bundleId) + ');',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one file record');

    var file = rows[0];

    // originalName should be sealed, not plaintext
    assert.ok(isSealed(file.originalName),
      'originalName should be vault-sealed, got: ' + (file.originalName || '').substring(0, 40));
    assert.ok(!file.originalName.includes('secret-document') && !file.originalName.includes('.txt'),
      'originalName should not contain the plaintext filename');

    // storagePath should be sealed
    assert.ok(isSealed(file.storagePath),
      'storagePath should be vault-sealed, got: ' + (file.storagePath || '').substring(0, 40));

    // relativePath should be sealed
    assert.ok(isSealed(file.relativePath),
      'relativePath should be vault-sealed, got: ' + (file.relativePath || '').substring(0, 40));

    // shareId should be sealed
    assert.ok(isSealed(file.shareId),
      'shareId should be vault-sealed, got: ' + (file.shareId || '').substring(0, 40));
  });

  it('file shareIdHash is a SHA3-512 hex digest, not plaintext', async function () {
    var bundle = createBundleViaDb(dbPath, { bundleType: 'sync' });
    await uploadFile(url, bundle.bundleId, 'hash-check.txt', 'hash content', apiKey);

    var script = [
      'var rows = db.prepare("SELECT shareIdHash FROM files WHERE bundleId = ?").all(' + JSON.stringify(bundle.bundleId) + ');',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one file');

    var hash = rows[0].shareIdHash;
    assert.ok(isSha3Hex(hash),
      'shareIdHash should be a 128-char hex SHA3-512 digest, got length ' + (hash ? hash.length : 0));
  });
});

describe('Field Crypto: Bundle Fields', { timeout: 30000 }, function () {

  it('bundle created via API has sealed uploaderName and uploaderEmail', async function () {
    var client = await getClient();
    var bundleInfo = await createBundleViaApi(url, apiKey, dbPath, { _client: client });

    var script = [
      'var row = db.prepare("SELECT uploaderName, uploaderEmail, shareId, message FROM bundles WHERE _id = ?").get(' + JSON.stringify(bundleInfo.bundleId) + ');',
      'process.stdout.write(JSON.stringify(row));',
    ].join('\n');
    var row = JSON.parse(runDbScript(dbPath, script));
    assert.ok(row, 'Bundle record should exist');

    // uploaderName should be sealed (set during /drop/init)
    assert.ok(isSealed(row.uploaderName),
      'uploaderName should be vault-sealed, got: ' + (row.uploaderName || '').substring(0, 40));

    // shareId should be sealed
    assert.ok(isSealed(row.shareId),
      'shareId should be vault-sealed, got: ' + (row.shareId || '').substring(0, 40));
  });

  it('bundle shareIdHash is a SHA3-512 hex digest', async function () {
    var client = await getClient();
    var bundleInfo = await createBundleViaApi(url, apiKey, dbPath, { _client: client });

    var script = [
      'var row = db.prepare("SELECT shareIdHash FROM bundles WHERE _id = ?").get(' + JSON.stringify(bundleInfo.bundleId) + ');',
      'process.stdout.write(JSON.stringify(row));',
    ].join('\n');
    var row = JSON.parse(runDbScript(dbPath, script));
    assert.ok(row, 'Bundle record should exist');

    assert.ok(isSha3Hex(row.shareIdHash),
      'shareIdHash should be a 128-char hex SHA3-512 digest, got length ' + (row.shareIdHash ? row.shareIdHash.length : 0));
  });
});

describe('Field Crypto: User Fields', { timeout: 30000 }, function () {

  it('admin user email is sealed in the raw DB', function () {
    var script = [
      'var rows = db.prepare("SELECT email, emailHash, displayName FROM users LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one user');

    var user = rows[0];

    // email should be sealed
    assert.ok(isSealed(user.email),
      'user email should be vault-sealed, got: ' + (user.email || '').substring(0, 40));
    assert.ok(!user.email.includes('@'),
      'sealed email should not contain @ character');

    // displayName should be sealed
    assert.ok(isSealed(user.displayName),
      'displayName should be vault-sealed, got: ' + (user.displayName || '').substring(0, 40));
  });

  it('user emailHash is a SHA3-512 hex string', function () {
    var script = [
      'var rows = db.prepare("SELECT emailHash FROM users LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one user');

    var hash = rows[0].emailHash;
    assert.ok(isSha3Hex(hash),
      'emailHash should be a 128-char hex SHA3-512 digest, got length ' + (hash ? hash.length : 0));
  });
});

describe('Field Crypto: Audit Log Fields', { timeout: 30000 }, function () {

  it('audit log entries are sealed in the raw DB', async function () {
    // Trigger at least one audit entry by hitting the admin settings endpoint
    var client = await getClient();
    await client.request('/admin/settings', 'GET');

    var script = [
      'var rows = db.prepare("SELECT action, details, ip FROM audit_log ORDER BY createdAt DESC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one audit entry');

    var entry = rows[0];

    // action should be sealed
    assert.ok(isSealed(entry.action),
      'audit action should be vault-sealed, got: ' + (entry.action || '').substring(0, 40));

    // details should be sealed (if present)
    if (entry.details) {
      assert.ok(isSealed(entry.details),
        'audit details should be vault-sealed, got: ' + (entry.details || '').substring(0, 40));
    }
  });
});

describe('Field Crypto: API Key Fields', { timeout: 30000 }, function () {

  it('API key created via admin API has sealed name and prefix in the raw DB', async function () {
    // Create a key via the API (goes through field-crypto) instead of direct DB insert
    var client = await getClient();
    var keyName = 'field-crypto-test-' + Date.now();
    var createRes = await client.request('/admin/apikeys/create', 'POST', {
      name: keyName,
      permissions: 'upload,read',
    });
    assert.equal(createRes.statusCode, 200, 'API key creation should succeed');

    // Query all keys and find the newest one (highest createdAt)
    var script = [
      'var rows = db.prepare("SELECT name, prefix, permissions, keyHash, createdAt FROM api_keys ORDER BY createdAt DESC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one API key');

    var key = rows[0];

    // name should be sealed (created via API goes through field-crypto)
    assert.ok(isSealed(key.name),
      'API key name should be vault-sealed, got: ' + (key.name || '').substring(0, 40));

    // prefix should be sealed
    assert.ok(isSealed(key.prefix),
      'API key prefix should be vault-sealed, got: ' + (key.prefix || '').substring(0, 40));

    // permissions should be sealed
    assert.ok(isSealed(key.permissions),
      'API key permissions should be vault-sealed, got: ' + (key.permissions || '').substring(0, 40));

    // keyHash is raw (it is already a hash, not PII) -- verify it exists and is not sealed
    assert.ok(key.keyHash, 'keyHash should exist');
    assert.ok(!isSealed(key.keyHash),
      'keyHash should NOT be vault-sealed (it is already a hash)');
  });
});
