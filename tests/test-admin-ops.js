'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  ApiClient, httpRequest, runDbScript, sha3, createApiKey,
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

/**
 * Shared ApiClient for admin requests (lazy-init, reused across tests
 * to avoid rate-limiting on /drop/init from repeated ECIES key exchanges).
 * Call resetClient() after any test that invalidates sessions.
 */
var _sharedClient = null;
async function adminClient() {
  if (_sharedClient) return _sharedClient;
  _sharedClient = new ApiClient(url, apiKey, {
    clientCert: clientCert,
    clientKey: clientKey,
    ca: caCert,
  });
  await _sharedClient.init();
  return _sharedClient;
}
function resetClient() { _sharedClient = null; }

/**
 * Helper: create a test user directly in the DB.
 * Returns { userId, email }.
 */
function createTestUser(opts) {
  var email = (opts && opts.email) || ('testuser-' + b.crypto.generateToken(4) + '@hermitstash.com');
  var userId = b.crypto.generateToken(32);
  var displayName = (opts && opts.displayName) || 'Test User';
  var role = (opts && opts.role) || 'user';
  var status = (opts && opts.status) || 'active';
  var now = new Date().toISOString();

  var script = [
    'db.prepare("INSERT INTO users (_id, email, emailHash, displayName, role, status, authType, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(userId) + ',',
    '    ' + JSON.stringify(email) + ',',
    '    ' + JSON.stringify(sha3('hs-email:' + email.toLowerCase())) + ',',
    '    ' + JSON.stringify(displayName) + ',',
    '    ' + JSON.stringify(role) + ',',
    '    ' + JSON.stringify(status) + ',',
    '    "local",',
    '    ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');

  var result = runDbScript(dbPath, script);
  if (result !== 'OK') throw new Error('Failed to create test user: ' + result);
  return { userId: userId, email: email };
}

describe('Admin: User Management API', { timeout: 30000 }, function () {

  it('GET /admin/users/api returns a user list with expected fields', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/users/api', 'GET');
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(Array.isArray(data.users), 'Response should contain a users array');
    assert.ok(typeof data.total === 'number', 'Response should contain a total count');
    assert.ok(typeof data.page === 'number', 'Response should contain a page number');
    // At least the admin user should exist
    assert.ok(data.users.length >= 1, 'Should have at least one user (the admin)');
    var user = data.users[0];
    assert.ok(user._id, 'User should have an _id');
    assert.ok(user.role, 'User should have a role');
    assert.ok(user.status, 'User should have a status');
    assert.ok(user.createdAt, 'User should have a createdAt');
    // passwordHash should be stripped from the response
    assert.equal(user.passwordHash, undefined, 'passwordHash should not be in the response');
  });

  it('POST /admin/users/:id/suspend suspends a user', async function () {
    var testUser = createTestUser();
    var client = await adminClient();
    var res = await client.request('/admin/users/' + testUser.userId + '/suspend', 'POST', {});
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(data.success, 'Response should indicate success');

    // Verify in DB that the user is suspended
    var script = [
      'var row = db.prepare("SELECT status FROM users WHERE _id = ?").get(' + JSON.stringify(testUser.userId) + ');',
      'process.stdout.write(row ? row.status : "NOT_FOUND");',
    ].join('\n');
    var status = runDbScript(dbPath, script);
    assert.equal(status, 'suspended', 'User status should be suspended in DB');
  });

  it('POST /admin/users/:id/unsuspend restores a user', async function () {
    var testUser = createTestUser({ status: 'suspended' });
    // Set the user to suspended in the DB to match
    runDbScript(dbPath, [
      'db.prepare("UPDATE users SET status = ? WHERE _id = ?").run("suspended", ' + JSON.stringify(testUser.userId) + ');',
      'process.stdout.write("OK");',
    ].join('\n'));

    var client = await adminClient();
    var res = await client.request('/admin/users/' + testUser.userId + '/unsuspend', 'POST', {});
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(data.success, 'Response should indicate success');

    // Verify in DB that the user is active again
    var script = [
      'var row = db.prepare("SELECT status FROM users WHERE _id = ?").get(' + JSON.stringify(testUser.userId) + ');',
      'process.stdout.write(row ? row.status : "NOT_FOUND");',
    ].join('\n');
    var status = runDbScript(dbPath, script);
    assert.equal(status, 'active', 'User status should be active in DB');
  });

  it('POST /admin/users/:id/delete removes a user', async function () {
    var testUser = createTestUser();
    var client = await adminClient();
    var res = await client.request('/admin/users/' + testUser.userId + '/delete', 'POST', {});
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(data.success, 'Response should indicate success');

    // Verify the user is removed from the DB (hard delete, not soft delete)
    var script = [
      'var row = db.prepare("SELECT status FROM users WHERE _id = ?").get(' + JSON.stringify(testUser.userId) + ');',
      'process.stdout.write(row ? row.status : "NOT_FOUND");',
    ].join('\n');
    var status = runDbScript(dbPath, script);
    assert.equal(status, 'NOT_FOUND', 'User should be removed from DB after delete');
  });

  it('suspend/delete of nonexistent user returns 404', async function () {
    var fakeId = b.crypto.generateToken(32);
    var client = await adminClient();

    var res1 = await client.request('/admin/users/' + fakeId + '/suspend', 'POST', {});
    assert.equal(res1.statusCode, 404, 'Suspend of nonexistent user should return 404');

    var res2 = await client.request('/admin/users/' + fakeId + '/delete', 'POST', {});
    assert.equal(res2.statusCode, 404, 'Delete of nonexistent user should return 404');
  });
});

describe('Admin: Settings API', { timeout: 30000 }, function () {

  it('GET /admin/settings returns current settings object', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/settings', 'GET');
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(typeof data === 'object', 'Settings should be an object');
    // Settings should contain at least some expected keys
    assert.ok('siteName' in data || 'publicUpload' in data || 'registrationOpen' in data,
      'Settings should contain known configuration keys');
  });

  it('POST /admin/settings saves a setting (roundtrip verify)', async function () {
    var client = await adminClient();

    // Read current settings
    var before = await client.request('/admin/settings', 'GET');
    assert.equal(before.statusCode, 200);
    var beforeData = before.decrypted || before.json;
    var originalName = beforeData ? beforeData.siteName : undefined;

    // Update the site name
    var newName = 'E2E Test Instance ' + b.crypto.generateToken(3);
    var saveRes = await client.request('/admin/settings', 'POST', {
      siteName: newName,
    });
    assert.equal(saveRes.statusCode, 200, 'POST /admin/settings should return 200, got ' + saveRes.statusCode);
    var saveData = saveRes.decrypted || saveRes.json;
    assert.ok(saveData, 'Save response should contain data');
    assert.ok(saveData.success, 'Save response should indicate success');

    // Verify the new value via GET
    var after = await client.request('/admin/settings', 'GET');
    assert.equal(after.statusCode, 200);
    var afterData = after.decrypted || after.json;
    assert.ok(afterData, 'After-save settings should contain data');
    assert.equal(afterData.siteName, newName, 'Site name should match the saved value');

    // Restore original value if it existed
    if (originalName !== undefined) {
      await client.request('/admin/settings', 'POST', { siteName: originalName });
    }
  });
});

describe('Admin: Audit Log API', { timeout: 30000 }, function () {

  it('GET /admin/audit/api returns audit log entries', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/audit/api', 'GET');
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    // The response may have entries or data array depending on the service
    var entries = data.entries || data.data || [];
    assert.ok(Array.isArray(entries), 'Audit log should contain an array of entries');
    // There should be at least one entry from the admin requests above
    assert.ok(entries.length >= 1, 'Audit log should have at least one entry');
  });
});

describe('Admin: Session Purge', { timeout: 30000 }, function () {

  it('POST /admin/sessions/revoke-all returns success', async function () {
    var client = await adminClient();
    var res = await client.request('/admin/sessions/revoke-all', 'POST', {});
    assert.equal(res.statusCode, 200, 'Expected 200, got ' + res.statusCode);
    var data = res.decrypted || res.json;
    assert.ok(data, 'Response should contain data');
    assert.ok(data.success, 'Response should indicate success');
    assert.ok(data.message, 'Response should include a message');
    // Session revoke invalidates the shared client's session key
    resetClient();
  });
});

describe('Admin: Access Control', { timeout: 30000 }, function () {

  it('non-admin API key is rejected from admin endpoints', async function () {
    var uploadOnlyKey = createApiKey(dbPath, 'upload,read');
    var client = new ApiClient(url, uploadOnlyKey, {
      clientCert: clientCert,
      clientKey: clientKey,
      ca: caCert,
    });
    await client.init();

    var res = await client.request('/admin/settings', 'GET');
    assert.equal(res.statusCode, 403, 'Non-admin key should get 403 on admin route, got ' + res.statusCode);
  });

  it('request without API key is rejected from admin endpoints', async function () {
    var res = await httpRequest(url + '/admin/settings', {
      headers: { 'Content-Type': 'application/json' },
    });
    assert.equal(res.statusCode, 403, 'No-auth request should get 403 on admin route, got ' + res.statusCode);
  });
});
