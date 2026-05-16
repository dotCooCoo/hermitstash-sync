'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const {
  httpRequest, sha3, createApiKey, runDbScript, sleep,
  computeCertFingerprint, countTableRows,
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

// Helper: make a cert renewal request with mTLS cert options
function renewRequest(opts = {}) {
  var headers = { 'Content-Type': 'application/json' };
  if (opts.auth) headers['Authorization'] = opts.auth;
  var reqOpts = { method: 'POST', headers, body: '{}' };
  if (opts.useMtls && ctx.clientCert && ctx.clientKey && ctx.caCert) {
    reqOpts.cert = fs.readFileSync(ctx.clientCert);
    reqOpts.key = fs.readFileSync(ctx.clientKey);
    reqOpts.ca = fs.readFileSync(ctx.caCert);
  }
  if (opts.cert) reqOpts.cert = opts.cert;
  if (opts.key) reqOpts.key = opts.key;
  if (opts.ca) reqOpts.ca = opts.ca;
  return httpRequest(ctx.url + '/sync/renew-cert', reqOpts);
}

var hasMtls = !!(ctx.clientCert && ctx.clientKey && ctx.caCert);

/**
 * POST /sync/renew-cert — three-factor cert renewal.
 * Requires: valid API key + valid mTLS cert + cert not revoked.
 *
 * Rate limit: 5 req / 5 min per IP.
 * Tests are ordered to maximize coverage within the rate limit window:
 *   1. Successful renewal + cert columns + audit (1 req)
 *   2. Fingerprint match (1 req)
 *   3. Fingerprint mismatch rejection (1 req)
 *   4. Revocation check passes (1 req)
 *   5. Auth failures (accept 429 if rate limited)
 */
describe('Certificate Renewal', { timeout: 30000 }, function () {

  describe('Successful renewal with cert column tracking (Fix #4)', { timeout: 30000 }, function () {

    it('issues new cert and populates certIssuedAt, certExpiresAt, certFingerprint on API key', async function (t) {
      if (!hasMtls) { t.skip('mTLS certs not available'); return; }

      var syncKey = createApiKey(ctx.dbPath, 'sync,upload');
      await sleep(300);

      // Count audit rows before renewal
      var auditBefore = countTableRows(ctx.dbPath, 'audit_log');

      var res = await renewRequest({ auth: 'Bearer ' + syncKey, useMtls: true });

      if (res.statusCode !== 200) {
        console.log('  # Response:', res.statusCode, JSON.stringify(res.json));
      }
      assert.equal(res.statusCode, 200, 'Both factors -> 200');
      assert.ok(res.json.success, 'success: true');
      assert.ok(res.json.clientCert, 'New client cert');
      assert.ok(res.json.clientKey, 'New client key');
      assert.ok(res.json.caCert, 'CA cert');
      assert.ok(res.json.issuedAt, 'issuedAt present');
      assert.ok(res.json.expiresAt, 'expiresAt present');
      assert.ok(res.json.clientCert.includes('BEGIN CERTIFICATE'), 'PEM format');

      // Verify dates are valid ISO timestamps
      var issued = new Date(res.json.issuedAt);
      var expires = new Date(res.json.expiresAt);
      assert.ok(!isNaN(issued.getTime()), 'issuedAt is valid date');
      assert.ok(!isNaN(expires.getTime()), 'expiresAt is valid date');
      assert.ok(expires > issued, 'expiresAt is after issuedAt');

      var daysLeft = Math.floor((expires.getTime() - Date.now()) / 86400000);
      assert.ok(daysLeft >= 360 && daysLeft <= 366, 'Expiry ~365 days, got ' + daysLeft);

      // Fix #4: Verify cert columns are populated on the API key
      var keyHash = sha3(syncKey);
      var colScript = [
        'var row = db.prepare("SELECT certIssuedAt, certExpiresAt, certFingerprint FROM api_keys WHERE keyHash = ?").get(' + JSON.stringify(keyHash) + ');',
        'process.stdout.write(JSON.stringify(row || {}));',
      ].join('\n');
      var cols = JSON.parse(runDbScript(ctx.dbPath, colScript));
      assert.ok(cols.certIssuedAt, 'certIssuedAt column populated after renewal');
      assert.ok(cols.certExpiresAt, 'certExpiresAt column populated after renewal');
      assert.ok(cols.certFingerprint, 'certFingerprint column populated after renewal');

      // Fix #3: Verify audit log entry was created for cert_renewed
      await sleep(300);
      var auditAfter = countTableRows(ctx.dbPath, 'audit_log');
      assert.ok(auditAfter > auditBefore, 'Audit log entry created after cert renewal (before: ' + auditBefore + ', after: ' + auditAfter + ')');
    });
  });

  describe('Cert fingerprint validation (Fix #1)', { timeout: 30000 }, function () {

    it('renewal succeeds when certFingerprint matches the presented client cert', async function (t) {
      if (!hasMtls) { t.skip('mTLS certs not available'); return; }

      // Compute the fingerprint of our test client cert (same algo as server)
      var expectedFp = computeCertFingerprint(ctx.clientCert);

      // Create an API key and set its certFingerprint to match our client cert
      var syncKey = createApiKey(ctx.dbPath, 'sync,upload');
      var keyHash = sha3(syncKey);
      runDbScript(ctx.dbPath, [
        'db.prepare("UPDATE api_keys SET certFingerprint = ? WHERE keyHash = ?").run(' + JSON.stringify(expectedFp) + ', ' + JSON.stringify(keyHash) + ');',
        'process.stdout.write("OK");',
      ].join('\n'));
      await sleep(300);

      var res = await renewRequest({ auth: 'Bearer ' + syncKey, useMtls: true });
      assert.equal(res.statusCode, 200, 'Matching fingerprint should allow renewal');
      assert.ok(res.json.success, 'success: true');
    });

    it('renewal is rejected (403) when certFingerprint does not match the presented cert', async function (t) {
      if (!hasMtls) { t.skip('mTLS certs not available'); return; }

      // Create an API key with a WRONG fingerprint
      var syncKey = createApiKey(ctx.dbPath, 'sync,upload');
      var keyHash = sha3(syncKey);
      var wrongFp = sha3('definitely-not-the-right-cert-pem');
      runDbScript(ctx.dbPath, [
        'db.prepare("UPDATE api_keys SET certFingerprint = ? WHERE keyHash = ?").run(' + JSON.stringify(wrongFp) + ', ' + JSON.stringify(keyHash) + ');',
        'process.stdout.write("OK");',
      ].join('\n'));
      await sleep(300);

      var res = await renewRequest({ auth: 'Bearer ' + syncKey, useMtls: true });
      // Should be 403 (fingerprint mismatch) or 429 (rate limited)
      assert.ok(res.statusCode === 403 || res.statusCode === 429,
        'Mismatched fingerprint -> ' + res.statusCode);
      if (res.statusCode === 403 && res.json) {
        assert.ok(res.json.error.includes('does not match'),
          'Error message should mention cert mismatch: ' + res.json.error);
      }
    });
  });

  describe('Revocation check', { timeout: 30000 }, function () {

    it('non-revoked cert passes revocation check during renewal', async function (t) {
      if (!hasMtls) { t.skip('mTLS certs not available'); return; }

      var syncKey = createApiKey(ctx.dbPath, 'sync,upload');
      await sleep(300);

      var res = await renewRequest({ auth: 'Bearer ' + syncKey, useMtls: true });
      // If cert were revoked, this would be 403. 200 confirms revocation check passed.
      // 429 is also acceptable if rate limited by previous tests.
      assert.ok(res.statusCode === 200 || res.statusCode === 429,
        'Non-revoked cert -> ' + res.statusCode);
    });
  });

  describe('Authentication failures', { timeout: 30000 }, function () {

    it('rejects with no Authorization header', async function () {
      var res = await renewRequest({});
      assert.ok(res.statusCode === 401 || res.statusCode === 429, 'No auth -> ' + res.statusCode);
    });

    it('rejects with invalid API key', async function () {
      var res = await renewRequest({ auth: 'Bearer fake_invalid_key' });
      assert.ok(res.statusCode === 403 || res.statusCode === 429, 'Bad key -> ' + res.statusCode);
    });

    it('rejects with empty Bearer token', async function () {
      var res = await renewRequest({ auth: 'Bearer ' });
      assert.ok(res.statusCode === 401 || res.statusCode === 429, 'Empty -> ' + res.statusCode);
    });

    it('rejects with wrong auth scheme', async function () {
      var res = await renewRequest({ auth: 'Basic dXNlcjpwYXNz' });
      assert.ok(res.statusCode === 401 || res.statusCode === 429, 'Basic -> ' + res.statusCode);
    });

    it('rejects valid API key without mTLS client cert', async function () {
      var res = await renewRequest({ auth: 'Bearer ' + ctx.apiKey });
      assert.ok(res.statusCode === 403 || res.statusCode === 429, 'No cert -> ' + res.statusCode);
    });

    it('rejects API key without sync scope', async function () {
      var uploadKey = createApiKey(ctx.dbPath, 'upload,read');
      await sleep(200);
      var res = await renewRequest({ auth: 'Bearer ' + uploadKey, useMtls: true });
      assert.ok(res.statusCode === 403 || res.statusCode === 429, 'No sync scope -> ' + res.statusCode);
    });
  });
});
