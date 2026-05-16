'use strict';

/**
 * E2E tests for admin settings validation.
 *
 * Verifies settings-schema rejects bad data (400) and accepts valid data (200)
 * via the admin API. Uses raw httpRequest with API key auth.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { ApiClient, httpRequest } = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL');
  process.exit(1);
}

// Shared ApiClient for encrypted settings requests (lazy-init)
var _client = null;
async function ensureClient() {
  if (_client) return _client;
  _client = new ApiClient(ctx.url, ctx.apiKey, {
    clientCert: ctx.clientCert,
    clientKey: ctx.clientKey,
    ca: ctx.caCert,
  });
  await _client.init();
  return _client;
}

function postSettings(body) {
  return httpRequest(ctx.url + '/admin/settings', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + ctx.apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

async function getSettings() {
  var client = await ensureClient();
  var res = await client.request('/admin/settings', 'GET');
  var data = res.decrypted || res.json;
  return { statusCode: res.statusCode, json: data };
}

describe('Settings Validation: reject bad data', { timeout: 30000 }, () => {

  it('rejects port above max (65535)', async () => {
    var res = await postSettings({ port: '99999' });
    assert.equal(res.statusCode, 400, 'port 99999 should be rejected, got ' + res.statusCode);
  });

  it('rejects port below min (0)', async () => {
    var res = await postSettings({ port: '0' });
    assert.equal(res.statusCode, 400, 'port 0 should be rejected, got ' + res.statusCode);
  });

  it('rejects non-numeric port', async () => {
    var res = await postSettings({ port: 'hello' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects invalid URL for rpOrigin', async () => {
    var res = await postSettings({ rpOrigin: 'not-a-url' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects invalid enum for storageBackend', async () => {
    var res = await postSettings({ storageBackend: 'azure' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects hostname with spaces for s3Bucket', async () => {
    var res = await postSettings({ s3Bucket: 'my bucket!' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects path traversal in uploadDir', async () => {
    var res = await postSettings({ uploadDir: '../../../etc/passwd' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects CSS injection in themeFont', async () => {
    var res = await postSettings({ themeFont: 'Roboto; } body { display:none' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects invalid boolean', async () => {
    var res = await postSettings({ landingEnabled: 'yes' });
    assert.equal(res.statusCode, 400);
  });

  it('rejects multiple bad fields', async () => {
    var res = await postSettings({ port: '99999', storageBackend: 'gcp', s3Bucket: 'bad bucket!' });
    assert.equal(res.statusCode, 400);
  });
});

describe('Settings Validation: accept valid data', { timeout: 30000 }, () => {

  it('accepts valid siteName', async () => {
    var res = await postSettings({ siteName: 'E2E Test Site' });
    assert.strictEqual(res.statusCode, 200, 'valid siteName rejected: ' + (res.body || '').substring(0, 200));
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.ok(saved.json, 'GET /admin/settings should return JSON');
    assert.strictEqual(saved.json.siteName, 'E2E Test Site', 'siteName should be persisted');
  });

  it('accepts valid boolean', async () => {
    var res = await postSettings({ maintenanceMode: 'false' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.strictEqual(String(saved.json.maintenanceMode), 'false', 'maintenanceMode should be persisted as false');
  });

  it('accepts empty string for optional fields', async () => {
    var res = await postSettings({ announcementBanner: '' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.strictEqual(saved.json.announcementBanner, '', 'announcementBanner should be persisted as empty string');
  });

  it('accepts valid URL', async () => {
    var res = await postSettings({ rpOrigin: 'https://localhost:3000' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.strictEqual(saved.json.rpOrigin, 'https://localhost:3000', 'rpOrigin should be persisted');
  });

  it('accepts valid enum (case-insensitive)', async () => {
    var res = await postSettings({ emailTemplateMode: 'HTML' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    // Enum may be stored lowercased by the settings service
    assert.ok(
      saved.json.emailTemplateMode === 'HTML' || saved.json.emailTemplateMode === 'html',
      'emailTemplateMode should be persisted, got: ' + saved.json.emailTemplateMode
    );
  });

  it('accepts valid number within range', async () => {
    var res = await postSettings({ maxFileSize: '104857600' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.strictEqual(Number(saved.json.maxFileSize), 104857600, 'maxFileSize should be persisted');
  });

  it('accepts valid hostname for s3Region', async () => {
    var res = await postSettings({ s3Region: 'us-west-1' });
    assert.strictEqual(res.statusCode, 200);
    var saved = await getSettings();
    assert.strictEqual(saved.statusCode, 200);
    assert.strictEqual(saved.json.s3Region, 'us-west-1', 's3Region should be persisted');
  });
});

describe('Settings Validation: sanitization applied', { timeout: 30000 }, () => {

  it('accepts siteName with leading/trailing whitespace (trimmed on save)', async () => {
    var res = await postSettings({ siteName: '  Trimmed Name  ' });
    assert.equal(res.statusCode, 200, 'whitespace siteName should be accepted (trimmed)');
  });

  it('accepts uppercase hostname (lowercased on save)', async () => {
    var res = await postSettings({ s3Region: 'US-WEST-1' });
    assert.equal(res.statusCode, 200, 'uppercase hostname should be accepted (lowercased)');
  });

  it('accepts siteName with control chars (stripped on save)', async () => {
    var res = await postSettings({ siteName: 'Clean\x00Name' });
    assert.equal(res.statusCode, 200, 'control chars should be stripped, not rejected');
  });
});

describe('Settings Validation: edge cases', { timeout: 30000 }, () => {

  it('rejects empty object', async () => {
    var res = await postSettings({});
    assert.equal(res.statusCode, 400);
  });

  it('silently ignores unknown keys alongside valid ones', async () => {
    var res = await postSettings({ siteName: 'Valid', unknownKey999: 'whatever' });
    assert.equal(res.statusCode, 200, 'unknown keys should be ignored');
  });

  it('rejects oversized value (>10000 chars)', async () => {
    var res = await postSettings({ siteName: 'A'.repeat(10001) });
    assert.equal(res.statusCode, 400);
  });

  it('accepts masked credential values without error', async () => {
    var res = await postSettings({ sessionSecret: '\u2022'.repeat(20) });
    assert.equal(res.statusCode, 200, 'masked values should be skipped, not rejected');
  });
});
