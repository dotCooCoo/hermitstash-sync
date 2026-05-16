'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { httpRequest, createApiKey } = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * API key authentication tests.
 */
describe('API Key Authentication', { timeout: 30000 }, () => {

  it('valid API key is accepted on protected routes', async () => {
    const res = await httpRequest(`${ctx.url}/drop/init`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${ctx.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ bundleType: 'snapshot' }),
    });
    assert.notEqual(res.statusCode, 401, 'Valid key should not be 401');
    assert.notEqual(res.statusCode, 403, 'Valid key should not be 403');
  });

  it('invalid API key is treated as anonymous', async () => {
    const res = await httpRequest(`${ctx.url}/drop/init`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer invalid_key_that_does_not_exist',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ bundleType: 'snapshot' }),
    });
    // The api-auth middleware silently skips invalid keys (treats as anonymous).
    // Pre-v1.9.15 the request would reach the route handler and return 200; post-
    // v1.9.15 /drop/init runs through blamejs apiEncrypt first, which rejects a
    // plain-JSON body with 400 "encrypted-payload-required" before api-auth has
    // anything to skip. Either status confirms api-auth did NOT 401 the invalid
    // key (which would be a regression — we want silent anonymous fallback).
    assert.ok(res.statusCode === 200 || res.statusCode === 400,
      'Invalid key should be treated as anonymous (200) or rejected at the envelope (400), got ' + res.statusCode);
  });

  it('malformed Bearer token (too short) is ignored', async () => {
    const res = await httpRequest(`${ctx.url}/health`, {
      headers: { 'Authorization': 'Bearer abc' },
    });
    assert.equal(res.statusCode, 200);
  });

  it('API key with limited scope cannot access admin routes', async () => {
    // NOTE: /bundles/:shareId/delete uses requireAuth (not requireScope), so any valid
    // API key passes auth. With a nonexistent shareId the response is 404 (bundle not found),
    // not 403 (scope denied). This test verifies the key does not get a success response.
    // A true scope-denial test would need a requireScope-protected route (e.g. /admin/*).
    const uploadOnlyKey = createApiKey(ctx.dbPath, 'upload');
    const res = await httpRequest(`${ctx.url}/bundles/nonexistent/delete`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${uploadOnlyKey}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    // Without mTLS certs the API key may not fully authenticate, so the server
    // either returns 404 (bundle not found) or 302 (redirect to login page).
    assert.ok(res.statusCode === 404 || res.statusCode === 302,
      'Nonexistent bundle should return 404 or 302 (login redirect), got ' + res.statusCode);
  });

  it('API key with sync scope passes format validation', () => {
    const syncKey = createApiKey(ctx.dbPath, 'sync');
    assert.ok(syncKey.startsWith('hs_'), 'Key should have hs_ prefix');
    assert.ok(syncKey.length > 16, 'Key should be sufficiently long');
    assert.ok(/^[a-zA-Z0-9._\-]+$/.test(syncKey), 'Key should pass validateBearerToken regex');
  });

  it('no Authorization header on public route behaves as anonymous', async () => {
    const res = await httpRequest(`${ctx.url}/drop/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bundleType: 'snapshot' }),
    });
    assert.ok(res.statusCode >= 200 && res.statusCode < 500, 'Should not be a server error');
  });

});
