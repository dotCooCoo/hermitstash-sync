'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { httpRequest } = require('./test-helpers');

// Server context from environment (set by run-all.js)
const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  port: process.env.HERMITSTASH_TEST_PORT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * Health check, sitemap, and public endpoint tests.
 * These endpoints are before the api-encrypt middleware, so they return plain JSON/XML.
 */
describe('Health & Public Endpoints', { timeout: 30000 }, () => {

  it('GET /health returns 200 with status ok', async () => {
    const res = await httpRequest(`${ctx.url}/health`);
    assert.equal(res.statusCode, 200);
    assert.ok(res.json, 'Response should be valid JSON');
    assert.equal(res.json.status, 'ok');
    assert.ok(res.json.uptime >= 0, 'Should include uptime');
    assert.ok(res.json.timestamp, 'Should include timestamp');
  });

  it('GET /health Content-Type is application/json', async () => {
    const res = await httpRequest(`${ctx.url}/health`);
    assert.ok(res.headers['content-type'].includes('application/json'));
  });

  it('GET /sitemap.xml returns valid XML', async () => {
    const res = await httpRequest(`${ctx.url}/sitemap.xml`);
    assert.equal(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('application/xml'));
    assert.ok(res.body.includes('<urlset'), 'Should contain urlset element');
    assert.ok(res.body.includes('<?xml'), 'Should have XML declaration');
  });

  it('GET /manifest.json returns 200', async () => {
    const res = await httpRequest(`${ctx.url}/manifest.json`);
    assert.equal(res.statusCode, 200);
  });

  it('security headers are present on responses', async () => {
    var res = await httpRequest(`${ctx.url}/health`);
    var hdrs = res.headers;
    assert.ok(hdrs['x-content-type-options'], 'x-content-type-options header should be present');
    assert.strictEqual(hdrs['x-content-type-options'], 'nosniff', 'x-content-type-options should be nosniff');
    assert.ok(hdrs['x-frame-options'], 'x-frame-options header should be present');
    assert.ok(hdrs['content-security-policy'], 'content-security-policy header should be present');
    assert.ok(hdrs['referrer-policy'], 'referrer-policy header should be present');
  });

  it('unknown route returns 403 (bot guard) or 404', async () => {
    const res = await httpRequest(`${ctx.url}/this-route-does-not-exist-${Date.now()}`);
    // Raw HTTP clients without browser headers are blocked by bot guard (403)
    // Real browsers would get 404 — both are correct
    assert.ok(res.statusCode === 403 || res.statusCode === 404, `Expected 403 or 404, got ${res.statusCode}`);
  });

});
