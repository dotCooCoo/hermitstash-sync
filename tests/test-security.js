'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  MSG, httpRequest, uploadFile, sha3, runDbScript,
  createBundleViaDb, countBundleFiles,
  newTestWsClient, waitFor, connectWsClient, expectWsRejectClient,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL');
  process.exit(1);
}

describe('Security: Bot Guard', { timeout: 30000 }, () => {

  it('raw HTTP GET to a page route is blocked (no browser headers)', async () => {
    const res = await httpRequest(`${ctx.url}/drop`, { bare: true });
    // Bot guard checks accept-language, sec-fetch-dest — raw request has neither
    assert.equal(res.statusCode, 403, 'Should block non-browser request');
  });

  it('exempt paths are not blocked (health, sitemap)', async () => {
    const health = await httpRequest(`${ctx.url}/health`);
    assert.equal(health.statusCode, 200);

    const sitemap = await httpRequest(`${ctx.url}/sitemap.xml`);
    assert.equal(sitemap.statusCode, 200);
  });

  it('API key requests bypass bot guard', async () => {
    const res = await httpRequest(`${ctx.url}/drop`, {
      headers: { 'Authorization': `Bearer ${ctx.apiKey}` },
    });
    // Should not be 403 — API key clients are exempt
    assert.notEqual(res.statusCode, 403, 'API key should bypass bot guard');
  });

  it('POST requests bypass bot guard', async () => {
    const res = await httpRequest(`${ctx.url}/drop/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    // POST should not be blocked by bot guard (it has its own auth)
    assert.notEqual(res.statusCode, 403, 'POST should bypass bot guard');
  });
});

describe('Security: Path Traversal', { timeout: 30000 }, () => {

  it('upload with path traversal in relativePath is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const res = await uploadFile(
      ctx.url, bundle.bundleId,
      '../../etc/passwd', 'malicious content', ctx.apiKey
    );
    // Server should sanitize or reject traversal paths
    assert.ok(
      res.statusCode === 400 || res.statusCode === 200,
      'Should handle traversal path safely'
    );
    // If it accepted, verify the stored relativePath was sanitized
    if (res.statusCode === 200) {
      const files = runDbScript(ctx.dbPath, [
        `var rows = db.prepare("SELECT * FROM files WHERE bundleId = ?").all(${JSON.stringify(bundle.bundleId)});`,
        `process.stdout.write(JSON.stringify(rows));`,
      ].join('\n'));
      const parsed = JSON.parse(files);
      for (const f of parsed) {
        // relativePath should not contain ..
        if (f.relativePath) {
          assert.ok(!f.relativePath.includes('..'), 'Stored path should not contain ..');
        }
      }
    }
  });
});

describe('Security: ECIES Protocol Version', { timeout: 30000 }, () => {

  it('WebSocket upgrade with valid API key establishes encrypted session', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 0);
    const hb = await hbP;
    assert.equal(hb.type, MSG.HEARTBEAT);
    ws.close();
  });
});

describe('Security: Rate Limiting', { timeout: 30000 }, () => {

  it('registration endpoint rate limits after many requests', async () => {
    // Registration has a 10/15min limit — send 15 to reliably trigger it
    var statuses = [];
    for (var i = 0; i < 15; i++) {
      var res = await httpRequest(`${ctx.url}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'rl' + i + '@test.com', password: 'testpass123', displayName: 'Rate Test' }),
      });
      statuses.push(res.statusCode);
    }
    // At least some should be rate limited (429)
    var has429 = statuses.some(s => s === 429);
    assert.ok(has429, 'Should hit rate limit after rapid requests: ' + statuses.join(','));
  });
});

describe('Security: CSRF Protection', { timeout: 30000 }, () => {

  it('non-JSON POST to protected route is rejected', async () => {
    // Send a form-encoded POST without CSRF token — should be rejected
    const res = await httpRequest(`${ctx.url}/admin/settings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${ctx.apiKey}`,
      },
      body: 'key=value',
    });
    // Should be 400 (bad body), 403 (CSRF), or 404 — not 200
    assert.ok(res.statusCode >= 400, `Non-JSON POST should be rejected, got ${res.statusCode}`);
  });
});

describe('Security: WebSocket Auth', { timeout: 30000 }, () => {

  it('WebSocket without Authorization header is rejected (401)', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const result = await expectWsRejectClient(ctx.url, null, bundle.bundleId, 0);
    assert.equal(result.statusCode, 401, 'No auth should be rejected');
  });
});

describe('Security: Oversized Payloads', { timeout: 30000 }, () => {

  it('extremely large upload filename is handled safely', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const longName = 'a'.repeat(1000) + '.txt';
    const res = await uploadFile(ctx.url, bundle.bundleId, longName, 'small content', ctx.apiKey);
    // Should either accept (with truncated name) or reject — not crash
    assert.ok(res.statusCode === 200 || res.statusCode === 400,
      `Expected 200 or 400, got ${res.statusCode}`);
  });
});

describe('Security: CSRF on form POST endpoints', { timeout: 30000 }, () => {

  it('form POST to /auth/logout without CSRF token is rejected', async () => {
    // Send a form-encoded POST without CSRF token — CSRF middleware should reject
    const res = await httpRequest(`${ctx.url}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'action=logout',
    });
    // Should be 403 (CSRF rejection) — not 200 or 302
    assert.ok(res.statusCode === 403 || res.statusCode === 400,
      `Form POST without CSRF token should be rejected, got ${res.statusCode}`);
  });
});

describe('Security: Bot guard on all public routes', { timeout: 30000 }, () => {

  it('GET / without browser headers is blocked', async () => {
    const res = await httpRequest(`${ctx.url}/`, { bare: true });
    assert.equal(res.statusCode, 403, 'Root page should be blocked without browser headers');
  });

  it('GET /b/fake without browser headers is blocked', async () => {
    const res = await httpRequest(`${ctx.url}/b/fake-bundle-id`, { bare: true });
    assert.equal(res.statusCode, 403, '/b/ route should be blocked without browser headers');
  });

  it('GET /s/fake without browser headers is blocked', async () => {
    // /s/ is not in bot guard exempt prefixes — should be blocked
    const res = await httpRequest(`${ctx.url}/s/fake-stash-id`, { bare: true });
    assert.equal(res.statusCode, 403, '/s/ route should be blocked without browser headers');
  });

  it('GET /auth/login without browser headers is blocked by bot guard', async () => {
    // Raw request with no Accept-Language, no Sec-Fetch-Dest, no Sec-Fetch-Mode
    const res = await httpRequest(`${ctx.url}/auth/login`, { bare: true });
    assert.equal(res.statusCode, 403, '/auth/login should be blocked without browser headers');
  });

  it('GET /auth/register without browser headers is blocked by bot guard', async () => {
    // Raw request with no browser fingerprint headers
    const res = await httpRequest(`${ctx.url}/auth/register`, { bare: true });
    assert.equal(res.statusCode, 403, '/auth/register should be blocked without browser headers');
  });
});

describe('Security: Logout is POST-only', { timeout: 30000 }, () => {

  it('GET /auth/logout is not a valid endpoint', async () => {
    // Logout must be POST-only (with CSRF token). GET should not work.
    // The bot guard may block this first (403) or the router returns 404.
    const res = await httpRequest(`${ctx.url}/auth/logout`, {
      headers: {
        'Authorization': `Bearer ${ctx.apiKey}`,
      },
    });
    // Should be 404 (no GET route defined), 403 (bot guard), or 405 (method not allowed)
    // It must NOT be 200 or 302 (redirect) — that would mean GET logout works
    assert.ok(
      res.statusCode === 404 || res.statusCode === 403 || res.statusCode === 405,
      'GET /auth/logout should not be a valid route, got ' + res.statusCode
    );
  });
});
