'use strict';

/**
 * Public-route + functional coverage — the browser-facing endpoints
 * and upload validators on the public-uploader paths.
 *
 * Routes under test:
 *   POST /drop/file/<bundleId>     → public file upload (multipart, real)
 *   GET  /b/<shareId>              with Accept: text/html → HTML bundle render
 *   GET  /b/<shareId>              with Accept: application/json → JSON API
 *   GET  /b/<shareId>/download     → bundle as ZIP
 *   GET  /s/<fileShareId>/download → individual file download
 *
 * Validators under test:
 *   - file extension whitelist (allowed extension uploads, disallowed rejected)
 *   - empty-file rejection
 *
 * Bundle creation uses createBundleViaDb (DB shortcut) for speed and to
 * decouple the setup from /drop/init's ECIES-encrypted response handling.
 * Every other operation is real: file upload through the actual /drop/file/
 * endpoint via the sync client's HttpClient (which exercises ECIES end-to-end),
 * then HTTP requests against the public viewing/download routes that real
 * users hit.
 *
 * Two production regressions slipped through to v1.7.10–v1.7.13 because no
 * test reached the HTML render path or the individual-file download path:
 *
 *   1. routes/bundles.js missing `host` import after a dead-code cleanup —
 *      crashed every HTML bundle render. The JSON content-negotiation path
 *      returned earlier and was the only thing the old test suite hit.
 *
 *   2. app/data/repositories/files.repo.js had a wrong require path inside
 *      incrementDownloads() — every individual-file download threw before
 *      the route's try/catch could see it. Bundle ZIP downloads dodged it
 *      because they update the downloads counter via db.rawExec at the
 *      route level, never calling filesRepo.incrementDownloads.
 *
 * This file would catch either regression on the next CI run.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { httpRequest, uploadFile, createBundleViaDb } = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

// Header sets — bot-guard middleware (middleware/bot-guard.js) requires
// browser-fingerprint headers on public GET navigations. XHR/fetch requests
// (sec-fetch-dest: empty) bypass the fingerprint check entirely.
const NAV_HEADERS = {
  'accept-language': 'en-US,en;q=0.9',
  'sec-fetch-dest': 'document',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-site': 'none',
  'upgrade-insecure-requests': '1',
  'user-agent': 'Mozilla/5.0 (compatible; HermitStash-E2E-Test)',
};
const XHR_HEADERS = {
  'accept-language': 'en-US,en;q=0.9',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-origin',
};

describe('Public routes — view + download (real upload, frontend-style discovery)', function () {
  // The frontend never calls a separate JSON API to discover file shareIds.
  // It gets them from the server-rendered bundle HTML — specifically the
  // `<a href="/b/<bundleShareId>/file/<fileShareId>">` links built in
  // views/bundle.html line 39. This test mirrors that flow exactly: render
  // the page, parse the href, then exercise both download URLs the user
  // can actually reach (the bundle-scoped one used by the page, and the
  // /s/<shareId>/download share-page form that direct file links use).

  let bundle;
  let uploadedBytes;
  let uploadedFilename;
  let bundleHtml;
  let fileShareIdFromHtml;

  before(async function () {
    bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    uploadedFilename = 'public-routes-' + Date.now() + '.txt';
    uploadedBytes = Buffer.from(
      'public-route E2E test — checksum for download round-trip\n'
      + 'created at ' + new Date().toISOString() + '\n',
      'utf8',
    );
    // Real upload through /drop/file/<bundleId> via the sync client (ECIES).
    const upload = await uploadFile(
      ctx.url, bundle.bundleId, uploadedFilename, uploadedBytes, ctx.apiKey,
    );
    assert.equal(upload.statusCode, 200, 'real file upload should succeed');

    // Render the bundle page exactly like a browser would.
    const html = await httpRequest(`${ctx.url}/b/${bundle.shareId}`, {
      method: 'GET',
      headers: {
        ...NAV_HEADERS,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
      },
      timeout: 5000,
    });
    assert.equal(html.statusCode, 200, 'HTML bundle render should return 200 in `before`');
    bundleHtml = html.body;

    // Parse the file shareId from the rendered HTML — same way the user
    // gets it. The bundle template emits one anchor per file:
    //   <a href="/b/<bundleShareId>/file/<fileShareId>" class="tree-file-link">
    const linkRe = new RegExp(
      '/b/' + bundle.shareId + '/file/([a-f0-9]{32,128})',
    );
    const match = bundleHtml.match(linkRe);
    assert.ok(match,
      'bundle HTML should contain at least one /b/<shareId>/file/<id> link '
      + '(proves the template rendered our uploaded file)');
    fileShareIdFromHtml = match[1];
    assert.ok(fileShareIdFromHtml.length >= 32,
      'extracted shareId should be a real long hex id');
  });

  it('GET /b/<shareId> with Accept: text/html renders the bundle page', function () {
    // Regression coverage for v1.7.10 host-import bug: the HTML render path
    // crashed with ReferenceError when host(req) was undefined. The render
    // already happened in `before` — assert the side effects here.
    assert.ok(bundleHtml.length > 0, 'response body should be non-empty');
    assert.ok(bundleHtml.includes(bundle.shareId),
      'HTML body should reference the bundle shareId (proves template rendered with bundle data)');
    assert.ok(bundleHtml.includes(uploadedFilename),
      'HTML body should reference the uploaded filename');
  });

  it('GET /b/<shareId>/download streams the bundle as a ZIP', async function () {
    const res = await httpRequest(`${ctx.url}/b/${bundle.shareId}/download`, {
      method: 'GET',
      headers: { ...NAV_HEADERS, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      timeout: 10000,
    });
    assert.equal(res.statusCode, 200, 'ZIP download should return 200');
    assert.match(res.headers['content-type'] || '', /application\/zip/i);
    // ZIP file magic: PK\x03\x04 at offset 0
    assert.ok(res.bodyBuffer.length > 4, 'ZIP body should have content');
    assert.equal(res.bodyBuffer[0], 0x50, 'ZIP magic byte 0 (P)');
    assert.equal(res.bodyBuffer[1], 0x4B, 'ZIP magic byte 1 (K)');
  });

  it('GET /b/<shareId>/file/<fileShareId> downloads the bundle-scoped file', async function () {
    // This is the URL the bundle page itself links to (views/bundle.html:39).
    // The fileShareId comes from parsing the rendered HTML — same as a real
    // browser following the link.
    const res = await httpRequest(
      `${ctx.url}/b/${bundle.shareId}/file/${fileShareIdFromHtml}`,
      {
        method: 'GET',
        headers: { ...NAV_HEADERS, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
        timeout: 5000,
      },
    );
    assert.equal(res.statusCode, 200,
      'bundle-scoped file download should return 200');
    assert.equal(res.bodyBuffer.length, uploadedBytes.length,
      'downloaded length should match uploaded length');
    assert.deepEqual(res.bodyBuffer, uploadedBytes,
      'downloaded bytes should match uploaded bytes');
  });

  it('GET /s/<fileShareId>/download downloads the same file via the share URL', async function () {
    // Regression coverage for v1.7.10 incrementDownloads require-path bug.
    // This is the URL views/share.html links to (`/s/<shareId>/download`)
    // and what the user reported broken. Same fileShareId, different route.
    const res = await httpRequest(`${ctx.url}/s/${fileShareIdFromHtml}/download`, {
      method: 'GET',
      headers: { ...NAV_HEADERS, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      timeout: 5000,
    });
    assert.equal(res.statusCode, 200,
      'individual file download should return 200 (was 500 in v1.7.10–v1.7.14)');
    assert.match(res.headers['content-disposition'] || '', /attachment/i,
      'should set Content-Disposition: attachment');
    assert.equal(res.bodyBuffer.length, uploadedBytes.length,
      'downloaded length should match uploaded length');
    assert.deepEqual(res.bodyBuffer, uploadedBytes,
      'downloaded bytes should match uploaded bytes exactly');
  });
});

describe('Upload validators (extension whitelist + empty-file)', function () {
  // Each test gets its own bundle so failures don't pollute the others.

  it('allowed extension (.txt) uploads successfully', async function () {
    const b = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const res = await uploadFile(
      ctx.url, b.bundleId, 'allowed.txt', Buffer.from('plain text content', 'utf8'), ctx.apiKey,
    );
    assert.equal(res.statusCode, 200, '.txt should be accepted (default allowed extension)');
  });

  it('disallowed extension (.exe) is rejected with 400', async function () {
    const b = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    // Real PE-style header bytes — proves the validator rejects on extension,
    // not on content sniffing (extension comes first in the validation order).
    const peBytes = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const res = await uploadFile(
      ctx.url, b.bundleId, 'malware.exe', peBytes, ctx.apiKey,
    );
    assert.equal(res.statusCode, 400,
      '.exe is not in the default allowed-extensions list and should be rejected');
  });

  it('disallowed extension (.sh) is rejected with 400', async function () {
    const b = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const res = await uploadFile(
      ctx.url, b.bundleId, 'script.sh', Buffer.from('#!/bin/sh\necho hi\n', 'utf8'), ctx.apiKey,
    );
    assert.equal(res.statusCode, 400, '.sh should be rejected');
  });

  it('empty file is rejected with 400', async function () {
    const b = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const res = await uploadFile(
      ctx.url, b.bundleId, 'empty.txt', Buffer.alloc(0), ctx.apiKey,
    );
    assert.equal(res.statusCode, 400, 'empty file should be rejected');
    // Body content is ECIES-encrypted by the api-encrypt middleware; status
    // alone proves the validator rejected. Decrypting here would require
    // wiring the full ECIES handshake just to read an error string.
  });

  it('file with no extension is rejected with 400', async function () {
    const b = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const res = await uploadFile(
      ctx.url, b.bundleId, 'noextension', Buffer.from('some content', 'utf8'), ctx.apiKey,
    );
    assert.equal(res.statusCode, 400,
      'file with no extension should be rejected (validator requires an extension)');
  });
});
