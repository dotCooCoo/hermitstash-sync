'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  MSG, uploadFile, sha3, runDbScript, sleep,
  createBundleViaDb, createSnapshotBundleViaDb,
  getBundleFromDb, getBundleFilesFromDb, countBundleFiles,
  newTestWsClient, waitFor, connectWsClient,
} = require('./test-helpers');

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
 * File upload tests.
 *
 * Sealed fields (checksum, relativePath) are verified through WebSocket events
 * which transmit them in plaintext. Structural checks (file count, seq, size)
 * use raw DB fields.
 */
describe('File Upload', { timeout: 30000 }, () => {

  after(async () => { await sleep(500); });

  it('upload a file to a sync bundle succeeds (HTTP 200)', async () => {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var content = 'Hello, HermitStash! ' + b.crypto.generateToken(8);
    var res = await uploadFile(ctx.url, bundle.bundleId, 'test-file.txt', content, ctx.apiKey);
    assert.strictEqual(res.statusCode, 200, 'Expected 200, got ' + res.statusCode + ': ' + res.body);
    // Response may be encrypted (json contains {_e: "..."}) — verify via status code
    assert.ok(res.json, 'Response body should be valid JSON');
    // Check for success: either decrypted {success: true} or encrypted envelope {_e: "..."}
    assert.ok(res.json.success === true || res.json._e,
      'Response should contain success: true or encrypted payload');
  });

  it('uploaded file checksum matches SHA3-512 of content (via WebSocket event)', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const content = 'Checksum test content ' + Date.now();
    const expectedChecksum = sha3(content);

    // Connect WebSocket to receive the file_added event which includes the plaintext checksum
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_ADDED, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    await uploadFile(ctx.url, bundle.bundleId, 'checksum-test.txt', content, ctx.apiKey);
    const event = await eventP;

    assert.equal(event.checksum, expectedChecksum, 'WebSocket event checksum should match SHA3-512');
    assert.equal(event.relativePath, 'checksum-test.txt', 'relativePath should be correct');

    ws.close();
  });

  it('bundle counters update after upload', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'counter-test.txt', 'Counter test ' + Date.now(), ctx.apiKey);

    const updated = getBundleFromDb(ctx.dbPath, bundle.bundleId);
    assert.equal(updated.receivedFiles, 1, 'receivedFiles should be 1');
    assert.ok(updated.totalSize > 0, 'totalSize should be > 0');
    assert.equal(updated.seq, 1, 'seq should be 1 after first upload');
  });

  it('upload to a nonexistent bundle returns 404', async () => {
    const fakeBundleId = b.crypto.generateToken(32);
    const res = await uploadFile(ctx.url, fakeBundleId, 'orphan.txt', 'data', ctx.apiKey);
    assert.equal(res.statusCode, 404);
  });

  it('upload with disallowed extension is rejected', async () => {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var res = await uploadFile(ctx.url, bundle.bundleId, 'malware.exe', 'MZ...', ctx.apiKey);
    assert.strictEqual(res.statusCode, 400, 'Should reject disallowed extension');
    // Error responses may be encrypted — verify via status code (400 already confirms rejection).
    // If body is plaintext, verify it mentions the extension.
    if (res.body && !res.body.includes('"_e"')) {
      assert.ok(res.body.toLowerCase().includes('.exe'),
        'Error message should mention the rejected extension, got: ' + (res.body || '').substring(0, 200));
    }
  });

  it('multiple files can be uploaded to the same sync bundle', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    await uploadFile(ctx.url, bundle.bundleId, 'file1.txt', 'content1', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'file2.txt', 'content2', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'subdir/file3.txt', 'content3', ctx.apiKey);

    const count = countBundleFiles(ctx.dbPath, bundle.bundleId);
    assert.equal(count, 3, 'Should have 3 active files');
  });

  it('upload to a finalized snapshot bundle is rejected', async () => {
    const bundle = createSnapshotBundleViaDb(ctx.dbPath);

    runDbScript(ctx.dbPath, [
      `db.prepare("UPDATE bundles SET status = 'complete' WHERE _id = ?").run(${JSON.stringify(bundle.bundleId)});`,
      `process.stdout.write('OK');`,
    ].join('\n'));

    const res = await uploadFile(ctx.url, bundle.bundleId, 'late-file.txt', 'late data', ctx.apiKey);
    assert.equal(res.statusCode, 404, 'Should reject upload to finalized snapshot');
  });

  it('file size is recorded correctly', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const content = 'A'.repeat(1000);
    await uploadFile(ctx.url, bundle.bundleId, 'sized-file.txt', content, ctx.apiKey);

    const files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    assert.ok(files.length > 0);
    assert.equal(files[0].size, 1000, 'File size should be 1000 bytes');
  });

  it('large file upload succeeds (1 MB)', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    // Use .txt extension with text content to pass magic byte validation
    const content = Buffer.alloc(1024 * 1024, 'A', 'utf8');
    const res = await uploadFile(ctx.url, bundle.bundleId, 'large-file.txt', content, ctx.apiKey);
    assert.equal(res.statusCode, 200, `Large upload should succeed, got ${res.statusCode}`);
  });

  it('file with mismatched magic bytes is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    // .pdf extension but plain text content — magic bytes won't match %PDF signature
    const content = 'This is definitely not a PDF file, just plain text content.';
    const res = await uploadFile(ctx.url, bundle.bundleId, 'fake-document.pdf', content, ctx.apiKey);
    assert.equal(res.statusCode, 400, 'Mismatched magic bytes should be rejected');
  });

});
