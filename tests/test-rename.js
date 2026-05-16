'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  MSG, httpRequest, encryptedRequest, uploadFile, sha3, runDbScript,
  createBundleViaDb, countBundleFiles,
  newTestWsClient, waitFor, connectWsClient,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  // mTLS materials needed by encryptedRequest() — blamejs apiEncrypt
  // routes (POST /sync/rename) require a Bearer-authed mTLS client.
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey:  process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert:     process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL');
  process.exit(1);
}

describe('File Rename in Sync Bundle', { timeout: 30000 }, () => {

  it('rename updates relativePath without re-uploading', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    // Upload a file
    await uploadFile(ctx.url, bundle.bundleId, 'original-name.txt', 'rename test content', ctx.apiKey);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    // Connect WebSocket with listener pre-attached so no event races the connect.
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const renameEventP = waitFor(ws, 'message', m => m.type === MSG.FILE_RENAMED, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    // Call the rename endpoint (blamejs apiEncrypt route as of v1.9.15)
    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'original-name.txt',
        newRelativePath: 'renamed-file.txt',
      },
    });
    assert.equal(res.statusCode, 200, 'Rename HTTP ' + res.statusCode + ' body=' + (res.body || '').substring(0, 500));

    // Should get a file_renamed event
    const msg = await renameEventP;
    assert.equal(msg.type, MSG.FILE_RENAMED);
    assert.equal(msg.oldRelativePath, 'original-name.txt');
    assert.equal(msg.relativePath, 'renamed-file.txt');
    assert.ok(msg.seq > 0, 'Should have a seq number');

    // File count should stay the same (no new file, no deleted file)
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    ws.close();
  });

  it('rename to subdirectory works', async () => {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'flat-file.txt', 'will be moved', ctx.apiKey);

    // Pre-attach the rename listener, then connect and trigger.
    var ws = newTestWsClient(ctx.url, ctx.apiKey);
    var renameP = waitFor(ws, 'message', function (m) { return m.type === MSG.FILE_RENAMED; }, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    var res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'flat-file.txt',
        newRelativePath: 'docs/moved-file.txt',
      },
    });
    assert.strictEqual(res.statusCode, 200);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    // Verify the WebSocket event contains the new relativePath
    var msg = await renameP;
    assert.strictEqual(msg.relativePath, 'docs/moved-file.txt', 'Rename event should carry the new relativePath');
    ws.close();
  });

  it('rename nonexistent file returns 404', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'nonexistent.txt',
        newRelativePath: 'new-name.txt',
      },
    });
    assert.ok(res.statusCode >= 400, `Should fail: ${res.statusCode}`);
  });

  it('rename without auth is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const res = await httpRequest(`${ctx.url}/sync/rename`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bundleId: bundle.bundleId,
        oldRelativePath: 'test.txt',
        newRelativePath: 'renamed.txt',
      }),
    });
    // Server v1.9.15+ runs blamejs apiEncrypt before api-auth on /sync/rename,
    // so a no-Bearer plain-JSON request is rejected at the envelope layer (400
    // "encrypted-payload-required") rather than at api-auth (401). Either is
    // a hard refusal of an unauthenticated rename — accept both.
    assert.ok(res.statusCode === 401 || res.statusCode === 400,
      'Unauth rename should be rejected with 400 or 401, got ' + res.statusCode);
  });

  it('rename preserves file count (no duplicate)', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'a.txt', 'content a', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'b.txt', 'content b', ctx.apiKey);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 2);

    // Rename a.txt to c.txt
    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'a.txt',
        newRelativePath: 'c.txt',
      },
    });
    assert.equal(res.statusCode, 200);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 2, 'Should still have 2 files');
  });

  it('rename on non-sync bundle is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'snapshot' });

    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'test.txt',
        newRelativePath: 'renamed.txt',
      },
    });
    assert.ok(res.statusCode >= 400, `Non-sync bundle rename should fail: ${res.statusCode}`);
  });

  it('rename with path traversal in newRelativePath is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'innocent.txt', 'safe content', ctx.apiKey);

    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'innocent.txt',
        newRelativePath: '../../etc/passwd',
      },
    });
    // Server sanitizes traversal segments — verify it either rejects or sanitizes the path
    if (res.statusCode === 200) {
      // If accepted, the stored path must not contain ".."
      const files = JSON.parse(runDbScript(ctx.dbPath, [
        `var rows = db.prepare("SELECT relativePath FROM files WHERE bundleId = ? AND deletedAt IS NULL").all(${JSON.stringify(bundle.bundleId)});`,
        `process.stdout.write(JSON.stringify(rows));`,
      ].join('\n')));
      for (const f of files) {
        assert.ok(!f.relativePath.includes('..'),
          'Stored relativePath must not contain path traversal: ' + f.relativePath);
      }
    } else {
      assert.equal(res.statusCode, 400, 'Path traversal should be rejected with 400');
    }
  });

  it('rename with empty newRelativePath is rejected', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'will-rename.txt', 'content', ctx.apiKey);

    const res = await encryptedRequest(ctx, '/sync/rename', {
      body: {
        bundleId: bundle.bundleId,
        oldRelativePath: 'will-rename.txt',
        newRelativePath: '',
      },
    });
    assert.equal(res.statusCode, 400, 'Empty newRelativePath should be rejected');
  });
});
