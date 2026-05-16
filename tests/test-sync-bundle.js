'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  MSG, uploadFile, sha3, runDbScript, httpRequest, sleep,
  createBundleViaApi, createBundleViaDb, createSnapshotBundleViaDb,
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
 * Sync bundle mutation tests.
 *
 * File delete and replace are verified through WebSocket events (which contain
 * plaintext checksum and relativePath) and DB counters (which are raw fields).
 */
describe('Sync Bundle Mutations', { timeout: 30000 }, () => {

  after(async () => { await sleep(500); });

  it('sync bundle starts as status: complete with bundleType: sync', () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const db = getBundleFromDb(ctx.dbPath, bundle.bundleId);
    assert.equal(db.status, 'complete');
    assert.equal(db.bundleType, 'sync');
  });

  it('file replace: same relativePath emits file_replaced event', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    // Upload original
    await uploadFile(ctx.url, bundle.bundleId, 'replaceable.txt', 'original', ctx.apiKey);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    // Pre-attach the replace listener, then connect.
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_REPLACED, 5000);
    await connectWsClient(ws, bundle.bundleId, 99999);

    const replacement = 'replaced ' + Date.now();
    await uploadFile(ctx.url, bundle.bundleId, 'replaceable.txt', replacement, ctx.apiKey);
    const event = await eventP;

    assert.equal(event.relativePath, 'replaceable.txt');
    assert.equal(event.checksum, sha3(replacement), 'Replace event checksum should match new content');
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1, 'Still 1 active file');

    ws.close();
  });

  it('file delete emits file_removed event via WebSocket', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    // Upload a file
    await uploadFile(ctx.url, bundle.bundleId, 'delete-me.txt', 'doomed', ctx.apiKey);

    // Get the file's _id from the DB
    const files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    assert.ok(files.length > 0, 'Should have at least 1 file');
    const fileId = files[0]._id;

    // Pre-attach the remove listener, then connect and delete.
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const removeEventP = waitFor(ws, 'message', m => m.type === MSG.FILE_REMOVED, 5000);
    await connectWsClient(ws, bundle.bundleId, 99999);

    await httpRequest(`${ctx.url}/bundles/${bundle.shareId}/file/${fileId}/delete`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${ctx.apiKey}`, 'Content-Type': 'application/json' },
      body: '{}',
    });
    const removeEvent = await removeEventP;

    assert.equal(removeEvent.type, MSG.FILE_REMOVED);
    assert.equal(removeEvent.relativePath, 'delete-me.txt');

    ws.close();
  });

  it('bundle receivedFiles counter tracks adds and replaces', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    await uploadFile(ctx.url, bundle.bundleId, 'a.txt', 'aaa', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'b.txt', 'bbb', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'c.txt', 'ccc', ctx.apiKey);

    let db = getBundleFromDb(ctx.dbPath, bundle.bundleId);
    assert.equal(db.receivedFiles, 3);

    // Replace b.txt (count stays at 3)
    await uploadFile(ctx.url, bundle.bundleId, 'b.txt', 'bbb-v2', ctx.apiKey);
    db = getBundleFromDb(ctx.dbPath, bundle.bundleId);
    assert.equal(db.receivedFiles, 3);
  });

  it('seq counter increments on add and replace', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    assert.equal(getBundleFromDb(ctx.dbPath, bundle.bundleId).seq, 0);

    await uploadFile(ctx.url, bundle.bundleId, 'seq.txt', 'v1', ctx.apiKey);
    assert.equal(getBundleFromDb(ctx.dbPath, bundle.bundleId).seq, 1);

    await uploadFile(ctx.url, bundle.bundleId, 'seq.txt', 'v2', ctx.apiKey);
    assert.equal(getBundleFromDb(ctx.dbPath, bundle.bundleId).seq, 2);

    await uploadFile(ctx.url, bundle.bundleId, 'seq2.txt', 'data', ctx.apiKey);
    assert.equal(getBundleFromDb(ctx.dbPath, bundle.bundleId).seq, 3);
  });

  it('seq increments on delete', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    // Upload a file
    await uploadFile(ctx.url, bundle.bundleId, 'del-seq.txt', 'data', ctx.apiKey);
    const seqBefore = getBundleFromDb(ctx.dbPath, bundle.bundleId).seq;

    // Get the file's _id from the DB
    const files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    assert.ok(files.length > 0);
    const fileId = files[0]._id;

    // Delete
    await httpRequest(`${ctx.url}/bundles/${bundle.shareId}/file/${fileId}/delete`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${ctx.apiKey}`, 'Content-Type': 'application/json' },
      body: '{}',
    });

    const seqAfter = getBundleFromDb(ctx.dbPath, bundle.bundleId).seq;
    assert.equal(seqAfter, seqBefore + 1, 'seq should increment on delete');
  });

  it('snapshot bundle rejects uploads after finalization', async () => {
    const bundle = createSnapshotBundleViaDb(ctx.dbPath);

    const r1 = await uploadFile(ctx.url, bundle.bundleId, 'snap.txt', 'data', ctx.apiKey);
    assert.equal(r1.statusCode, 200);

    runDbScript(ctx.dbPath, [
      `db.prepare("UPDATE bundles SET status = 'complete' WHERE _id = ?").run(${JSON.stringify(bundle.bundleId)});`,
      `process.stdout.write('OK');`,
    ].join('\n'));

    const r2 = await uploadFile(ctx.url, bundle.bundleId, 'late.txt', 'late', ctx.apiKey);
    assert.equal(r2.statusCode, 404);
  });

});
