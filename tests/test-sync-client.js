'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  MSG, sleep, sha3, createTempDir, rmrf,
  createBundleViaDb, uploadFile,
  countBundleFiles, newTestWsClient, waitFor, connectWsClient,
  getBundleFilesFromDb, httpRequest, runDbScript,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');

/**
 * Sync client module integration tests.
 *
 * The HttpClient.downloadFile() uses /files/:fileId/download which does not
 * exist on the current server (files are downloaded via /s/:shareId/download
 * or /b/:bundleShareId/file/:fileShareId). Tests verify the upload path
 * and WebSocket integration instead.
 */
describe('Sync Client Modules', { timeout: 30000 }, () => {

  it('HttpClient.healthCheck() returns true', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    const client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    try {
      const result = await client.healthCheck();
      assert.equal(result, true);
    } finally {
      client.destroy();
    }
  });

  it('HttpClient.uploadFile() lands on server (verified via DB count)', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    const client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const tempDir = createTempDir('client-upload');
    const filePath = path.join(tempDir, 'client-upload.txt');
    fs.writeFileSync(filePath, 'HttpClient upload test ' + Date.now());

    try {
      await client.uploadFile(bundle.bundleId, 'client-upload.txt', filePath);
      assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1, 'File should exist in DB');
    } finally {
      client.destroy();
      rmrf(tempDir);
    }
  });

  it('HttpClient.uploadFile() checksum verified via WebSocket event', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    const client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const content = 'Checksum via WS ' + Date.now();
    const expectedChecksum = sha3(content);

    const tempDir = createTempDir('ws-checksum');
    const filePath = path.join(tempDir, 'ws-check.txt');
    fs.writeFileSync(filePath, content);

    // Connect WebSocket with listener pre-attached to capture the event
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_ADDED, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    try {
      await client.uploadFile(bundle.bundleId, 'ws-check.txt', filePath);

      var event = await eventP;
      assert.equal(event.checksum, expectedChecksum, 'Checksum in WS event should match SHA3-512');
      assert.equal(event.relativePath, 'ws-check.txt');
    } finally {
      ws.close();
      client.destroy();
      rmrf(tempDir);
    }
  });

  it('WebSocket receives file_added events in seq order', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const events = [];
    ws.on('message', msg => {
      if (msg.type === MSG.FILE_ADDED) events.push(msg);
    });
    await connectWsClient(ws, bundle.bundleId, 0);

    await uploadFile(ctx.url, bundle.bundleId, 'order-1.txt', 'one', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'order-2.txt', 'two', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'order-3.txt', 'three', ctx.apiKey);

    // Wait until we have all 3 events (or time out).
    for (let i = 0; i < 20 && events.length < 3; i++) await sleep(50);

    assert.equal(events.length, 3, `Should get 3 events, got ${events.length}`);
    for (let i = 1; i < events.length; i++) {
      assert.ok(events[i].seq > events[i - 1].seq, 'seq should increase');
    }
    ws.close();
  });

  it('state-db opens, stores, and retrieves data', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    const tempDir = createTempDir('state-db-test');
    const dbFile = path.join(tempDir, 'test-state.db');

    try {
      stateDb.open(dbFile);

      stateDb.setMeta('test_key', 'test_value');
      assert.equal(stateDb.getMeta('test_key'), 'test_value');

      stateDb.setLastSeq(42);
      assert.equal(stateDb.getLastSeq(), 42);

      stateDb.upsertFile({
        relativePath: 'test/file.txt',
        serverFileId: 'abc123',
        localChecksum: 'deadbeef',
        serverChecksum: 'deadbeef',
        localMtime: Date.now(),
        size: 1024,
        serverSeq: 1,
        status: 'synced',
      });

      const file = stateDb.getFile('test/file.txt');
      assert.ok(file);
      assert.equal(file.serverFileId, 'abc123');
      assert.equal(file.size, 1024);

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  // --- HttpClient method tests (Bearer + mTLS, plain JSON envelope post v1.9.15) ---

  it('HttpClient.healthCheck() returns true via production client', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    var client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    client._agent.options.rejectUnauthorized = false;
    try {
      var ok = await client.healthCheck();
      assert.strictEqual(ok, true);
    } finally {
      client.destroy();
    }
  });

  it('HttpClient.deleteFile() removes a file from a sync bundle', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    var client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    client._agent.options.rejectUnauthorized = false;

    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'delete-via-client.txt', 'content ' + Date.now(), ctx.apiKey);
    var files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    assert.ok(files.length > 0, 'Should have a file to delete');
    var fileId = files[0]._id;

    await client.deleteFile(fileId);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 0, 'File should be gone after deleteFile()');
    client.destroy();
  });

  it('sync file delete via server route removes file from bundle', async () => {
    // Use the correct server endpoint POST /bundles/:shareId/file/:fileId/delete
    // to verify the full delete flow that the client intends to exercise.
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'server-delete.txt', 'doomed ' + Date.now(), ctx.apiKey);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    var files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    var fileId = files[0]._id;

    var res = await httpRequest(ctx.url + '/bundles/' + bundle.shareId + '/file/' + fileId + '/delete', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ctx.apiKey, 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.equal(res.statusCode, 200, 'Delete should succeed: HTTP ' + res.statusCode);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 0, 'File should be gone');
  });

  it('HttpClient.renameFile() updates relativePath', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    var client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    client._agent.options.rejectUnauthorized = false;

    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'before-rename.txt', 'rename content', ctx.apiKey);
    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);

    // Connect WebSocket with listener pre-attached to capture the rename event
    var ws = newTestWsClient(ctx.url, ctx.apiKey);
    var renameP = waitFor(ws, 'message', function (m) { return m.type === MSG.FILE_RENAMED; }, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    await client.renameFile(bundle.bundleId, 'before-rename.txt', 'after-rename.txt');

    var msg = await renameP;
    assert.equal(msg.relativePath, 'after-rename.txt', 'Rename event should carry new relativePath');

    assert.equal(countBundleFiles(ctx.dbPath, bundle.bundleId), 1);
    ws.close();
    client.destroy();
  });

  it('HttpClient.renameFile() surfaces the decrypted server error detail on failure', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    var client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    client._agent.options.rejectUnauthorized = false;

    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    // No file exists at 'ghost.txt', so the server returns a 404 problem-details
    // — encrypted inside the per-session envelope on this route. The client must
    // resolve the non-2xx response (responseMode passthrough), decrypt it, and
    // surface `.detail` rather than throwing on raw ciphertext. A bare
    // "Rename failed: HTTP 404" would mean the encrypted error never decrypted.
    await assert.rejects(
      client.renameFile(bundle.bundleId, 'ghost.txt', 'renamed.txt'),
      function (err) {
        assert.match(err.message, /File not found at old nodePath/i,
          'thrown error should carry the decrypted server detail, got: ' + err.message);
        return true;
      }
    );
    client.destroy();
  });

  it('HttpClient.getBundleMetadata() returns file list', async () => {
    const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
    var client = new HttpClient({ server: ctx.url, mtls: { cert: ctx.clientCert, key: ctx.clientKey, ca: ctx.caCert } }, ctx.apiKey);
    client._agent.options.rejectUnauthorized = false;

    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'meta-file-1.txt', 'content 1', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'meta-file-2.txt', 'content 2', ctx.apiKey);

    var metadata = await client.getBundleMetadata(bundle.shareId);
    assert.ok(metadata, 'Should return metadata object');
    assert.ok(Array.isArray(metadata.files), 'Should have files array');
    assert.equal(metadata.files.length, 2, 'Should have 2 files');
    assert.equal(metadata.bundleType, 'sync');
    assert.equal(metadata.shareId, bundle.shareId);

    client.destroy();
  });

  // --- state-db extended tests ---

  it('state-db getAllFiles returns all stored files', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-getall');
    var dbFile = path.join(tempDir, 'test-getall.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({ relativePath: 'a.txt', serverFileId: 'id-a', localChecksum: 'aa', size: 100, status: 'synced' });
      stateDb.upsertFile({ relativePath: 'b.txt', serverFileId: 'id-b', localChecksum: 'bb', size: 200, status: 'pending' });
      stateDb.upsertFile({ relativePath: 'c.txt', serverFileId: 'id-c', localChecksum: 'cc', size: 300, status: 'synced' });

      var all = stateDb.getAllFiles();
      assert.equal(all.length, 3, 'Should return all 3 files');

      var paths = all.map(function (f) { return f.relativePath; }).sort();
      assert.deepStrictEqual(paths, ['a.txt', 'b.txt', 'c.txt']);

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db getFilesByStatus filters correctly', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-status');
    var dbFile = path.join(tempDir, 'test-status.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({ relativePath: 'synced-1.txt', status: 'synced', size: 10 });
      stateDb.upsertFile({ relativePath: 'synced-2.txt', status: 'synced', size: 20 });
      stateDb.upsertFile({ relativePath: 'pending-1.txt', status: 'pending', size: 30 });
      stateDb.upsertFile({ relativePath: 'error-1.txt', status: 'error', size: 40 });

      var synced = stateDb.getFilesByStatus('synced');
      assert.equal(synced.length, 2, 'Should have 2 synced files');
      synced.forEach(function (f) { assert.equal(f.status, 'synced'); });

      var pending = stateDb.getFilesByStatus('pending');
      assert.equal(pending.length, 1);
      assert.equal(pending[0].relativePath, 'pending-1.txt');

      var errors = stateDb.getFilesByStatus('error');
      assert.equal(errors.length, 1);
      assert.equal(errors[0].relativePath, 'error-1.txt');

      var none = stateDb.getFilesByStatus('nonexistent');
      assert.equal(none.length, 0, 'Unknown status should return empty');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db removeFile deletes a specific file', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-remove');
    var dbFile = path.join(tempDir, 'test-remove.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({ relativePath: 'keep.txt', serverFileId: 'id-keep', size: 100, status: 'synced' });
      stateDb.upsertFile({ relativePath: 'remove.txt', serverFileId: 'id-remove', size: 200, status: 'synced' });

      assert.ok(stateDb.getFile('remove.txt'), 'File should exist before removal');
      stateDb.removeFile('remove.txt');
      assert.equal(stateDb.getFile('remove.txt'), undefined, 'File should be gone after removal');

      // The other file should still exist
      var kept = stateDb.getFile('keep.txt');
      assert.ok(kept, 'Other file should remain');
      assert.equal(kept.serverFileId, 'id-keep');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db clearAll removes everything', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-clear');
    var dbFile = path.join(tempDir, 'test-clear.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({ relativePath: 'x.txt', size: 10, status: 'synced' });
      stateDb.upsertFile({ relativePath: 'y.txt', size: 20, status: 'pending' });
      stateDb.setMeta('cursor', '999');
      stateDb.setLastSeq(50);

      assert.equal(stateDb.getAllFiles().length, 2, 'Should have 2 files before clear');
      assert.equal(stateDb.getMeta('cursor'), '999');

      stateDb.clearAll();

      assert.equal(stateDb.getAllFiles().length, 0, 'Should have 0 files after clearAll');
      assert.equal(stateDb.getMeta('cursor'), null, 'Meta should be cleared');
      assert.equal(stateDb.getLastSeq(), 0, 'Last seq should reset to 0');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db integrityCheck returns true on healthy database', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-integrity');
    var dbFile = path.join(tempDir, 'test-integrity.db');

    try {
      stateDb.open(dbFile);

      // Insert some data to make it non-trivial
      stateDb.upsertFile({ relativePath: 'healthy.txt', size: 42, status: 'synced' });
      stateDb.setMeta('check', 'ok');

      var result = stateDb.integrityCheck();
      assert.strictEqual(result, true, 'Healthy DB should pass integrity check');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db updateFileStatus changes status without affecting other fields', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-update-status');
    var dbFile = path.join(tempDir, 'test-update-status.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({
        relativePath: 'status-test.txt',
        serverFileId: 'sid-1',
        localChecksum: 'checksum-orig',
        size: 512,
        serverSeq: 3,
        status: 'synced',
      });

      stateDb.updateFileStatus('status-test.txt', 'error');

      var file = stateDb.getFile('status-test.txt');
      assert.equal(file.status, 'error', 'Status should be updated');
      assert.equal(file.serverFileId, 'sid-1', 'serverFileId should be unchanged');
      assert.equal(file.localChecksum, 'checksum-orig', 'Checksum should be unchanged');
      assert.equal(file.size, 512, 'Size should be unchanged');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

  it('state-db upsertFile updates existing record on conflict', () => {
    const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
    var tempDir = createTempDir('state-db-upsert');
    var dbFile = path.join(tempDir, 'test-upsert.db');

    try {
      stateDb.open(dbFile);

      stateDb.upsertFile({
        relativePath: 'upsert.txt',
        serverFileId: 'id-v1',
        localChecksum: 'check-v1',
        size: 100,
        status: 'synced',
      });

      // Upsert with same path but different data
      stateDb.upsertFile({
        relativePath: 'upsert.txt',
        serverFileId: 'id-v2',
        localChecksum: 'check-v2',
        size: 999,
        status: 'pending',
      });

      var all = stateDb.getAllFiles();
      assert.equal(all.length, 1, 'Should still have 1 record (upsert, not duplicate)');

      var file = stateDb.getFile('upsert.txt');
      assert.equal(file.serverFileId, 'id-v2', 'Should have updated serverFileId');
      assert.equal(file.localChecksum, 'check-v2', 'Should have updated checksum');
      assert.equal(file.size, 999, 'Should have updated size');
      assert.equal(file.status, 'pending', 'Should have updated status');

      stateDb.close();
    } finally {
      rmrf(tempDir);
    }
  });

});
