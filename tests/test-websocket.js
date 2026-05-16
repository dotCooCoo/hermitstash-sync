'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  MSG, newTestWsClient, waitFor, connectWsClient, expectWsRejectClient,
  uploadFile, sleep, httpRequest, createBundleViaDb, createSnapshotBundleViaDb,
  getBundleFilesFromDb, createApiKey,
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
 * WebSocket sync channel tests. Uses the real lib/ws-client.js (WsClient) so the
 * tests exercise the same code path the sync daemon runs — NOT a parallel
 * test-only WebSocket implementation. reconnect:false is set so negative-path
 * assertions aren't masked by auto-retry.
 */
describe('WebSocket Sync Channel', { timeout: 30000 }, () => {

  // Give server time to clean up connections after all tests in this file
  after(async () => { await sleep(1000); });

  it('upgrade with valid API key succeeds', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 0);
    const hb = await hbP;
    assert.equal(hb.type, MSG.HEARTBEAT);
    assert.ok(hb.seq !== undefined);
    ws.close();
  });

  it('upgrade without auth returns 401', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const result = await expectWsRejectClient(ctx.url, null, bundle.bundleId, 0);
    assert.equal(result.statusCode, 401);
  });

  it('upgrade with invalid API key returns 401', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const fakeKey = 'hs_invalid_' + b.crypto.generateToken(16);
    const result = await expectWsRejectClient(ctx.url, fakeKey, bundle.bundleId, 0);
    assert.equal(result.statusCode, 401);
  });

  it('upgrade with nonexistent bundleId returns 404', async () => {
    const fakeBundleId = b.crypto.generateToken(32);
    const result = await expectWsRejectClient(ctx.url, ctx.apiKey, fakeBundleId, 0);
    assert.equal(result.statusCode, 404);
  });

  it('upgrade with non-sync bundle returns 404', async () => {
    const bundle = createSnapshotBundleViaDb(ctx.dbPath);
    const result = await expectWsRejectClient(ctx.url, ctx.apiKey, bundle.bundleId, 0);
    assert.equal(result.statusCode, 404);
  });

  it('heartbeat received within 35 seconds', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 35000);
    await connectWsClient(ws, bundle.bundleId, 0);
    const hb = await hbP;
    assert.equal(hb.type, MSG.HEARTBEAT);
    assert.ok(hb.timestamp);
    ws.close();
  });

  it('file upload triggers file_added event', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_ADDED, 5000);
    await connectWsClient(ws, bundle.bundleId, 0);

    const content = 'ws-event-test ' + Date.now();
    await uploadFile(ctx.url, bundle.bundleId, 'ws-event.txt', content, ctx.apiKey);
    const event = await eventP;

    assert.equal(event.type, MSG.FILE_ADDED);
    assert.equal(event.relativePath, 'ws-event.txt');
    assert.ok(event.checksum, 'Event should include checksum');
    assert.strictEqual(event.checksum.length, 128, 'SHA3-512 checksum should be exactly 128 hex chars, got ' + event.checksum.length);
    assert.ok(/^[0-9a-f]{128}$/.test(event.checksum), 'Checksum should be lowercase hex');
    assert.ok(typeof event.size === 'number' && event.size > 0, 'Event should include a positive size field');
    assert.ok(event.seq > 0);
    assert.ok(event.fileId);
    ws.close();
  });

  it('file replace triggers file_replaced event', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'replace-ev.txt', 'v1', ctx.apiKey);

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_REPLACED, 5000);
    await connectWsClient(ws, bundle.bundleId, 99999);

    await uploadFile(ctx.url, bundle.bundleId, 'replace-ev.txt', 'v2-' + Date.now(), ctx.apiKey);
    const event = await eventP;

    assert.equal(event.type, MSG.FILE_REPLACED);
    assert.equal(event.relativePath, 'replace-ev.txt');
    ws.close();
  });

  it('file delete triggers file_removed event', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'remove-ev.txt', 'will be removed', ctx.apiKey);

    const files = getBundleFilesFromDb(ctx.dbPath, bundle.bundleId);
    const fileId = files[0]._id;

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const eventP = waitFor(ws, 'message', m => m.type === MSG.FILE_REMOVED, 5000);
    await connectWsClient(ws, bundle.bundleId, 99999);

    await httpRequest(`${ctx.url}/bundles/${bundle.shareId}/file/${fileId}/delete`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${ctx.apiKey}`, 'Content-Type': 'application/json' },
      body: '{}',
    });
    const event = await eventP;

    assert.equal(event.type, MSG.FILE_REMOVED);
    assert.equal(event.relativePath, 'remove-ev.txt');
    assert.ok(event.seq > 0);
    ws.close();
  });

  it('catch-up: since=1 on connect receives events with seq>1', async () => {
    // Upload 3 files (seq 1,2,3), connect with since=1, expect events with seq>1.
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'cu-1.txt', 'one', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'cu-2.txt', 'two', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'cu-3.txt', 'three', ctx.apiKey);

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const fileEvents = [];
    ws.on('message', m => {
      if (m.type === MSG.FILE_ADDED || m.type === MSG.FILE_REPLACED) fileEvents.push(m);
    });
    // Wait for the catch-up-complete heartbeat — all catch-up file events arrive before it.
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 1);
    await hbP;

    assert.ok(fileEvents.length >= 2, `Should get >= 2 file events (seq>1), got ${fileEvents.length}`);
    for (const ev of fileEvents) {
      assert.ok(ev.seq > 1, `Event seq (${ev.seq}) should be > 1`);
    }
    for (let i = 1; i < fileEvents.length; i++) {
      assert.ok(fileEvents[i].seq >= fileEvents[i - 1].seq, 'Events should be ordered by seq');
    }
    ws.close();
  });

  it('catch-up: since=N receives only events after N', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'p-1.txt', 'one', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'p-2.txt', 'two', ctx.apiKey);
    await uploadFile(ctx.url, bundle.bundleId, 'p-3.txt', 'three', ctx.apiKey);

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const fileEvents = [];
    ws.on('message', m => {
      if (m.type === MSG.FILE_ADDED || m.type === MSG.FILE_REPLACED) fileEvents.push(m);
    });
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 1);
    await hbP;

    for (const ev of fileEvents) {
      assert.ok(ev.seq > 1, `Event seq (${ev.seq}) should be > 1`);
    }
    ws.close();
  });

  it('client ping receives heartbeat response', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const firstHbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 0);
    await firstHbP;

    const pongP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    ws.send({ type: 'ping' });
    const hb = await pongP;
    assert.equal(hb.type, MSG.HEARTBEAT);
    ws.close();
  });

  it('client catch_up message triggers replay', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'cu-msg.txt', 'data', ctx.apiKey);

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    // Connect with high since so catch-up on connect is empty.
    await connectWsClient(ws, bundle.bundleId, 99999);

    // Attach file-event listener, then send catch_up.
    const fileEventP = waitFor(ws, 'message', m => m.type === MSG.FILE_ADDED, 2000);
    ws.send({ type: 'catch_up', since: 0 });
    const fileEvent = await fileEventP;
    assert.equal(fileEvent.type, MSG.FILE_ADDED);
    assert.equal(fileEvent.relativePath, 'cu-msg.txt');
    ws.close();
  });

  it('API key without sync scope is rejected (403)', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const uploadOnlyKey = createApiKey(ctx.dbPath, 'upload,read');
    const result = await expectWsRejectClient(ctx.url, uploadOnlyKey, bundle.bundleId, 0);
    assert.equal(result.statusCode, 403);
  });

  it('malformed JSON message is handled without crashing', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const firstHbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 0);
    await firstHbP;

    // Send an invalid-JSON text frame directly (bypasses WsClient.send() which calls JSON.stringify).
    ws._sendFrame(0x01, Buffer.from('this is not valid json {{{', 'utf8'));

    // Verify the connection survives: send a valid ping, expect a heartbeat back.
    const pongP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    ws.send({ type: 'ping' });
    const hb = await pongP;
    assert.equal(hb.type, MSG.HEARTBEAT, 'Connection should still be alive after malformed message');
    ws.close();
  });

  it('two clients on same bundle both receive events', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const ws1 = newTestWsClient(ctx.url, ctx.apiKey);
    const ws2 = newTestWsClient(ctx.url, ctx.apiKey);
    const event1P = waitFor(ws1, 'message', m => m.type === MSG.FILE_ADDED, 5000);
    const event2P = waitFor(ws2, 'message', m => m.type === MSG.FILE_ADDED, 5000);
    await connectWsClient(ws1, bundle.bundleId, 0);
    await connectWsClient(ws2, bundle.bundleId, 0);

    const content = 'multi-client-test ' + Date.now();
    await uploadFile(ctx.url, bundle.bundleId, 'multi-client.txt', content, ctx.apiKey);

    const event1 = await event1P;
    const event2 = await event2P;

    assert.equal(event1.type, MSG.FILE_ADDED);
    assert.equal(event1.relativePath, 'multi-client.txt');
    assert.equal(event2.type, MSG.FILE_ADDED);
    assert.equal(event2.relativePath, 'multi-client.txt');

    ws1.close();
    ws2.close();
  });

  it('since equal to current seq returns no catch-up events', async () => {
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    await uploadFile(ctx.url, bundle.bundleId, 'seq-test.txt', 'data', ctx.apiKey);

    const ws = newTestWsClient(ctx.url, ctx.apiKey);
    const fileEvents = [];
    ws.on('message', m => {
      if (m.type === MSG.FILE_ADDED || m.type === MSG.FILE_REPLACED || m.type === MSG.FILE_REMOVED) {
        fileEvents.push(m);
      }
    });
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 2000);
    await connectWsClient(ws, bundle.bundleId, 1);
    await hbP;

    assert.equal(fileEvents.length, 0,
      'Should get no catch-up file events when since equals current seq, got ' + fileEvents.length);
    ws.close();
  });

});
