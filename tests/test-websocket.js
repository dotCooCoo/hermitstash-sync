'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const b = require('../vendor/blamejs');
const WsClient = require('../lib/ws-client');
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

/**
 * Reconnect terminality — locks the boundary between errors that should
 * permanently disable the wrapper's since-aware reconnect loop and those
 * that should fall through to a fresh dial.
 *
 * blamejs constructs every WsClientError as `alwaysPermanent`, so its
 * `err.permanent` flag can't distinguish a dead-peer pong-timeout (which
 * MUST reconnect) from a 4xx handshake rejection (which must not). These
 * cases drive the production WsClient's real 'error'/'close' handlers
 * through a stubbed transport — only `b.wsClient.connect` is swapped for a
 * peer-contract emitter, so the wrapper's own classifier is exercised
 * end-to-end without needing a live server or a real timed-out heartbeat.
 *
 * Reconnect is ENABLED here (no `reconnect: false`), unlike the helper-built
 * clients above, so a transient drop actually schedules a redial.
 */
describe('WsClient reconnect terminality', () => {
  const WsClientError = b.wsClient.WsClientError;

  // Stand up a production WsClient whose underlying b.wsClient.connect is
  // replaced by a controllable peer-contract emitter. Returns the wrapper,
  // the stub transport, and a restore() to undo the monkeypatch.
  function withStubbedTransport() {
    const realConnect = b.wsClient.connect;
    const stub = new EventEmitter();
    stub.readyState = 'connecting';
    stub.send = () => {};
    stub.close = () => {};
    stub.cancelReconnect = () => {};
    b.wsClient.connect = () => stub;

    // reconnect enabled (omit reconnect:false) so _scheduleReconnect arms.
    // Server URL is the https form the wrapper expects — _dial derives the
    // wss:// dial URL from it. The host is never contacted: b.wsClient.connect
    // is stubbed out, so the dial is fully synthetic.
    const ws = new WsClient({ server: 'https://stub.invalid:443', reconnect: true }, 'hs_stub_key');
    ws.connect('stub-bundle', 0);

    return {
      ws,
      stub,
      restore() { b.wsClient.connect = realConnect; },
    };
  }

  // blamejs emits 'error' then 'close' on a socket failure; the wrapper
  // decides terminality on 'error' and acts on 'close'. Replay that order.
  function driveError(stub, err) {
    stub.emit('error', err);
    stub.emit('close', 1006, err.message || 'error');
  }

  it('pong-timeout reconnects instead of wedging offline', async () => {
    const { ws, stub, restore } = withStubbedTransport();
    try {
      const reconnectingP = waitFor(ws, 'reconnecting', () => true, 3000);
      // Swallow the wrapper's re-emitted transient 'error' so it doesn't
      // surface as an unhandled 'error' on the EventEmitter.
      ws.on('error', () => {});

      driveError(stub, new WsClientError('ws-client/pong-timeout',
        'no pong received within 90000ms'));

      const attempt = await reconnectingP;
      assert.ok(attempt >= 1, 'reconnecting should fire with an attempt number');
      assert.equal(ws._closing, false,
        'pong-timeout is transient — _closing must stay false so reconnect proceeds');
    } finally {
      ws.close();
      restore();
    }
  });

  it('handshake-timeout reconnects instead of wedging offline', async () => {
    const { ws, stub, restore } = withStubbedTransport();
    try {
      const reconnectingP = waitFor(ws, 'reconnecting', () => true, 3000);
      ws.on('error', () => {});

      driveError(stub, new WsClientError('ws-client/handshake-timeout',
        'handshake did not complete within timeout'));

      const attempt = await reconnectingP;
      assert.ok(attempt >= 1, 'reconnecting should fire with an attempt number');
      assert.equal(ws._closing, false,
        'handshake-timeout is transient — _closing must stay false so reconnect proceeds');
    } finally {
      ws.close();
      restore();
    }
  });

  it('4xx bad-status is terminal — sets _closing, emits upgrade_rejected/auth_error, no reconnect', async () => {
    const { ws, stub, restore } = withStubbedTransport();
    try {
      const rejectedP = waitFor(ws, 'upgrade_rejected', info => info.status === 403, 3000);
      const authP = waitFor(ws, 'auth_error', info => info.status === 403, 3000);
      let reconnected = false;
      ws.on('reconnecting', () => { reconnected = true; });

      const err = new WsClientError('ws-client/bad-status',
        'handshake response status was 403 (expected 101 Switching Protocols)');
      err.status = 403;
      err.body = 'forbidden';
      driveError(stub, err);

      const rejected = await rejectedP;
      const authErr = await authP;
      assert.equal(rejected.status, 403, 'upgrade_rejected carries the parsed HTTP status');
      assert.equal(authErr.status, 403, 'auth_error fires for a 403 handshake rejection');
      assert.equal(ws._closing, true,
        '4xx bad-status is terminal — _closing must be set so reconnect is suppressed');

      // Give any erroneously-scheduled reconnect a beat to fire.
      await sleep(50);
      assert.equal(reconnected, false, 'a terminal 4xx must NOT schedule a reconnect');
    } finally {
      ws.close();
      restore();
    }
  });

  it('5xx bad-status is transient — reconnects rather than wedging', async () => {
    const { ws, stub, restore } = withStubbedTransport();
    try {
      const reconnectingP = waitFor(ws, 'reconnecting', () => true, 3000);
      // A 5xx still routes through the upgrade_rejected path (it's a
      // non-101 handshake response) but must NOT mark the client terminal.
      ws.on('upgrade_rejected', () => {});

      const err = new WsClientError('ws-client/bad-status',
        'handshake response status was 503 (expected 101 Switching Protocols)');
      err.status = 503;
      err.body = 'service unavailable';
      driveError(stub, err);

      const attempt = await reconnectingP;
      assert.ok(attempt >= 1, 'reconnecting should fire for a transient 5xx');
      assert.equal(ws._closing, false,
        '5xx bad-status is a server blip — _closing must stay false so reconnect proceeds');
    } finally {
      ws.close();
      restore();
    }
  });

});
