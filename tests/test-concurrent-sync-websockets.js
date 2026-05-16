'use strict';

/**
 * Concurrency test for the sync bundle seq counter.
 *
 * Every upload to a sync bundle does:
 *   bundle = bundlesRepo.findById(bundleId);           // read
 *   await storage.saveFile(...);                       // ⟵ yields event loop
 *   bundlesRepo.update(..., { seq: (bundle.seq||0)+1 });  // stale-read write
 *   syncEmitter.emit({ ..., seq: (bundle.seq||0)+1 });
 *
 * Two uploads fired in parallel both read bundle.seq at the top, both await
 * storage, then both write `oldSeq + 1` — producing duplicate seq values on
 * the WebSocket stream. Downstream sync clients use `seq > lastSeq` for
 * catch-up, so a duplicate silently drops an event.
 *
 * This test fires N concurrent uploads against the same sync bundle while
 * one WS client is subscribed, collects every observed seq value, and
 * asserts they form a strictly monotonic, no-duplicate, no-gap sequence.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  MSG, newTestWsClient, waitFor, connectWsClient, uploadFile,
  createBundleViaDb, sleep,
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

describe('Concurrent sync uploads — seq monotonicity', { timeout: 30000 }, function () {
  // Leave the server a beat to drain after tests so subsequent files see a clean WS state.
  after(async function () { await sleep(500); });

  it('N=5 parallel uploads produce 5 distinct, strictly-increasing seq values on the WS stream', async function () {
    const N = 5;
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    const ws = newTestWsClient(ctx.url, ctx.apiKey);

    // Collect every file_added event before firing uploads — listener attached
    // synchronously so no event is missed.
    const collected = [];
    ws.on('message', function (m) {
      if (m.type === MSG.FILE_ADDED) collected.push({ seq: m.seq, path: m.relativePath });
    });

    // Wait for the initial heartbeat before starting so we're sure the
    // subscription is active. Catch-up since=0 replays none (bundle is new).
    const hbP = waitFor(ws, 'message', m => m.type === MSG.HEARTBEAT, 3000);
    await connectWsClient(ws, bundle.bundleId, 0);
    await hbP;

    // Fire N uploads in parallel. The event-loop yield inside each upload
    // (storage.saveFile is async) is where the stale-read race would fire.
    const uploads = [];
    for (let i = 0; i < N; i++) {
      uploads.push(uploadFile(ctx.url, bundle.bundleId, 'conc-' + i + '.txt', 'payload-' + i, ctx.apiKey));
    }
    const results = await Promise.all(uploads);

    // All uploads must succeed — if any returned non-200 the seq check is moot.
    for (let i = 0; i < N; i++) {
      assert.equal(results[i].statusCode, 200, 'upload ' + i + ' → 200, got ' + results[i].statusCode);
    }

    // WS events are emitted synchronously from syncEmitter, but the client
    // receives them over the socket — give the event loop a beat to flush.
    // Repeatedly poll until we've seen N events or we time out at 3s.
    const deadline = Date.now() + 3000;
    while (collected.length < N && Date.now() < deadline) {
      await sleep(50);
    }

    ws.close();

    assert.equal(collected.length, N,
      'WS should receive exactly ' + N + ' file_added events, got ' + collected.length +
      ' (events: ' + JSON.stringify(collected) + ')');

    // Extract seq values and verify properties.
    const seqs = collected.map(e => e.seq).sort((a, b) => a - b);

    // All distinct?
    const distinct = new Set(seqs);
    assert.equal(distinct.size, N,
      'all ' + N + ' events must have distinct seq values (got ' + seqs.length + ' events, ' +
      distinct.size + ' distinct — duplicates: ' + JSON.stringify(seqs) + ')');

    // Monotonic with no gaps? Seqs should be exactly startingSeq+1 ... startingSeq+N.
    const first = seqs[0];
    for (let i = 0; i < N; i++) {
      assert.equal(seqs[i], first + i,
        'seq values must be contiguous (expected ' + (first + i) + ' at index ' + i +
        ', got ' + seqs[i] + ') — full seq list: ' + JSON.stringify(seqs));
    }
  });

  it('two WS clients on the same bundle both observe the same seq stream', async function () {
    const N = 4;
    const bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });

    const ws1 = newTestWsClient(ctx.url, ctx.apiKey);
    const ws2 = newTestWsClient(ctx.url, ctx.apiKey);
    const collected1 = [];
    const collected2 = [];
    ws1.on('message', m => { if (m.type === MSG.FILE_ADDED) collected1.push(m.seq); });
    ws2.on('message', m => { if (m.type === MSG.FILE_ADDED) collected2.push(m.seq); });

    const hb1 = waitFor(ws1, 'message', m => m.type === MSG.HEARTBEAT, 3000);
    const hb2 = waitFor(ws2, 'message', m => m.type === MSG.HEARTBEAT, 3000);
    await connectWsClient(ws1, bundle.bundleId, 0);
    await connectWsClient(ws2, bundle.bundleId, 0);
    await Promise.all([hb1, hb2]);

    const uploads = [];
    for (let i = 0; i < N; i++) {
      uploads.push(uploadFile(ctx.url, bundle.bundleId, 'fan-' + i + '.txt', 'x-' + i, ctx.apiKey));
    }
    await Promise.all(uploads);

    const deadline = Date.now() + 3000;
    while ((collected1.length < N || collected2.length < N) && Date.now() < deadline) {
      await sleep(50);
    }

    ws1.close();
    ws2.close();

    assert.equal(collected1.length, N, 'ws1 got ' + collected1.length + '/' + N);
    assert.equal(collected2.length, N, 'ws2 got ' + collected2.length + '/' + N);

    // Both clients saw the same distinct seqs (order may differ under concurrency).
    const set1 = new Set(collected1);
    const set2 = new Set(collected2);
    assert.equal(set1.size, N, 'ws1 should have ' + N + ' distinct seqs, got ' + set1.size);
    assert.equal(set2.size, N, 'ws2 should have ' + N + ' distinct seqs, got ' + set2.size);
    assert.deepEqual([...set1].sort((a, b) => a - b), [...set2].sort((a, b) => a - b),
      'both clients must observe identical seq sets');
  });
});
