'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  MSG, sleep, sha3, createTempDir, rmrf,
} = require('./test-helpers');

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');
const SyncEngine = require(path.join(CLIENT_LIB, 'sync-engine'));
const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
const { FILE_STATUS, SYNC_STATE } = require(path.join(CLIENT_LIB, 'constants'));

/**
 * Server-event serialization + durable-cursor tests.
 *
 * These exercise the production SyncEngine apply path directly. The wire
 * layer (HTTP download, WebSocket transport, fs watcher) is replaced with
 * controlled stubs so a test can make an earlier-seq download slower than a
 * later-seq one, force a download failure, and observe the SYNCED
 * transition deterministically — none of which is reliably reproducible
 * through a live server. The engine logic under test (apply-chain
 * serialization, seq-cursor gating, the reconcile sweep, and the SYNCED
 * derivation from pool depth + download counter) is the real shipped code.
 *
 * No encryption is bypassed: there is no wire crypto in this layer. The
 * checksums are produced via the production lib/checksum SHA3-512 path
 * (sha3() in test-helpers) and gated end-to-end, exactly as in production.
 */

// Minimal real state-db + sync folder per engine, with stubbed wire layer.
function makeEngine(opts) {
  opts = opts || {};
  const root = createTempDir('sync-serialize');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = {
    syncFolder,
    bundleId: 'bundle-test',
    // No mtls block → _checkCertExpiry is a no-op; we never call start().
  };
  const engine = new SyncEngine(config, 'hs_test_key');

  // Stub the WebSocket so _updateSeq's updateSince + heartbeat ack don't NPE.
  const acks = [];
  engine._ws = {
    send: (m) => acks.push(m),
    updateSince: () => {},
    close: () => {},
    reloadMtlsCerts: () => {},
  };
  // Selective-sync patterns default to "sync everything".
  engine._ignorePatterns = [];
  engine._includePatterns = [];

  // Stub _http with a controllable download. Each call writes the expected
  // content to destPath (verifying the checksum the way the real client
  // does) after an optional per-fileId delay, or rejects to simulate a
  // failed transfer.
  const downloads = opts.downloads || {}; // fileId -> { content, delayMs, fail }
  const downloadLog = [];
  engine._http = {
    async downloadFile(fileId, destPath, expectedChecksum) {
      const spec = downloads[fileId] || {};
      if (typeof spec.delayMs === 'number' && spec.delayMs > 0) await sleep(spec.delayMs);
      downloadLog.push({ fileId, destPath, finishedAt: Date.now() });
      if (spec.fail) throw new Error('simulated download failure for ' + fileId);
      const content = spec.content != null ? spec.content : ('content-' + fileId);
      const buf = Buffer.from(content, 'utf8');
      if (expectedChecksum && sha3(buf) !== expectedChecksum) {
        throw new Error('checksum mismatch for ' + fileId);
      }
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.writeFileSync(destPath, buf);
      return destPath;
    },
    reloadMtlsCerts() {},
    destroy() {},
  };

  return { engine, root, syncFolder, dbFile, acks, downloadLog, downloads };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* allow:silent-catch — best-effort teardown */ }
  rmrf(h.root);
}

describe('Server-event serialization + durable seq cursor', { timeout: 30000 }, () => {

  it('same-path events apply highest-seq-last even when the earlier download is slower', async () => {
    const content5 = 'A-payload';
    const content6 = 'B-payload';
    const checksum5 = sha3(content5);
    const checksum6 = sha3(content6);

    // seq=5 download is deliberately slower than seq=6. Without
    // serialization, the slow seq=5 write would land AFTER seq=6 and
    // clobber the newer content. The apply chain must enforce 5-then-6.
    const h = makeEngine({
      downloads: {
        'file-5': { content: content5, delayMs: 120 },
        'file-6': { content: content6, delayMs: 5 },
      },
    });

    try {
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-5', relativePath: 'same.txt', checksum: checksum5, size: content5.length, seq: 5 });
      h.engine._onServerMessage({ type: MSG.FILE_REPLACED, fileId: 'file-6', relativePath: 'same.txt', checksum: checksum6, size: content6.length, seq: 6 });

      // Drain the apply chain.
      await h.engine._applyChain;

      const onDisk = fs.readFileSync(path.join(h.syncFolder, 'same.txt'), 'utf8');
      assert.equal(onDisk, content6, 'newest seq content must win on disk');

      const row = stateDb.getFile('same.txt');
      assert.equal(row.localChecksum, checksum6, 'recorded checksum must be the newest seq');
      assert.equal(stateDb.getLastSeq(), 6, 'cursor must be at the newest applied seq');

      // The slow seq=5 download must have committed before seq=6 started.
      assert.equal(h.downloadLog.length, 2);
      assert.equal(h.downloadLog[0].fileId, 'file-5', 'seq 5 applies first');
      assert.equal(h.downloadLog[1].fileId, 'file-6', 'seq 6 applies second');
    } finally {
      cleanup(h);
    }
  });

  it('a failed download leaves lastSeq unadvanced and the row recoverable', async () => {
    const content = 'will-fail';
    const checksum = sha3(content);
    const h = makeEngine({
      downloads: { 'file-9': { content, fail: true } },
    });

    try {
      stateDb.setLastSeq(8);
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-9', relativePath: 'broken.txt', checksum, size: content.length, seq: 9 });
      await h.engine._applyChain;

      assert.equal(stateDb.getLastSeq(), 8, 'cursor must NOT advance past a failed download');
      const row = stateDb.getFile('broken.txt');
      assert.ok(row, 'a recoverable row must remain');
      assert.equal(row.status, FILE_STATUS.ERROR, 'row should be flagged ERROR for the reconcile sweep');
      assert.equal(row.serverFileId, 'file-9');
      assert.equal(row.serverChecksum, checksum);
    } finally {
      cleanup(h);
    }
  });

  it('the reconcile sweep re-drives a stranded ERROR row once the transfer can succeed', async () => {
    const content = 'recovers-later';
    const checksum = sha3(content);
    const h = makeEngine({
      downloads: { 'file-3': { content, fail: true } },
    });

    try {
      // First apply fails and strands the row.
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-3', relativePath: 'heal.txt', checksum, size: content.length, seq: 3 });
      await h.engine._applyChain;
      assert.equal(stateDb.getFile('heal.txt').status, FILE_STATUS.ERROR);

      // The underlying transfer now succeeds (server object became fetchable).
      h.downloads['file-3'] = { content };

      // A reconcile pass keys off persisted row state, independent of seq.
      await h.engine._recoverPending();

      const row = stateDb.getFile('heal.txt');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'reconcile must re-drive the stranded row to SYNCED');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, 'heal.txt'), 'utf8'), content);
    } finally {
      cleanup(h);
    }
  });

  it('SYNCED is not reported while a download is in flight, only after it commits', async () => {
    const content = 'in-flight';
    const checksum = sha3(content);
    const h = makeEngine({
      downloads: { 'file-1': { content, delayMs: 80 } },
    });

    try {
      // Steady state (post-catch-up): a normal download must show DOWNLOADING
      // while in flight and only return to SYNCED once it commits. Catch-up
      // downloads intentionally stay CATCHING_UP and complete only on the
      // trailing heartbeat — that path is covered by the heartbeat tests below.
      h.engine._setState(SYNC_STATE.SYNCED);

      const states = [];
      h.engine.on('state', (s) => states.push(s));

      const applyP = h.engine._applyChain.then(() => {});
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-1', relativePath: 'live.txt', checksum, size: content.length, seq: 1 });

      // While the download is delayed, the engine must be DOWNLOADING, not SYNCED.
      await sleep(30);
      assert.equal(h.engine.state, SYNC_STATE.DOWNLOADING, 'must be DOWNLOADING mid-transfer');
      assert.ok(h.engine._activeDownloads > 0, 'download counter must be > 0 mid-transfer');

      await h.engine._applyChain;
      await applyP;

      // The download committed; no work remains, so SYNCED is now allowed.
      h.engine._maybeMarkSynced();
      assert.equal(h.engine.state, SYNC_STATE.SYNCED, 'SYNCED only after the transfer commits');
      assert.ok(!states.includes(SYNC_STATE.SYNCED) || states.indexOf(SYNC_STATE.SYNCED) === states.lastIndexOf(SYNC_STATE.SYNCED),
        'SYNCED must not have flapped mid-transfer');
    } finally {
      cleanup(h);
    }
  });

  it('a seq===0 "connection live" heartbeat does not declare catch-up complete while work is pending', async () => {
    const content = 'pending-work';
    const checksum = sha3(content);
    const h = makeEngine({
      downloads: { 'file-7': { content, delayMs: 100 } },
    });

    try {
      h.engine._setState(SYNC_STATE.CATCHING_UP);

      // Start a slow catch-up download.
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-7', relativePath: 'cu.txt', checksum, size: content.length, seq: 7 });

      // A seq===0 liveness heartbeat must NOT flip to SYNCED mid-batch. The
      // download is still in flight (state DOWNLOADING) and _catchUpPending
      // is > 0, so the catch-up-complete gate must refuse to transition.
      await sleep(20);
      assert.ok(h.engine._catchUpPending > 0 || h.engine._activeDownloads > 0, 'catch-up work must be outstanding mid-batch');
      h.engine._caughtUpAtSeq = false; // a seq===0 heartbeat does not set this
      h.engine._handleHeartbeat({ seq: 0 });
      assert.notEqual(h.engine.state, SYNC_STATE.SYNCED, 'seq===0 heartbeat must not complete catch-up on its own');

      // Drain, then a genuine caught-up-at-seq heartbeat completes it.
      await h.engine._applyChain;
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      h.engine._handleHeartbeat({ seq: 7 });
      assert.equal(h.engine.state, SYNC_STATE.SYNCED, 'genuine caught-up heartbeat completes catch-up once work drained');
    } finally {
      cleanup(h);
    }
  });

  it('a catch-up download completing stays CATCHING_UP until the trailing heartbeat', async () => {
    const content = 'catchup-bytes';
    const checksum = sha3(content);
    const h = makeEngine({
      downloads: { 'file-cu': { content, delayMs: 40 } },
    });
    try {
      h.engine._setState(SYNC_STATE.CATCHING_UP);

      // A catch-up file_added download runs to completion.
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'file-cu', relativePath: 'cu2.txt', checksum, size: content.length, seq: 9 });
      await h.engine._applyChain;

      // The download committed and no transfer remains, but NO caught-up
      // heartbeat has arrived. The engine must stay CATCHING_UP rather than let
      // the finishing transfer flip it to SYNCED — that premature flip both
      // reports SYNCED with catch-up events possibly still queued and destroys
      // the CATCHING_UP state the heartbeat's completion guard depends on.
      assert.equal(h.engine.state, SYNC_STATE.CATCHING_UP, 'stays CATCHING_UP until the heartbeat, not SYNCED');

      // The genuine caught-up-at-seq heartbeat now owns the completion.
      h.engine._handleHeartbeat({ seq: 9 });
      assert.equal(h.engine.state, SYNC_STATE.SYNCED, 'heartbeat completes catch-up -> SYNCED');
    } finally {
      cleanup(h);
    }
  });

  it('remote delete preserves a locally-modified file as a conflict copy', async () => {
    const h = makeEngine({});
    try {
      // Record a synced file, then diverge the local bytes from last-synced.
      const synced = 'original-bytes';
      const syncedChecksum = sha3(synced);
      const filePath = path.join(h.syncFolder, 'keepme.txt');
      fs.writeFileSync(filePath, 'LOCALLY EDITED — different from synced');
      stateDb.upsertFile({
        relativePath: 'keepme.txt',
        serverFileId: 'fid',
        localChecksum: syncedChecksum,
        serverChecksum: syncedChecksum,
        size: synced.length,
        serverSeq: 4,
        status: FILE_STATUS.SYNCED,
      });

      h.engine._onServerMessage({ type: MSG.FILE_REMOVED, relativePath: 'keepme.txt', seq: 5 });
      await h.engine._applyChain;

      // Original path must be gone (renamed aside), a conflict copy must exist.
      assert.ok(!fs.existsSync(filePath), 'original path renamed aside, not destroyed');
      const conflicts = fs.readdirSync(h.syncFolder).filter(n => n.includes('.conflict-'));
      assert.equal(conflicts.length, 1, 'a single conflict copy must be preserved');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, conflicts[0]), 'utf8'), 'LOCALLY EDITED — different from synced');
      assert.equal(stateDb.getFile('keepme.txt'), undefined, 'DB row removed after the delete applies');
      assert.equal(stateDb.getLastSeq(), 5, 'cursor advances once the delete is honored');
    } finally {
      cleanup(h);
    }
  });

  it('remote delete of an unmodified file deletes it without a conflict copy', async () => {
    const h = makeEngine({});
    try {
      const synced = 'unchanged-bytes';
      const syncedChecksum = sha3(synced);
      const filePath = path.join(h.syncFolder, 'gone.txt');
      fs.writeFileSync(filePath, synced);
      stateDb.upsertFile({
        relativePath: 'gone.txt',
        serverFileId: 'fid2',
        localChecksum: syncedChecksum,
        serverChecksum: syncedChecksum,
        size: synced.length,
        serverSeq: 2,
        status: FILE_STATUS.SYNCED,
      });

      h.engine._onServerMessage({ type: MSG.FILE_REMOVED, relativePath: 'gone.txt', seq: 3 });
      await h.engine._applyChain;

      assert.ok(!fs.existsSync(filePath), 'unmodified file is deleted');
      const conflicts = fs.readdirSync(h.syncFolder).filter(n => n.includes('.conflict-'));
      assert.equal(conflicts.length, 0, 'no conflict copy for an uncontested delete');
      assert.equal(stateDb.getFile('gone.txt'), undefined);
      assert.equal(stateDb.getLastSeq(), 3);
    } finally {
      cleanup(h);
    }
  });

});
