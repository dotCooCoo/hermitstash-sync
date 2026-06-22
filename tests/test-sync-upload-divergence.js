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
 * Last-write-wins / conflict-preservation tests for the local-upload and
 * initial-sync overwrite paths.
 *
 * These drive the production SyncEngine directly with a stubbed wire layer so
 * a concurrent local edit during an upload, an offline-diverged file on a
 * cold-start initial sync, and a remote delete racing an in-flight download
 * are all reproducible. The checksums flow through the production SHA3-512
 * path; no encryption is bypassed (this layer has no wire crypto).
 */

function makeEngine(opts) {
  opts = opts || {};
  const root = createTempDir('upload-divergence');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = { syncFolder, bundleId: 'bundle-test', shareId: 'share-test' };
  const engine = new SyncEngine(config, 'hs_test_key');

  engine._ws = {
    send: () => {},
    updateSince: () => {},
    close: () => {},
    reloadMtlsCerts: () => {},
  };
  engine._ignorePatterns = [];
  engine._includePatterns = [];

  const downloads = opts.downloads || {};
  const downloadLog = [];
  const uploadLog = [];
  let uploadSeq = 100;

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
    // The server hashes the bytes it receives — model that by reading the file
    // at the moment the stream is consumed, BEFORE any onUpload hook mutates
    // the disk to simulate a concurrent writer. result.checksum is the bytes
    // the server actually stored.
    async uploadFile(bundleId, relativePath, fullPath) {
      const receivedBuf = fs.readFileSync(fullPath);
      const serverChecksum = sha3(receivedBuf);
      uploadLog.push({ relativePath, serverChecksum });
      // Simulate a concurrent local edit landing during/right after the
      // stream read but before the engine's post-upload re-hash.
      if (typeof opts.onUpload === 'function') {
        opts.onUpload(relativePath, fullPath);
      }
      return { fileId: 'srv-' + (uploadSeq), checksum: serverChecksum, seq: uploadSeq++ };
    },
    async getBundleMetadata() {
      return opts.bundleMeta || { files: [], totalSize: 0 };
    },
    async deleteFile() { return true; },
    reloadMtlsCerts() {},
    destroy() {},
  };

  return { engine, root, syncFolder, dbFile, downloadLog, uploadLog, downloads };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

describe('Upload post-hash divergence (lost-update protection)', { timeout: 30000 }, () => {

  it('a concurrent local edit during upload does not settle SYNCED masking the drift', async () => {
    const v1 = 'version-one-uploaded';
    const v2 = 'version-two-edited-concurrently';
    const v1Checksum = sha3(v1);
    const v2Checksum = sha3(v2);
    const rel = 'race.txt';

    let edited = false;
    const h = makeEngine({
      // When the upload "completes" the first time, overwrite the file on disk
      // with v2 to model an external writer mutating it mid-stream.
      onUpload(relativePath, fullPath) {
        if (!edited) {
          edited = true;
          fs.writeFileSync(fullPath, v2);
        }
      },
    });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, v1);

      // First upload: caller hashes v1, uploads v1 (server records v1), then
      // the onUpload hook writes v2 to disk before the post-upload re-hash.
      await h.engine._uploadFile(rel, filePath, v1Checksum);

      // The row must NOT be a SYNCED row whose localChecksum masks v2. It is
      // either PENDING_UPLOAD (re-queued) — never SYNCED with localChecksum=v2.
      let row = stateDb.getFile(rel);
      assert.ok(row, 'a row exists after the diverged upload');
      assert.notEqual(row.status, FILE_STATUS.SYNCED,
        'a diverged upload must NOT settle SYNCED');
      assert.notEqual(row.localChecksum, v2Checksum,
        'localChecksum must never record the un-uploaded v2 bytes (that would mask the drift)');

      // Drain the rescan the engine enqueued, which re-detects v2 != stored
      // localChecksum and re-uploads. The disk no longer changes (edited=true),
      // so this convergence run uploads v2 and lands SYNCED at v2.
      await h.engine._applyChain;
      // Give the pool-routed rescan upload time to settle.
      for (let i = 0; i < 50 && stateDb.getFile(rel).status !== FILE_STATUS.SYNCED; i++) {
        await sleep(10);
      }

      row = stateDb.getFile(rel);
      assert.equal(fs.readFileSync(filePath, 'utf8'), v2, 'disk holds v2');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'eventually converges to SYNCED on v2');
      assert.equal(row.localChecksum, v2Checksum, 'final localChecksum matches the v2 bytes the server now has');
      // The server received v2 on the convergence upload (last entry).
      assert.equal(h.uploadLog[h.uploadLog.length - 1].serverChecksum, v2Checksum,
        'the server ends up holding v2, not stranded on v1');
    } finally {
      cleanup(h);
    }
  });

  it('an uncontested upload (no concurrent edit) settles SYNCED on the uploaded bytes', async () => {
    const content = 'stable-bytes';
    const checksum = sha3(content);
    const rel = 'stable.txt';
    const h = makeEngine({}); // no onUpload hook → no concurrent edit
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, content);

      await h.engine._uploadFile(rel, filePath, checksum);

      const row = stateDb.getFile(rel);
      assert.equal(row.status, FILE_STATUS.SYNCED, 'a clean upload lands SYNCED');
      assert.equal(row.localChecksum, checksum, 'localChecksum is the uploaded bytes');
      assert.equal(row.serverChecksum, checksum, 'serverChecksum is what the server received');
    } finally {
      cleanup(h);
    }
  });

});

describe('Initial sync conflict-copy protection', { timeout: 30000 }, () => {

  it('initial sync preserves a locally-diverged file as a conflict copy before overwriting', async () => {
    const serverContent = 'authoritative-server-bytes';
    const serverChecksum = sha3(serverContent);
    const localOffline = 'OFFLINE EDIT — different from the server version';
    const rel = 'offline.txt';

    const h = makeEngine({
      downloads: { 'srv-file': { content: serverContent } },
      bundleMeta: {
        files: [{ id: 'srv-file', relativePath: rel, checksum: serverChecksum, size: serverContent.length, seq: 1 }],
        totalSize: serverContent.length,
      },
    });
    try {
      // Pre-populate the sync folder with a file that differs from the
      // server's version of the same relativePath, with an EMPTY state.db
      // (lastSeq=0) — the cold-start / resync / state-reset condition.
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, localOffline);
      assert.equal(stateDb.getLastSeq(), 0, 'precondition: empty cursor');

      await h.engine._initialSync();

      // The server bytes must land at the path...
      assert.equal(fs.readFileSync(filePath, 'utf8'), serverContent,
        'server content lands at the path');
      // ...and the original offline edit must be preserved as a conflict copy.
      const conflicts = fs.readdirSync(h.syncFolder).filter(n => n.includes('.conflict-'));
      assert.equal(conflicts.length, 1, 'a single conflict copy of the offline edit is preserved');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, conflicts[0]), 'utf8'), localOffline,
        'the conflict copy holds the original offline bytes, not the server bytes');

      const row = stateDb.getFile(rel);
      assert.equal(row.status, FILE_STATUS.SYNCED);
      assert.equal(row.localChecksum, serverChecksum);
    } finally {
      cleanup(h);
    }
  });

  it('initial sync with a matching local file does not create a conflict copy', async () => {
    const content = 'already-in-sync';
    const checksum = sha3(content);
    const rel = 'match.txt';
    const h = makeEngine({
      bundleMeta: {
        files: [{ id: 'srv-m', relativePath: rel, checksum, size: content.length, seq: 1 }],
        totalSize: content.length,
      },
    });
    try {
      fs.writeFileSync(path.join(h.syncFolder, rel), content);
      await h.engine._initialSync();

      const conflicts = fs.readdirSync(h.syncFolder).filter(n => n.includes('.conflict-'));
      assert.equal(conflicts.length, 0, 'a matching local file needs no conflict copy and no download');
      assert.equal(h.downloadLog.length, 0, 'no download for a checksum-matching local file');
      assert.equal(stateDb.getFile(rel).status, FILE_STATUS.SYNCED);
    } finally {
      cleanup(h);
    }
  });

});

describe('Local changes during the ERROR window recover on reconnect', { timeout: 30000 }, () => {

  it('a local change made while state===ERROR is re-detected by the reconnect rescan', async () => {
    const content = 'edited-while-control-channel-was-down';
    const checksum = sha3(content);
    const rel = 'errwindow.txt';
    const h = makeEngine({});
    try {
      // The control channel drops: state goes ERROR. A local edit fires while
      // ERROR — _onLocalChange's early return drops it, so it is NOT uploaded.
      h.engine._setState(SYNC_STATE.ERROR);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, content);
      await h.engine._onLocalChange({ type: 'change', relativePath: rel, fullPath: filePath, size: content.length, mtime: Date.now() });

      // The change was dropped — no row, nothing uploaded.
      assert.equal(stateDb.getFile(rel), undefined, 'the ERROR-window change is dropped, not tracked');
      assert.equal(h.uploadLog.length, 0, 'nothing uploaded while in ERROR');

      // Reconnect: the open handler enqueues a local rescan when the prior
      // state was ERROR/RECONNECTING. Model that recovery directly — the rescan
      // re-walks disk and re-detects the change against real state.
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      h.engine._enqueueLocalRescan();
      await h.engine._applyChain;
      for (let i = 0; i < 50 && !stateDb.getFile(rel); i++) await sleep(10);
      for (let i = 0; i < 50 && stateDb.getFile(rel) && stateDb.getFile(rel).status !== FILE_STATUS.SYNCED; i++) await sleep(10);

      const row = stateDb.getFile(rel);
      assert.ok(row, 'the rescan re-detected the missed change');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'the missed change uploaded and converged without a daemon restart');
      assert.equal(row.localChecksum, checksum);
      assert.equal(h.uploadLog.length, 1, 'the recovered change was uploaded exactly once');
      assert.equal(h.uploadLog[0].serverChecksum, checksum, 'the server received the edited bytes');
    } finally {
      cleanup(h);
    }
  });

});

describe('Remote delete racing an in-flight same-path download', { timeout: 30000 }, () => {

  it('file_removed during an in-flight download leaves a consistent DB + disk, no torn file', async () => {
    const content = 'downloaded-then-deleted';
    const checksum = sha3(content);
    const rel = 'racy.txt';
    const h = makeEngine({
      downloads: { 'fid-x': { content, delayMs: 80 } },
    });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);

      // Start a slow download for the path (file_added), then fire a
      // same-path file_removed while it is in flight. The apply chain
      // serializes same-path events, so the delete applies after the
      // download commits — and must act on a fully-written file, never a
      // partial one.
      h.engine._onServerMessage({ type: MSG.FILE_ADDED, fileId: 'fid-x', relativePath: rel, checksum, size: content.length, seq: 1 });
      await sleep(20); // let the download enter its delay
      h.engine._onServerMessage({ type: MSG.FILE_REMOVED, relativePath: rel, seq: 2 });

      await h.engine._applyChain;

      const filePath = path.join(h.syncFolder, rel);
      // No leftover temp from a torn download.
      const temps = fs.readdirSync(h.syncFolder).filter(n => /\.tmp\.[0-9a-f]+$/.test(n));
      assert.equal(temps.length, 0, 'no orphaned download temp left behind');
      // No half-written conflict copy.
      const conflicts = fs.readdirSync(h.syncFolder).filter(n => n.includes('.conflict-'));
      for (const c of conflicts) {
        const body = fs.readFileSync(path.join(h.syncFolder, c), 'utf8');
        assert.equal(body, content, 'any conflict copy holds the full downloaded bytes, never a partial');
      }
      // Final state is well-defined: the file was downloaded (unmodified vs the
      // server checksum), so the delete is uncontested and removes it cleanly.
      assert.ok(!fs.existsSync(filePath), 'the file is gone after the serialized delete');
      assert.equal(stateDb.getFile(rel), undefined, 'no orphaned DB row');
      assert.equal(stateDb.getLastSeq(), 2, 'cursor at the delete seq, both events applied in order');
    } finally {
      cleanup(h);
    }
  });

});
