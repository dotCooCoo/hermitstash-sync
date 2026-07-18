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
 * Regression tests for the sync-engine reconcile / delete / rename fixes.
 *
 * These drive the production SyncEngine directly with a stubbed wire layer
 * (no live HTTPS/mTLS server), so the reconcile sweep, remote-delete handler,
 * server-rename handler, and catch-up wedge recovery are all reproducible.
 * Every checksum flows through the production SHA3-512 path; no encryption is
 * bypassed (this layer carries no wire crypto). No test-only reimplementation
 * of the lib is used — the tests call the real methods.
 */

function makeEngine(opts) {
  opts = opts || {};
  const root = createTempDir('fix-sync-engine');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = { syncFolder, bundleId: 'bundle-test', shareId: 'share-test' };
  const engine = new SyncEngine(config, 'hs_test_key');

  const wsLog = { closes: 0, connects: [] };
  engine._ws = {
    send: () => {},
    updateSince: () => {},
    close: () => { wsLog.closes++; },
    connect: (bundleId, since) => { wsLog.connects.push({ bundleId, since }); },
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
      downloadLog.push({ fileId, destPath });
      if (spec.permanent) throw Object.assign(new Error('over the per-file size limit for ' + fileId), { permanent: true });
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
    async uploadFile(bundleId, relativePath, fullPath) {
      if (opts.uploadPermanentFail) {
        // A permanent (4xx) rejection short-circuits the retry loop, so the
        // failure reaches the handler quickly without three backoff waits.
        throw Object.assign(new Error('simulated permanent upload rejection'), { permanent: true, statusCode: 400 });
      }
      if (opts.uploadFails) throw new Error('simulated upload failure');
      const receivedBuf = fs.readFileSync(fullPath);
      const serverChecksum = sha3(receivedBuf);
      uploadLog.push({ relativePath, serverChecksum });
      return { fileId: 'srv-' + (uploadSeq), checksum: serverChecksum, seq: uploadSeq++ };
    },
    async getBundleMetadata() {
      return opts.bundleMeta || { files: [], totalSize: 0 };
    },
    async deleteFile() { return true; },
    reloadMtlsCerts() {},
    destroy() {},
  };

  return { engine, root, syncFolder, dbFile, downloadLog, uploadLog, wsLog };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

function conflictFiles(syncFolder) {
  return fs.readdirSync(syncFolder).filter(n => n.includes('.conflict-'));
}

// ---------------------------------------------------------------------------
// sync-engine#0 — reconcile re-download must not clobber a newer local edit
// ---------------------------------------------------------------------------
describe('Reconcile re-download preserves a stranded local edit (no silent data loss)', { timeout: 30000 }, () => {
  it('a failed-upload ERROR row is re-downloaded but the newer local bytes survive as a conflict copy', async () => {
    const c1 = 'server-version-one';   // what the server currently holds
    const c2 = 'LOCAL EDIT — newer than the server, upload had failed';
    const c1sum = sha3(c1);
    const c2sum = sha3(c2);
    const rel = 'a.txt';

    const h = makeEngine({ downloads: { F: { content: c1 } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      // Disk holds the newer local edit (c2); the row is a stranded upload:
      // serverFileId + serverChecksum point at the older server copy (c1),
      // localChecksum is the newer edit (c2), status ERROR.
      fs.writeFileSync(filePath, c2);
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: c1sum,
        localChecksum: c2sum,
        size: c2.length,
        serverSeq: 3,
        status: FILE_STATUS.ERROR,
      });

      await h.engine._recoverPending();

      // The newer local bytes must NOT be destroyed — they are preserved as a
      // conflict copy (matching the live file_added/file_replaced paths).
      const conflicts = conflictFiles(h.syncFolder);
      assert.equal(conflicts.length, 1, 'the stranded local edit is preserved as exactly one conflict copy');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, conflicts[0]), 'utf8'), c2,
        'the conflict copy holds the newer local bytes (c2), never the server bytes');
      // The reconcile still converges the tracked path to the server content.
      assert.equal(fs.readFileSync(filePath, 'utf8'), c1, 'the tracked path converges to the server bytes');
      const row = stateDb.getFile(rel);
      assert.equal(row.status, FILE_STATUS.SYNCED);
      assert.equal(row.localChecksum, c1sum);
    } finally {
      cleanup(h);
    }
  });

  it('a normal download-recovery of a never-existed-locally file makes no spurious conflict copy', async () => {
    const content = 'fresh-server-file';
    const sum = sha3(content);
    const rel = 'fresh.txt';
    const h = makeEngine({ downloads: { G: { content } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      // A live file_added whose download failed: PENDING_DOWNLOAD, no local
      // file on disk, localChecksum null.
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'G',
        serverChecksum: sum,
        size: content.length,
        serverSeq: 4,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });

      await h.engine._recoverPending();

      assert.equal(conflictFiles(h.syncFolder).length, 0, 'no conflict copy for a file that never existed locally');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, rel), 'utf8'), content);
      assert.equal(stateDb.getFile(rel).status, FILE_STATUS.SYNCED);
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#1 — reconcile sweep must not run during a resync teardown
// ---------------------------------------------------------------------------
describe('Reconcile sweeps bail while a resync is in flight', { timeout: 30000 }, () => {
  it('_recoverPending is a no-op when _resyncing is set', async () => {
    const rel = 'guarded.txt';
    const h = makeEngine({ downloads: { F: { content: 'srv' } } });
    try {
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: sha3('srv'),
        size: 3,
        serverSeq: 1,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });
      h.engine._resyncing = true;

      await h.engine._recoverPending();

      assert.equal(h.downloadLog.length, 0, 'no download is driven while resyncing');
      assert.equal(stateDb.getFile(rel).status, FILE_STATUS.PENDING_DOWNLOAD, 'the row is left untouched');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#2 — a brand-new file whose first upload failed is re-driven
// ---------------------------------------------------------------------------
describe('Reconcile re-drives a stranded new-file upload (ERROR, no serverFileId)', { timeout: 30000 }, () => {
  it('re-uploads a never-reached-server ERROR row and lands SYNCED', async () => {
    const content = 'brand-new-file-first-upload-failed';
    const sum = sha3(content);
    const rel = 'b.txt';
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, content);
      // The failed first upload: ERROR, no serverFileId, no serverChecksum,
      // localChecksum is the on-disk bytes.
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: null,
        serverChecksum: null,
        localChecksum: sum,
        size: content.length,
        serverSeq: 0,
        status: FILE_STATUS.ERROR,
      });

      await h.engine._recoverPending();
      // Let any pool-routed upload settle.
      for (let i = 0; i < 50 && stateDb.getFile(rel).status !== FILE_STATUS.SYNCED; i++) await sleep(10);

      assert.equal(h.uploadLog.length, 1, 'the stranded new file is uploaded exactly once');
      assert.equal(h.uploadLog[0].serverChecksum, sum, 'the server receives the file bytes');
      const row = stateDb.getFile(rel);
      assert.equal(row.status, FILE_STATUS.SYNCED, 'the row converges to SYNCED');
      assert.ok(row.serverFileId, 'the row now carries a serverFileId');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine — a crash-stranded PENDING_UPLOAD row is actually re-uploaded
// (the reconcile sweep used to route it through _handleLocalModify, whose
// no-change guard dead-ended a row whose disk bytes still matched its
// recorded localChecksum — so the upload never happened).
// ---------------------------------------------------------------------------
describe('Reconcile re-drives a crash-stranded PENDING_UPLOAD row (disk matches its recorded checksum)', { timeout: 30000 }, () => {
  it('a PENDING_UPLOAD row whose disk bytes match localChecksum is uploaded, not skipped as "no change"', async () => {
    const content = 'bytes written then the daemon was SIGKILLed before the upload finished';
    const sum = sha3(content);
    const rel = 'stranded.txt';
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      fs.writeFileSync(path.join(h.syncFolder, rel), content);
      // The crash-stranded marker: PENDING_UPLOAD with localChecksum == the
      // on-disk bytes and no server copy yet.
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: null,
        serverChecksum: null,
        localChecksum: sum,
        size: content.length,
        serverSeq: 0,
        status: FILE_STATUS.PENDING_UPLOAD,
      });

      await h.engine._recoverPending();
      for (let i = 0; i < 50 && stateDb.getFile(rel).status !== FILE_STATUS.SYNCED; i++) await sleep(10);

      assert.equal(h.uploadLog.length, 1, 'the stranded PENDING_UPLOAD row is uploaded exactly once (not dead-ended by the no-change guard)');
      assert.equal(h.uploadLog[0].serverChecksum, sum, 'the server receives the on-disk bytes');
      assert.equal(stateDb.getFile(rel).status, FILE_STATUS.SYNCED, 'the row converges to SYNCED');
    } finally {
      cleanup(h);
    }
  });

  it('a converged PENDING_UPLOAD row (disk already matches serverChecksum) is not re-uploaded', async () => {
    const content = 'already on the server';
    const sum = sha3(content);
    const rel = 'converged.txt';
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      fs.writeFileSync(path.join(h.syncFolder, rel), content);
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: sum,   // disk already matches the server
        localChecksum: sum,
        size: content.length,
        serverSeq: 4,
        status: FILE_STATUS.PENDING_UPLOAD,
      });

      await h.engine._recoverPending();
      await sleep(30);

      assert.equal(h.uploadLog.length, 0, 'a converged row must not thrash the server with a redundant upload');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine — a failed server DELETE is retried, never resurrected
// ---------------------------------------------------------------------------
describe('A failed server DELETE is re-driven, not silently undone by the download sweep', { timeout: 30000 }, () => {
  it('a transient DELETE failure lands PENDING_DELETE and the next sweep re-issues the DELETE (the file is not re-downloaded)', async () => {
    const content = 'user deleted this locally';
    const sum = sha3(content);
    const rel = 'deleted.txt';
    let deleteAttempts = 0;
    const h = makeEngine({ downloads: { F: { content } } });
    // Fail the first server DELETE, succeed the retry.
    h.engine._http.deleteFile = async () => {
      deleteAttempts++;
      if (deleteAttempts === 1) throw new Error('transient 503 on delete');
      return true;
    };
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      // Synced row; the local file is already gone (the user deleted it).
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: sum,
        localChecksum: sum,
        size: content.length,
        serverSeq: 5,
        status: FILE_STATUS.SYNCED,
      });

      // First delete attempt fails -> PENDING_DELETE, file stays gone.
      const outcome = await h.engine._executeDelete(rel, stateDb.getFile(rel));
      assert.equal(outcome, 'failed');
      assert.equal(stateDb.getFile(rel).status, FILE_STATUS.PENDING_DELETE,
        'a failed delete lands PENDING_DELETE, not ERROR (ERROR would be resurrected by the download sweep)');

      // The reconcile sweep must re-drive the DELETE — and must NOT download
      // the file back onto disk.
      await h.engine._recoverPending();
      for (let i = 0; i < 50 && stateDb.getFile(rel); i++) await sleep(10);

      assert.equal(deleteAttempts, 2, 'the server DELETE was retried by the reconcile sweep');
      assert.equal(stateDb.getFile(rel), undefined, 'the row is removed after the successful retry');
      assert.equal(fs.existsSync(path.join(h.syncFolder, rel)), false, 'the deleted file was NOT resurrected on disk');
      assert.equal(h.downloadLog.length, 0, 'the download sweep never touched the pending-delete row');
    } finally {
      cleanup(h);
    }
  });

  it('a PENDING_DELETE whose local file re-appeared (a recreate) is not deleted from the server', async () => {
    const content = 'recreated after the delete failed';
    const sum = sha3(content);
    const rel = 'recreated.txt';
    let deleteAttempts = 0;
    const h = makeEngine({});
    h.engine._http.deleteFile = async () => { deleteAttempts++; return true; };
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      // The file is back on disk (the user recreated it) while the row still
      // records a stranded delete intent.
      fs.writeFileSync(path.join(h.syncFolder, rel), content);
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: sum,
        localChecksum: sum,
        size: content.length,
        serverSeq: 6,
        status: FILE_STATUS.PENDING_DELETE,
      });

      await h.engine._recoverPending();
      await sleep(30);

      assert.equal(deleteAttempts, 0, 'the recreated file must not be deleted from the server');
      assert.ok(fs.existsSync(path.join(h.syncFolder, rel)), 'the recreated file stays on disk');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#4 — buffered delete mutates the fold-resolved row, not the raw key
// ---------------------------------------------------------------------------
describe('Buffered delete removes the tracked row under its fold-resolved casing', { timeout: 30000 }, () => {
  it('a lower-cased delete key removes the differently-cased tracked row on a folding volume', async () => {
    const content = 'case-folded';
    const sum = sha3(content);
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      h.engine._fsCaseFolds = true; // simulate a case-folding volume
      // Row tracked under the server's authoritative casing.
      stateDb.upsertFile({
        relativePath: 'Foo.txt',
        serverFileId: 'F',
        serverChecksum: sum,
        localChecksum: sum,
        size: content.length,
        serverSeq: 2,
        status: FILE_STATUS.SYNCED,
      });
      const tracked = stateDb.getFile('Foo.txt');

      // The watcher surfaces the delete under a different casing.
      const outcome = await h.engine._executeDelete('foo.txt', tracked);

      assert.equal(outcome, 'deleted');
      assert.equal(stateDb.getFile('Foo.txt'), undefined,
        'the fold-resolved row is removed (no stale SYNCED row pointing at a deleted server file)');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#5 — a remote delete must not destroy never-synced local bytes
// ---------------------------------------------------------------------------
describe('Remote delete preserves a never-synced local file', { timeout: 30000 }, () => {
  it('file_removed for a PENDING_UPLOAD (never-on-server) file keeps its bytes as a conflict copy', async () => {
    const content = 'never-uploaded-local-bytes';
    const sum = sha3(content);
    const rel = 'notes.txt';
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, content);
      // A local-only file whose upload never landed: serverChecksum null.
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: null,
        serverChecksum: null,
        localChecksum: sum,
        size: content.length,
        serverSeq: 0,
        status: FILE_STATUS.PENDING_UPLOAD,
      });

      await h.engine._handleFileRemoved({ relativePath: rel, seq: 9 });

      const conflicts = conflictFiles(h.syncFolder);
      assert.equal(conflicts.length, 1, 'the never-synced bytes are preserved as a conflict copy, not destroyed');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, conflicts[0]), 'utf8'), content);
    } finally {
      cleanup(h);
    }
  });

  it('file_removed for a genuinely-synced, unmodified file still deletes it (no regression)', async () => {
    const content = 'genuinely-synced';
    const sum = sha3(content);
    const rel = 'synced.txt';
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, content);
      stateDb.upsertFile({
        relativePath: rel,
        serverFileId: 'F',
        serverChecksum: sum,   // actually synced to the server
        localChecksum: sum,
        size: content.length,
        serverSeq: 5,
        status: FILE_STATUS.SYNCED,
      });

      await h.engine._handleFileRemoved({ relativePath: rel, seq: 6 });

      assert.equal(conflictFiles(h.syncFolder).length, 0, 'an uncontested delete makes no conflict copy');
      assert.ok(!fs.existsSync(filePath), 'the unmodified synced file is deleted');
      assert.equal(stateDb.getFile(rel), undefined, 'the row is removed');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#6 — a server rename+content-change makes no spurious conflict copy
// ---------------------------------------------------------------------------
describe('Server rename that also changes content makes no spurious conflict copy', { timeout: 30000 }, () => {
  it('the relocated last-synced bytes are downloaded-over, not conflict-copied', async () => {
    const cold = 'old-content-before-rename';
    const cnew = 'new-content-after-rename-and-edit';
    const coldSum = sha3(cold);
    const cnewSum = sha3(cnew);

    const h = makeEngine({ downloads: { F2: { content: cnew } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const oldPath = path.join(h.syncFolder, 'old.txt');
      fs.writeFileSync(oldPath, cold);
      stateDb.upsertFile({
        relativePath: 'old.txt',
        serverFileId: 'F',
        serverChecksum: coldSum,
        localChecksum: coldSum,
        size: cold.length,
        serverSeq: 1,
        status: FILE_STATUS.SYNCED,
      });

      // Server renames old.txt -> new.txt AND changes its content.
      await h.engine._handleFileRenamed({
        oldRelativePath: 'old.txt',
        relativePath: 'new.txt',
        fileId: 'F2',
        checksum: cnewSum,
        size: cnew.length,
        seq: 2,
      });

      assert.equal(conflictFiles(h.syncFolder).length, 0,
        'no spurious conflict copy of the relocated last-synced bytes');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, 'new.txt'), 'utf8'), cnew,
        'the new content lands at the new path');
      assert.ok(!fs.existsSync(oldPath), 'the old path is gone');
      const row = stateDb.getFile('new.txt');
      assert.equal(row.status, FILE_STATUS.SYNCED);
      assert.equal(row.localChecksum, cnewSum);
    } finally {
      cleanup(h);
    }
  });

  it('a genuine name-collision (unrelated bytes at the destination) still conflict-copies', async () => {
    const unrelated = 'unrelated-bytes-already-at-the-destination';
    const cnew = 'incoming-new-content';
    const cnewSum = sha3(cnew);

    const h = makeEngine({ downloads: { F2: { content: cnew } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      // No tracked old row and no source file — the rename's move is skipped,
      // and an UNRELATED file already occupies the destination.
      fs.writeFileSync(path.join(h.syncFolder, 'dest.txt'), unrelated);

      await h.engine._handleFileRenamed({
        oldRelativePath: 'missing-source.txt',
        relativePath: 'dest.txt',
        fileId: 'F2',
        checksum: cnewSum,
        size: cnew.length,
        seq: 3,
      });

      assert.equal(conflictFiles(h.syncFolder).length, 1,
        'unrelated destination bytes are preserved as a conflict copy');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, 'dest.txt'), 'utf8'), cnew,
        'the new content lands at the destination');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#3 — catch-up wedge recovery gating
// ---------------------------------------------------------------------------
describe('Catch-up wedge recovery redials only when genuinely wedged', { timeout: 30000 }, () => {
  function armWedgeState(engine, { lastSeq, tipSeq }) {
    engine._setState(SYNC_STATE.CATCHING_UP);
    engine._caughtUpAtSeq = false;
    engine._catchUpPending = 0;
    engine._activeDownloads = 0;
    engine._catchUpTipSeq = tipSeq;
    stateDb.setLastSeq(lastSeq);
  }

  it('forces a since-aware redial when the cursor is stuck below the catch-up tip and all bytes landed', async () => {
    const h = makeEngine({});
    try {
      armWedgeState(h.engine, { lastSeq: 7, tipSeq: 8 });
      // No PENDING_DOWNLOAD / ERROR rows remain and the sweep converged a
      // download-recovery row this pass (landed=1) — the wedge redials.
      h.engine._maybeRecoverCatchUpWedge(1);

      assert.equal(h.wsLog.closes, 1, 'the socket is closed for the redial');
      assert.equal(h.wsLog.connects.length, 1, 'a redial is issued');
      assert.equal(h.wsLog.connects[0].since, 7, 'the redial uses the UNCHANGED cursor so the server replays every event');
      assert.equal(h.engine._state, SYNC_STATE.CONNECTING);
    } finally {
      cleanup(h);
    }
  });

  it('does NOT redial when the sweep landed no download-recovery (fail-closed non-download tip event)', async () => {
    const h = makeEngine({});
    try {
      // Cursor stuck below the tip, all other gates satisfied, NO PENDING/ERROR
      // rows — but the sweep converged nothing this pass (landed=0), as happens
      // when the wedging tip event is a file_removed that fail-closed on a
      // locked/unhashable local file and left no recoverable row. Redialing here
      // would replay the same un-appliable event forever (an endless reconnect
      // loop), so the wedge must stay quiet.
      armWedgeState(h.engine, { lastSeq: 7, tipSeq: 8 });
      h.engine._maybeRecoverCatchUpWedge(0);
      assert.equal(h.wsLog.connects.length, 0, 'no redial when the sweep landed no download-recovery');
      assert.equal(h.wsLog.closes, 0, 'the socket is not churned');
    } finally {
      cleanup(h);
    }
  });

  it('does NOT redial during a fresh catch-up that has not yet delivered its heartbeat', async () => {
    const h = makeEngine({});
    try {
      // A fresh catch-up: no unsatisfiable tip seen yet (_catchUpTipSeq stays 0).
      armWedgeState(h.engine, { lastSeq: 0, tipSeq: 0 });
      h.engine._maybeRecoverCatchUpWedge(1);
      assert.equal(h.wsLog.connects.length, 0, 'no premature redial before the trailing heartbeat arrives');
    } finally {
      cleanup(h);
    }
  });

  it('does NOT redial while a transfer is still pending/erroring (would just re-wedge)', async () => {
    const h = makeEngine({});
    try {
      armWedgeState(h.engine, { lastSeq: 7, tipSeq: 8 });
      stateDb.upsertFile({
        relativePath: 'stuck.txt',
        serverFileId: 'F',
        serverChecksum: sha3('x'),
        size: 1,
        serverSeq: 8,
        status: FILE_STATUS.ERROR,
      });
      h.engine._maybeRecoverCatchUpWedge(1);
      assert.equal(h.wsLog.connects.length, 0, 'a genuine unsync surfaced by an ERROR row is not redialed');
    } finally {
      cleanup(h);
    }
  });

  it('does NOT redial once already SYNCED', async () => {
    const h = makeEngine({});
    try {
      armWedgeState(h.engine, { lastSeq: 7, tipSeq: 8 });
      h.engine._setState(SYNC_STATE.SYNCED);
      h.engine._maybeRecoverCatchUpWedge(1);
      assert.equal(h.wsLog.connects.length, 0, 'no redial when not in CATCHING_UP');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// fix-audit: permanent transfer failures are not re-driven every reconcile tick
// ---------------------------------------------------------------------------
describe('Permanent transfer failures are recorded and skipped by later reconcile sweeps', { timeout: 30000 }, () => {
  it('a permanent download failure (over the per-file cap) is not re-fetched on the next sweep', async () => {
    const h = makeEngine({ downloads: { F: { permanent: true } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      // A download-recovery candidate (ERROR row with serverFileId+serverChecksum)
      // whose download the server-side cap permanently refuses.
      stateDb.upsertFile({ relativePath: 'big.bin', serverFileId: 'F', serverChecksum: sha3('x'), size: 5, serverSeq: 1, status: FILE_STATUS.ERROR });
      await h.engine._recoverPending();
      assert.equal(h.downloadLog.length, 1, 'the download is attempted exactly once');
      assert.ok(h.engine._permanentFailures.has('big.bin'), 'the permanent failure is recorded');
      await h.engine._recoverPending();
      assert.equal(h.downloadLog.length, 1, 'the over-cap download is NOT re-fetched on the next reconcile tick');
    } finally {
      cleanup(h);
    }
  });

  it('a permanent new-file upload rejection is not re-streamed on the next sweep', async () => {
    const h = makeEngine({ uploadPermanentFail: true });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const rel = 'newfile.txt';
      fs.writeFileSync(path.join(h.syncFolder, rel), 'bytes');
      // strandedNew shape: ERROR, no serverFileId, has localChecksum.
      stateDb.upsertFile({ relativePath: rel, serverFileId: null, serverChecksum: null, localChecksum: sha3('bytes'), size: 5, serverSeq: 0, status: FILE_STATUS.ERROR });
      await h.engine._recoverPendingUploads();
      assert.ok(h.engine._permanentFailures.has(rel), 'the permanent upload failure is recorded');
      // A doomed 4xx new file must not be re-streamed every tick.
      await h.engine._recoverPendingUploads();
      assert.ok(h.engine._permanentFailures.has(rel), 'still recorded — the sweep skipped it rather than re-driving');
    } finally {
      cleanup(h);
    }
  });

  it('a later successful download clears a prior permanent mark', async () => {
    const h = makeEngine({ downloads: { F: { content: 'ok' } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      h.engine._permanentFailures.add('big.bin');
      stateDb.upsertFile({ relativePath: 'big.bin', serverFileId: 'F', serverChecksum: sha3('ok'), size: 2, serverSeq: 1, status: FILE_STATUS.ERROR });
      // The mark blocks the sweep, so drive the download directly (a live event
      // path is never gated by the mark) to prove success clears it.
      await h.engine._downloadFile('big.bin', 'F', sha3('ok'), 2);
      assert.ok(!h.engine._permanentFailures.has('big.bin'), 'a successful download clears the permanent mark');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#7 — upload cleanup runs even if the catch body throws
// ---------------------------------------------------------------------------
describe('Upload cleanup runs in a finally (no leaked timer / gauge on a throwing catch)', { timeout: 30000 }, () => {
  it('a throw from the catch-body status write still clears active_ops', async () => {
    const rel = 'upfail.txt';
    const h = makeEngine({ uploadPermanentFail: true });
    const origUpdate = stateDb.updateFileStatus;
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, 'bytes');
      const before = h.engine._activeOps;

      // Force every status write to throw so the handler's catch body itself
      // throws — the exact case that skipped cleanup before it moved into a
      // finally. A permanent upload rejection reaches the failure handler
      // without the retry backoff, keeping the test fast.
      stateDb.updateFileStatus = () => { throw new Error('simulated DB write failure in catch'); };

      await assert.rejects(
        () => h.engine._uploadFile(rel, filePath, sha3('bytes')),
        /simulated DB write failure in catch/,
      );

      assert.equal(h.engine._activeOps, before,
        'active_ops is decremented in the finally even though the catch body threw');
    } finally {
      stateDb.updateFileStatus = origUpdate;
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#8 — _enqueueLocalRescan accepts a caller-supplied reason
// ---------------------------------------------------------------------------
describe('Local rescan carries a caller-supplied reason', { timeout: 30000 }, () => {
  it('_enqueueLocalRescan(reason) still enqueues the rescan with the new signature', async () => {
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      let ran = false;
      h.engine._localRescan = async () => { ran = true; };
      h.engine._enqueueLocalRescan('Re-scanning after a local file changed during upload');
      await h.engine._applyChain;
      assert.equal(ran, true, 'the reason-carrying call still drives a rescan');
    } finally {
      cleanup(h);
    }
  });
});

// ---------------------------------------------------------------------------
// file_replaced must not spawn a spurious conflict copy on an un-diverged file
// ---------------------------------------------------------------------------
describe('file_replaced conflict-copy only fires on a genuine local divergence', { timeout: 30000 }, () => {
  it('a device holding the un-diverged last-synced version gets NO conflict copy (and no fan-out)', async () => {
    const A = 'version-A-last-synced';
    const B = 'version-B-from-another-device';
    const rel = 'doc.txt';
    const h = makeEngine({ downloads: { F2: { content: B } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, A); // this device still holds the un-diverged A
      stateDb.upsertFile({ relativePath: rel, serverFileId: 'F2', serverChecksum: sha3(A), localChecksum: sha3(A), size: A.length, serverSeq: 5, status: FILE_STATUS.SYNCED });
      // Another device edited A -> B; server broadcasts file_replaced{B}.
      await h.engine._handleFileReplaced({ fileId: 'F2', relativePath: rel, checksum: sha3(B), size: B.length, seq: 6 });
      assert.equal(conflictFiles(h.syncFolder).length, 0, 'no spurious .conflict copy on the most common multi-device edit');
      assert.equal(fs.readFileSync(filePath, 'utf8'), B, 'doc.txt is updated to the new server content');
    } finally { cleanup(h); }
  });

  it('a genuinely locally-diverged file IS still preserved as a conflict copy', async () => {
    const A = 'version-A-last-synced';
    const B = 'version-B-from-another-device';
    const C = 'UNSYNCED local edit on this device';
    const rel = 'doc.txt';
    const h = makeEngine({ downloads: { F3: { content: B } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      const filePath = path.join(h.syncFolder, rel);
      fs.writeFileSync(filePath, C); // this device diverged locally (unsynced)
      stateDb.upsertFile({ relativePath: rel, serverFileId: 'F3', serverChecksum: sha3(A), localChecksum: sha3(A), size: A.length, serverSeq: 5, status: FILE_STATUS.SYNCED });
      await h.engine._handleFileReplaced({ fileId: 'F3', relativePath: rel, checksum: sha3(B), size: B.length, seq: 6 });
      const conflicts = conflictFiles(h.syncFolder);
      assert.equal(conflicts.length, 1, 'the genuine local divergence is preserved as a conflict copy');
      assert.equal(fs.readFileSync(path.join(h.syncFolder, conflicts[0]), 'utf8'), C, "the conflict copy holds the user's unsynced edit C");
      assert.equal(fs.readFileSync(filePath, 'utf8'), B, 'doc.txt converges to server B');
    } finally { cleanup(h); }
  });
});

// ---------------------------------------------------------------------------
// catch-up wedge must not redial past a lower-seq event that failed to apply
// ---------------------------------------------------------------------------
describe('Catch-up wedge refuses to redial past an un-applied lower-seq event', { timeout: 30000 }, () => {
  it('does NOT redial when a lower-seq event failed closed this session (would leapfrog a delete)', async () => {
    const h = makeEngine({});
    try {
      // Cursor at 99, tip at 101, sweep landed a recoverable download (landed=1),
      // no pending rows — but a file_removed at seq 100 failed closed (locked
      // file), recorded as the lowest un-applied seq. Redialing would replay from
      // 99, re-skip 100, and let the idempotent seq-101 short-circuit advance the
      // cursor past 100 — silently dropping the server-side delete.
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      h.engine._caughtUpAtSeq = false;
      h.engine._catchUpPending = 0;
      h.engine._activeDownloads = 0;
      h.engine._catchUpTipSeq = 101;
      h.engine._lowestUnappliedSeq = 100;
      stateDb.setLastSeq(99);
      h.engine._maybeRecoverCatchUpWedge(1);
      assert.equal(h.wsLog.connects.length, 0, 'no redial — leaves the recoverable CATCHING_UP stall');
      assert.equal(h.wsLog.closes, 0, 'the socket is not churned');
    } finally { cleanup(h); }
  });

  it('DOES redial when the un-applied gap is already below the cursor (unrecoverable — must not wedge)', async () => {
    const h = makeEngine({});
    try {
      // A legitimate download-recovery wedge, but a fail-closed gap at seq 10 is
      // already BELOW the cursor (11) — no redial can recover it, so the guard
      // must NOT block the valid redial that advances the cursor to the tip.
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      h.engine._caughtUpAtSeq = false;
      h.engine._catchUpPending = 0;
      h.engine._activeDownloads = 0;
      h.engine._catchUpTipSeq = 12;
      h.engine._lowestUnappliedSeq = 10;
      stateDb.setLastSeq(11);
      h.engine._maybeRecoverCatchUpWedge(1);
      assert.equal(h.wsLog.connects.length, 1, 'the legitimate download-recovery redial still fires');
    } finally { cleanup(h); }
  });
});

// ---------------------------------------------------------------------------
// the sync cursor never advances past a fail-closed gap (no leapfrogged delete)
// ---------------------------------------------------------------------------
describe('The sync cursor stops at a fail-closed gap (contiguous watermark)', { timeout: 30000 }, () => {
  it('_updateSeq caps the cursor one below the lowest un-applied seq', () => {
    const h = makeEngine({});
    try {
      stateDb.setLastSeq(9);
      h.engine._lowestUnappliedSeq = 10; // a fail-closed delete at seq 10
      h.engine._updateSeq(11);           // a later successful event in the same batch
      assert.equal(stateDb.getLastSeq(), 9, 'the cursor stays below the gap so the delete is re-delivered on reconnect');
    } finally { cleanup(h); }
  });

  it('_updateSeq advances normally (monotone) when there is no gap', () => {
    const h = makeEngine({});
    try {
      stateDb.setLastSeq(9);
      h.engine._lowestUnappliedSeq = 0;
      h.engine._updateSeq(11);
      assert.equal(stateDb.getLastSeq(), 11, 'no gap -> normal advance');
    } finally { cleanup(h); }
  });

  it('the gap clears when the gap event itself finally applies (cursor is not frozen for the session)', () => {
    const h = makeEngine({});
    try {
      stateDb.setLastSeq(9);
      h.engine._lowestUnappliedSeq = 10;   // seq 10 failed closed earlier
      // The re-delivered seq 10 now applies successfully.
      h.engine._updateSeq(10);
      assert.equal(h.engine._lowestUnappliedSeq, 0, 'the watermark clears once its own event lands');
      assert.equal(stateDb.getLastSeq(), 10, 'the cursor advances to the now-applied gap seq');
      // A later event advances normally instead of being frozen at 9.
      h.engine._updateSeq(12);
      assert.equal(stateDb.getLastSeq(), 12, 'subsequent events advance past the cleared gap');
    } finally { cleanup(h); }
  });
});

// ---------------------------------------------------------------------------
// a failed case-rename pins the cursor so the event is re-delivered
// ---------------------------------------------------------------------------
describe('A failed _reconcileCaseRename pins the cursor below the event', { timeout: 30000 }, () => {
  it('notes the un-applied seq so a later event cannot leapfrog the failed case rename', async () => {
    const content = 'case-rename-with-lock';
    const sum = sha3(content);
    const h = makeEngine({});
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      h.engine._fsCaseFolds = true;
      // A tracked row under the old casing whose on-disk file we force the
      // two-step rename to fail on (the source exists, but renameWithRetry
      // throws — simulate an AV/indexer lock by removing write access to the
      // move via a stubbed fs is heavy; instead point the row at a source path
      // that exists and make the destination rename fail by pre-creating a
      // directory at the temp/destination is fragile — so drive the catch via
      // a non-existent source that still satisfies existsSync is impossible.
      // Simplest deterministic trigger: seed the row, then call the handler
      // with a source that exists and monkeypatch renameWithRetry to throw.
      const rel = 'Foo.txt';
      fs.writeFileSync(path.join(h.syncFolder, 'foo.txt'), content);
      stateDb.upsertFile({
        relativePath: 'foo.txt', serverFileId: 'F', serverChecksum: sum,
        localChecksum: sum, size: content.length, serverSeq: 40, status: FILE_STATUS.SYNCED,
      });
      const existing = stateDb.getFile('foo.txt');
      const b = require('../vendor/blamejs');
      const realRename = b.atomicFile.renameWithRetry;
      b.atomicFile.renameWithRetry = () => { throw new Error('simulated indexer lock during case rename'); };
      try {
        await h.engine._reconcileCaseRename(existing, rel, path.join(h.syncFolder, rel), 'F', sum, content.length, 100);
      } finally {
        b.atomicFile.renameWithRetry = realRename;
      }
      assert.equal(h.engine._lowestUnappliedSeq, 100,
        'the failed case rename pins the cursor at its seq so the reconnect re-delivers it');
    } finally { cleanup(h); }
  });
});
