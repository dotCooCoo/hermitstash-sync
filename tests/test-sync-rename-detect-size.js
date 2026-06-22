'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  sha3, createTempDir, rmrf,
} = require('./test-helpers');

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');
const SyncEngine = require(path.join(CLIENT_LIB, 'sync-engine'));
const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
const { FILE_STATUS, SYNC_STATE } = require(path.join(CLIENT_LIB, 'constants'));

/**
 * Rename-detection size-recovery test.
 *
 * Rename detection requires a numeric size to match a buffered delete by
 * checksum + size + locality. Some watcher backends deliver a change event
 * without a numeric `ev.size`; the engine must recover the size by stat'ing
 * the file so a move is still detected (rather than degrading to a server
 * delete + fresh re-upload) AND the persisted row records the real size.
 *
 * Drives the production engine directly with a stubbed rename endpoint. The
 * checksum flows through the production SHA3-512 path; no encryption involved.
 */

function makeEngine() {
  const root = createTempDir('rename-detect-size');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = { syncFolder, bundleId: 'bundle-test' };
  const engine = new SyncEngine(config, 'hs_test_key');

  engine._ws = { send: () => {}, updateSince: () => {}, close: () => {}, reloadMtlsCerts: () => {} };
  engine._ignorePatterns = [];
  engine._includePatterns = [];

  const renameLog = [];
  engine._http = {
    async renameFile(bundleId, oldPath, newPath) {
      renameLog.push({ oldPath, newPath });
      return { seq: 42 };
    },
    async deleteFile() { return true; },
    reloadMtlsCerts() {},
    destroy() {},
  };

  return { engine, root, syncFolder, dbFile, renameLog };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

describe('Rename detection recovers a missing watcher event size', { timeout: 30000 }, () => {

  it('detects a rename even when ev.size is undefined, and stores the real file size', async () => {
    const h = makeEngine();
    try {
      h.engine._setState(SYNC_STATE.SYNCED);

      const content = 'movable content with a real size';
      const checksum = sha3(content);
      const size = Buffer.byteLength(content);

      // A tracked SYNCED file under the old name, with a buffered delete for it
      // (as if the watcher saw the source vanish and buffered it for rename
      // detection).
      stateDb.upsertFile({
        relativePath: 'dir/old-name.txt',
        serverFileId: 'fid-rename',
        localChecksum: checksum,
        serverChecksum: checksum,
        size,
        serverSeq: 1,
        status: FILE_STATUS.SYNCED,
      });
      h.engine._pendingDeletes.set('dir/old-name.txt', {
        checksum,
        size,
        fileId: 'fid-rename',
        existing: stateDb.getFile('dir/old-name.txt'),
        timer: setTimeout(() => {}, 60000),
      });
      // unref so the placeholder timer never holds the loop open.
      const pending = h.engine._pendingDeletes.get('dir/old-name.txt');
      if (pending.timer.unref) pending.timer.unref();

      // The new file lands at a same-dir new name with the SAME content. Write
      // it to disk so the size-recovery stat can read the real size.
      const newRel = 'dir/new-name.txt';
      const newFull = path.join(h.syncFolder, newRel);
      fs.mkdirSync(path.dirname(newFull), { recursive: true });
      fs.writeFileSync(newFull, content);

      // Drive the modify with size=undefined — the case a watcher backend that
      // omits ev.size produces. Without size recovery, `undefined > 0` is false
      // and rename detection is skipped entirely.
      await h.engine._handleLocalModify(newRel, newFull, undefined, Date.now());

      // The rename endpoint must have been called (move detected), not a
      // delete + fresh upload.
      assert.equal(h.renameLog.length, 1, 'rename detected and routed to the rename endpoint');
      assert.equal(h.renameLog[0].oldPath, 'dir/old-name.txt');
      assert.equal(h.renameLog[0].newPath, newRel);

      // The DB row moved to the new path, and the stored size is the REAL file
      // size (recovered via stat), not null.
      assert.equal(stateDb.getFile('dir/old-name.txt'), undefined, 'old row removed');
      const row = stateDb.getFile(newRel);
      assert.ok(row, 'new row exists');
      assert.equal(row.status, FILE_STATUS.SYNCED);
      assert.equal(row.size, size, 'stored size is the real file size, recovered from stat');
      assert.equal(row.localChecksum, checksum);

      // The buffered delete was consumed by the rename, not left to fire.
      assert.equal(h.engine._pendingDeletes.has('dir/old-name.txt'), false,
        'the buffered delete was consumed by rename detection');
    } finally {
      cleanup(h);
    }
  });

});
