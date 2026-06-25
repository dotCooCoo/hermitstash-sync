'use strict';

// Regression: a case-only local rename on a case-folding filesystem must not
// self-deadlock the per-path mutex when the server rename fails and the engine
// falls back to delete-old + upload-new.
//
// _handleLocalRename runs inside newPath's per-path mutex (acquired by
// _handleLocalModify before it dispatched into rename detection). On a
// case-folding FS (_fsCaseFolds === true) oldPath and newPath fold to the SAME
// _suppKey, so the fallback's delete of oldPath would re-acquire the already-held
// (non-reentrant) mutex and hang the daemon forever. The fix runs the locked
// delete body directly when the keys collide. Drives the production engine — no
// reimplementation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { sha3, createTempDir, rmrf } = require('./test-helpers');

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');
const SyncEngine = require(path.join(CLIENT_LIB, 'sync-engine'));
const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
const { FILE_STATUS, SYNC_STATE } = require(path.join(CLIENT_LIB, 'constants'));

describe('case-only local rename does not deadlock the per-path mutex on a case-folding FS', { timeout: 15000 }, () => {
  it('resolves (does not hang) when the server rename fails and oldPath/newPath fold to one lock key', async () => {
    const root = createTempDir('rename-deadlock');
    const syncFolder = path.join(root, 'sync');
    const dbFile = path.join(root, 'state.db');
    fs.mkdirSync(path.join(syncFolder, 'd'), { recursive: true });
    stateDb.open(dbFile);
    try {
      const bytes = Buffer.from('case-only-rename-body');
      const cksum = sha3(bytes);
      // The new-case file exists on disk so the (stubbed) upload leg's caller can stat it.
      fs.writeFileSync(path.join(syncFolder, 'd', 'A.txt'), bytes);

      const engine = new SyncEngine({ syncFolder, bundleId: 'bundle-test' }, 'hs_test_key');
      engine._ws = { send: () => {}, updateSince: () => {}, close: () => {}, reloadMtlsCerts: () => {} };
      engine._ignorePatterns = [];
      engine._includePatterns = [];
      engine._state = SYNC_STATE.SYNCED;     // not a teardown state, so the fallback runs
      engine._fsCaseFolds = true;            // force the case-folding code path on any host

      let deleted = false;
      engine._http = {
        async renameFile() { throw new Error('server rename failed (simulated)'); },
        async deleteFile() { deleted = true; return true; },
        reloadMtlsCerts() {}, destroy() {},
      };
      // Isolate the test to the DELETE leg's locking — stub the upload leg to a no-op.
      engine._handleLocalModifyLocked = async () => {};

      const existing = {
        relativePath: 'd/a.txt', serverFileId: 'srv-1',
        localChecksum: cksum, serverChecksum: cksum, size: bytes.length,
        status: FILE_STATUS.SYNCED, serverSeq: 1,
      };
      stateDb.upsertFile(existing);
      const pending = { checksum: cksum, size: bytes.length, fileId: 'srv-1', existing };

      // Run the rename UNDER newPath's per-path lock — exactly as production does.
      const renameP = engine._withPathLock('d/A.txt', () =>
        engine._handleLocalRename('d/a.txt', 'd/A.txt', pending, cksum, bytes.length, Date.now()));

      const timeoutP = new Promise((_, rej) =>
        setTimeout(() => rej(new Error('DEADLOCK — _handleLocalRename did not resolve within 4s')), 4000));

      await Promise.race([renameP, timeoutP]);
      assert.equal(deleted, true, 'the fallback delete of the old path should have executed under the held lock');
    } finally {
      try { stateDb.close(); } catch { /* best-effort */ }
      rmrf(root);
    }
  });
});
