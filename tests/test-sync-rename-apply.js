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
const { FILE_STATUS } = require(path.join(CLIENT_LIB, 'constants'));

/**
 * Server-driven file_renamed apply tests.
 *
 * These exercise the production SyncEngine._handleFileRenamed apply path
 * directly — the inbound (server -> client) rename direction, which is the
 * data-integrity surface that gates SYNCED on `moved` (did WE relocate the
 * source), `landed` (the move actually produced a file at the new path),
 * `bytesMatch` (the moved bytes match the server's content), and the
 * delete-old + re-download-new recovery fallback when the rename did NOT
 * produce a verified SYNCED file.
 *
 * The wire layer is stubbed (download + bundle metadata) so the move /
 * recovery branches are deterministic. Checksums flow through the production
 * SHA3-512 path. No encryption is bypassed — this layer has no wire crypto.
 */

function makeEngine(opts) {
  opts = opts || {};
  const root = createTempDir('rename-apply');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = { syncFolder, bundleId: 'bundle-test' };
  const engine = new SyncEngine(config, 'hs_test_key');

  engine._ws = {
    send: () => {},
    updateSince: () => {},
    close: () => {},
    reloadMtlsCerts: () => {},
  };
  engine._ignorePatterns = [];
  engine._includePatterns = [];

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

  return { engine, root, syncFolder, dbFile, downloadLog, downloads };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

describe('Server-driven file_renamed apply', { timeout: 30000 }, () => {

  it('pure rename of a tracked SYNCED file moves on disk, swaps the row, advances seq', async () => {
    const h = makeEngine({});
    try {
      const content = 'renamed-bytes';
      const checksum = sha3(content);
      const oldFull = path.join(h.syncFolder, 'old.txt');
      fs.writeFileSync(oldFull, content);
      stateDb.upsertFile({
        relativePath: 'old.txt',
        serverFileId: 'fid-1',
        localChecksum: checksum,
        serverChecksum: checksum,
        size: content.length,
        serverSeq: 4,
        status: FILE_STATUS.SYNCED,
      });

      // Pure rename — server omits checksum (content unchanged).
      h.engine._onServerMessage({
        type: MSG.FILE_RENAMED, fileId: 'fid-1',
        oldRelativePath: 'old.txt', relativePath: 'new.txt', seq: 5,
      });
      await h.engine._applyChain;

      const newFull = path.join(h.syncFolder, 'new.txt');
      assert.ok(!fs.existsSync(oldFull), 'old path moved away');
      assert.ok(fs.existsSync(newFull), 'new path now holds the bytes');
      assert.equal(fs.readFileSync(newFull, 'utf8'), content, 'bytes preserved through the move');

      assert.equal(stateDb.getFile('old.txt'), undefined, 'old row removed');
      const row = stateDb.getFile('new.txt');
      assert.ok(row, 'new row exists');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'new row is SYNCED');
      assert.equal(row.localChecksum, checksum, 'moved bytes keep their checksum');
      assert.equal(row.serverFileId, 'fid-1');
      assert.equal(stateDb.getLastSeq(), 5, 'cursor advanced after the verified rename');

      // No download happened — a pure rename never re-fetches.
      assert.equal(h.downloadLog.length, 0, 'pure rename does not download');
    } finally {
      cleanup(h);
    }
  });

  it('rename with an ABSENT source recovers via delete-old + re-download-new', async () => {
    const recoveredContent = 'fresh-from-server';
    const checksum = sha3(recoveredContent);
    const h = makeEngine({
      downloads: { 'fid-2': { content: recoveredContent } },
    });
    try {
      // Tracked row exists but the source bytes were never on disk (an earlier
      // download left a PENDING_DOWNLOAD row, say).
      stateDb.upsertFile({
        relativePath: 'absent-old.txt',
        serverFileId: 'fid-2',
        serverChecksum: checksum,
        size: recoveredContent.length,
        serverSeq: 3,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });

      h.engine._onServerMessage({
        type: MSG.FILE_RENAMED, fileId: 'fid-2',
        oldRelativePath: 'absent-old.txt', relativePath: 'absent-new.txt',
        checksum, size: recoveredContent.length, seq: 6,
      });
      await h.engine._applyChain;

      const newFull = path.join(h.syncFolder, 'absent-new.txt');
      assert.ok(fs.existsSync(newFull), 'recovery downloaded the file fresh at the new path');
      assert.equal(fs.readFileSync(newFull, 'utf8'), recoveredContent);

      assert.equal(stateDb.getFile('absent-old.txt'), undefined, 'stale old row cleared by recovery delete');
      const row = stateDb.getFile('absent-new.txt');
      assert.ok(row, 'new row created by the recovery download');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'new path SYNCED only after the download committed');
      assert.equal(stateDb.getLastSeq(), 6, 'cursor advances only after the recovery download landed');
      assert.equal(h.downloadLog.length, 1, 'recovery performed exactly one download');
      assert.equal(h.downloadLog[0].fileId, 'fid-2');
    } finally {
      cleanup(h);
    }
  });

  it('rename whose checksum DIFFERS from the tracked bytes recovers fresh content', async () => {
    const oldContent = 'old-content';
    const oldChecksum = sha3(oldContent);
    const newContent = 'new-content-after-rename';
    const newChecksum = sha3(newContent);
    const h = makeEngine({
      downloads: { 'fid-3': { content: newContent } },
    });
    try {
      const oldFull = path.join(h.syncFolder, 'cc-old.txt');
      fs.writeFileSync(oldFull, oldContent);
      stateDb.upsertFile({
        relativePath: 'cc-old.txt',
        serverFileId: 'fid-3',
        localChecksum: oldChecksum,
        serverChecksum: oldChecksum,
        size: oldContent.length,
        serverSeq: 7,
        status: FILE_STATUS.SYNCED,
      });

      // Rename event carries a checksum that does NOT match our tracked bytes,
      // i.e. the rename also changed the content. bytesMatch must be false, so
      // the recovery path downloads the fresh content.
      h.engine._onServerMessage({
        type: MSG.FILE_RENAMED, fileId: 'fid-3',
        oldRelativePath: 'cc-old.txt', relativePath: 'cc-new.txt',
        checksum: newChecksum, size: newContent.length, seq: 8,
      });
      await h.engine._applyChain;

      const newFull = path.join(h.syncFolder, 'cc-new.txt');
      assert.ok(fs.existsSync(newFull), 'new path exists');
      assert.equal(fs.readFileSync(newFull, 'utf8'), newContent, 'on-disk bytes equal the NEW content, not the moved old bytes');
      assert.equal(stateDb.getFile('cc-old.txt'), undefined, 'old row removed');
      const row = stateDb.getFile('cc-new.txt');
      assert.equal(row.status, FILE_STATUS.SYNCED);
      assert.equal(row.localChecksum, newChecksum, 'row records the new content checksum');
      assert.equal(stateDb.getLastSeq(), 8);
      assert.ok(h.downloadLog.length >= 1, 'content-changed rename re-downloads');
    } finally {
      cleanup(h);
    }
  });

  it('rename does NOT claim an UNRELATED local file already at the destination', async () => {
    const foreign = 'i-am-an-unrelated-local-file';
    const foreignChecksum = sha3(foreign);
    const trackedContent = 'tracked-bytes';
    const trackedChecksum = sha3(trackedContent);
    const h = makeEngine({
      downloads: { 'fid-4': { content: trackedContent } },
    });
    try {
      // The tracked source is ABSENT on disk, but an unrelated file already
      // occupies the destination path. The `moved` gate must prevent marking
      // that foreign file SYNCED under the renamed identity.
      const destFull = path.join(h.syncFolder, 'dest.txt');
      fs.writeFileSync(destFull, foreign);
      stateDb.upsertFile({
        relativePath: 'src.txt',
        serverFileId: 'fid-4',
        serverChecksum: trackedChecksum,
        size: trackedContent.length,
        serverSeq: 9,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });

      h.engine._onServerMessage({
        type: MSG.FILE_RENAMED, fileId: 'fid-4',
        oldRelativePath: 'src.txt', relativePath: 'dest.txt',
        checksum: trackedChecksum, size: trackedContent.length, seq: 10,
      });
      await h.engine._applyChain;

      const row = stateDb.getFile('dest.txt');
      assert.ok(row, 'dest row exists after recovery');
      // The foreign bytes must NOT have been claimed SYNCED under the renamed
      // identity — recovery re-downloaded the tracked content over them.
      assert.equal(fs.readFileSync(destFull, 'utf8'), trackedContent,
        'recovery downloaded the tracked content, did not claim the foreign bytes');
      assert.equal(row.localChecksum, trackedChecksum,
        'row checksum is the tracked content, never the foreign file checksum');
      assert.notEqual(row.localChecksum, foreignChecksum,
        'foreign bytes were never recorded as the synced identity');
      assert.equal(stateDb.getLastSeq(), 10, 'cursor advances after the verified recovery download');
    } finally {
      cleanup(h);
    }
  });

});
