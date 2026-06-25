'use strict';

// Lower the file-size ceiling BEFORE any require, so lib/constants snapshots a
// tiny MAX_SYNC_FILE_BYTES and lib/checksum's hashFile rejects a small "oversize"
// file. That is the cheapest cross-platform way to drive the indeterminate-hash
// branch (the alternative triggers — a special file or an unreadable mode — are
// POSIX-only). Each test file runs in its own process (tests/run-all.js), so the
// lowered cap is scoped to this file.
process.env.HERMITSTASH_MAX_FILE_BYTES = '64';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const { hashFile } = require('../lib/checksum');
const SyncEngine = require('../lib/sync-engine');
const stateDb = require('../lib/state-db');
const { FILE_STATUS, SYNC_STATE } = require('../lib/constants');
const logger = require('../lib/logger');

logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fixrd-' + process.pid + '.log') });

function mkTmp(p) { return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), p)); }
function rm(d) { try { nodeFs.rmSync(d, { recursive: true, force: true }); } catch { /* best-effort */ } }

// Precondition: the lowered cap makes hashFile reject an over-64-byte file, so
// the engine's `actualLocal = await hashFile(...)` genuinely lands in the catch.
describe('fail-closed preconditions', () => {
  it('hashFile rejects a file over the lowered size ceiling', async () => {
    const tmp = mkTmp('hs-fixrd-pre-');
    try {
      const p = nodePath.join(tmp, 'big.txt');
      nodeFs.writeFileSync(p, 'x'.repeat(100)); // > 64-byte cap
      await assert.rejects(() => hashFile(p), 'an oversize file makes hashFile reject (indeterminate hash)');
    } finally { rm(tmp); }
  });
});

// A remote delete must NOT destroy a tracked file we cannot hash — we can't
// confirm it still matches what we synced, so we keep it and let a reconnect
// re-drive the delete once it is hashable again.
describe('sync-engine — remote delete fails CLOSED on an indeterminate local hash', () => {
  it('preserves a tracked, unhashable file (and its row) against a remote delete', async () => {
    const tmp = mkTmp('hs-fixrd-del-');
    stateDb.open(nodePath.join(tmp, 'state.db'));
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.SYNCED;
      const rel = 'doc.bin';
      const full = nodePath.join(tmp, rel);
      nodeFs.writeFileSync(full, 'y'.repeat(100)); // oversize → unhashable
      stateDb.upsertFile({ relativePath: rel, serverFileId: 'fid', localChecksum: 'H1abc', serverChecksum: 'H1abc', size: 100, serverSeq: 1, status: FILE_STATUS.SYNCED });
      assert.ok(stateDb.getFile(rel), 'row seeded');

      await e._handleFileRemoved({ seq: 5, relativePath: rel });

      assert.equal(nodeFs.existsSync(full), true, 'the unhashable local file is PRESERVED, not deleted (fail closed)');
      assert.ok(stateDb.getFile(rel), 'the DB row is kept so a reconnect re-drives the delete');
    } finally { stateDb.close(); rm(tmp); }
  });

  it('still deletes a tracked file whose hash matches the last synced value (uncontested)', async () => {
    const tmp = mkTmp('hs-fixrd-del2-');
    stateDb.open(nodePath.join(tmp, 'state.db'));
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.SYNCED;
      const rel = 'small.txt';
      const full = nodePath.join(tmp, rel);
      nodeFs.writeFileSync(full, 'hi'); // 2 bytes, under cap → hashable
      const h = await hashFile(full);
      stateDb.upsertFile({ relativePath: rel, serverFileId: 'fid', localChecksum: h, serverChecksum: h, size: 2, serverSeq: 1, status: FILE_STATUS.SYNCED });

      await e._handleFileRemoved({ seq: 6, relativePath: rel });

      assert.equal(nodeFs.existsSync(full), false, 'an uncontested (matching) delete still removes the file');
      assert.equal(stateDb.getFile(rel), undefined, 'and removes the row');
    } finally { stateDb.close(); rm(tmp); }
  });
});

// Before a server-driven overwrite, a local file we cannot hash must be moved
// aside (conflict copy), not silently overwritten — fail closed.
describe('sync-engine — _maybeSaveConflictCopy preserves an unhashable local file', () => {
  it('renames the local file aside when it cannot be hashed (no silent overwrite)', async () => {
    const tmp = mkTmp('hs-fixrd-cc-');
    stateDb.open(nodePath.join(tmp, 'state.db'));
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      const rel = 'over.bin';
      const full = nodePath.join(tmp, rel);
      nodeFs.writeFileSync(full, 'z'.repeat(100)); // oversize → unhashable

      await e._maybeSaveConflictCopy(rel, full, 'incomingHashHex');

      assert.equal(nodeFs.existsSync(full), false, 'the original path is vacated (file moved aside, not left to be overwritten)');
      const conflicts = nodeFs.readdirSync(tmp).filter(n => n.includes('.conflict-'));
      assert.ok(conflicts.length >= 1, 'a conflict copy of the unhashable file is preserved');
    } finally { stateDb.close(); rm(tmp); }
  });
});
