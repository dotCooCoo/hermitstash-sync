'use strict';

// Regression tests for the sync-cursor (last_seq) finiteness guards in
// lib/state-db.js. A corrupt / non-numeric stored value must never surface as
// NaN: NaN poisons the engine's monotonic guard (`seq > getLastSeq()` is always
// false against NaN), stranding the cursor so every reconnect re-runs a full
// catch-up. And setLastSeq must refuse to persist a non-finite / negative value
// so a transient NaN upstream can't be written and become self-perpetuating.
//
// CONFIG_DIR is pointed at a fresh tmpdir before any lib require; the DB path is
// passed explicitly to open(). Self-contained — no server.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const TMP_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-sdb-seq-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_DIR;

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const stateDb = require('../lib/state-db');
const DB = nodePath.join(TMP_DIR, 'seq.db');

before(() => { stateDb.open(DB); });
after(() => {
  try { stateDb.close(); } catch { /* idempotent */ }
  try { nodeFs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

describe('state-db last_seq finiteness guards', () => {
  it('getLastSeq returns 0 for a corrupt / non-numeric stored value (never NaN)', () => {
    for (const bad of ['not-a-number', 'NaN', '', '-5', 'Infinity']) {
      stateDb.setMeta('last_seq', bad);
      const got = stateDb.getLastSeq();
      assert.ok(Number.isFinite(got), `getLastSeq must be finite for stored ${JSON.stringify(bad)}, got ${got}`);
      assert.equal(got, 0, `getLastSeq must clamp ${JSON.stringify(bad)} to 0`);
    }
  });

  it('getLastSeq round-trips a valid non-negative integer', () => {
    stateDb.setMeta('last_seq', '42');
    assert.equal(stateDb.getLastSeq(), 42);
    stateDb.setLastSeq(100);
    assert.equal(stateDb.getLastSeq(), 100);
  });

  it('setLastSeq refuses a non-finite / negative value (cursor unchanged)', () => {
    stateDb.setLastSeq(7);
    assert.equal(stateDb.getLastSeq(), 7);
    stateDb.setLastSeq(NaN);
    assert.equal(stateDb.getLastSeq(), 7, 'NaN must not overwrite the cursor');
    stateDb.setLastSeq(-1);
    assert.equal(stateDb.getLastSeq(), 7, 'negative must not overwrite the cursor');
    stateDb.setLastSeq(Infinity);
    assert.equal(stateDb.getLastSeq(), 7, 'Infinity must not overwrite the cursor');
  });
});
