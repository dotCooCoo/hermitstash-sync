'use strict';

// SDB-1 regression: the needsBytes ALTER in state-db.open() is a schema WRITE.
// Read-only consumers (status / stats / diagnose) open with recovery: 'refuse'
// precisely because the live daemon may hold the DB open under WAL — they must
// never issue a write. This test proves the migration is gated on the daemon's
// exclusive-owner recovery mode and skipped in 'refuse' mode, while still
// running on the default ('rename-and-recreate') boot path.
//
// CONFIG_DIR is resolved once from HERMITSTASH_SYNC_CONFIG_DIR at constants.js
// load time, so it is pointed at a fresh tmpdir before any lib require. The DB
// path is passed explicitly to open(), so this never touches a real install.
// Self-contained: `node tests/test-state-db-refuse-migration.js` runs it.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const TMP_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-sdb-refuse-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_DIR;

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');

const stateDb = require('../lib/state-db');

after(() => {
  try { stateDb.close(); } catch { /* idempotent */ }
  try { nodeFs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

// Build a pre-needsBytes legacy DB: the files table without the needsBytes
// column, plus the sync_state table. CREATE TABLE IF NOT EXISTS (replayed by
// state-db's schemaSql on open) will NOT add a column to an existing table, so
// whether needsBytes appears is governed solely by the gated ALTER.
function makeLegacyDb(file) {
  const d = new DatabaseSync(file);
  d.exec(`
    CREATE TABLE files (
      relativePath TEXT PRIMARY KEY,
      serverFileId TEXT,
      localChecksum TEXT,
      serverChecksum TEXT,
      localMtime REAL,
      size INTEGER,
      serverSeq INTEGER DEFAULT 0,
      status TEXT DEFAULT 'synced'
    );
    CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT);
  `);
  d.close();
}

function hasNeedsBytes(file) {
  const d = new DatabaseSync(file, { readOnly: true });
  try {
    return d.prepare('PRAGMA table_info(files)').all().some(c => c.name === 'needsBytes');
  } finally {
    d.close();
  }
}

describe('state-db needsBytes migration is recovery-gated (SDB-1)', () => {
  it('refuse mode does NOT add the needsBytes column to a legacy DB', () => {
    const file = nodePath.join(TMP_DIR, 'legacy-refuse.db');
    makeLegacyDb(file);
    assert.equal(hasNeedsBytes(file), false, 'precondition: legacy DB has no needsBytes');

    stateDb.open(file, { recovery: 'refuse' });
    // A refuse-mode reader uses SELECT * and never names needsBytes, so it works
    // fine without the column.
    assert.deepEqual(stateDb.getAllFiles(), []);
    assert.equal(stateDb.getLastSeq(), 0);
    stateDb.close();

    assert.equal(hasNeedsBytes(file), false,
      'refuse mode must not perform the schema-write ALTER on a daemon-held DB');
  });

  it('default (rename-and-recreate) mode DOES add the column to the same legacy DB', () => {
    const file = nodePath.join(TMP_DIR, 'legacy-default.db');
    makeLegacyDb(file);
    assert.equal(hasNeedsBytes(file), false, 'precondition: legacy DB has no needsBytes');

    stateDb.open(file); // default recovery = 'rename-and-recreate'
    stateDb.close();

    assert.equal(hasNeedsBytes(file), true,
      'the daemon boot path must converge the schema by adding needsBytes');
  });

  it('a current-schema DB is unchanged under refuse mode and reads cleanly', () => {
    const file = nodePath.join(TMP_DIR, 'current.db');
    stateDb.open(file); // creates current schema (with needsBytes via SCHEMA_SQL)
    stateDb.upsertFile({ relativePath: 'a.txt', status: 'synced', needsBytes: 0 });
    stateDb.close();
    assert.equal(hasNeedsBytes(file), true, 'precondition: current DB has needsBytes');

    stateDb.open(file, { recovery: 'refuse' });
    const rows = stateDb.getAllFiles();
    stateDb.close();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].relativePath, 'a.txt');
  });
});
