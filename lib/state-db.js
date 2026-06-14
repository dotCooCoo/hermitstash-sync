'use strict';

const nodeFs = require('node:fs');
const b = require('../vendor/blamejs');
const { STATE_DB_FILE, CONFIG_DIR } = require('./constants');

// b.localDb.thin owns the SQLite open dance: parent-dir mkdir,
// WAL + foreign-keys pragmas, PRAGMA integrity_check, rename-corrupt
// + recreate recovery (with bounded retry on Windows where the
// SQLite handle stays locked for a few hundred ms after close()),
// and prepared-statement caching. Schema migration stays here —
// every re-open replays CREATE TABLE IF NOT EXISTS so first-boot
// and subsequent-boot land on the same shape.

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS files (
    relativePath TEXT PRIMARY KEY,
    serverFileId TEXT,
    localChecksum TEXT,
    serverChecksum TEXT,
    localMtime REAL,
    size INTEGER,
    serverSeq INTEGER DEFAULT 0,
    status TEXT DEFAULT 'synced',
    needsBytes INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS sync_state (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`;

// Bring forward a pre-needsBytes schema. CREATE TABLE IF NOT EXISTS won't
// add a column to a table that already exists, so add it idempotently
// after open. The column records the free-space shortfall (bytes) a
// download row needs before it can be re-driven, so the reconcile sweep
// doesn't re-exhaust the disk fetching an unfittable file every tick.
function _migrateNeedsBytes(d) {
  try { d.exec('ALTER TABLE files ADD COLUMN needsBytes INTEGER DEFAULT 0'); }
  catch { /* allow:silent-catch — column already present on a current-schema DB */ }
}

let _handle = null;

// opts.recovery selects how a corrupt file is handled:
//   'rename-and-recreate' (default) — the daemon owns this DB exclusively,
//     so a failed integrity_check renames the corrupt file aside and starts
//     fresh. Correct for the daemon's own start() path.
//   'refuse' — surface corruption as a thrown error and leave the file
//     untouched. Used by read-only consumers (e.g. diagnose) that must
//     never mutate a DB the live daemon may still hold open.
function open(dbPath, opts) {
  opts = opts || {};
  const recovery = opts.recovery || 'rename-and-recreate';
  nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
  const file = dbPath || STATE_DB_FILE;
  // b.localDb.thin's built-in pragmas already cover WAL +
  // foreign_keys=ON plus stricter defaults the standalone open() never
  // set (synchronous=NORMAL, busy_timeout=5000, secure_delete=ON,
  // trusted_schema=OFF, cell_size_check=ON). No extras needed.
  _handle = b.localDb.thin({
    file,
    schemaSql: SCHEMA_SQL,
    recovery:  recovery,
    audit:     false,
    // Parse-time resource floor (blamejs v0.15.11+ threads these into the
    // node:sqlite handle): reject a SQL statement over 1 MiB before the
    // parser chews on it, and deny ATTACH DATABASE outright. This DB is
    // local-daemon-owned and every statement is a fixed literal with bound
    // parameters, so it never approaches the cap and never attaches — a
    // stricter floor than the framework default costs nothing here.
    limits:    { sqlLength: b.constants.BYTES.mib(1), attach: 0 },
  });
  _migrateNeedsBytes(_handle.db);
  return _handle.db;
}

function close() {
  if (_handle) {
    _handle.close();
    _handle = null;
  }
}

function _h() {
  if (!_handle) throw new Error('State DB not opened. Call stateDb.open() first.');
  return _handle;
}

function db() { return _h().db; }

// --- sync_state key/value store ---

function getMeta(key) {
  const row = _h().prepare('SELECT value FROM sync_state WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setMeta(key, value) {
  _h().prepare(
    'INSERT INTO sync_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?'
  ).run(key, String(value), String(value));
}

function getLastSeq() {
  const v = getMeta('last_seq');
  return v ? parseInt(v, 10) : 0;
}

function setLastSeq(seq) {
  setMeta('last_seq', seq);
}

// --- file records ---

function getFile(relativePath) {
  return _h().prepare('SELECT * FROM files WHERE relativePath = ?').get(relativePath);
}

// Case-fold-aware lookup for filesystems that collide one inode against
// two byte-distinct keys (NTFS, HFS+, exFAT/FAT, a Linux box on a
// case-folding Dropbox mount). The caller probes the live filesystem at
// boot — os.platform() is not a reliable signal — and passes `folded:
// true` only when the probe confirmed folding. COLLATE NOCASE folds
// ASCII only; a "Foo.txt" vs "foo.txt" collision (the common case)
// resolves to the single tracked row, while non-ASCII case differences
// fall through to the exact match. Returns the exact-match row first so
// a same-case lookup never pays the NOCASE scan.
function getFileFolded(relativePath, folded) {
  const exact = getFile(relativePath);
  if (exact || !folded) return exact;
  return _h().prepare('SELECT * FROM files WHERE relativePath = ? COLLATE NOCASE').get(relativePath);
}

function getAllFiles() {
  return _h().prepare('SELECT * FROM files').all();
}

function getFilesByStatus(status) {
  return _h().prepare('SELECT * FROM files WHERE status = ?').all(status);
}

function upsertFile(file) {
  _h().prepare(`
    INSERT INTO files (relativePath, serverFileId, localChecksum, serverChecksum, localMtime, size, serverSeq, status, needsBytes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(relativePath) DO UPDATE SET
      serverFileId = excluded.serverFileId,
      localChecksum = excluded.localChecksum,
      serverChecksum = excluded.serverChecksum,
      localMtime = excluded.localMtime,
      size = excluded.size,
      serverSeq = excluded.serverSeq,
      status = excluded.status,
      needsBytes = excluded.needsBytes
  `).run(
    file.relativePath,
    file.serverFileId || null,
    file.localChecksum || null,
    file.serverChecksum || null,
    file.localMtime ?? null,
    file.size ?? null,
    file.serverSeq || 0,
    file.status || 'synced',
    file.needsBytes || 0,
  );
}

function updateFileStatus(relativePath, status) {
  _h().prepare('UPDATE files SET status = ? WHERE relativePath = ?').run(status, relativePath);
}

function removeFile(relativePath) {
  _h().prepare('DELETE FROM files WHERE relativePath = ?').run(relativePath);
}

// Atomically move a tracked file's row from oldPath to newRow.relativePath.
// removeFile + upsertFile are otherwise two autocommit statements; a crash
// between them strands the file tracked at neither path. BEGIN IMMEDIATE
// takes the write lock up front so a concurrent reconcile read under WAL
// busy_timeout can't wedge the commit on a lock-upgrade. On any failure the
// ROLLBACK restores the pre-rename state (old row intact), so the server's
// replay re-applies the rename cleanly with no tracked-at-neither-path
// window.
function renameFile(oldPath, newRow) {
  const d = db();
  d.exec('BEGIN IMMEDIATE');
  try {
    removeFile(oldPath);
    upsertFile(newRow);
    d.exec('COMMIT');
  } catch (err) {
    try { d.exec('ROLLBACK'); } catch { /* allow:silent-catch — best-effort rollback on a failed renameFile */ }
    throw err;
  }
}

// Clear both tables as one all-or-nothing transaction. Two bare DELETEs
// in autocommit can tear on a crash: the files table empties but
// sync_state keeps last_seq, stranding the cursor ahead of an empty file
// set so catch-up never re-pulls. BEGIN IMMEDIATE takes the write lock up
// front. The DELETEs run sync_state-first so that even the
// impossible-with-a-transaction torn case degrades to cursor=0 + stale
// files (which the next boot's initial sync, gated on lastSeq===0, self-
// heals) rather than cursor=N + empty files (which wedges forever). BEGIN
// and COMMIT stay as separate exec() calls bracketing the try/catch so a
// throw mid-DELETE still reaches the ROLLBACK.
function clearAll() {
  const d = db();
  d.exec('BEGIN IMMEDIATE');
  try {
    d.exec('DELETE FROM sync_state');
    d.exec('DELETE FROM files');
    d.exec('COMMIT');
  } catch (err) {
    try { d.exec('ROLLBACK'); } catch { /* allow:silent-catch — best-effort rollback on a failed clearAll */ }
    throw err;
  }
}

/**
 * Integrity check — returns true if DB is healthy
 */
function integrityCheck() {
  try {
    const result = _h().prepare('PRAGMA integrity_check').get();
    return result && result.integrity_check === 'ok';
  } catch {
    return false;
  }
}

/**
 * Schema + row counts for `hermitstash-sync diagnose`. Returns the
 * literal CREATE statements (no data — the file table can hold user
 * paths) plus a count per table so support can see whether the daemon
 * has seen any traffic without leaking what the operator synced.
 */
function dumpSchema() {
  try {
    const objects = _h().prepare(
      "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).all();
    const counts = {};
    for (const o of objects) {
      if (o.type !== 'table') continue;
      try {
        const row = _h().prepare(`SELECT COUNT(*) AS n FROM "${o.name}"`).get();
        counts[o.name] = row ? row.n : null;
      } catch {
        counts[o.name] = null;
      }
    }
    return { objects: objects.map(o => ({ type: o.type, name: o.name, sql: o.sql })), counts };
  } catch (err) {
    return { error: err.message, objects: [], counts: {} };
  }
}

module.exports = {
  open,
  close,
  db,
  getMeta,
  setMeta,
  getLastSeq,
  setLastSeq,
  getFile,
  getFileFolded,
  getAllFiles,
  getFilesByStatus,
  upsertFile,
  updateFileStatus,
  removeFile,
  renameFile,
  clearAll,
  integrityCheck,
  dumpSchema,
};
