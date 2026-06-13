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
    status TEXT DEFAULT 'synced'
  );

  CREATE TABLE IF NOT EXISTS sync_state (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`;

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
  });
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

function getAllFiles() {
  return _h().prepare('SELECT * FROM files').all();
}

function getFilesByStatus(status) {
  return _h().prepare('SELECT * FROM files WHERE status = ?').all(status);
}

function upsertFile(file) {
  _h().prepare(`
    INSERT INTO files (relativePath, serverFileId, localChecksum, serverChecksum, localMtime, size, serverSeq, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(relativePath) DO UPDATE SET
      serverFileId = excluded.serverFileId,
      localChecksum = excluded.localChecksum,
      serverChecksum = excluded.serverChecksum,
      localMtime = excluded.localMtime,
      size = excluded.size,
      serverSeq = excluded.serverSeq,
      status = excluded.status
  `).run(
    file.relativePath,
    file.serverFileId || null,
    file.localChecksum || null,
    file.serverChecksum || null,
    file.localMtime || null,
    file.size || null,
    file.serverSeq || 0,
    file.status || 'synced',
  );
}

function updateFileStatus(relativePath, status) {
  _h().prepare('UPDATE files SET status = ? WHERE relativePath = ?').run(status, relativePath);
}

function removeFile(relativePath) {
  _h().prepare('DELETE FROM files WHERE relativePath = ?').run(relativePath);
}

function clearAll() {
  db().exec('DELETE FROM files; DELETE FROM sync_state;');
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
  getAllFiles,
  getFilesByStatus,
  upsertFile,
  updateFileStatus,
  removeFile,
  clearAll,
  integrityCheck,
  dumpSchema,
};
