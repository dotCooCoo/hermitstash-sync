'use strict';

const { DatabaseSync } = require('node:sqlite');
const { STATE_DB_FILE, CONFIG_DIR } = require('./constants');
const fs = require('node:fs');
const log = require('./logger');

let _db = null;

function open(dbPath) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const file = dbPath || STATE_DB_FILE;
  _db = new DatabaseSync(file);
  _db.exec('PRAGMA journal_mode=WAL');
  _db.exec('PRAGMA foreign_keys=ON');
  _migrate();
  return _db;
}

function _migrate() {
  _db.exec(`
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
  `);
}

function close() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

function db() {
  if (!_db) throw new Error('State DB not opened. Call stateDb.open() first.');
  return _db;
}

// --- sync_state key/value store ---

function getMeta(key) {
  const row = db().prepare('SELECT value FROM sync_state WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setMeta(key, value) {
  db().prepare(
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
  return db().prepare('SELECT * FROM files WHERE relativePath = ?').get(relativePath);
}

function getAllFiles() {
  return db().prepare('SELECT * FROM files').all();
}

function getFilesByStatus(status) {
  return db().prepare('SELECT * FROM files WHERE status = ?').all(status);
}

function upsertFile(file) {
  db().prepare(`
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
  db().prepare('UPDATE files SET status = ? WHERE relativePath = ?').run(status, relativePath);
}

function removeFile(relativePath) {
  db().prepare('DELETE FROM files WHERE relativePath = ?').run(relativePath);
}

function clearAll() {
  db().exec('DELETE FROM files; DELETE FROM sync_state;');
}

/**
 * Integrity check — returns true if DB is healthy
 */
function integrityCheck() {
  try {
    const result = db().prepare('PRAGMA integrity_check').get();
    return result && result.integrity_check === 'ok';
  } catch {
    return false;
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
};
