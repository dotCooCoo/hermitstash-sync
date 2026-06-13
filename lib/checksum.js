'use strict';

const nodeFs = require('node:fs');
const b = require('../vendor/blamejs');
const { longPath } = require('./long-path');
const { MAX_SYNC_FILE_BYTES } = require('./constants');
const log = require('./logger');

// Windows surfaces a 260-char MAX_PATH limit on the fs syscalls that
// back hashing unless the path carries the `\\?\` prefix. longPath()
// applies that prefix at the syscall boundary (no-op off Windows and on
// short / already-prefixed paths), so files in deep trees still hash and
// sync instead of silently failing the stat/open. Callers keep passing
// ordinary paths — the prefixing is contained here.

// Single ceiling shared by every hashing path so the streaming and batch
// routes can never disagree on which files are too large to sync. Both
// pass MAX_SYNC_FILE_BYTES; the value is operator-tunable in constants.js.
const MAX_BYTES_PER_FILE = MAX_SYNC_FILE_BYTES;

// Hashing-pool sizing (file counts, not byte sizes). Mirrors blamejs's
// own hashFilesParallel defaults so concurrency behaviour is unchanged.
const HASH_CONCURRENCY_CAP = 256;     // allow:raw-byte-literal — max parallel hashers (count, not bytes)
const DEFAULT_HASH_CONCURRENCY = 8;   // allow:raw-byte-literal — default pool size (count, not bytes)

// Streaming SHA3-512 hex digest of a file. b.crypto.hashFile pipes the
// file Readable through hashStream and returns the raw digest Buffer;
// we hex-encode so callers compare against the server's `checksum`
// field directly. The path is long-path-prefixed for the open syscall.
//
// A size pre-check enforces the same MAX_BYTES_PER_FILE ceiling the batch
// path applies, so both routes agree on which files are too large to sync
// rather than one being unbounded and the other capped. The default
// ceiling is large enough that no ordinary file trips it; callers already
// treat a rejection here as "skip this file".
async function hashFile(filePath) {
  const lp = longPath(filePath);
  const st = nodeFs.statSync(lp);
  if (st.size > MAX_BYTES_PER_FILE) {
    throw new Error(
      `File ${filePath} is ${st.size} bytes, exceeding the sync size limit ` +
      `(${MAX_BYTES_PER_FILE}). Raise HERMITSTASH_MAX_FILE_BYTES or exclude it.`
    );
  }
  const buf = await b.crypto.hashFile(lp, 'sha3-512');
  return buf.toString('hex');
}

// Synchronous SHA3-512 hex digest of a Buffer (or string).
const hashBuffer = b.crypto.sha3Hash;

// Hash one file through the batch primitive so the size ceiling + symlink
// / special-file refusal apply uniformly. Returns the `{ filePath,
// checksum }` row shape callers expect, or a row with `checksum: null`
// when the file can't be hashed (oversize, unreadable, special-file) so a
// single bad file degrades to "skip that one" instead of aborting the
// whole reconciliation. The path is long-path-prefixed before it reaches
// the fs syscalls inside blamejs.
async function _hashOne(filePath) {
  try {
    const rows = await b.crypto.hashFilesParallel([longPath(filePath)], {
      algorithms:      ['sha3-512'],
      maxBytesPerFile: MAX_BYTES_PER_FILE,
    });
    return { filePath, checksum: rows[0].sha3_512 };
  } catch (err) {
    log.warn('Skipping file during hashing — could not read or it exceeds the sync size limit', {
      filePath,
      maxBytes: MAX_BYTES_PER_FILE,
      error: err && err.message ? err.message : String(err),
    });
    return { filePath, checksum: null };
  }
}

// Hash a list of files in bounded parallel. Returns one `{ filePath,
// checksum }` row per input path, in input order — callers that index the
// result positionally (sync-engine upload scan) stay aligned even when a
// file fails. Per-file error isolation lives here because the underlying
// b.crypto.hashFilesParallel is all-or-nothing (one bad file rejects the
// whole batch via its internal pool); routing each path through _hashOne
// gives the same bounded concurrency while letting one un-hashable file
// degrade to a null-checksum row rather than aborting the cold-start
// scan for every other file.
async function hashFilesParallel(filePaths, opts = {}) {
  if (filePaths.length === 0) return [];

  const concurrency = (Number.isInteger(opts.concurrency) && opts.concurrency > 0)
    ? Math.min(opts.concurrency, HASH_CONCURRENCY_CAP)
    : Math.min(DEFAULT_HASH_CONCURRENCY, filePaths.length);

  const rows = new Array(filePaths.length);
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= filePaths.length) return;
      rows[i] = await _hashOne(filePaths[i]);
    }
  }
  const workers = [];
  for (let w = 0; w < concurrency; w++) workers.push(worker());
  await Promise.all(workers);
  return rows;
}

module.exports = {
  hashFile,
  hashBuffer,
  hashFilesParallel,
  MAX_BYTES_PER_FILE,
};
