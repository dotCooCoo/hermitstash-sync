'use strict';

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

// SHA3-512 hex digest of a single file. Routes through the same hardened
// batch primitive as the parallel path (b.crypto.hashFilesParallel) so a
// non-regular file (symlink / FIFO / device) is refused and the
// MAX_BYTES_PER_FILE ceiling is enforced at the streaming byte boundary —
// a bare b.crypto.hashFile would do neither, letting a special file in the
// sync folder hang or escape the size ceiling. The path is long-path-
// prefixed before it reaches the fs syscalls inside blamejs; we return the
// row's sha3-512 hex so callers compare against the server's `checksum`
// field directly. Oversize / missing / special-file inputs reject here,
// which callers already treat as "skip this file".
async function hashFile(filePath) {
  const lp = longPath(filePath);
  let rows;
  try {
    rows = await b.crypto.hashFilesParallel([lp], {
      algorithms:      ['sha3-512'],
      maxBytesPerFile: MAX_BYTES_PER_FILE,
    });
  } catch (err) {
    // The hardened primitive aborts an over-ceiling file with its own internal
    // wording. Re-throw with the actionable size-limit message the single-file
    // callers expect (and that points the operator at the override).
    if (err && /maxBytesPerFile|exceeded/i.test(err.message || '')) {
      throw new Error(
        `File ${filePath} exceeds the sync size limit (${MAX_BYTES_PER_FILE} bytes). ` +
        `Raise HERMITSTASH_MAX_FILE_BYTES or exclude it.`
      );
    }
    throw err;
  }
  // A null checksum row means the file could not be read (missing, permission,
  // or a non-regular file the primitive refused). Surface it as a rejection so
  // callers skip it, matching the single-file path's prior behavior.
  const hex = rows[0] && rows[0].sha3_512;
  if (!hex) {
    throw new Error(`Could not hash ${filePath}: unreadable, missing, or not a regular file.`);
  }
  return hex;
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
