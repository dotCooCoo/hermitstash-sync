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
    // The hardened primitive tags an over-ceiling file with the stable code
    // `crypto/hash-max-bytes-exceeded` (blamejs v0.17.13+). Branch on that code
    // — not a message substring — and re-throw with the actionable size-limit
    // message the single-file callers expect (and that points the operator at
    // the override). A code check cannot be fooled by a filename that merely
    // contains the word "exceeded", and it cannot drift if upstream rewords the
    // reject message. Every other failure falls through to the raw re-throw
    // with its true cause — and its code — intact.
    if (err && err.code === 'crypto/hash-max-bytes-exceeded') {
      throw new Error(
        `File ${filePath} exceeds the sync size limit (${MAX_BYTES_PER_FILE} bytes). ` +
        `Raise HERMITSTASH_MAX_FILE_BYTES or exclude it.`
      );
    }
    // b.crypto.hashFilesParallel now preserves the underlying fs error's code
    // on both the pre-open lstat failure and a mid-stream read error
    // (ENOENT/EACCES/…), and tags its symlink / non-regular / size-cap refusals
    // with stable `crypto/hash-*` codes (blamejs v0.17.13+). So a caller can
    // distinguish a routine save-then-delete race (ENOENT — the file vanished
    // before it could be hashed) from a real read failure without a re-stat
    // workaround; the error propagates with its code intact for the sync engine
    // to classify.
    throw err;
  }
  // b.crypto.hashFilesParallel REJECTS (not null-rows) on every unreadable /
  // missing / special-file / oversize case, all caught above — a resolved
  // row always carries a sha3-512 digest. This guard is therefore only a
  // fail-closed backstop against a future contract change in the vendored
  // primitive (a digest that ever came back falsy would otherwise propagate
  // as undefined to a checksum comparison).
  const hex = rows[0] && rows[0].sha3_512;
  if (!hex) {
    throw new Error(`Could not hash ${filePath}: hash primitive returned no sha3-512 digest (unexpected — the primitive normally rejects on unreadable input).`);
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
    // A file that vanished between the scan enumerating it and this hash — the
    // routine save-then-delete / editor-atomic-rename race — rejects with
    // ENOENT (b.crypto.hashFilesParallel now preserves the fs code). That is
    // expected churn during active editing, not an error, so log it at debug to
    // avoid alarming the operator with a warning for every transient file. A
    // genuine unreadable / oversize / refused-symlink file stays at warn with
    // its stable crypto/hash-* code surfaced.
    const benignRace = !!(err && err.code === 'ENOENT');
    const meta = {
      filePath,
      maxBytes: MAX_BYTES_PER_FILE,
      code: err && err.code,
      error: err && err.message ? err.message : String(err),
    };
    if (benignRace) {
      log.debug('Skipping a file that was removed mid-scan (save-then-delete race)', meta);
    } else {
      log.warn('Skipping file during hashing — could not read or it exceeds the sync size limit', meta);
    }
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
// scan for every other file. The bounded concurrency is driven through
// b.promisePool (the same first-party pool the sync engine uses for
// uploads) rather than a local worker loop — _hashOne never rejects, so
// Promise.all settles every task and Array#map keeps the rows positionally
// aligned with the input.
async function hashFilesParallel(filePaths, opts = {}) {
  if (filePaths.length === 0) return [];

  const concurrency = (Number.isInteger(opts.concurrency) && opts.concurrency > 0)
    ? Math.min(opts.concurrency, HASH_CONCURRENCY_CAP)
    : Math.min(DEFAULT_HASH_CONCURRENCY, filePaths.length);

  const pool = b.promisePool.create({ concurrency });
  const rows = await Promise.all(filePaths.map(p => pool.run(() => _hashOne(p))));
  await pool.drain({ close: true });
  return rows;
}

module.exports = {
  hashFile,
  hashBuffer,
  hashFilesParallel,
  MAX_BYTES_PER_FILE,
};
