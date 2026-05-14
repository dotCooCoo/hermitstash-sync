'use strict';

const b = require('../vendor/blamejs');

// Streaming SHA3-512 hex digest of a file. b.crypto.hashFile pipes the
// file Readable through hashStream and returns the raw digest Buffer;
// we hex-encode so callers compare against the server's `checksum`
// field directly.
function hashFile(filePath) {
  return b.crypto.hashFile(filePath, 'sha3-512').then(buf => buf.toString('hex'));
}

// Synchronous SHA3-512 hex digest of a Buffer (or string).
const hashBuffer = b.crypto.sha3Hash;

// Hash a list of files in bounded parallel. blamejs v0.9.14+ ships
// `b.crypto.hashFilesParallel` with the same cursor-pool shape we
// used to maintain locally; this is a thin reshape so existing
// callers keep consuming `{ filePath, checksum }` rows.
async function hashFilesParallel(filePaths, opts = {}) {
  if (filePaths.length === 0) return [];
  const rows = await b.crypto.hashFilesParallel(filePaths, {
    algorithms:  ['sha3-512'],
    concurrency: opts.concurrency,
  });
  return rows.map(r => ({ filePath: r.path, checksum: r.sha3_512 }));
}

module.exports = {
  hashFile,
  hashBuffer,
  hashFilesParallel,
};
