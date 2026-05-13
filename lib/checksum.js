'use strict';

const os = require('node:os');
const b = require('../vendor/blamejs');

// Default concurrency for parallel hashing. Node's `crypto.createHash` runs
// the digest steps inline but file reads come off the libuv thread pool, so
// overlapping a small number of streaming hashes lets I/O wait time hide
// behind compute time. Benchmarks (250 MiB / 50 × 5 MiB) showed serial =
// 798ms, Promise.all (unbounded) = 632ms, 4-wide bounded = 634ms — bounded
// is essentially free relative to unbounded and bounds FD pressure on
// large bundles. CPU count is the cap.
const DEFAULT_CONCURRENCY = Math.min(8, Math.max(2, // allow:raw-byte-literal — concurrency upper bound, not byte size
  os.availableParallelism ? os.availableParallelism() : os.cpus().length));

// Streaming SHA3-512 hex digest of a file. b.crypto.hashFile pipes the
// file Readable through hashStream and returns the raw digest Buffer;
// we hex-encode so callers compare against the server's `checksum`
// field directly.
function hashFile(filePath) {
  return b.crypto.hashFile(filePath, 'sha3-512').then(buf => buf.toString('hex'));
}

// Synchronous SHA3-512 hex digest of a Buffer (or string).
const hashBuffer = b.crypto.sha3Hash;

// Hash a list of files with bounded concurrency. Workers race a shared
// cursor — the first N files start hashing in parallel, each picks up
// the next file when it finishes. Cleanly handles 1 file or 100K.
// Returns a list shaped { filePath, checksum } in the same order as
// the input. No b.* equivalent yet — keep the cursor pattern local.
async function hashFilesParallel(filePaths, opts = {}) {
  if (filePaths.length === 0) return [];
  const concurrency = Math.max(1, Math.min(opts.concurrency || DEFAULT_CONCURRENCY, filePaths.length));
  const results = new Array(filePaths.length);
  let nextIdx = 0;

  async function worker() {
    while (true) {
      const idx = nextIdx++;
      if (idx >= filePaths.length) return;
      results[idx] = { filePath: filePaths[idx], checksum: await hashFile(filePaths[idx]) };
    }
  }

  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

module.exports = {
  hashFile,
  hashBuffer,
  hashFilesParallel,
};
