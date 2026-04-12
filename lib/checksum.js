'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const WorkerPool = require('./worker-pool');

var _pool = null;

/**
 * Compute SHA3-512 hash of a file (streaming — handles large files).
 * Runs on the main thread. Use hashFilesParallel() for bulk operations.
 * Returns hex string matching server's `checksum` field.
 */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    var hash = crypto.createHash('sha3-512');
    var stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Compute SHA3-512 hash of a Buffer.
 */
function hashBuffer(buffer) {
  return crypto.createHash('sha3-512').update(buffer).digest('hex');
}

/**
 * Start the checksum worker pool.
 * Call once at engine startup.
 * @param {object} [opts]
 * @param {number} [opts.size]  Pool size (default: auto from CPU count)
 */
function startPool(opts) {
  if (_pool) return;
  var workerScript = path.join(__dirname, 'workers', 'checksum-worker.js');
  _pool = new WorkerPool(workerScript, opts);
}

/**
 * Stop the checksum worker pool.
 * Call on engine shutdown.
 */
async function stopPool() {
  if (!_pool) return;
  await _pool.destroy();
  _pool = null;
}

/**
 * Get the worker pool instance (for stats/monitoring).
 * Returns null if pool is not started.
 */
function getPool() {
  return _pool;
}

/**
 * Hash a single file using the worker pool.
 * Falls back to main-thread hashFile() if pool isn't started.
 * @param {string} filePath
 * @returns {Promise<string>}  hex SHA3-512 hash
 */
function hashFileWorker(filePath) {
  if (!_pool) return hashFile(filePath);
  return _pool.run({ filePath });
}

/**
 * Hash multiple files in parallel using the worker pool.
 * Falls back to sequential main-thread hashing if pool isn't started.
 * @param {string[]} filePaths
 * @returns {Promise<Array<{filePath: string, checksum: string}>>}
 */
async function hashFilesParallel(filePaths) {
  if (!_pool || filePaths.length === 0) {
    // Sequential fallback
    var results = [];
    for (var fp of filePaths) {
      var checksum = await hashFile(fp);
      results.push({ filePath: fp, checksum });
    }
    return results;
  }

  var tasks = filePaths.map(fp => ({ filePath: fp }));
  var hashes = await _pool.runBatch(tasks);
  return filePaths.map((fp, i) => ({ filePath: fp, checksum: hashes[i] }));
}

module.exports = {
  hashFile,
  hashBuffer,
  startPool,
  stopPool,
  getPool,
  hashFileWorker,
  hashFilesParallel,
};
