'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

/**
 * Compute SHA3-512 hash of a file (streaming — handles large files)
 * Returns hex string matching server's `checksum` field
 */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha3-512');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Compute SHA3-512 hash of a Buffer
 */
function hashBuffer(buffer) {
  return crypto.createHash('sha3-512').update(buffer).digest('hex');
}

module.exports = { hashFile, hashBuffer };
