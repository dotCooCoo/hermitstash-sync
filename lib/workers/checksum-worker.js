'use strict';

const { parentPort } = require('node:worker_threads');
const crypto = require('node:crypto');
const fs = require('node:fs');

/**
 * Worker thread for SHA3-512 file hashing.
 * Receives: { id, task: { filePath } }
 * Posts:    { id, result: "<hex hash>" } or { id, error: "<message>" }
 */
parentPort.on('message', ({ id, task }) => {
  var filePath = task.filePath;
  var hash = crypto.createHash('sha3-512');
  var stream = fs.createReadStream(filePath);

  stream.on('data', chunk => hash.update(chunk));

  stream.on('end', () => {
    parentPort.postMessage({ id, result: hash.digest('hex') });
  });

  stream.on('error', err => {
    parentPort.postMessage({ id, error: err.message });
  });
});
