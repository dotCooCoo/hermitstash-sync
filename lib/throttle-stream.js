'use strict';

// Shared token-bucket rate limiter + a Transform that runs every
// chunk through it. Lets concurrent upload streams (or download
// streams) share one budget so N parallel transfers don't each get
// the full rate.
//
// Pure-Node implementation — pairs with the upload pool's bounded
// concurrency. Limiter is fairness-naive (no FIFO queue); for our
// use case (≤16 concurrent transfers per direction) the simplest
// per-chunk async wait gives even-enough sharing in practice.
//
// Upstream candidate: b.stream.throttle({ bytesPerSec }) — universal
// primitive every blamejs daemon doing bulk I/O could want. Issue
// to file once the shape stabilizes here.

const { Transform } = require('node:stream');
const b = require('../vendor/blamejs');

const C = b.constants;

function createLimiter(opts) {
  opts = opts || {};
  const bytesPerSec = Math.max(0, opts.bytesPerSec | 0);

  // bytesPerSec === 0 → no limit. Return a sentinel that resolves
  // immediately on consume() so the Transform reduces to a pass-through.
  if (bytesPerSec === 0) {
    return { consume() { return Promise.resolve(); }, bytesPerSec: 0 };
  }

  // Bucket holds up to one second's worth of tokens — bursty traffic
  // can drain it in one go, then waits for refill at the configured
  // rate. Lazy refill (computed on each consume) keeps the limiter
  // timer-free.
  const capacity = bytesPerSec;
  let tokens = capacity;
  let last = Date.now();

  function _refill() {
    const now = Date.now();
    const elapsedMs = now - last;
    if (elapsedMs <= 0) return;
    tokens = Math.min(capacity, tokens + (elapsedMs * bytesPerSec / C.TIME.seconds(1)));
    last = now;
  }

  function consume(n) {
    if (n <= 0) return Promise.resolve();
    _refill();
    if (tokens >= n) {
      tokens -= n;
      return Promise.resolve();
    }
    // Need more tokens than we have — sleep until the deficit refills.
    const deficit = n - tokens;
    const waitMs = Math.ceil(deficit / bytesPerSec * C.TIME.seconds(1));
    return new Promise(resolve => {
      setTimeout(() => {
        _refill();
        // Even if a concurrent consumer raced ahead of us, take what we
        // need (going temporarily negative). The deficit just delays the
        // next caller — overall throughput still tracks bytesPerSec.
        tokens -= n;
        resolve();
      }, waitMs);
    });
  }

  return { consume, bytesPerSec };
}

function createTransform(limiter) {
  if (!limiter || limiter.bytesPerSec === 0) {
    return new Transform({
      transform(chunk, _enc, cb) { cb(null, chunk); },
    });
  }
  return new Transform({
    transform(chunk, _enc, cb) {
      limiter.consume(chunk.length).then(() => cb(null, chunk), cb);
    },
  });
}

module.exports = { createLimiter, createTransform };
