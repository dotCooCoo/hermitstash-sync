'use strict';

// Bounded-concurrency promise pool. Each run(fn) returns a promise
// that resolves to fn()'s return value; the pool guarantees no more
// than `concurrency` task functions are in-flight at once. Excess
// run() callers queue until a slot frees, applying back-pressure to
// the producer.
//
// drain() resolves when every queued + in-flight task has settled.
// Tasks that throw are still counted as "settled" — the pool itself
// never rejects; per-task results are returned through their own
// run() promise.
//
// Used by sync-engine to bound parallel uploads (initial-scan fan-out
// + watcher-driven changes) at a configurable cap (default 4).
// Upstream candidate: b.taskPool.create({ concurrency, drainTimeoutMs }).

function create(opts) {
  opts = opts || {};
  const concurrency = Math.max(1, Math.min(64, opts.concurrency | 0 || 4)); // allow:raw-byte-literal — pool sanity cap (count, not bytes)

  let inFlight = 0;
  const queue = [];
  const drainWaiters = [];

  function _maybeDispatch() {
    while (inFlight < concurrency && queue.length > 0) {
      const job = queue.shift();
      inFlight++;
      Promise.resolve()
        .then(job.fn)
        .then(
          v => job.resolve(v),
          e => job.reject(e),
        )
        .finally(() => {
          inFlight--;
          _maybeDispatch();
          if (inFlight === 0 && queue.length === 0 && drainWaiters.length > 0) {
            const w = drainWaiters.splice(0, drainWaiters.length);
            for (const r of w) r();
          }
        });
    }
  }

  return {
    run(fn) {
      return new Promise((resolve, reject) => {
        queue.push({ fn, resolve, reject });
        _maybeDispatch();
      });
    },
    drain() {
      if (inFlight === 0 && queue.length === 0) return Promise.resolve();
      return new Promise(resolve => drainWaiters.push(resolve));
    },
    inFlight() { return inFlight; },
    queueDepth() { return queue.length; },
    concurrency,
  };
}

module.exports = { create };
