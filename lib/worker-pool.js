'use strict';

const { Worker } = require('node:worker_threads');
const os = require('node:os');
const log = require('./logger');

/**
 * Generic worker thread pool.
 * Maintains a fixed set of workers and dispatches tasks via a queue.
 * Each worker runs a script that receives { id, task } and posts back { id, result } or { id, error }.
 */
class WorkerPool {
  /**
   * @param {string} workerScript  Absolute path to the worker .js file
   * @param {object} [opts]
   * @param {number} [opts.size]   Pool size (default: CPU cores, min 2, max 8)
   */
  constructor(workerScript, opts = {}) {
    const cpus = os.availableParallelism ? os.availableParallelism() : os.cpus().length;
    this._size = Math.min(Math.max(opts.size || cpus, 2), 8);
    this._workerScript = workerScript;
    this._workers = [];
    this._idle = [];
    this._queue = [];          // pending tasks: { task, resolve, reject, id }
    this._pending = new Map(); // id -> { resolve, reject }
    this._nextId = 1;
    this._destroyed = false;
    this._totalDispatched = 0;
    this._totalCompleted = 0;

    this._spawn();
  }

  get size() { return this._size; }
  get queued() { return this._queue.length; }
  get active() { return this._pending.size; }
  get stats() {
    return {
      poolSize: this._size,
      queued: this._queue.length,
      active: this._pending.size,
      totalDispatched: this._totalDispatched,
      totalCompleted: this._totalCompleted,
    };
  }

  _spawn() {
    for (var i = 0; i < this._size; i++) {
      var w = new Worker(this._workerScript);
      w._poolIndex = i;
      w.on('message', msg => this._onMessage(w, msg));
      w.on('error', err => this._onError(w, err));
      w.on('exit', code => this._onExit(w, code));
      this._workers.push(w);
      this._idle.push(w);
    }
    log.debug('Worker pool started', { size: this._size, script: this._workerScript });
  }

  /**
   * Submit a task to the pool. Returns a promise that resolves with the worker's result.
   * @param {*} task  Serializable data sent to the worker
   * @returns {Promise<*>}
   */
  run(task) {
    if (this._destroyed) return Promise.reject(new Error('Pool is destroyed'));

    return new Promise((resolve, reject) => {
      var id = this._nextId++;
      this._totalDispatched++;

      if (this._idle.length > 0) {
        this._dispatch(this._idle.shift(), { id, task, resolve, reject });
      } else {
        this._queue.push({ id, task, resolve, reject });
      }
    });
  }

  /**
   * Submit multiple tasks and return all results (parallel).
   * @param {Array<*>} tasks
   * @returns {Promise<Array<*>>}
   */
  runBatch(tasks) {
    return Promise.all(tasks.map(t => this.run(t)));
  }

  _dispatch(worker, job) {
    this._pending.set(job.id, { resolve: job.resolve, reject: job.reject });
    worker.postMessage({ id: job.id, task: job.task });
  }

  _onMessage(worker, msg) {
    var job = this._pending.get(msg.id);
    if (!job) return;
    this._pending.delete(msg.id);
    this._totalCompleted++;

    if (msg.error) {
      job.reject(new Error(msg.error));
    } else {
      job.resolve(msg.result);
    }

    // Dispatch next queued task or return worker to idle
    if (this._queue.length > 0) {
      this._dispatch(worker, this._queue.shift());
    } else {
      this._idle.push(worker);
    }
  }

  _onError(worker, err) {
    log.error('Worker thread error', { index: worker._poolIndex, error: err.message });
    // Reject all pending tasks for this worker — but we can't tell which one,
    // so just let the exit handler deal with respawning
  }

  _onExit(worker, code) {
    if (this._destroyed) return;

    // Remove from idle list if present
    var idleIdx = this._idle.indexOf(worker);
    if (idleIdx !== -1) this._idle.splice(idleIdx, 1);

    // Respawn the worker
    log.warn('Worker exited unexpectedly, respawning', { index: worker._poolIndex, code });
    var idx = worker._poolIndex;
    var w = new Worker(this._workerScript);
    w._poolIndex = idx;
    w.on('message', msg => this._onMessage(w, msg));
    w.on('error', err => this._onError(w, err));
    w.on('exit', c => this._onExit(w, c));
    this._workers[idx] = w;

    // Put new worker to work immediately if queue has items
    if (this._queue.length > 0) {
      this._dispatch(w, this._queue.shift());
    } else {
      this._idle.push(w);
    }
  }

  /**
   * Gracefully shut down all workers. Pending tasks are rejected.
   */
  async destroy() {
    if (this._destroyed) return;
    this._destroyed = true;

    // Reject all queued tasks
    for (var job of this._queue) {
      job.reject(new Error('Pool destroyed'));
    }
    this._queue = [];

    // Reject all pending tasks
    for (var [, job] of this._pending) {
      job.reject(new Error('Pool destroyed'));
    }
    this._pending.clear();

    // Terminate all workers
    var exits = this._workers.map(w => w.terminate());
    await Promise.all(exits);

    this._workers = [];
    this._idle = [];
    log.debug('Worker pool destroyed');
  }
}

module.exports = WorkerPool;
