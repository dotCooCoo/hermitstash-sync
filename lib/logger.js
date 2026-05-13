'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LOG_FILE } = require('./constants');
const b = require('../vendor/blamejs');

// Thin shim over `b.logStream` — gives us the framework's redaction-before-
// emit, size + age rotation, and gzip-retained backups without owning that
// plumbing in-tree. The shim preserves the existing init/close/debug/info/
// warn/error surface (113 call sites across lib/) and adds the colour-coded
// stdout output b.logStream doesn't provide (its sinks are file/syslog/otlp/
// cloudwatch, not TTY).
//
// Rotation policy is tuned for desktop / daemon use, not operator-grade
// volume: 10 MiB per file, 5 retained gzipped rotations (~50 MiB ceiling).
// For long-running deployments operators can override these via env.

const C = b.constants;
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const MAX_LOG_SIZE = C.BYTES.mib(10);   // 10 MiB per file
const KEEP_ROTATIONS = 5;               // .log.1.gz .. .log.5.gz

let _level = LEVELS.info;
let _stdout = true;
let _initialized = false;

function init(opts = {}) {
  if (opts.level && LEVELS[opts.level] !== undefined) {
    _level = LEVELS[opts.level];
  }
  if (opts.stdout === false) _stdout = false;

  const logPath = opts.file || LOG_FILE;
  const dir = path.dirname(logPath);
  const base = path.basename(logPath, path.extname(logPath));

  fs.mkdirSync(dir, { recursive: true });

  // Symlink-attack defence: if the active log path is a symlink, drop it
  // before b.logStreamLocal opens an append-mode fd at that path. Without
  // this, an attacker with write access to the parent dir could redirect
  // logs to an arbitrary file via a pre-planted symlink.
  const activePath = path.join(dir, base + '.log');
  try {
    const stat = fs.lstatSync(activePath);
    if (stat.isSymbolicLink()) fs.unlinkSync(activePath);
  } catch { /* ENOENT is fine */ }

  if (_initialized) {
    // b.logStream.init is idempotent (returns early on second call), so
    // re-init under a different config requires a shutdown first. Tests
    // that re-init within a process need this branch.
    b.logStream.shutdown();
    _initialized = false;
  }

  b.logStream.init({
    minLevel: opts.level || 'info',
    sinks: {
      file: {
        protocol:          'local',
        dir:               dir,
        fileNamePrefix:    base,
        maxFileBytes:      MAX_LOG_SIZE,
        keepRotations:     KEEP_ROTATIONS,
        compressRotations: true,
        fileMode:          0o600,
      },
    },
  });
  _initialized = true;
}

function _emit(level, msg, data) {
  if (LEVELS[level] < _level) return;

  // Forward to b.logStream (file sink with rotation + redaction). Pass
  // metadata as an object so b.logStream's redactor can scan it for PHI/
  // PCI patterns; Errors get unwrapped to { message, stack } so the JSON
  // serialiser doesn't drop the stack.
  if (_initialized) {
    let meta;
    if (data instanceof Error) meta = { error: { message: data.message, stack: data.stack } };
    else if (data !== undefined) meta = { data: data };
    b.logStream.emit(level, msg, meta);
  }

  if (_stdout) {
    const ts = new Date().toISOString().slice(11, 19);
    const prefix = level === 'error' ? '\x1b[31m'
      : level === 'warn'  ? '\x1b[33m'
      : level === 'debug' ? '\x1b[90m' : '';
    const reset = prefix ? '\x1b[0m' : '';
    const display = data instanceof Error
      ? `${msg}: ${data.message}`
      : data !== undefined
        ? `${msg} ${typeof data === 'object' ? JSON.stringify(data) : data}`
        : msg;
    process.stdout.write(`${prefix}[${ts}] ${level.toUpperCase().padEnd(5)} ${display}${reset}\n`);
  }
}

function close() {
  if (!_initialized) return Promise.resolve();
  _initialized = false;
  // b.logStream.shutdown drains in-flight emits before closing fds. Return
  // the Promise so callers in async shutdown handlers can await; the
  // existing sync call sites (`log.close()` without await) still work —
  // they just don't block on the drain. Drain timeout is short (~ms) so
  // missed-await isn't a meaningful regression.
  return b.logStream.shutdown();
}

module.exports = {
  init,
  close,
  debug: (msg, data) => _emit('debug', msg, data),
  info:  (msg, data) => _emit('info', msg, data),
  warn:  (msg, data) => _emit('warn', msg, data),
  error: (msg, data) => _emit('error', msg, data),
};
