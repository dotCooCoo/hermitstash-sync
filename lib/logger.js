'use strict';

const nodeFs = require('node:fs');
const nodePath = require('node:path');
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
// The active file is <prefix>.log; the framework sink rotates to
// <prefix>-<UTC-timestamp>.log.gz, retaining the newest KEEP_ROTATIONS.
// Long-running deployments override the size + retention via
// HERMITSTASH_LOG_MAX_MIB and HERMITSTASH_LOG_KEEP_ROTATIONS (read in
// init() below).

const C = b.constants;
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const MAX_LOG_SIZE = C.BYTES.mib(10);   // 10 MiB per file (default)
const KEEP_ROTATIONS = 5;               // retained gzipped rotations (default)

// Operator overrides for the rotation policy. Both floor at 1 and ignore
// non-positive / non-numeric values (falling back to the desktop default)
// so a typo can't disable rotation or wipe the retained history.
function _resolveMaxLogBytes() {
  const raw = parseInt(b.safeEnv.readVar('HERMITSTASH_LOG_MAX_MIB', { type: 'string', default: '' }), 10);
  return (Number.isFinite(raw) && raw >= 1) ? C.BYTES.mib(raw) : MAX_LOG_SIZE;
}
function _resolveKeepRotations() {
  const raw = parseInt(b.safeEnv.readVar('HERMITSTASH_LOG_KEEP_ROTATIONS', { type: 'string', default: '' }), 10);
  return (Number.isFinite(raw) && raw >= 1) ? raw : KEEP_ROTATIONS;
}

let _level = LEVELS.info;
let _stdout = true;
let _initialized = false;

function init(opts = {}) {
  if (opts.level && LEVELS[opts.level] !== undefined) {
    _level = LEVELS[opts.level];
  }
  if (opts.stdout === false) _stdout = false;

  const logPath = opts.file || LOG_FILE;
  const dir = nodePath.dirname(logPath);
  const base = nodePath.basename(logPath, nodePath.extname(logPath));

  // Create the log dir 0o700 (not the umask-default 0o755). This is the most
  // effective mitigation for the symlink race below: a non-owner cannot plant a
  // symlink in a dir only the owner can write. On POSIX, tighten an existing
  // dir an older version created loosely. b.atomicFile.ensureDir applies the
  // restrictive mode on creation.
  b.atomicFile.ensureDir(dir, 0o700);
  if (process.platform !== 'win32') {
    try {
      const dst = nodeFs.statSync(dir);
      if ((dst.mode & 0o077) !== 0) nodeFs.chmodSync(dir, 0o700);
    } catch { /* best-effort tightening; absence/race is harmless */ }
  }

  // Symlink-attack defence: if the active log path is a symlink, drop it
  // before b.logStream's local sink opens an append-mode fd at that path.
  // Without this, an attacker with write access to the parent dir could
  // redirect logs to an arbitrary file via a pre-planted symlink. The check
  // and the sink's open are separate syscalls, so this pre-check narrows but
  // cannot close the race on its own — the 0o700 dir above is what removes the
  // attacker's ability to plant the symlink, and the post-open verification
  // below refuses loudly if one slipped through anyway.
  const activePath = nodePath.join(dir, base + '.log');
  try {
    const stat = nodeFs.lstatSync(activePath);
    if (stat.isSymbolicLink()) nodeFs.unlinkSync(activePath);
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
        maxFileBytes:      _resolveMaxLogBytes(),
        keepRotations:     _resolveKeepRotations(),
        compressRotations: true,
        fileMode:          0o600,
      },
    },
  });
  _initialized = true;

  // Post-open verification: the local sink opens the active file with a plain
  // append flag (no O_NOFOLLOW), so a symlink re-planted in the window between
  // the pre-check above and the sink's open would be followed. Confirm the
  // active path the sink just opened is a regular file; if it is a symlink the
  // race was lost — tear the sink down and refuse rather than stream logs into
  // an attacker-chosen file. An atomic O_NOFOLLOW append in the sink itself is
  // the complete fix and is tracked upstream.
  try {
    const post = nodeFs.lstatSync(activePath);
    if (post.isSymbolicLink()) {
      b.logStream.shutdown();
      _initialized = false;
      throw new Error(
        `log path ${activePath} is a symlink — refusing to write logs through it. ` +
        `Remove it and restart, and ensure only the daemon owner can write ${dir}.`);
    }
  } catch (err) {
    if (err && /refusing to write logs/.test(err.message)) throw err;
    /* lstat ENOENT/race on a non-symlink path is benign — the sink owns the file */
  }
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
    // Run `data` through the same redactor (b.redact, which b.logStream
    // applies to the file sink) before it reaches stdout — otherwise a secret
    // in `data` would be masked in the rotated log file but printed verbatim
    // to journald / Docker logs / the terminal. Mirror the file sink's meta
    // shape so the two sinks mask identically.
    let display;
    if (data instanceof Error) {
      const safe = b.redact.redact({ error: { message: data.message } });
      display = `${msg}: ${safe.error.message}`;
    } else if (data !== undefined) {
      const safe = b.redact.redact({ data });
      display = `${msg} ${typeof data === 'object' ? JSON.stringify(safe.data) : safe.data}`;
    } else {
      display = msg;
    }
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
