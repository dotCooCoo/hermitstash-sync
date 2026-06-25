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
const DEFAULT_LOG_MAX_MIB = 10;         // 10 MiB per file (default), in MiB
const MAX_LOG_SIZE = C.BYTES.mib(DEFAULT_LOG_MAX_MIB);
const KEEP_ROTATIONS = 5;               // retained gzipped rotations (default)

// Operator overrides for the rotation policy. Both floor at 1 and ignore
// non-positive / non-numeric values (falling back to the desktop default)
// so a typo can't disable rotation or wipe the retained history.
function _resolveMaxLogBytes() {
  // readVar with type:'number' rejects unit-suffixed garbage ('10MiB' → throw)
  // that the old parseInt silently truncated to 10. The default is the MiB
  // count (not bytes) so the absent path flows through the same C.BYTES.mib()
  // conversion as a valid override. Number.isInteger also rejects float/Infinity
  // the old parseInt would have truncated.
  let raw;
  try { raw = b.safeEnv.readVar('HERMITSTASH_LOG_MAX_MIB', { type: 'number', default: DEFAULT_LOG_MAX_MIB }); }
  catch { return MAX_LOG_SIZE; } // present-but-garbage → default, never crash boot
  return (Number.isInteger(raw) && raw >= 1) ? C.BYTES.mib(raw) : MAX_LOG_SIZE;
}
function _resolveKeepRotations() {
  let raw;
  try { raw = b.safeEnv.readVar('HERMITSTASH_LOG_KEEP_ROTATIONS', { type: 'number', default: KEEP_ROTATIONS }); }
  catch { return KEEP_ROTATIONS; }
  return (Number.isInteger(raw) && raw >= 1) ? raw : KEEP_ROTATIONS;
}

let _level = LEVELS.info;
let _stdout = true;
let _initialized = false;

function init(opts = {}) {
  // Sanitize the level ONCE and feed the same validated value to both the local
  // numeric gate and the b.logStream sink. Previously the local gate silently
  // tolerated an unknown level (kept the default) while opts.level was passed
  // raw to b.logStream.init, which THROWS INVALID_LEVEL on anything outside
  // debug/info/warn/error — so a typo'd level (e.g. 'verbose') was accepted
  // here yet crashed the unguarded init call. The loud rejection still happens
  // at config.validate() on the start path; admin paths (resync) that skip it
  // now degrade gracefully to 'info' instead of throwing.
  const lvl = (opts.level && LEVELS[opts.level] !== undefined) ? opts.level : 'info';
  _level = LEVELS[lvl];
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

  // Symlink-attack defence on the active log path. The 0o700 dir above removes
  // an attacker's ability to plant a symlink in the first place; the local sink
  // then opens the active file with O_NOFOLLOW append (via
  // b.atomicFile.openAppendNoFollowSync), so a symlink re-planted in the race
  // window is refused atomically at open time — there is no separate user-land
  // check that could lose the race. b.logStream.init throws a SYMLINK_REFUSED
  // LogStreamError in that case, which we translate below into an actionable
  // message.
  const activePath = nodePath.join(dir, base + '.log');

  if (_initialized) {
    // b.logStream.init is idempotent (returns early on second call), so
    // re-init under a different config requires a shutdown first. Tests
    // that re-init within a process need this branch.
    b.logStream.shutdown();
    _initialized = false;
  }

  try {
    b.logStream.init({
      minLevel: lvl,
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
  } catch (err) {
    // The sink refuses a symlinked active path atomically at open time. Surface
    // the framework's typed SYMLINK_REFUSED outcome as the actionable message
    // operators expect rather than an opaque framework error code.
    if (err && (err.code === 'SYMLINK_REFUSED' || /symlink/i.test(err.message || ''))) {
      throw new Error(
        `log path ${activePath} is a symlink — refusing to write logs through it. ` +
        `Remove it and restart, and ensure only the daemon owner can write ${dir}.`);
    }
    throw err;
  }
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
  // Exposed so the diagnose bundle can size its decompression-bomb cap off the
  // SAME configured rotation policy rather than a hardcoded constant that would
  // silently drop logs once an operator raises HERMITSTASH_LOG_MAX_MIB. A single
  // rotated .log.gz decompresses to at most one rotation's worth of bytes.
  resolveMaxLogBytes: _resolveMaxLogBytes,
};
