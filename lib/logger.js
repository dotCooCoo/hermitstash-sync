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

// Register an in-string `Bearer <token>` value detector on the process-wide
// redaction chain, once at module load (registerValueDetector has no dedupe;
// module scope — not init(), which re-runs). The built-in detectors are
// anchored to full-string or structured shapes (a whole-string JWT, a URL
// query, user:pass@), so a resolved bearer credential EMBEDDED in a longer
// string — an error echoing a request header — passed every one of them.
// Function-form replacement masks only the token, in place. Case-insensitive:
// RFC 9110 auth schemes match case-insensitively. Known trade-off: a
// non-secret phrase shaped like `Bearer <8+ chars>` over-masks; masking too
// much beats leaking a credential. The diagnose bundle keeps its bundle-time
// pass for bytes written before this detector existed.
// Two regex instances: .test() must NOT use the g flag (a g-flagged regex
// carries lastIndex across calls and alternates false negatives), while
// .replace() needs g to mask every occurrence in the string.
const BEARER_IN_STRING_TEST = /\b(bearer)\s+[A-Za-z0-9._~+\/=-]{8,}/i;
const BEARER_IN_STRING_ALL  = /\b(bearer)\s+[A-Za-z0-9._~+\/=-]{8,}/gi;
b.redact.registerValueDetector(
  'bearer-in-string',
  (v) => typeof v === 'string' && BEARER_IN_STRING_TEST.test(v),
  (v) => String(v).replace(BEARER_IN_STRING_ALL, '$1 [REDACTED-CREDENTIAL]')
);
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

async function init(opts = {}) {
  // Sanitize the level ONCE and feed the same validated value to both the local
  // numeric gate and the b.logStream sink. Previously the local gate silently
  // tolerated an unknown level (kept the default) while opts.level was passed
  // raw to b.logStream.init, which THROWS INVALID_LEVEL on anything outside
  // debug/info/warn/error — so a typo'd level (e.g. 'verbose') was accepted
  // here yet crashed the unguarded init call. The loud rejection still happens
  // at config.validate() on the start path; admin paths (resync) that skip it
  // now degrade gracefully to 'info' instead of throwing.
  // Own-property membership, not a truthiness/undefined read: a level named
  // after an inherited object member ('constructor', 'toString') would
  // otherwise resolve to the prototype function, slip this sanitize, and
  // crash the unvalidated resync-path init the fallback exists to protect.
  const lvl = (typeof opts.level === 'string' && Object.hasOwn(LEVELS, opts.level)) ? opts.level : 'info';
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
    // b.logStream.init is idempotent (returns early while still initialized), so
    // re-init under a different config requires a shutdown first. shutdown() is
    // async and only clears the framework's initialized flag AFTER awaiting the
    // drain + sink close — so we MUST await it; a fire-and-forget shutdown
    // returns with the flag still set, the next init() no-ops, the new sink is
    // never opened, and every subsequent record is silently dropped. A fresh
    // (first) init has nothing to await, so the boot path is unchanged.
    await b.logStream.shutdown();
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
  // Own-property resolution: an unknown or inherited-member level name from a
  // future call site would make `LEVELS[level] < _level` an always-false NaN
  // comparison and skip the gate entirely; treat it as 'info' instead.
  const lvlNum = Object.hasOwn(LEVELS, level) ? LEVELS[level] : LEVELS.info;
  if (lvlNum < _level) return;

  // Redact the MESSAGE string itself before any sink sees it. b.logStream's
  // emit runs b.redact only over meta — record.message reaches every sink
  // verbatim — so a credential interpolated into a free-form message (an
  // error echoing an Authorization header) would land in the rotated log
  // file and on stdout unmasked. A top-level string traverses the full
  // detector chain, including the bearer-in-string detector registered
  // above. Reported upstream against b.logStream; this stays load-bearing
  // until the framework redacts record.message itself.
  const safeMsg = typeof msg === 'string' ? b.redact.redact(msg) : msg;

  // Forward to b.logStream (file sink with rotation + redaction). Pass
  // metadata as an object so b.logStream's redactor can scan it for PHI/
  // PCI patterns; Errors get unwrapped to { message, stack } so the JSON
  // serialiser doesn't drop the stack.
  if (_initialized) {
    let meta;
    if (data instanceof Error) meta = { error: { message: data.message, stack: data.stack } };
    else if (data !== undefined) meta = { data: data };
    b.logStream.emit(level, safeMsg, meta);
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
      display = `${safeMsg}: ${safe.error.message}`;
    } else if (data !== undefined) {
      const safe = b.redact.redact({ data });
      display = `${safeMsg} ${typeof data === 'object' ? JSON.stringify(safe.data) : safe.data}`;
    } else {
      display = safeMsg;
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
