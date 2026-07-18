'use strict';

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const { CONFIG_DIR, CONFIG_FILE, DEFAULT_IGNORES } = require('./constants');
const pathFilter = require('./path-filter');
const b = require('../vendor/blamejs');

const C = b.constants;

// Cap on the user's config.json — defensive ceiling against a corrupted
// or attacker-influenced file in the user's CONFIG_DIR. The settings doc
// is human-edited and naturally tiny; 1 MiB is generous.
const CONFIG_MAX_BYTES = C.BYTES.mib(1);

const DEFAULTS = {
  server: '',
  bundleId: '',
  shareId: '',
  syncFolder: '',
  apiKeyRef: 'keychain:hermitstash-sync',
  mtls: null,
  ignore: [],
  include: [],          // selective sync — empty = sync everything; entries = sync ONLY paths matching at least one pattern (then ignore is applied)
  pinnedServerSpki: [], // SPKI pin(s) for the server's TLS leaf cert — strings in `sha256/<base64>` form. Empty array = no pinning (default trust chain wins). Multiple entries support planned rotations (operator includes the new pin alongside the old until the cutover completes).
  maxFileSize: 0,       // per-file upload/download ceiling in bytes; 0 = fall back to the process default (HERMITSTASH_MAX_FILE_BYTES / MAX_SYNC_FILE_BYTES). A non-zero value can only LOWER that default, never raise it (enforced client-side in lib/http-client.js).
  logLevel: 'info',
  autoUpdate: true,     // poll GitHub Releases every 6h and self-replace (SEA only)
  autoUpdateChannel: 'stable', // 'stable' (default, /releases/latest, no prereleases) | 'beta' (includes prereleases)
  uploadConcurrency: 4, // allow:raw-byte-literal — parallel-upload pool concurrency (count, not bytes); clamped 1..16 inside the engine
  uploadBytesPerSec: 0,   // 0 = unlimited; shared across concurrent uploads (token-bucket)
  downloadBytesPerSec: 0, // 0 = unlimited; shared across concurrent downloads (token-bucket)
};

// CONFIG_DIR holds credentials, state.db, the config file, mTLS material, and
// the update marker, so it must not be world-traversable. b.atomicFile.ensureDir
// creates it 0o700 (matching the framework's own atomic-write mkdir) instead of
// relying on the process umask, which leaves it 0o755 under the common 022.
function ensureDir() {
  b.atomicFile.ensureDir(CONFIG_DIR, 0o700);
}

function exists() {
  return nodeFs.existsSync(CONFIG_FILE);
}

// Env-var overlay applied on top of config.json so operators in
// Docker / Kubernetes / Unraid / systemd can tune behavior without
// editing a file in a mounted volume. Documented as HERMITSTASH_*
// in README + the unraid-template; consumed here on every load().
// Validation happens after the overlay, so a typed env value is
// surfaced with the same error path as a typo in config.json.
function _applyEnvOverlay(cfg) {
  const overlay = Object.assign({}, cfg);
  // Maps config key -> the env var that set it, so validate() can blame the
  // env var ("HERMITSTASH_UPLOAD_CONCURRENCY=-5 invalid: ...") instead of the
  // config field a container operator never touched. Non-enumerable so it
  // never serialises back into config.json via save().
  const envSources = {};
  // codebase-patterns:allow inline-block raw-process-env — operator-
  // facing env vars are the documented surface for container deploys.
  const pe = process.env;                                                       // allow:raw-process-env
  function _int(name, key) {
    if (pe[name] === undefined) return;
    // Strict integer only. parseInt() silently drops trailing garbage
    // ("10MB" -> 10) and yields NaN for non-numeric values ("unlimited"),
    // both of which the old `Number.isFinite` guard either accepted as a
    // wrong number or dropped without surfacing — leaving the DEFAULTS value
    // in place while the operator believed their env var took effect (e.g. a
    // believed-but-absent bytes/sec throttle). Require a clean optional-sign
    // integer; otherwise assign the raw string so validate()'s _intGte0
    // rejects it with the env-var name.
    const raw = pe[name].trim();
    // Blank / whitespace-only is "unset", not "malformed": container platforms
    // (Unraid passes Default="" for any advanced variable left blank, Docker
    // Compose `VAR=` / env_file) routinely hand an empty string for an optional
    // numeric. Keep the DEFAULTS value rather than failing validation, matching
    // the _csv blank no-op. Only a non-empty, non-integer value (e.g.
    // "unlimited", "10MB", "-5") is surfaced to validate() with its env-var name.
    if (raw === '') return;
    overlay[key] = /^[+-]?\d+$/.test(raw) ? parseInt(raw, 10) : pe[name];
    envSources[key] = name;
  }
  function _bool(name, key) {
    if (pe[name] === undefined) return;
    // Blank / whitespace-only is "unset", not "false": container platforms
    // (Unraid passes Default="" for any advanced variable left blank, Docker
    // Compose `VAR=` / env_file) routinely hand an empty string for an optional
    // boolean. Without this guard `!/^(0|false|no|off)$/.test('')` is true, so a
    // blank env var would force the value ON and silently override an operator's
    // explicit config.json `false` (e.g. re-enabling the self-replace update
    // path they disabled). Keep the config.json value on blank, matching _int /
    // _csv. Only an explicit non-blank token sets the overlay.
    const raw = pe[name].trim();
    if (raw === '') return;
    overlay[key] = !/^(0|false|no|off)$/i.test(raw);
    envSources[key] = name;
  }
  function _str(name, key) {
    if (typeof pe[name] === 'string' && pe[name].length > 0) { overlay[key] = pe[name]; envSources[key] = name; }
  }
  function _csv(name, key) {
    if (typeof pe[name] !== 'string') return;                 // unset -> keep config.json value
    const parts = pe[name].split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length === 0) return;                           // blank/whitespace-only -> no-op, not a clear
    overlay[key] = parts;
    envSources[key] = name;
  }
  _int('HERMITSTASH_UPLOAD_CONCURRENCY',   'uploadConcurrency');
  _int('HERMITSTASH_UPLOAD_BYTES_PER_SEC', 'uploadBytesPerSec');
  _int('HERMITSTASH_DOWNLOAD_BYTES_PER_SEC', 'downloadBytesPerSec');
  _bool('HERMITSTASH_AUTO_UPDATE',         'autoUpdate');
  _str('HERMITSTASH_AUTO_UPDATE_CHANNEL',  'autoUpdateChannel');
  _str('HERMITSTASH_LOG_LEVEL',            'logLevel');
  _csv('HERMITSTASH_PINNED_SERVER_SPKI',   'pinnedServerSpki');
  _csv('HERMITSTASH_INCLUDE',              'include');
  _csv('HERMITSTASH_IGNORE',               'ignore');
  Object.defineProperty(overlay, '_envSources', { value: envSources, enumerable: false, configurable: true });
  return overlay;
}

// Single home for hostname-level loopback classification (127.0.0.0/8, ::1,
// the "localhost" name). Contract: takes a b.safeUrl.parse-shaped hostname
// (IPv6 arrives bracketed — "[::1]" — and is unbracketed here), special-cases
// the "localhost" NAME (b.ssrfGuard.isLoopback is IP-literal-only), and fails
// closed on any classifier error. Shared with lib/http-client.js's plaintext
// WARN path so the two security-relevant classifications can never drift; the
// refusal POLICY (why loopback may speak plaintext http://) lives at the
// validate() call site below.
function isLoopbackHost(hostname) {
  if (typeof hostname !== 'string' || hostname === '') return false;
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost') return true;
  try { return b.ssrfGuard.isLoopback(h); } catch { return false; }
}

// Deliberate opt-out for an operator who terminates TLS at a trusted proxy and
// must reach it over plaintext on a non-loopback address. Mirrors the
// HERMITSTASH_ALLOW_CLASSICAL_TLS escape hatch in lib/http-client.js. Default
// OFF — https:// is the floor. Read at validate() time so a changed value takes
// effect on the next config load / SIGHUP reload.
function _allowPlaintextServer() {
  const raw = b.safeEnv.readVar('HERMITSTASH_ALLOW_PLAINTEXT', { type: 'string', default: '' });
  return raw === '1' || raw === 'true' || raw === 'yes';
}

function load() {
  // Single TOCTOU-safe read instead of an existsSync pre-flight + a separate
  // readFileSync (a double syscall with a swap window between them): open the
  // file once and bind the bytes to the held inode. ENOENT is mapped to the
  // same actionable "run init first" message the explicit pre-check produced.
  const raw = b.atomicFile.fdSafeReadSync(CONFIG_FILE, {
    encoding: 'utf8',
    maxBytes: CONFIG_MAX_BYTES,
    errorFor: (kind) => kind === 'enoent'
      ? new Error(`Config not found at ${CONFIG_FILE}. Run 'hermitstash-sync init' first.`)
      : new Error(`Config at ${CONFIG_FILE} could not be read (${kind}). Fix or re-run 'hermitstash-sync init'.`),
  });
  // b.safeJson.parse: depth-cap (defends against hand-edited deeply-nested
  // junk), size-cap, and prototype-pollution refusal on `__proto__` / etc.
  // — the user's config.json is human-edited so a typo or paste accident
  // shouldn't mutate Object.prototype.
  const parsed = b.safeJson.parse(raw, { maxBytes: CONFIG_MAX_BYTES });
  // safeJson.parse accepts any valid JSON document — an array, scalar, or null
  // are all "valid JSON" but not a config object. Spreading a non-object into
  // `{ ...DEFAULTS, ...parsed }` silently produces junk (`["x"]` -> `{ 0: 'x' }`,
  // `"oops"` -> `{ 0:'o', 1:'o', ... }`) that then fails validation with a
  // misleading "server is required" instead of naming the real mistake. Assert
  // the root shape up front so a hand-broken top-level type is actionable.
  if (!b.safeJson.isJsonObject(parsed)) {
    const found = Array.isArray(parsed) ? 'array' : parsed === null ? 'null' : typeof parsed;
    throw new Error(
      `Config at ${CONFIG_FILE} must be a JSON object (found ${found}). ` +
      `Fix the JSON, or re-run 'hermitstash-sync init'.`);
  }
  return _applyEnvOverlay({ ...DEFAULTS, ...parsed });
}

// Cap on an operator-authored .hermitstash-ignore / .hermitstash-include file.
// These hold only glob lines, so 256 KiB is far above any realistic list while
// still refusing a bloated/decoy file planted in the (operator- or
// other-writable) sync folder.
const PATTERN_FILE_MAX_BYTES = C.BYTES.kib(256);

// Read a sync-folder pattern file TOCTOU-safely. A missing file is the common
// case (no extra patterns) and maps to []. Any other failure — a symlink swap,
// an over-cap file, an unreadable inode — is suspect for a file living in the
// synced tree, so we FAIL CLOSED with an actionable error rather than silently
// treating it as "no patterns": an unreadable .hermitstash-ignore degrading to
// empty would UPLOAD files the operator meant to exclude (a confidentiality
// regression), and an unreadable .hermitstash-include degrading to empty would
// disable selective sync and upload everything.
function _readPatternFile(file) {
  let raw;
  try {
    raw = b.atomicFile.fdSafeReadSync(file, {
      encoding:      'utf8',
      maxBytes:      PATTERN_FILE_MAX_BYTES,
      refuseSymlink: true,
      errorFor: (kind) => kind === 'enoent'
        ? Object.assign(new Error('no-file'), { _noFile: true })
        : new Error(kind),
    });
  } catch (err) {
    // refuseSymlink lstats the path first, so a genuinely-missing file surfaces
    // as a raw ENOENT from that lstat (before the openSync enoent hook) — treat
    // both the typed sentinel and a raw ENOENT as "no pattern file present".
    if (err && (err._noFile || err.code === 'ENOENT')) return [];
    throw new Error(
      `Cannot read ${file}: ${err.message}. Remove or fix this file ` +
      `(it must be a regular file ≤256 KiB, not a symlink).`);
  }
  return raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
}

function save(config) {
  ensureDir();
  const data = JSON.stringify(config, null, 2) + '\n';
  // b.atomicFile.writeSync: write to a sibling temp file, fsync, rename
  // over the target, fsync the parent dir. A crash mid-write leaves the
  // previous config intact instead of a truncated half-write. The
  // permission bits come from opts.fileMode (opts.mode is ignored); 0o600
  // is already the primitive default but we pass it explicitly so the
  // restrictive mode is visible at the call site.
  b.atomicFile.writeSync(CONFIG_FILE, data, { fileMode: 0o600 });
}

function validate(config) {
  const errors = [];
  // When a value arrived via an env overlay, blame the env var by name —
  // a container operator who set HERMITSTASH_UPLOAD_CONCURRENCY=-5 never
  // touched the `uploadConcurrency` config field and shouldn't be pointed at
  // it. Falls back to the config-field name for hand-edited config.json.
  const envSources = (config && config._envSources) || {};
  const _label = key => (Object.hasOwn(envSources, key) ? envSources[key] : key);
  if (!config.server) errors.push('server is required');
  if (!config.syncFolder) errors.push('syncFolder is required');
  if (!config.bundleId && !config.shareId) errors.push('bundleId or shareId is required');

  // Core identity/path fields must be strings when present. The truthiness
  // gates above don't catch a wrong-typed value: a hand-edited `"bundleId": {}`
  // is truthy so it passes the required check, then serialises into request
  // URLs as "[object Object]"; a non-string syncFolder throws inside
  // path.join on the SIGHUP pattern-reload path, silently discarding the
  // operator's valid pattern edits in that same reload. Name the wrong type
  // here at config-load rather than letting it fail opaquely mid-run.
  for (const k of ['server', 'syncFolder', 'bundleId', 'shareId']) {
    if (config[k] !== undefined && config[k] !== null && typeof config[k] !== 'string') {
      errors.push(`${_label(k)} must be a string, got ${typeof config[k]}`);
    }
  }

  // Validate server URL via b.safeUrl.parse — scheme allowlist + credential
  // refusal + authority normalisation in one pass. A plaintext http:// server
  // is refused for any non-loopback host: it disables TLS, mTLS, the PQC group
  // pinning, and the classical-downgrade guard, shipping the Bearer API key and
  // all sync metadata in cleartext — a direct breach of the "no plaintext on
  // the wire" floor. Loopback (a TLS-terminating sidecar on the same host, or a
  // dev/test target) stays allowed; a deliberate non-loopback plaintext hop
  // requires the explicit HERMITSTASH_ALLOW_PLAINTEXT opt-out.
  if (typeof config.server === 'string' && config.server) {
    let parsedServer = null;
    try {
      parsedServer = b.safeUrl.parse(config.server, { allowedProtocols: ['http:', 'https:'] });
    } catch {
      errors.push(`server "${config.server}" is not a valid URL`);
    }
    if (parsedServer && parsedServer.protocol === 'http:' &&
        !isLoopbackHost(parsedServer.hostname) && !_allowPlaintextServer()) {
      errors.push(
        `server "${config.server}" uses plaintext http:// to a non-loopback host — ` +
        `the API key and all sync traffic would travel unencrypted with no post-quantum ` +
        `TLS protection. Use https:// (the HermitStash server requires PQC-mTLS), or set ` +
        `HERMITSTASH_ALLOW_PLAINTEXT=1 only when you terminate TLS at a trusted loopback proxy.`
      );
    }
  }

  // Validate sync folder exists. Gate on `typeof === 'string'`: a non-string
  // syncFolder is already named by the type check above, and passing a
  // non-string to fs.existsSync is deprecated (DEP0187) and slated to throw.
  if (typeof config.syncFolder === 'string' && config.syncFolder && !nodeFs.existsSync(config.syncFolder)) {
    errors.push(`syncFolder "${config.syncFolder}" does not exist`);
  }

  // mTLS material: null/undefined is valid (no client cert). If present it
  // must be a plain object whose cert/key/ca paths are either ALL absent or
  // ALL present — a partial trio cannot complete an mTLS handshake, so name
  // it at config-load rather than letting the daemon hit an opaque TLS error
  // mid-run. A string/number/array mtls would make the old `if (config.mtls)`
  // truthy while every `config.mtls.cert` access returned undefined, so it
  // passed validation then failed at the handshake; reject the shape here.
  if (config.mtls !== null && config.mtls !== undefined) {
    if (typeof config.mtls !== 'object' || Array.isArray(config.mtls)) {
      errors.push(`${_label('mtls')} must be null or an object with cert/key/ca paths, got ${typeof config.mtls}`);
    } else {
      const have = ['cert', 'key', 'ca'].filter(k => config.mtls[k] !== undefined && config.mtls[k] !== null);
      if (have.length > 0 && have.length < 3) {
        const missing = ['cert', 'key', 'ca'].filter(k => config.mtls[k] === undefined || config.mtls[k] === null);
        errors.push(`${_label('mtls')} requires cert, key, and ca together — missing: ${missing.join(', ')}. Re-enroll with "hermitstash-sync init".`);
      }
      for (const [k, lbl] of [['cert', 'cert'], ['key', 'key'], ['ca', 'CA']]) {
        const v = config.mtls[k];
        if (v !== undefined && v !== null && typeof v !== 'string') {
          errors.push(`${_label('mtls')}.${k} must be a string path, got ${typeof v}`);
        } else if (typeof v === 'string' && !nodeFs.existsSync(v)) {
          errors.push(`mTLS ${lbl} "${v}" does not exist`);
        }
      }
    }
  }

  // Bound the tuning knobs added in v0.8.1 — v0.8.12 so a typo is
  // surfaced at config-load time instead of the daemon hitting it
  // mid-run. Numeric fields must be non-negative integers; range
  // clamps still apply at use-site, but a wildly out-of-range value
  // (negative concurrency, bytesPerSec of "yes please") shouldn't
  // silently degrade behavior. Pre-v0.8.13 these all passed through.
  function _intGte0(name) {
    if (config[name] === undefined) return;
    if (!Number.isInteger(config[name]) || config[name] < 0) {
      errors.push(`${_label(name)} must be a non-negative integer, got ${JSON.stringify(config[name])}`);
    }
  }
  _intGte0('uploadConcurrency');
  _intGte0('uploadBytesPerSec');
  _intGte0('downloadBytesPerSec');
  _intGte0('maxFileSize');

  if (config.autoUpdateChannel !== undefined &&
      config.autoUpdateChannel !== 'stable' &&
      config.autoUpdateChannel !== 'beta') {
    errors.push(`${_label('autoUpdateChannel')} must be 'stable' or 'beta', got ${JSON.stringify(config.autoUpdateChannel)}`);
  }

  // autoUpdate gates the in-binary self-replace path, which is checked at
  // use-site with a strict `!== false` (only the boolean false disables it).
  // A hand-edited non-boolean — most naturally a quoted "false", or 0/null —
  // is therefore truthy-for-the-gate and silently leaves self-replace ENABLED,
  // the opposite of what an operator writing `"autoUpdate": "false"` intends.
  // The env-overlay path already coerces this; the config.json path must too.
  // Reject it at load so the daemon fails fast with an actionable message
  // instead of self-updating a binary the operator believed was pinned.
  if (config.autoUpdate !== undefined && typeof config.autoUpdate !== 'boolean') {
    errors.push(`${_label('autoUpdate')} must be true or false (an unquoted JSON boolean, not a quoted string), got ${JSON.stringify(config.autoUpdate)}`);
  }

  // include + ignore must be arrays of strings; non-string entries
  // would crash the matcher on first use.
  function _stringArray(name) {
    if (config[name] === undefined) return;
    if (!Array.isArray(config[name])) {
      errors.push(`${_label(name)} must be an array, got ${typeof config[name]}`);
      return;
    }
    for (let i = 0; i < config[name].length; i++) {
      if (typeof config[name][i] !== 'string') {
        errors.push(`${_label(name)}[${i}] must be a string, got ${typeof config[name][i]}`);
      }
    }
  }
  _stringArray('include');
  _stringArray('ignore');

  // SPKI pins must be `sha256/<base64>` strings (HPKP / Apple
  // TrustEvaluation shape). A malformed pin would silently match
  // nothing and refuse every connection — better caught here.
  if (config.pinnedServerSpki !== undefined) {
    if (!Array.isArray(config.pinnedServerSpki)) {
      errors.push(`${_label('pinnedServerSpki')} must be an array of "sha256/<base64>" strings`);
    } else {
      for (let i = 0; i < config.pinnedServerSpki.length; i++) {
        const p = config.pinnedServerSpki[i];
        if (typeof p !== 'string' || !/^sha256\/[A-Za-z0-9+/]{43}=$/.test(p)) {
          errors.push(`${_label('pinnedServerSpki')}[${i}] must match "sha256/<43-char-base64>=", got ${JSON.stringify(p)}`);
        }
      }
    }
  }

  if (config.logLevel !== undefined &&
      ['debug', 'info', 'warn', 'error'].indexOf(config.logLevel) === -1) {
    errors.push(`${_label('logLevel')} must be one of debug/info/warn/error, got ${JSON.stringify(config.logLevel)}`);
  }

  return errors;
}

/**
 * Get all ignore patterns (defaults + user config + .hermitstash-ignore file)
 */
function getIgnorePatterns(config) {
  const patterns = [...DEFAULT_IGNORES];

  if (config.ignore && Array.isArray(config.ignore)) {
    patterns.push(...config.ignore);
  }

  // Check for .hermitstash-ignore in sync folder. Gate on `typeof === 'string'`
  // (not bare truthiness): validate() only WARNS on a non-string syncFolder on
  // the SIGHUP reload path, so a wrong-typed value can still reach here — and
  // path.join(nonString, ...) throws, which daemon.js swallows as "keeping
  // previous patterns", silently discarding the operator's valid pattern edits
  // in the same reload. Degrade to "no pattern file" instead of throwing.
  if (typeof config.syncFolder === 'string' && config.syncFolder) {
    const ignoreFile = nodePath.join(config.syncFolder, '.hermitstash-ignore');
    patterns.push(..._readPatternFile(ignoreFile));
  }

  // Drop any non-string entry. A hand-edited config.json `ignore` array can
  // carry a number/boolean/object; validate() warns on it (and die()s on the
  // start path), but the SIGHUP reload path only warns and continues, so a
  // non-string would otherwise flow on to the pattern matcher — where
  // `_matchPattern` calls `.includes` on it and throws — and to
  // warnUnsupportedPatterns. A non-string can never match a path, so dropping
  // it here is the correct, crash-free behavior; the operator still hears
  // about it via validate()'s string-array check.
  return [...new Set(patterns)].filter(p => typeof p === 'string'); // dedupe + string-only
}

/**
 * Get all include (allowlist) patterns — config.include plus an
 * optional .hermitstash-include file in the sync folder. Empty
 * result = sync everything (selective sync disabled); non-empty =
 * sync ONLY paths matching at least one entry.
 */
function getIncludePatterns(config) {
  const patterns = [];

  if (config.include && Array.isArray(config.include)) {
    patterns.push(...config.include);
  }

  // Same `typeof === 'string'` gate as getIgnorePatterns: a non-string
  // syncFolder on the reload path must degrade to "no pattern file" rather than
  // throw inside path.join and drop the operator's valid edits.
  if (typeof config.syncFolder === 'string' && config.syncFolder) {
    const includeFile = nodePath.join(config.syncFolder, '.hermitstash-include');
    patterns.push(..._readPatternFile(includeFile));
  }

  // String-only, for the same reason as getIgnorePatterns: a non-string
  // include entry can never match and would crash the matcher / warn helper.
  return [...new Set(patterns)].filter(p => typeof p === 'string');
}

// Shape-specific remediation for a pattern the matcher treats literally (and
// so silently never matches). Each branch tells the operator exactly what to
// type instead — the matcher's grammar is narrow and documented, so a mistyped
// glob is an operator error we can name precisely rather than a hard failure.
function _unsupportedPatternHelp(pattern) {
  // classifyPattern reports a non-string as 'unsupported', so this helper can
  // be reached with one. Guard before any string method runs — warnUnsupportedPatterns
  // documents a "never throw" contract, and a TypeError here would abort the
  // whole SIGHUP pattern reload (dropping valid edits in the same batch).
  if (typeof pattern !== 'string') {
    return `is a ${pattern === null ? 'null' : typeof pattern}, not a string; every ignore/include entry must be a quoted string — it will match nothing`;
  }
  if (pattern.startsWith('/')) {
    const fixed = pattern.replace(/^\/+/, '');
    return `is anchored with a leading '/', which is not honored here; drop the leading slash → '${fixed}'`;
  }
  if (pattern.endsWith('/')) {
    return `matches nothing; a trailing-slash bare directory is not honored — use '${pattern}**' to match the directory subtree`;
  }
  if (pattern.includes('[') || pattern.includes(']')) {
    return `uses a character range, which is unsupported; only '*.ext' and '*~' wildcards are honored — list extensions explicitly instead (e.g. '*.o','*.a')`;
  }
  if (pattern.includes('?')) {
    return `uses a '?' single-char wildcard, which is unsupported; only '*.ext' and '*~' wildcards are honored — it will match nothing`;
  }
  if (pattern.includes('!')) {
    return `uses '!' negation, which is unsupported and treated literally; it will match nothing`;
  }
  if (pattern.includes('**')) {
    return `uses a mid-path '**', which is unsupported; only a single trailing '/**' recursive-dir is honored — it will match nothing`;
  }
  if (pattern.includes('*')) {
    return `uses a prefix/infix '*', which is unsupported; only '*.ext' and '*~' are special — it will match nothing`;
  }
  return `uses an unsupported glob shape; only basename, '*.ext', '*~', a trailing '/**', a path-qualified directory, or an exact path are honored — it will match nothing`;
}

/**
 * Warn (never throw) on any include/ignore pattern that uses a shape the
 * matcher does not support. An unsupported pattern silently matches nothing,
 * so a mistyped glob would either upload a file class the operator meant to
 * exclude (ignore) or drop one they meant to keep (include). We surface that
 * loudly at config load with shape-specific remediation and the fail direction
 * so the stakes are unambiguous. `log` is the lib/logger.js surface (or any
 * { warn } shim in tests). Returns the list of unsupported entries for callers
 * that want to assert on it.
 */
function warnUnsupportedPatterns(patterns, kind, log) {
  const unsupported = [];
  if (!Array.isArray(patterns)) return unsupported;
  // ignore: a no-op pattern means the file class is UPLOADED.
  // include: a no-op pattern means matching files are NOT synced.
  const consequence = kind === 'include'
    ? 'matching files will NOT be synced'
    : 'this file class will be UPLOADED';
  for (const pattern of patterns) {
    if (pathFilter.classifyPattern(pattern) !== 'unsupported') continue;
    unsupported.push(pattern);
    if (log && typeof log.warn === 'function') {
      log.warn(`${kind} pattern '${pattern}' ${_unsupportedPatternHelp(pattern)} — ${consequence}`);
    }
  }
  return unsupported;
}

module.exports = { exists, load, save, validate, ensureDir, getIgnorePatterns, getIncludePatterns, warnUnsupportedPatterns, isLoopbackHost, DEFAULTS };
