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
  maxFileSize: 0,       // 0 = no limit (server enforces its own limits)
  logLevel: 'info',
  autoUpdate: true,     // poll GitHub Releases every 6h and self-replace (SEA only)
  autoUpdateChannel: 'stable', // 'stable' (default, /releases/latest, no prereleases) | 'beta' (includes prereleases)
  uploadConcurrency: 4, // allow:raw-byte-literal — parallel-upload pool concurrency (count, not bytes); clamped 1..16 inside the engine
  uploadBytesPerSec: 0,   // 0 = unlimited; shared across concurrent uploads (token-bucket)
  downloadBytesPerSec: 0, // 0 = unlimited; shared across concurrent downloads (token-bucket)
};

function ensureDir() {
  nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
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
    const n = parseInt(pe[name], 10);
    if (Number.isFinite(n)) { overlay[key] = n; envSources[key] = name; }
  }
  function _bool(name, key) {
    if (pe[name] === undefined) return;
    overlay[key] = !/^(0|false|no|off)$/i.test(pe[name]);
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

function load() {
  if (!exists()) {
    throw new Error(`Config not found at ${CONFIG_FILE}. Run 'hermitstash-sync init' first.`);
  }
  const raw = nodeFs.readFileSync(CONFIG_FILE, 'utf8');
  // b.safeJson.parse: depth-cap (defends against hand-edited deeply-nested
  // junk), size-cap, and prototype-pollution refusal on `__proto__` / etc.
  // — the user's config.json is human-edited so a typo or paste accident
  // shouldn't mutate Object.prototype.
  const parsed = b.safeJson.parse(raw, { maxBytes: CONFIG_MAX_BYTES });
  return _applyEnvOverlay({ ...DEFAULTS, ...parsed });
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
  const _label = key => envSources[key] || key;
  if (!config.server) errors.push('server is required');
  if (!config.syncFolder) errors.push('syncFolder is required');
  if (!config.bundleId && !config.shareId) errors.push('bundleId or shareId is required');

  // Validate server URL via b.safeUrl.parse — scheme allowlist + credential
  // refusal + authority normalisation in one pass.
  if (config.server) {
    try {
      b.safeUrl.parse(config.server, { allowedProtocols: ['http:', 'https:'] });
    } catch {
      errors.push(`server "${config.server}" is not a valid URL`);
    }
  }

  // Validate sync folder exists
  if (config.syncFolder && !nodeFs.existsSync(config.syncFolder)) {
    errors.push(`syncFolder "${config.syncFolder}" does not exist`);
  }

  // Validate mTLS paths if configured
  if (config.mtls) {
    if (config.mtls.cert && !nodeFs.existsSync(config.mtls.cert)) {
      errors.push(`mTLS cert "${config.mtls.cert}" does not exist`);
    }
    if (config.mtls.key && !nodeFs.existsSync(config.mtls.key)) {
      errors.push(`mTLS key "${config.mtls.key}" does not exist`);
    }
    if (config.mtls.ca && !nodeFs.existsSync(config.mtls.ca)) {
      errors.push(`mTLS CA "${config.mtls.ca}" does not exist`);
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

  // Check for .hermitstash-ignore in sync folder
  if (config.syncFolder) {
    const ignoreFile = nodePath.join(config.syncFolder, '.hermitstash-ignore');
    if (nodeFs.existsSync(ignoreFile)) {
      const lines = nodeFs.readFileSync(ignoreFile, 'utf8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      patterns.push(...lines);
    }
  }

  return [...new Set(patterns)]; // dedupe
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

  if (config.syncFolder) {
    const includeFile = nodePath.join(config.syncFolder, '.hermitstash-include');
    if (nodeFs.existsSync(includeFile)) {
      const lines = nodeFs.readFileSync(includeFile, 'utf8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      patterns.push(...lines);
    }
  }

  return [...new Set(patterns)];
}

// Shape-specific remediation for a pattern the matcher treats literally (and
// so silently never matches). Each branch tells the operator exactly what to
// type instead — the matcher's grammar is narrow and documented, so a mistyped
// glob is an operator error we can name precisely rather than a hard failure.
function _unsupportedPatternHelp(pattern) {
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

module.exports = { exists, load, save, validate, ensureDir, getIgnorePatterns, getIncludePatterns, warnUnsupportedPatterns, DEFAULTS };
