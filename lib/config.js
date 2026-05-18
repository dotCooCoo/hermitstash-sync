'use strict';

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const { CONFIG_DIR, CONFIG_FILE, DEFAULT_IGNORES } = require('./constants');
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
  return { ...DEFAULTS, ...parsed };
}

function save(config) {
  ensureDir();
  const data = JSON.stringify(config, null, 2) + '\n';
  // b.atomicFile.writeSync: write to a sibling temp file, fsync, rename
  // over the target, fsync the parent dir. A crash mid-write leaves the
  // previous config intact instead of a truncated half-write.
  b.atomicFile.writeSync(CONFIG_FILE, data, { mode: 0o600 });
}

function validate(config) {
  const errors = [];
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

module.exports = { exists, load, save, validate, ensureDir, getIgnorePatterns, getIncludePatterns, DEFAULTS };
