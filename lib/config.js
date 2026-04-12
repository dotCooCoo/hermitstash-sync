'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { CONFIG_DIR, CONFIG_FILE, DEFAULT_IGNORES } = require('./constants');

const DEFAULTS = {
  server: '',
  bundleId: '',
  shareId: '',
  syncFolder: '',
  apiKeyRef: 'keychain:hermitstash-sync',
  mtls: null,
  ignore: [],
  maxFileSize: 0,       // 0 = no limit (server enforces its own limits)
  logLevel: 'info',
};

function ensureDir() {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

function exists() {
  return fs.existsSync(CONFIG_FILE);
}

function load() {
  if (!exists()) {
    throw new Error(`Config not found at ${CONFIG_FILE}. Run 'hermitstash-sync init' first.`);
  }
  const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  return { ...DEFAULTS, ...parsed };
}

function save(config) {
  ensureDir();
  const data = JSON.stringify(config, null, 2) + '\n';
  fs.writeFileSync(CONFIG_FILE, data, { mode: 0o600 });
}

function validate(config) {
  const errors = [];
  if (!config.server) errors.push('server is required');
  if (!config.syncFolder) errors.push('syncFolder is required');
  if (!config.bundleId && !config.shareId) errors.push('bundleId or shareId is required');

  // Validate server URL
  if (config.server) {
    try {
      new URL(config.server);
    } catch {
      errors.push(`server "${config.server}" is not a valid URL`);
    }
  }

  // Validate sync folder exists
  if (config.syncFolder && !fs.existsSync(config.syncFolder)) {
    errors.push(`syncFolder "${config.syncFolder}" does not exist`);
  }

  // Validate mTLS paths if configured
  if (config.mtls) {
    if (config.mtls.cert && !fs.existsSync(config.mtls.cert)) {
      errors.push(`mTLS cert "${config.mtls.cert}" does not exist`);
    }
    if (config.mtls.key && !fs.existsSync(config.mtls.key)) {
      errors.push(`mTLS key "${config.mtls.key}" does not exist`);
    }
    if (config.mtls.ca && !fs.existsSync(config.mtls.ca)) {
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
    const ignoreFile = path.join(config.syncFolder, '.hermitstash-ignore');
    if (fs.existsSync(ignoreFile)) {
      const lines = fs.readFileSync(ignoreFile, 'utf8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      patterns.push(...lines);
    }
  }

  return [...new Set(patterns)]; // dedupe
}

module.exports = { exists, load, save, validate, ensureDir, getIgnorePatterns, DEFAULTS };
