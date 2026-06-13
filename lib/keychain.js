'use strict';

const nodeFs = require('node:fs');
const nodeOs = require('node:os');
const b = require('../vendor/blamejs');
const { CREDENTIALS_FILE, CONFIG_DIR } = require('./constants');
const log = require('./logger');

const SERVICE = 'hermitstash-sync';
const ACCOUNT = 'api-key';

// We intentionally don't use b.keychain's encrypted-file fallback (it
// needs an Argon2id passphrase the CLI has no good place to source
// from). Instead, when the native OS keychain is unreachable we keep
// the historical plaintext mode-0600 fallback at CREDENTIALS_FILE so
// existing installs keep working. b.keychain still owns the native
// path on every platform — including the macOS stdin sentinel that
// keeps the secret out of `ps`.
//
// Behavior preserved from the pre-blamejs lib/keychain.js: any native
// failure (binary missing, PowerShell module missing, secret-tool not
// installed, plain spawn error) falls through to the file fallback
// silently. Logging the failure as a warning would spam the daemon log
// on every retrieve when the user opted not to install the OS
// credential store.

async function store(apiKey) {
  try {
    const r = await b.keychain.store({
      service: SERVICE,
      account: ACCOUNT,
      password: apiKey,
      audit: false,
    });
    if (r && r.stored && r.backend && r.backend !== 'file') {
      // Native store succeeded — the keychain entry is now authoritative.
      // Remove any plaintext fallback left by an earlier install so the
      // secret never lives in two places at once. Best-effort + idempotent;
      // it only runs after a verified native success so it can never delete
      // a live file fallback, and the log line carries no key material.
      try {
        if (nodeFs.existsSync(CREDENTIALS_FILE)) {
          nodeFs.unlinkSync(CREDENTIALS_FILE);
          log.info('Migrated API key into the OS credential store; removed plaintext fallback file');
        }
      } catch (_e) { /* best-effort cleanup; keychain entry is authoritative */ }
      return 'keychain';
    }
  } catch (_e) {
    // Native unavailable — fall through to file fallback.
  }
  // Atomic secret write: temp + fsync + atomic-rename + parent-dir fsync,
  // with the Windows transient-lock retry (Dropbox/OneDrive/AV) on the
  // rename. The fresh O_EXCL inode re-applies 0o600 on every overwrite, so
  // a pre-existing loose-perm file is re-tightened instead of inheriting
  // its old mode, and a crash mid-write can never truncate the key.
  nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
  b.atomicFile.writeSync(CREDENTIALS_FILE, apiKey, { fileMode: 0o600 });
  return 'file';
}

async function retrieve() {
  try {
    const r = await b.keychain.retrieve({
      service: SERVICE,
      account: ACCOUNT,
      audit: false,
    });
    if (r && r.password) return r.password;
  } catch (_e) {
    // Native unavailable — fall through to file fallback.
  }
  if (nodeFs.existsSync(CREDENTIALS_FILE)) {
    if (nodeOs.platform() !== 'win32') {
      const stat = nodeFs.statSync(CREDENTIALS_FILE);
      const mode = (stat.mode & 0o777).toString(8); // allow:raw-byte-literal — POSIX mode-bit string radix, not a byte size
      if (mode !== '600') {
        // Correct a legacy loose-perm file on first read rather than only
        // logging it — a credentials file written before atomic 0o600 was
        // adopted gets tightened in place.
        try {
          nodeFs.chmodSync(CREDENTIALS_FILE, 0o600);
          log.info(`Tightened credentials file permissions from ${mode} to 600`);
        } catch (_e) {
          log.warn(`Credentials file has permissions ${mode}, should be 600`);
        }
      }
    }
    return nodeFs.readFileSync(CREDENTIALS_FILE, 'utf8').trim();
  }
  return null;
}

async function remove() {
  try {
    await b.keychain.remove({
      service: SERVICE,
      account: ACCOUNT,
      audit: false,
    });
  } catch (_e) {
    // Ignore — the entry might not exist on this backend.
  }
  if (nodeFs.existsSync(CREDENTIALS_FILE)) {
    nodeFs.unlinkSync(CREDENTIALS_FILE);
  }
}

module.exports = { store, retrieve, remove };
