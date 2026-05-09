'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
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
    if (r && r.stored && r.backend && r.backend !== 'file') return 'keychain';
  } catch (_e) {
    // Native unavailable — fall through to file fallback.
  }
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, apiKey, { mode: 0o600 });
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
  if (fs.existsSync(CREDENTIALS_FILE)) {
    if (os.platform() !== 'win32') {
      const stat = fs.statSync(CREDENTIALS_FILE);
      const mode = (stat.mode & 0o777).toString(8);
      if (mode !== '600') {
        log.warn(`Credentials file has permissions ${mode}, should be 600`);
      }
    }
    return fs.readFileSync(CREDENTIALS_FILE, 'utf8').trim();
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
  if (fs.existsSync(CREDENTIALS_FILE)) {
    fs.unlinkSync(CREDENTIALS_FILE);
  }
}

module.exports = { store, retrieve, remove };
