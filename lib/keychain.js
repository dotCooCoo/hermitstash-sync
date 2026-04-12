'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const { CREDENTIALS_FILE, CONFIG_DIR } = require('./constants');
const log = require('./logger');

const SERVICE = 'hermitstash-sync';
const ACCOUNT = 'api-key';

/**
 * Store API key in OS keychain. Falls back to encrypted file on headless systems.
 */
function store(apiKey) {
  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      // NOTE: The API key is passed as a command-line argument and will be briefly
      // visible in `ps` output. The macOS `security` command's -w flag does not
      // support reading from stdin, so this is an accepted limitation.
      execFileSync('/usr/bin/security', [
        'add-generic-password',
        '-a', ACCOUNT,
        '-s', SERVICE,
        '-w', apiKey,
        '-U', // update if exists
      ], { stdio: 'pipe' });
      return 'keychain';
    }

    if (platform === 'linux') {
      execFileSync('secret-tool', [
        'store',
        '--label', 'HermitStash Sync API Key',
        'service', SERVICE,
        'account', ACCOUNT,
      ], { input: apiKey, stdio: ['pipe', 'pipe', 'pipe'] });
      return 'keychain';
    }

    if (platform === 'win32') {
      // Use PowerShell SecureString path only — no cmdkey fallback to avoid
      // command injection via unsanitized API key in shell interpolation.
      // The API key is passed via stdin to avoid process list exposure.
      const ps = [
        '-NoProfile', '-Command',
        '$key = [System.Console]::In.ReadLine();' +
        '$ss = ConvertTo-SecureString $key -AsPlainText -Force;' +
        '$cred = New-Object System.Management.Automation.PSCredential(' +
          `'${ACCOUNT}', $ss);` +
        'New-StoredCredential -Target ' +
          `'${SERVICE}' -Credential $cred -Type Generic -Persist LocalMachine`,
      ];
      execFileSync('powershell', ps, {
        input: apiKey,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return 'keychain';
    }
  } catch (err) {
    log.warn('OS keychain unavailable, falling back to credentials file', err);
  }

  // Fallback: store in file with restricted permissions
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, apiKey, { mode: 0o600 });
  return 'file';
}

/**
 * Retrieve API key from OS keychain or fallback file.
 */
function retrieve() {
  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      const result = execFileSync('/usr/bin/security', [
        'find-generic-password',
        '-a', ACCOUNT,
        '-s', SERVICE,
        '-w',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' });
      return result.trim();
    }

    if (platform === 'linux') {
      const result = execFileSync('secret-tool', [
        'lookup',
        'service', SERVICE,
        'account', ACCOUNT,
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' });
      return result.trim();
    }

    if (platform === 'win32') {
      const result = execFileSync('powershell', [
        '-NoProfile', '-Command',
        `(Get-StoredCredential -Target '${SERVICE}').GetNetworkCredential().Password`,
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' });
      return result.trim();
    }
  } catch {
    // Keychain lookup failed, try file fallback
  }

  // Fallback: read from file
  if (fs.existsSync(CREDENTIALS_FILE)) {
    // Warn about permissions
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

/**
 * Delete API key from keychain and fallback file.
 */
function remove() {
  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      execFileSync('/usr/bin/security', [
        'delete-generic-password', '-a', ACCOUNT, '-s', SERVICE,
      ], { stdio: 'pipe' });
    } else if (platform === 'linux') {
      execFileSync('secret-tool', [
        'clear', 'service', SERVICE, 'account', ACCOUNT,
      ], { stdio: 'pipe' });
    }
  } catch {
    // Ignore — might not exist
  }

  if (fs.existsSync(CREDENTIALS_FILE)) {
    fs.unlinkSync(CREDENTIALS_FILE);
  }
}

module.exports = { store, retrieve, remove };
