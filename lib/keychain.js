'use strict';

const nodeFs = require('node:fs');
const nodeOs = require('node:os');
const nodePath = require('node:path');
const b = require('../vendor/blamejs');
const { CREDENTIALS_FILE, CONFIG_DIR } = require('./constants');
const log = require('./logger');

const DEFAULT_SERVICE = 'hermitstash-sync';
const ACCOUNT = 'api-key';

// We intentionally don't use b.keychain's encrypted-file fallback (it
// needs an Argon2id passphrase the CLI has no good place to source
// from). Instead, when the native OS keychain is unreachable we keep
// the historical plaintext mode-0600 fallback at CREDENTIALS_FILE so
// existing installs keep working. b.keychain still owns the native
// path on every platform — including the macOS stdin sentinel that
// keeps the secret out of `ps`.
//
// The OS-keychain service name is resolved from config.apiKeyRef so the
// field is load-bearing, not write-only: `keychain:<service>` selects a
// native entry under <service>; `file` (or any non-keychain value) forces
// the plaintext fallback and skips native probing entirely. With no ref the
// default service is used. parseApiKeyRef() is the single resolver every
// caller threads through store/retrieve/remove.

// Resolve config.apiKeyRef into a backend selection. Returns
//   { mode: 'keychain', service } | { mode: 'file' }
// 'keychain:<service>' selects a native entry under <service>; a bare
// 'keychain' uses the default service; 'file' (or anything else, or unset)
// forces the file fallback. An empty service after the colon falls back to
// the default rather than passing an invalid empty service to b.keychain.
function parseApiKeyRef(ref) {
  if (typeof ref === 'string' && ref.startsWith('keychain:')) {
    const service = ref.slice('keychain:'.length).trim();
    return { mode: 'keychain', service: service || DEFAULT_SERVICE };
  }
  if (ref === 'keychain') {
    return { mode: 'keychain', service: DEFAULT_SERVICE };
  }
  if (ref === 'file') {
    return { mode: 'file' };
  }
  // Unset / unrecognised → default to native-preferred under the default
  // service (matches the historical behavior before apiKeyRef was honored).
  return { mode: 'keychain', service: DEFAULT_SERVICE };
}

// True when a native OS credential store is present on this host. Mirrors the
// platform-binary probe b.keychain uses internally so retrieve() can tell
// "native backend went away" apart from "native backend is here but the entry
// is missing". A throw here is treated as "no native backend detectable".
function _nativeBackendPresent() {
  try {
    const p = nodeOs.platform();
    if (p === 'darwin') return _onPath('/usr/bin/security', true);
    if (p === 'linux') return _onPath('secret-tool', false);
    if (p === 'win32') return _onPath('powershell.exe', false) || _onPath('pwsh.exe', false);
  } catch (_e) { /* probe failure → treat as no native backend */ }
  return false;
}

// Resolve a binary either as an absolute path (absolutePath=true) or by
// scanning PATH for the bare name. Used only with the hardcoded platform
// binaries above — never with caller-supplied names.
function _onPath(bin, absolutePath) {
  if (absolutePath) {
    try { return nodeFs.statSync(bin).isFile(); } catch (_e) { return false; }
  }
  const pathEnv = process.env.PATH || process.env.Path || '';  // allow:raw-process-env — PATH probe for the native keychain binary
  const sep = nodeOs.platform() === 'win32' ? ';' : ':';
  for (const dir of pathEnv.split(sep)) {
    if (!dir) continue;
    try { if (nodeFs.statSync(nodePath.join(dir, bin)).isFile()) return true; } catch (_e) { /* keep scanning */ }
  }
  return false;
}

async function store(apiKey, ref) {
  const sel = parseApiKeyRef(ref);
  if (sel.mode === 'keychain') {
    try {
      const r = await b.keychain.store({
        service: sel.service,
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

// Read + harden the plaintext fallback file. On POSIX a world/group-readable
// file is a credential exposure, not a cosmetic warning: we re-tighten to
// 0o600 and only return the secret if the file is now private. If we cannot
// make it private (chmod failed), we REFUSE to use it — returning the secret
// from a file other users can read would silently keep an exposed credential
// in service. Throws a KeychainError on refusal so the caller surfaces an
// actionable message rather than an opaque auth failure.
function _readFileFallback() {
  if (nodeOs.platform() !== 'win32') {
    const stat = nodeFs.statSync(CREDENTIALS_FILE);
    const mode = (stat.mode & 0o777).toString(8); // allow:raw-byte-literal — POSIX mode-bit string radix, not a byte size
    const groupOrWorldReadable = (stat.mode & 0o077) !== 0;
    if (mode !== '600') {
      try {
        nodeFs.chmodSync(CREDENTIALS_FILE, 0o600);
        log.info(`Tightened credentials file permissions from ${mode} to 600`);
      } catch (_e) {
        if (groupOrWorldReadable) {
          // chmod failed AND the file is readable by other users → refuse.
          // Continuing would serve a credential out of a file the rest of the
          // box can read; the operator must fix the perms or re-enroll.
          throw new b.keychain.KeychainError('keychain/credentials-file-exposed',
            `credentials file ${CREDENTIALS_FILE} is readable by other users (mode ${mode}) and could not be tightened — ` +
            `fix it with 'chmod 600 ${CREDENTIALS_FILE}' or re-enroll with 'hermitstash-sync init'`);
        }
        log.warn(`Credentials file has permissions ${mode}, should be 600`);
      }
    }
  }
  return nodeFs.readFileSync(CREDENTIALS_FILE, 'utf8').trim();
}

// Detailed retrieve: distinguishes the three outcomes a bare string/null can't.
// Returns one of:
//   { found: true, apiKey }                 — a credential was resolved
//   { found: false }                        — genuinely no credential (no
//                                             native entry, no file, backend
//                                             was reachable)
//   { found: false, backendUnreachable }    — apiKeyRef points at the OS
//                                             keychain but no native backend is
//                                             reachable (secret-tool removed,
//                                             headless, login keychain locked),
//                                             and there is no file fallback to
//                                             fall back to. Callers surface an
//                                             actionable keychain-down message
//                                             instead of "no API key found".
async function retrieveDetailed(ref) {
  const sel = parseApiKeyRef(ref);
  let nativeThrew = false;
  if (sel.mode === 'keychain') {
    try {
      const r = await b.keychain.retrieve({
        service: sel.service,
        account: ACCOUNT,
        audit: false,
      });
      if (r && r.password) return { found: true, apiKey: r.password };
      // null/no-password → either the entry is missing OR no native backend
      // exists. We disambiguate below via the platform-binary probe.
    } catch (_e) {
      // A non-fallback native throw means the backend WAS present but failed
      // operationally (D-Bus session dead, keychain locked) — unreachable.
      nativeThrew = true;
    }
  }

  if (nodeFs.existsSync(CREDENTIALS_FILE)) {
    return { found: true, apiKey: _readFileFallback() };
  }

  // No file fallback. If the operator's apiKeyRef says the key lives in the OS
  // keychain but no native backend is reachable, this is "backend unreachable",
  // NOT "no credential" — re-enrolling would mint a needless new key. Bare-null
  // (found:false) is reserved for the genuine no-credential case: file mode
  // with no file, or a reachable native backend with no entry.
  if (sel.mode === 'keychain' && (nativeThrew || !_nativeBackendPresent())) {
    return { found: false, backendUnreachable: true, service: sel.service };
  }
  return { found: false };
}

// Back-compat string-or-null surface. Existing callers that only need the key
// (and don't branch on the unreachable case) keep working. The detailed
// outcome is available via retrieveDetailed() for the CLI's actionable
// messaging.
async function retrieve(ref) {
  const r = await retrieveDetailed(ref);
  return r.found ? r.apiKey : null;
}

async function remove(ref) {
  const sel = parseApiKeyRef(ref);
  if (sel.mode === 'keychain') {
    try {
      await b.keychain.remove({
        service: sel.service,
        account: ACCOUNT,
        audit: false,
      });
    } catch (_e) {
      // Ignore — the entry might not exist on this backend.
    }
  }
  if (nodeFs.existsSync(CREDENTIALS_FILE)) {
    nodeFs.unlinkSync(CREDENTIALS_FILE);
  }
}

module.exports = { store, retrieve, retrieveDetailed, remove, parseApiKeyRef };
