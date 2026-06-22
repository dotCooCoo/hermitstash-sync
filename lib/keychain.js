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
  // 0o700 so the secrets dir holding the fallback credentials file is not
  // world-traversable; the file itself is 0o600 below.
  b.atomicFile.ensureDir(CONFIG_DIR, 0o700);
  b.atomicFile.writeSync(CREDENTIALS_FILE, apiKey, { fileMode: 0o600 });
  return 'file';
}

// Read + harden the plaintext fallback file. On POSIX a world/group-readable
// file is a credential exposure, not a cosmetic warning: we REFUSE to serve a
// secret out of a file other users can read. The permission check is folded
// into the single TOCTOU-safe read so there is no path-based stat/chmod that an
// attacker with CONFIG_DIR write could re-resolve against a swapped symlink
// (CWE-367 + CWE-59): the mode we assert is the fstat of the symlink-refused,
// inode-pinned fd the bytes themselves came from. A loose-perm file is refused
// (not silently chmod'd) with an actionable re-enroll message — re-enrolling
// rewrites the file via b.atomicFile.writeSync's O_EXCL 0o600 inode, which
// fixes the perms cleanly. Throws a KeychainError on refusal so the caller
// surfaces an actionable message rather than an opaque auth failure.
function _readFileFallback() {
  // TOCTOU-safe read of the secret: open read-only and bind the returned bytes
  // (and, with withStat, the mode) to the held inode, refusing a symlink source
  // and any inode swap (the strongest posture, for operator-writable source
  // paths). We exclusively own CREDENTIALS_FILE in CONFIG_DIR — it is only ever
  // written via b.atomicFile.writeSync — so a symlink there is never legitimate;
  // it is exactly the swap an attacker with parent-dir write would plant. The
  // 64 KiB cap is far above any real API key / sync token but refuses a bloated
  // file. errorFor maps each refusal to an actionable KeychainError.
  const r = b.atomicFile.fdSafeReadSync(CREDENTIALS_FILE, {
    refuseSymlink: true,
    inodeCheck:    true,
    withStat:      true,
    maxBytes:      b.constants.BYTES.kib(64),
    encoding:      'utf8',
    errorFor: (kind) => new b.keychain.KeychainError(
      'keychain/credentials-file-' + kind,
      `credentials file ${CREDENTIALS_FILE} could not be read safely (${kind})` +
      (kind === 'symlink' || kind === 'toctou'
        ? ' — it is a symlink or was swapped mid-read; remove it and re-enroll with "hermitstash-sync init"'
        : kind === 'too-large'
          ? ' — it is unexpectedly large; remove it and re-enroll with "hermitstash-sync init"'
          : ''),
    ),
  });
  // POSIX-only: assert the secret is owner-only against the fd's own mode (no
  // re-stat that a swap could race). Windows POSIX mode bits are not meaningful,
  // so the check is gated off there exactly as before. A loose-perm file is
  // refused rather than served — chmodding it in place would have to follow a
  // path that an attacker could swap, which is the exact TOCTOU we removed.
  if (nodeOs.platform() !== 'win32' && (r.stat.mode & 0o077) !== 0) {
    const mode = (r.stat.mode & 0o777).toString(8); // allow:raw-byte-literal — POSIX mode-bit string radix, not a byte size
    throw new b.keychain.KeychainError('keychain/credentials-file-exposed',
      `credentials file ${CREDENTIALS_FILE} is readable by other users (mode ${mode}) — ` +
      `fix it with 'chmod 600 ${CREDENTIALS_FILE}' or re-enroll with 'hermitstash-sync init'`);
  }
  return r.bytes.trim();
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
