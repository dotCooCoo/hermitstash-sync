'use strict';

// Unit tests for lib/keychain.js. Server-independent. The OS native
// keychain is non-deterministic across CI hosts (no Secret Service on a
// headless Linux runner, a real Keychain prompt on macOS), so each
// scenario runs in a child process that:
//   - points CREDENTIALS_FILE at a throwaway dir via HERMITSTASH_SYNC_CONFIG_DIR
//   - monkeypatches b.keychain to a deterministic native-available or
//     native-unavailable stub before requiring lib/keychain.js
//
// Concerns:
//   1. A successful NATIVE store removes any stale plaintext fallback so
//      the secret never co-exists in two places.
//   2. The plaintext fallback is written atomically at 0o600 — an
//      overwrite of a pre-existing loose-perm file re-tightens to 0o600
//      rather than inheriting the old mode.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const KEYCHAIN = path.resolve(__dirname, '../lib/keychain.js');
const BLAMEJS = path.resolve(__dirname, '../vendor/blamejs');

function tmpConfigDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hs-keychain-${label}-`));
}

// Run `body` (a string of JS) in a child process with CREDENTIALS_FILE
// pointed at `configDir` and b.keychain replaced by `keychainStub` (a JS
// expression evaluated in the child). The body asserts and prints
// CHILD_OK on success.
function runChild(configDir, keychainStub, body) {
  const script = `
    const b = require(${JSON.stringify(BLAMEJS)});
    b.keychain = ${keychainStub};
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const path = require('node:path');
    const keychain = require(${JSON.stringify(KEYCHAIN)});
    const CREDENTIALS_FILE = path.join(${JSON.stringify(configDir)}, 'credentials');
    (async () => {
      ${body}
      console.log('CHILD_OK');
    })().catch(e => { console.error(e && e.stack ? e.stack : e); process.exit(1); });
  `;
  return execFileSync(process.execPath, ['-e', script], {
    env: Object.assign({}, process.env, { HERMITSTASH_SYNC_CONFIG_DIR: configDir }),
    encoding: 'utf8',
  });
}

// A native keychain stub backed by an in-memory map (per child process).
const NATIVE_AVAILABLE = `(() => {
  let mem = null;
  return {
    store: async ({ password }) => { mem = password; return { stored: true, backend: 'test-native' }; },
    retrieve: async () => (mem != null ? { password: mem } : {}),
    remove: async () => { mem = null; return { removed: true }; },
  };
})()`;

// A native keychain stub that always fails — forces the file fallback. Carries
// the real KeychainError so lib/keychain.js's world-readable-file refusal can
// construct the typed error it surfaces (b.keychain is replaced by this stub
// in the child, so the class has to come along).
const NATIVE_UNAVAILABLE = `{
  store: async () => { throw new Error('no native credential store'); },
  retrieve: async () => { throw new Error('no native credential store'); },
  remove: async () => { throw new Error('no native credential store'); },
  KeychainError: b.keychain.KeychainError,
}`;

// A native stub that records the service name it was called with into a
// global so the body can assert config.apiKeyRef threaded through to the
// backend. Backed by a per-(service) in-memory map so a custom service is
// isolated from the default.
const NATIVE_RECORDS_SERVICE = `(() => {
  globalThis.__svc = { store: null, retrieve: null, remove: null };
  const mem = {};
  return {
    store: async ({ service, password }) => { globalThis.__svc.store = service; mem[service] = password; return { stored: true, backend: 'test-native' }; },
    retrieve: async ({ service }) => { globalThis.__svc.retrieve = service; return (mem[service] != null ? { password: mem[service] } : {}); },
    remove: async ({ service }) => { globalThis.__svc.remove = service; delete mem[service]; return { removed: true }; },
    KeychainError: b.keychain.KeychainError,
  };
})()`;

describe('keychain — native store removes stale plaintext fallback', () => {
  it('store to file, then store with native available, leaves no plaintext file and reads from keychain', () => {
    const dir = tmpConfigDir('migrate');
    // First store with native unavailable → writes the plaintext fallback.
    runChild(dir, NATIVE_UNAVAILABLE, `
      const where = await keychain.store('FILE-SECRET');
      assert.equal(where, 'file');
      assert.ok(fs.existsSync(CREDENTIALS_FILE), 'plaintext fallback should exist after a file store');
    `);
    assert.ok(fs.existsSync(path.join(dir, 'credentials')), 'fallback present between runs');

    // Second store with native available → must migrate + delete the file.
    const out = runChild(dir, NATIVE_AVAILABLE, `
      const where = await keychain.store('KEYCHAIN-SECRET');
      assert.equal(where, 'keychain');
      assert.equal(fs.existsSync(CREDENTIALS_FILE), false, 'stale plaintext file must be removed after native store');
      const got = await keychain.retrieve();
      assert.equal(got, 'KEYCHAIN-SECRET', 'retrieve should return the keychain value');
    `);
    assert.match(out, /CHILD_OK/);
    assert.equal(fs.existsSync(path.join(dir, 'credentials')), false, 'no plaintext file after migration');
  });
});

describe('keychain — atomic 0o600 file fallback', () => {
  it('writes the plaintext fallback at 0o600 (POSIX)', () => {
    const dir = tmpConfigDir('mode');
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      await keychain.store('SECRET-A');
      if (process.platform !== 'win32') {
        const mode = (fs.statSync(CREDENTIALS_FILE).mode & 0o777).toString(8);
        assert.equal(mode, '600', 'fresh fallback must be 0o600');
      }
      const got = await keychain.retrieve();
      assert.equal(got, 'SECRET-A');
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('re-tightens a pre-existing loose-perm file to 0o600 on overwrite (POSIX)', function () {
    if (process.platform === 'win32') return; // POSIX mode bits only
    const dir = tmpConfigDir('retighten');
    // Pre-create a loose-perm credentials file by hand.
    const credFile = path.join(dir, 'credentials');
    fs.writeFileSync(credFile, 'OLD', { mode: 0o644 });
    fs.chmodSync(credFile, 0o644);
    assert.equal((fs.statSync(credFile).mode & 0o777).toString(8), '644', 'precondition: loose perms');

    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      await keychain.store('SECRET-B');
      const mode = (fs.statSync(CREDENTIALS_FILE).mode & 0o777).toString(8);
      assert.equal(mode, '600', 'overwrite of a loose-perm file must re-tighten to 0o600');
      const got = await keychain.retrieve();
      assert.equal(got, 'SECRET-B');
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('retrieve() actively tightens a legacy loose-perm file (POSIX)', function () {
    if (process.platform === 'win32') return;
    const dir = tmpConfigDir('readtighten');
    const credFile = path.join(dir, 'credentials');
    fs.writeFileSync(credFile, 'LEGACY-KEY', { mode: 0o644 });
    fs.chmodSync(credFile, 0o644);

    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const got = await keychain.retrieve();
      assert.equal(got, 'LEGACY-KEY');
      const mode = (fs.statSync(CREDENTIALS_FILE).mode & 0o777).toString(8);
      assert.equal(mode, '600', 'retrieve should correct loose perms in place');
    `);
    assert.match(out, /CHILD_OK/);
  });
});

describe('keychain — config.apiKeyRef is honored (R27)', () => {
  it('store/retrieve/remove thread keychain:<service> through to the backend', () => {
    const dir = tmpConfigDir('ref');
    const out = runChild(dir, NATIVE_RECORDS_SERVICE, `
      const REF = 'keychain:my-custom-stash';
      const where = await keychain.store('REF-SECRET', REF);
      assert.equal(where, 'keychain', 'native store under the custom service should win');
      assert.equal(globalThis.__svc.store, 'my-custom-stash', 'store must use the apiKeyRef service');
      const got = await keychain.retrieve(REF);
      assert.equal(got, 'REF-SECRET', 'retrieve must read back from the same service');
      assert.equal(globalThis.__svc.retrieve, 'my-custom-stash', 'retrieve must use the apiKeyRef service');
      await keychain.remove(REF);
      assert.equal(globalThis.__svc.remove, 'my-custom-stash', 'remove must use the apiKeyRef service');
      const gone = await keychain.retrieve(REF);
      assert.equal(gone, null, 'removed key should be gone');
    `);
    assert.match(out, /CHILD_OK/);
  });

  it("parseApiKeyRef maps the documented forms", () => {
    const dir = tmpConfigDir('parse');
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const k = require(${JSON.stringify(KEYCHAIN)});
      assert.deepEqual(k.parseApiKeyRef('keychain:foo'), { mode: 'keychain', service: 'foo' });
      assert.deepEqual(k.parseApiKeyRef('keychain'), { mode: 'keychain', service: 'hermitstash-sync' });
      assert.deepEqual(k.parseApiKeyRef('keychain:'), { mode: 'keychain', service: 'hermitstash-sync' });
      assert.deepEqual(k.parseApiKeyRef('file'), { mode: 'file' });
      assert.deepEqual(k.parseApiKeyRef(undefined), { mode: 'keychain', service: 'hermitstash-sync' });
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('file-mode ref forces the plaintext fallback and skips native probing', () => {
    const dir = tmpConfigDir('filemode');
    const out = runChild(dir, NATIVE_RECORDS_SERVICE, `
      const where = await keychain.store('FILE-MODE-SECRET', 'file');
      assert.equal(where, 'file', 'file-mode ref must write the plaintext fallback');
      assert.equal(globalThis.__svc.store, null, 'native store must not be touched in file mode');
      assert.ok(fs.existsSync(CREDENTIALS_FILE), 'plaintext fallback should exist');
      const got = await keychain.retrieve('file');
      assert.equal(got, 'FILE-MODE-SECRET');
      assert.equal(globalThis.__svc.retrieve, null, 'native retrieve must not be touched in file mode');
    `);
    assert.match(out, /CHILD_OK/);
  });
});

describe('keychain — backend-unreachable vs no-credential (R28)', () => {
  it('keychain ref + native throws + no file → retrieveDetailed signals backendUnreachable', () => {
    const dir = tmpConfigDir('unreach');
    // Native store succeeds (records the service), then on a fresh process the
    // native backend is unreachable (throws) and there is no file fallback —
    // the operator's key is still in the keychain, the store is just down.
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const r = await keychain.retrieveDetailed('keychain:hermitstash-sync');
      assert.equal(r.found, false, 'no usable credential resolved');
      assert.equal(r.backendUnreachable, true, 'must flag the backend as unreachable, not "no credential"');
      // The back-compat surface still returns null, but the DETAILED result is
      // what lets the CLI print the keychain-down guidance.
      const bare = await keychain.retrieve('keychain:hermitstash-sync');
      assert.equal(bare, null);
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('file-mode ref + no file → genuine no-credential (NOT backendUnreachable)', () => {
    const dir = tmpConfigDir('nocred');
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const r = await keychain.retrieveDetailed('file');
      assert.equal(r.found, false, 'no credential present');
      assert.notEqual(r.backendUnreachable, true, 'file mode with no file is genuine no-credential, not unreachable');
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('the unreachable signal does not fire when a file fallback exists', () => {
    const dir = tmpConfigDir('hasfile');
    // Plant a file fallback, then retrieve with a keychain ref + unreachable
    // native: the file answers, so this is NOT the unreachable case.
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      await keychain.store('FALLBACK-SECRET', 'file');
      const r = await keychain.retrieveDetailed('keychain:hermitstash-sync');
      assert.equal(r.found, true, 'file fallback should satisfy the retrieve');
      assert.equal(r.apiKey, 'FALLBACK-SECRET');
      assert.notEqual(r.backendUnreachable, true);
    `);
    assert.match(out, /CHILD_OK/);
  });
});

describe('keychain — world-readable credentials file is refused when un-tightenable (R29)', () => {
  it('refuses (does not serve) a world-readable file whose chmod fails (POSIX)', function () {
    if (process.platform === 'win32') return; // POSIX mode bits only
    const dir = tmpConfigDir('exposed');
    const credFile = path.join(dir, 'credentials');
    fs.writeFileSync(credFile, 'EXPOSED-KEY', { mode: 0o644 });
    fs.chmodSync(credFile, 0o644);

    // Make chmodSync throw so the self-heal can't tighten the loose perms; the
    // retrieve must then REFUSE rather than serve a credential other users can
    // read. A bare warn-and-return would silently keep the exposed key in use.
    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const realChmod = fs.chmodSync;
      fs.chmodSync = () => { throw Object.assign(new Error('EPERM: chmod blocked'), { code: 'EPERM' }); };
      let threw = null;
      try { await keychain.retrieve('file'); }
      catch (e) { threw = e; }
      finally { fs.chmodSync = realChmod; }
      assert.ok(threw, 'a world-readable file that cannot be tightened must be refused, not served');
      assert.match(String(threw.message), /readable by other users/i);
      assert.match(String(threw.message), /chmod 600|re-enroll/i, 'the error must be actionable');
    `);
    assert.match(out, /CHILD_OK/);
  });

  it('still tightens-and-serves when chmod succeeds (no regression)', function () {
    if (process.platform === 'win32') return;
    const dir = tmpConfigDir('tighten-ok');
    const credFile = path.join(dir, 'credentials');
    fs.writeFileSync(credFile, 'OK-KEY', { mode: 0o644 });
    fs.chmodSync(credFile, 0o644);

    const out = runChild(dir, NATIVE_UNAVAILABLE, `
      const got = await keychain.retrieve('file');
      assert.equal(got, 'OK-KEY', 'a tightenable loose-perm file should still be served after re-chmod');
      const mode = (fs.statSync(CREDENTIALS_FILE).mode & 0o777).toString(8);
      assert.equal(mode, '600');
    `);
    assert.match(out, /CHILD_OK/);
  });
});
