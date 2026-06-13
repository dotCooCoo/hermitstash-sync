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

// A native keychain stub that always fails — forces the file fallback.
const NATIVE_UNAVAILABLE = `{
  store: async () => { throw new Error('no native credential store'); },
  retrieve: async () => { throw new Error('no native credential store'); },
  remove: async () => { throw new Error('no native credential store'); },
}`;

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
