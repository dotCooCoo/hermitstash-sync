'use strict';

// Round-trip coverage for the config disk I/O wrappers around the blamejs
// primitives: config.save() writes atomically at 0o600 via
// b.atomicFile.writeSync, and config.load() parses via b.safeJson.parse with a
// CONFIG_MAX_BYTES cap. config.validate() is exercised elsewhere; this file
// covers the read/write path that touches disk.
//
// CONFIG_DIR is resolved once from HERMITSTASH_SYNC_CONFIG_DIR at constants.js
// load time, so the env var is set to a fresh tmpdir BEFORE any lib module is
// required. Self-contained: `node tests/test-config-roundtrip.js` runs it with
// no server.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const TMP_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-config-rt-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_DIR;

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');

const config = require('../lib/config');
const { CONFIG_FILE, CONFIG_DIR } = require('../lib/constants');

after(() => {
  try { nodeFs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
});

describe('config.save / config.load round-trip', () => {
  it('save then load returns an equal object (round-trip fidelity)', () => {
    const cfg = {
      server: 'https://example.test',
      bundleId: 'bundle-123',
      shareId: '',
      syncFolder: TMP_DIR,
      apiKeyRef: 'keychain:hermitstash-sync',
      mtls: null,
      ignore: ['*.log', 'cache/**'],
      include: ['work/**'],
      pinnedServerSpki: [],
      maxFileSize: 0,
      logLevel: 'info',
      autoUpdate: true,
      autoUpdateChannel: 'stable',
      uploadConcurrency: 4,
      uploadBytesPerSec: 0,
      downloadBytesPerSec: 0,
    };
    config.save(cfg);
    const loaded = config.load();
    // load() overlays DEFAULTS + env; with no env overrides the written fields
    // must survive the round-trip byte-for-byte.
    for (const k of Object.keys(cfg)) {
      assert.deepEqual(loaded[k], cfg[k], `field ${k} did not round-trip`);
    }
  });

  it('writes the config file with 0600 mode on POSIX', { skip: process.platform === 'win32' ? 'POSIX-only mode bits' : false }, () => {
    config.save({ server: 'https://example.test', syncFolder: TMP_DIR, bundleId: 'b' });
    const mode = nodeFs.statSync(CONFIG_FILE).mode & 0o777;
    assert.equal(mode, 0o600, `config file mode should be 0600, got ${mode.toString(8)}`);
  });

  it('CONFIG_DIR is created 0o700 (not world-traversable) on POSIX', { skip: process.platform === 'win32' ? 'POSIX-only mode bits' : false }, () => {
    // Loosen the dir then re-create via the save path; ensureDir's mode is a
    // no-op on an existing dir, so this asserts the creation mode on a fresh
    // dir rather than remediation of an existing one (daemon boot handles that).
    nodeFs.rmSync(CONFIG_DIR, { recursive: true, force: true });
    config.save({ server: 'https://example.test', syncFolder: TMP_DIR, bundleId: 'b' });
    const mode = nodeFs.statSync(CONFIG_DIR).mode & 0o777;
    assert.equal(mode, 0o700, `CONFIG_DIR mode should be 0700, got ${mode.toString(8)}`);
  });

  it('neutralizes a __proto__ payload in config.json (no prototype pollution)', () => {
    nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
    // A hand-edited / pasted config carrying a prototype-pollution payload.
    const hostile = '{"server":"https://example.test","syncFolder":"' +
      TMP_DIR.replace(/\\/g, '\\\\') + '","bundleId":"b","__proto__":{"polluted":"yes"}}';
    nodeFs.writeFileSync(CONFIG_FILE, hostile, 'utf8');
    const loaded = config.load();
    assert.equal(({}).polluted, undefined, 'Object.prototype was polluted by config.load');
    assert.equal(Object.prototype.hasOwnProperty.call(loaded, '__proto__'), false,
      'loaded config carries an own __proto__ key');
    // The legitimate fields still parsed.
    assert.equal(loaded.server, 'https://example.test');
  });

  it('rejects a config.json larger than CONFIG_MAX_BYTES rather than parsing it', () => {
    nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
    // CONFIG_MAX_BYTES is 1 MiB; pad a valid object past it.
    const padding = 'x'.repeat(1024 * 1024 + 1024);
    const oversized = '{"server":"https://example.test","_pad":"' + padding + '"}';
    nodeFs.writeFileSync(CONFIG_FILE, oversized, 'utf8');
    assert.throws(() => config.load(), /too-large|exceed|large/i,
      'oversized config should be refused, not parsed');
  });

  it('surfaces an actionable error on malformed JSON', () => {
    nodeFs.mkdirSync(CONFIG_DIR, { recursive: true });
    nodeFs.writeFileSync(CONFIG_FILE, '{ this is not json', 'utf8');
    assert.throws(() => config.load(), /json|syntax|invalid/i,
      'malformed config should throw a parse error');
  });
});
