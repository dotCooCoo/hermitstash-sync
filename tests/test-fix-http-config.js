'use strict';

// Lane "http-config" regression coverage. Exercises the REAL production libs
// (lib/config.js + lib/http-client.js) — no test-only reimplementations, no
// weakened crypto, no live server required. Runnable standalone via
// `node --test tests/test-fix-http-config.js`.
//
// Fixes covered:
//   http-client#9 / config#29 — plaintext http:// downgrade: config.validate()
//       fails closed on a non-loopback http:// server (Bearer key + all sync
//       metadata would travel cleartext with PQC-mTLS absent); the HttpClient
//       constructor emits a loud WARN as defense-in-depth.
//   config#27 / http-client#10 — int32 `| 0` throttle truncation: a large
//       validated bytes/sec cap is preserved instead of wrapping negative and
//       silently voiding the throttle.
//   config#28 — dead config.maxFileSize wired into real per-file enforcement
//       (0 = fall back to MAX_SYNC_FILE_BYTES; a non-zero value only lowers it).
//   config#30 — a non-object JSON config root is rejected with an actionable
//       error instead of spreading into junk keys.
//   config#31 — server/bundleId/shareId/syncFolder must be strings; a non-string
//       syncFolder no longer throws inside the pattern-file readers.
//
// CONFIG_DIR resolves once from HERMITSTASH_SYNC_CONFIG_DIR at constants.js load
// time, so set it to a fresh tmpdir BEFORE any lib module is required.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const TMP_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-http-config-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_DIR;

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const config = require('../lib/config');
const HttpClient = require('../lib/http-client');
const logger = require('../lib/logger');
const { CONFIG_FILE, MAX_SYNC_FILE_BYTES } = require('../lib/constants');

// A syncFolder that exists, so validate() doesn't add an unrelated
// "does not exist" error while we assert on the URL / type errors.
const SYNC_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-sync-'));

function baseCfg(extra) {
  return Object.assign({ server: 'https://sync.example.com', syncFolder: SYNC_DIR, bundleId: 'b1' }, extra || {});
}
function hasErr(errs, sub) { return errs.some(e => e.includes(sub)); }

after(() => {
  try { nodeFs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
  try { nodeFs.rmSync(SYNC_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

describe('http-config#9/#29 — plaintext http:// server is refused for non-loopback hosts', () => {
  const PLAINTEXT = 'plaintext http://';

  it('rejects a non-loopback http:// server (cleartext credential leak)', () => {
    const errs = config.validate(baseCfg({ server: 'http://sync.example.com' }));
    assert.ok(hasErr(errs, PLAINTEXT), 'non-loopback http:// must be refused: ' + JSON.stringify(errs));
  });

  it('allows loopback http:// (127.0.0.0/8, localhost, ::1) — sidecar / dev affordance', () => {
    for (const server of ['http://127.0.0.1:8080', 'http://127.5.5.5', 'http://localhost:8080', 'http://[::1]:8080']) {
      const errs = config.validate(baseCfg({ server }));
      assert.ok(!hasErr(errs, PLAINTEXT), server + ' (loopback) must be allowed: ' + JSON.stringify(errs));
    }
  });

  it('allows any https:// host (the PQC-mTLS floor)', () => {
    assert.ok(!hasErr(config.validate(baseCfg({ server: 'https://sync.example.com' })), PLAINTEXT));
  });

  it('HERMITSTASH_ALLOW_PLAINTEXT=1 opts a non-loopback http:// server back in', () => {
    process.env.HERMITSTASH_ALLOW_PLAINTEXT = '1';
    try {
      const errs = config.validate(baseCfg({ server: 'http://sync.example.com' }));
      assert.ok(!hasErr(errs, PLAINTEXT), 'opt-out must suppress the plaintext refusal: ' + JSON.stringify(errs));
    } finally {
      delete process.env.HERMITSTASH_ALLOW_PLAINTEXT;
    }
  });

  it('still rejects a genuinely malformed server URL', () => {
    assert.ok(hasErr(config.validate(baseCfg({ server: 'not-a-url' })), 'not a valid URL'));
  });
});

describe('http-config#9 — HttpClient constructor WARNs on a non-loopback plaintext transport', () => {
  let clients;
  let warns;
  let origWarn;
  before(() => { clients = []; });
  function makeClient(cfg) {
    warns = [];
    origWarn = logger.warn;
    logger.warn = (m) => { warns.push(String(m)); };
    try {
      const c = new HttpClient(cfg, 'k');
      clients.push(c);
      return c;
    } finally {
      logger.warn = origWarn;
    }
  }
  after(() => { for (const c of clients) { try { c.destroy(); } catch { /* noop */ } } });

  it('warns loudly for a non-loopback http:// server', () => {
    makeClient({ server: 'http://sync.example.com' });
    assert.ok(warns.some(w => /UNENCRYPTED/.test(w)), 'expected a plaintext WARN, got: ' + JSON.stringify(warns));
  });

  it('is quiet for loopback http:// and for https://', () => {
    makeClient({ server: 'http://127.0.0.1:9/' });
    assert.equal(warns.length, 0, 'loopback http:// must not warn');
    makeClient({ server: 'https://sync.example.com' });
    assert.equal(warns.length, 0, 'https:// must not warn');
  });

  it('does NOT throw on a non-loopback http:// server (preserves direct-caller / SSRF-guard paths)', () => {
    assert.doesNotThrow(() => makeClient({ server: 'http://169.254.169.254' }));
  });
});

describe('http-config#27/#10 — throttle rate is coerced without int32 truncation', () => {
  const clients = [];
  after(() => { for (const c of clients) { try { c.destroy(); } catch { /* noop */ } } });

  it('preserves a > 2^31 bytes/sec cap instead of wrapping it negative (throttle stays armed)', () => {
    const c = new HttpClient({ server: 'http://127.0.0.1:9/', uploadBytesPerSec: 3000000000, downloadBytesPerSec: 5000000000 }, 'k');
    clients.push(c);
    assert.equal(c._uploadBytesPerSec, 3000000000, 'a 3 GB/s cap must survive coercion');
    assert.ok(c._uploadLimiter, 'upload limiter must be constructed for a large positive rate');
    assert.equal(c._downloadBytesPerSec, 5000000000);
    assert.ok(c._downloadLimiter, 'download limiter must be constructed for a large positive rate');
  });

  it('0 / unset stays unlimited (null limiter), matching prior behaviour', () => {
    const c = new HttpClient({ server: 'http://127.0.0.1:9/' }, 'k');
    clients.push(c);
    assert.equal(c._uploadLimiter, null);
    assert.equal(c._downloadLimiter, null);
    assert.equal(c._uploadBytesPerSec, 0);
    assert.equal(c._downloadBytesPerSec, 0);
  });

  it('a normal small cap is unchanged', () => {
    const c = new HttpClient({ server: 'http://127.0.0.1:9/', uploadBytesPerSec: 4096 }, 'k');
    clients.push(c);
    assert.equal(c._uploadBytesPerSec, 4096);
    assert.ok(c._uploadLimiter);
  });
});

describe('http-config#28 — config.maxFileSize is wired into real per-file enforcement', () => {
  const clients = [];
  function make(cfg) { const c = new HttpClient(cfg, 'k'); clients.push(c); return c; }
  after(() => { for (const c of clients) { try { c.destroy(); } catch { /* noop */ } } });

  it('a non-zero maxFileSize below the process cap becomes the effective ceiling', () => {
    assert.equal(make({ server: 'http://127.0.0.1:9/', maxFileSize: 1048576 })._maxFileBytes, 1048576);
  });

  it('0 / unset falls back to MAX_SYNC_FILE_BYTES (env-driven default authoritative)', () => {
    assert.equal(make({ server: 'http://127.0.0.1:9/', maxFileSize: 0 })._maxFileBytes, MAX_SYNC_FILE_BYTES);
    assert.equal(make({ server: 'http://127.0.0.1:9/' })._maxFileBytes, MAX_SYNC_FILE_BYTES);
  });

  it('a maxFileSize above the process cap is clamped DOWN (can only tighten, never raise)', () => {
    assert.equal(make({ server: 'http://127.0.0.1:9/', maxFileSize: MAX_SYNC_FILE_BYTES * 10 })._maxFileBytes, MAX_SYNC_FILE_BYTES);
  });

  it('uploadFile refuses an over-cap file with a permanent error before any network op', async () => {
    const tmp = nodePath.join(TMP_DIR, 'over-cap.bin');
    nodeFs.writeFileSync(tmp, Buffer.alloc(100));
    const c = make({ server: 'http://127.0.0.1:9/', maxFileSize: 10 });
    let threw = null;
    try { await c.uploadFile('bundle', 'over-cap.bin', tmp); } catch (e) { threw = e; }
    assert.ok(threw, 'an over-cap upload must reject');
    assert.match(threw.message, /per-file size limit/);
    assert.equal(threw.permanent, true, 'the refusal must be permanent so the sync engine does not loop');
  });

  it('uploadFile does NOT size-refuse a file at/under the cap (over-rejection guard)', async () => {
    const tmp = nodePath.join(TMP_DIR, 'under-cap.bin');
    nodeFs.writeFileSync(tmp, Buffer.alloc(10));
    const c = make({ server: 'http://127.0.0.1:9/', maxFileSize: 10 });
    let threw = null;
    // No server is listening on :9, so this rejects with a connection error —
    // the point is that it is NOT the size-limit refusal (the file is at the cap).
    try { await c.uploadFile('bundle', 'under-cap.bin', tmp); } catch (e) { threw = e; }
    assert.ok(threw, 'expected a connection error (no server), got resolve');
    assert.doesNotMatch(threw.message, /per-file size limit/, 'a file at the cap must pass the size gate');
  });
});

describe('http-config#30 — config.load rejects a non-object JSON root', () => {
  for (const [label, body] of [['array', '["https://x"]'], ['string', '"oops"'], ['number', '5'], ['null', 'null']]) {
    it('rejects a top-level ' + label + ' with an actionable error', () => {
      nodeFs.mkdirSync(nodePath.dirname(CONFIG_FILE), { recursive: true });
      nodeFs.writeFileSync(CONFIG_FILE, body);
      assert.throws(() => config.load(), /must be a JSON object/);
    });
  }

  it('accepts a normal object root', () => {
    nodeFs.writeFileSync(CONFIG_FILE, JSON.stringify({ server: 'https://x', bundleId: 'b', syncFolder: SYNC_DIR }));
    const cfg = config.load();
    assert.equal(cfg.server, 'https://x');
  });
});

describe('http-config#31 — string-type validation for identity/path fields', () => {
  it('flags a non-string bundleId / shareId / syncFolder', () => {
    assert.ok(hasErr(config.validate(baseCfg({ bundleId: {} })), 'bundleId must be a string'));
    assert.ok(hasErr(config.validate(baseCfg({ bundleId: '', shareId: 42 })), 'shareId must be a string'));
    assert.ok(hasErr(config.validate(baseCfg({ syncFolder: ['/a', '/b'] })), 'syncFolder must be a string'));
  });

  it('a valid all-string config passes the type checks', () => {
    assert.ok(!hasErr(config.validate(baseCfg()), 'must be a string'));
  });

  it('getIgnorePatterns / getIncludePatterns do NOT throw on a non-string syncFolder (SIGHUP reload safety)', () => {
    assert.doesNotThrow(() => {
      const ig = config.getIgnorePatterns({ syncFolder: ['/a', '/b'], ignore: ['*.log'] });
      assert.ok(Array.isArray(ig) && ig.includes('*.log'), 'config.ignore entries must still flow through');
      const inc = config.getIncludePatterns({ syncFolder: ['/a', '/b'], include: ['docs/**'] });
      assert.ok(Array.isArray(inc) && inc.includes('docs/**'));
    });
  });
});
