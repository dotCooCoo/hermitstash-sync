'use strict';

// Pure-unit regression tests for the diagnose / logger / constants audit fixes
// (findings #39-#45). No server harness, no network — these drive the modules'
// public + closure-internal behavior directly against a throwaway CONFIG_DIR.
//
// CONFIG_DIR (and every path derived from it: CONFIG_FILE, LOG_FILE, etc.) is
// resolved once at require time inside lib/constants.js from
// HERMITSTASH_SYNC_CONFIG_DIR. We point it at a fresh temp dir BEFORE the first
// require so the whole module graph reads/writes there, then mutate config.json
// / log files / the update marker per test inside that dir.

const nodeOs = require('node:os');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeZlib = require('node:zlib');
const nodeCrypto = require('node:crypto');

const TMP_CONFIG_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-diag-fix-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = TMP_CONFIG_DIR;

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const b = require('../vendor/blamejs');
const C = b.constants;
const constants = require('../lib/constants');
const diagnose = require('../lib/diagnose');

const CONFIG_FILE = constants.CONFIG_FILE;
const CONFIG_DIR = constants.CONFIG_DIR;
const LOG_FILE = constants.LOG_FILE;
const LOG_DIR = nodePath.dirname(LOG_FILE);
const LOG_BASE = nodePath.basename(LOG_FILE, nodePath.extname(LOG_FILE));

// Can this host create a symlink? (Windows without Developer Mode / admin
// returns EPERM.) Symlink-refusal assertions are gated on this so the suite
// still passes on a locked-down Windows box.
function _canSymlink() {
  const probe = nodePath.join(TMP_CONFIG_DIR, '.symlink-probe');
  const target = nodePath.join(TMP_CONFIG_DIR, '.symlink-target');
  try {
    nodeFs.writeFileSync(target, 'x');
    nodeFs.symlinkSync(target, probe);
    nodeFs.unlinkSync(probe);
    nodeFs.unlinkSync(target);
    return true;
  } catch {
    try { nodeFs.unlinkSync(probe); } catch { /* ignore */ }
    try { nodeFs.unlinkSync(target); } catch { /* ignore */ }
    return false;
  }
}
const CAN_SYMLINK = _canSymlink();

function _writeConfig(obj) {
  nodeFs.writeFileSync(CONFIG_FILE, typeof obj === 'string' ? obj : JSON.stringify(obj));
}
function _rmConfig() {
  try { nodeFs.unlinkSync(CONFIG_FILE); } catch { /* ignore */ }
}
function _clearLogs() {
  for (const name of nodeFs.readdirSync(LOG_DIR)) {
    if (name === LOG_BASE + '.log' || (name.startsWith(LOG_BASE + '-') && name.endsWith('.log.gz'))) {
      try { nodeFs.unlinkSync(nodePath.join(LOG_DIR, name)); } catch { /* ignore */ }
    }
  }
}
function _rmMarker() {
  try { nodeFs.unlinkSync(nodePath.join(CONFIG_DIR, 'update-pending.json')); } catch { /* ignore */ }
}

// Minimal ZIP central-directory reader. blamejs's b.archive ships a zip WRITER
// only (no reader for stored entries), so the test parses the standard ZIP
// format (PK\x05\x06 EOCD → central directory → per-entry local header +
// deflated payload) to pull a named entry back out of a buildBundle archive.
// Entries are deflate-compressed (method 8); STORED (method 0) is also handled.
function _bundleEntry(outPath, entryName) {
  const buf = nodeFs.readFileSync(outPath);
  // Locate the End Of Central Directory record (signature 0x06054b50),
  // scanning backward from the tail (no zip comment is written here).
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('EOCD not found in ' + outPath);
  const cdCount = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16); // central-directory start offset
  for (let n = 0; n < cdCount; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad CD header');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString('utf8');
    if (name === entryName) {
      // Parse the local file header to find the payload start.
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      const dataStart = localOff + 30 + lNameLen + lExtraLen;
      const payload = buf.slice(dataStart, dataStart + compSize);
      return method === 0 ? payload : nodeZlib.inflateRawSync(payload);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

beforeEach(() => {
  _rmConfig();
  _rmMarker();
  _clearLogs();
});

describe('#39 — update-pending.json projection drops absolute prevBinaryPath', () => {
  it('ships only basename of prevBinaryPath; no path separators, no OS username', () => {
    _writeConfig({ server: 'https://example.test' });
    const username = nodeOs.userInfo().username;
    const absPrev = nodePath.join(
      nodeOs.homedir(), '.hermitstash-sync', 'hermitstash-sync.exe.prev');
    nodeFs.writeFileSync(
      nodePath.join(CONFIG_DIR, 'update-pending.json'),
      JSON.stringify({
        newVersion:     '9.9.9',
        prevBinaryPath: absPrev,
        installedAt:    1700000000000,
        gracefulAt:     1700000060000,
      }));

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-39.zip');
    diagnose.buildBundle(out);
    const raw = _bundleEntry(out, 'update-pending.json');
    assert.ok(raw, 'update-pending.json must be present in the bundle');
    const marker = JSON.parse(raw.toString('utf8'));

    // Guard against the OLD bug: the verbatim absolute path must NOT survive.
    assert.equal(marker.prevBinaryPath, 'hermitstash-sync.exe.prev');
    assert.ok(!String(marker.prevBinaryPath).includes('/'), 'no forward slash');
    assert.ok(!String(marker.prevBinaryPath).includes('\\'), 'no backslash');
    if (username && username.length > 2) {
      assert.ok(!JSON.stringify(marker).includes(username),
        'OS username must not leak via the marker');
    }
    // Non-identifying fields stay verbatim — a supporter still gets them.
    assert.equal(marker.newVersion, '9.9.9');
    assert.equal(marker.installedAt, 1700000000000);
    assert.equal(marker.gracefulAt, 1700000060000);

    nodeFs.unlinkSync(out);
  });

  it('null-safe when prevBinaryPath is absent', () => {
    _writeConfig({ server: 'https://example.test' });
    nodeFs.writeFileSync(
      nodePath.join(CONFIG_DIR, 'update-pending.json'),
      JSON.stringify({ newVersion: '1.2.3' }));
    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-39b.zip');
    diagnose.buildBundle(out);
    const marker = JSON.parse(_bundleEntry(out, 'update-pending.json').toString('utf8'));
    assert.equal(marker.prevBinaryPath, null);
    assert.equal(marker.newVersion, '1.2.3');
    nodeFs.unlinkSync(out);
  });
});

describe('#40 — rotated .log.gz decompressed under a bomb cap', () => {
  it('drops a ratio-bomb .log.gz from the bundle instead of OOM/shipping it', () => {
    _writeConfig({ server: 'https://example.test' });
    // 2 MiB of zeros compresses ~1000:1 — well past the 200:1 ratio cap, while
    // staying far under maxOutputBytes so the *ratio* arm is what refuses it.
    const bomb = nodeZlib.gzipSync(Buffer.alloc(C.BYTES.mib(2)));
    const bombName = LOG_BASE + '-20250101T000000000Z.log.gz';
    nodeFs.writeFileSync(nodePath.join(LOG_DIR, bombName), bomb);

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-40.zip');
    // Must complete without OOM / throw.
    const res = diagnose.buildBundle(out);
    assert.ok(res.entryCount >= 1);
    // The bomb file must be absent from the bundle's log/ dir.
    assert.equal(_bundleEntry(out, 'log/' + bombName), null,
      'decompression-bomb log must not be shipped');
    nodeFs.unlinkSync(out);
  });

  it('a legitimate low-ratio .log.gz still round-trips into the bundle', () => {
    _writeConfig({ server: 'https://example.test' });
    const line = JSON.stringify({ ts: 1, level: 'info', message: 'sync complete ' + 'x'.repeat(40) });
    const okName = LOG_BASE + '-20250102T000000000Z.log.gz';
    nodeFs.writeFileSync(nodePath.join(LOG_DIR, okName), nodeZlib.gzipSync(Buffer.from(line + '\n')));

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-40b.zip');
    diagnose.buildBundle(out);
    const got = _bundleEntry(out, 'log/' + okName);
    assert.ok(got, 'legit rotated log must be present');
    const text = nodeZlib.gunzipSync(got).toString('utf8');
    assert.ok(text.includes('sync complete'), 'redacted content preserved');
    nodeFs.unlinkSync(out);
  });
});

describe('#41 — config + cert read via b.atomicFile.fdSafeReadSync', () => {
  it('reads a present config.json and projects it into the bundle', () => {
    _writeConfig({ server: 'https://example.test', logLevel: 'warn', apiKey: 'deadbeefdeadbeef' });
    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-41.zip');
    diagnose.buildBundle(out);
    const cfg = JSON.parse(_bundleEntry(out, 'config.redacted.json').toString('utf8'));
    assert.equal(cfg.logLevel, 'warn');
    assert.ok(!cfg._absent, 'present config must not be marked absent');
    // The apiKey must never appear in the projection (allowlist + redact).
    assert.ok(!JSON.stringify(cfg).includes('deadbeefdeadbeef'));
    nodeFs.unlinkSync(out);
  });

  it('absent config.json still yields the {_absent} shape (ENOENT mapped to null)', () => {
    _rmConfig();
    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-41b.zip');
    diagnose.buildBundle(out);
    const cfg = JSON.parse(_bundleEntry(out, 'config.redacted.json').toString('utf8'));
    assert.equal(cfg._absent, true);
    nodeFs.unlinkSync(out);
  });

  it('refuses a symlinked config.json (TOCTOU/CWE-59 guard)', { skip: !CAN_SYMLINK }, () => {
    // Plant config.json as a symlink to a real JSON file elsewhere; the
    // fdSafeReadSync refuseSymlink posture must refuse to follow it, so the
    // projection reports the config unreadable rather than reading the target.
    const realTarget = nodePath.join(TMP_CONFIG_DIR, 'real-config-41c.json');
    nodeFs.writeFileSync(realTarget, JSON.stringify({ logLevel: 'debug', apiKey: 'leakytarget1234' }));
    _rmConfig();
    nodeFs.symlinkSync(realTarget, CONFIG_FILE);
    try {
      const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-41c.zip');
      diagnose.buildBundle(out);
      const cfg = JSON.parse(_bundleEntry(out, 'config.redacted.json').toString('utf8'));
      // OLD behavior (plain readFileSync) would follow the link and project
      // logLevel:'debug'; the fix must NOT — it surfaces the unreadable marker.
      assert.notEqual(cfg.logLevel, 'debug');
      assert.equal(cfg._unreadable, true);
      assert.ok(!JSON.stringify(cfg).includes('leakytarget1234'));
      nodeFs.unlinkSync(out);
    } finally {
      _rmConfig();
    }
  });

  it('_certInfo reads a real client cert via the safe reader and emits CN/serial only', async () => {
    const eng = require('../vendor/blamejs/lib/mtls-engine-default');
    const ca = await eng.generateCa({ generation: 1 });
    const signed = await eng.signClientCert({
      cn: 'diag-test-client', validityDays: 30, caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    });
    const certPath = nodePath.join(TMP_CONFIG_DIR, 'client-41d.crt');
    nodeFs.writeFileSync(certPath, signed.cert);
    _writeConfig({ server: 'https://example.test', mtls: { cert: certPath } });

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-41d.zip');
    diagnose.buildBundle(out);
    const ci = JSON.parse(_bundleEntry(out, 'cert-info.json').toString('utf8'));
    assert.equal(ci.subjectCN, 'diag-test-client');
    assert.ok(ci.serialNumber, 'serial present');
    assert.ok(ci.spkiPin && ci.spkiPin.startsWith('sha256/'));
    assert.ok(!ci._parse_error, 'cert must parse via the safe reader');

    // Cross-check: the same X509 parses identically from the raw bytes.
    const x = new nodeCrypto.X509Certificate(signed.cert);
    assert.equal(ci.serialNumber, x.serialNumber);
    nodeFs.unlinkSync(out);
    nodeFs.unlinkSync(certPath);
  });
});

describe('#42 — SEA detection uses node:sea.isSea()', () => {
  it('info.json.sea matches node:sea.isSea() (false under `node --test`)', () => {
    _writeConfig({ server: 'https://example.test' });
    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-42.zip');
    diagnose.buildBundle(out);
    const info = JSON.parse(_bundleEntry(out, 'info.json').toString('utf8'));
    let expected;
    try { expected = require('node:sea').isSea(); } catch { expected = false; }
    assert.equal(info.sea, expected);
    // This process runs with execArgv = ['--test'] (non-empty) and an execPath
    // that does NOT contain 'hermitstash-sync', so the OLD heuristic
    // (execArgv.length===0 && /hermitstash-sync/.test(execPath)) returns false
    // too here — but the key contract is parity with the authoritative API.
    assert.equal(typeof info.sea, 'boolean');
    nodeFs.unlinkSync(out);
  });
});

describe('#43 — logger sanitizes an invalid level for both the gate and the sink', () => {
  // Re-require logger fresh so init state is clean; it is a singleton shim.
  const logger = require('../lib/logger');

  it('an invalid opts.level does NOT throw (old bug: b.logStream.init threw INVALID_LEVEL)', () => {
    const file = nodePath.join(TMP_CONFIG_DIR, 'logger-43-' + process.pid + '.log');
    assert.doesNotThrow(() => {
      logger.init({ level: 'verbose', stdout: false, file });
    }, 'invalid level must fall back to info, not throw');
    return logger.close();
  });

  it('a valid level still initializes cleanly', () => {
    const file = nodePath.join(TMP_CONFIG_DIR, 'logger-43b-' + process.pid + '.log');
    assert.doesNotThrow(() => {
      logger.init({ level: 'warn', stdout: false, file });
    });
    return logger.close();
  });
});

describe('#44 — numeric env vars reject unit-suffixed garbage, fall back to default (real production resolvers)', () => {
  // Exercise the REAL production code (no parallel reimplementation): constants
  // resolves MAX_SYNC_FILE_BYTES once at module-load, so cache-bust + re-require
  // it under a set env var; logger.resolveMaxLogBytes() reads the env var at call
  // time, so call it directly. The top-level `constants` binding and diagnose's
  // captured copy are unaffected by the re-require (a fresh module object), and
  // each case re-requires once with clean env to leave the cache pristine.
  const logger = require('../lib/logger');

  function withEnv(name, value, fn) {
    const prev = process.env[name];
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
    try { return fn(); }
    finally { if (prev === undefined) delete process.env[name]; else process.env[name] = prev; }
  }
  function freshConstants() {
    delete require.cache[require.resolve('../lib/constants')];
    return require('../lib/constants');
  }

  it('constants.MAX_SYNC_FILE_BYTES rejects "256GB" and keeps the 256 GiB default (old parseInt → 256 bytes)', () => {
    const got = withEnv('HERMITSTASH_MAX_FILE_BYTES', '256GB', () => freshConstants().MAX_SYNC_FILE_BYTES);
    freshConstants(); // repopulate the cache with the clean-env build
    assert.equal(got, C.BYTES.gib(256), 'unit-suffixed value must fall back to the default, not 256 bytes');
    assert.notEqual(got, 256);
  });

  it('constants.MAX_SYNC_FILE_BYTES honors a plain integer override verbatim', () => {
    const got = withEnv('HERMITSTASH_MAX_FILE_BYTES', '1048576', () => freshConstants().MAX_SYNC_FILE_BYTES);
    freshConstants();
    assert.equal(got, 1048576);
  });

  it('logger.resolveMaxLogBytes() rejects "10MiB" and resolves to the same value as no override', () => {
    const garbage = withEnv('HERMITSTASH_LOG_MAX_MIB', '10MiB', () => logger.resolveMaxLogBytes());
    const dflt = withEnv('HERMITSTASH_LOG_MAX_MIB', undefined, () => logger.resolveMaxLogBytes());
    assert.equal(garbage, dflt, 'a unit-suffixed value must fall back to the default, not parse to 10');
    assert.equal(garbage, C.BYTES.mib(10), 'the default is 10 MiB');
  });

  it('logger.resolveMaxLogBytes() honors a clean integer override (in MiB)', () => {
    const got = withEnv('HERMITSTASH_LOG_MAX_MIB', '50', () => logger.resolveMaxLogBytes());
    assert.equal(got, C.BYTES.mib(50));
  });
});

describe('#45 — unparseable config.json surfaces as unreadable + still scrubs secrets', () => {
  it('config.redacted.json is marked _unreadable (not a misleading near-empty projection)', () => {
    _writeConfig('{ this is not valid json');
    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-45.zip');
    diagnose.buildBundle(out);
    const cfg = JSON.parse(_bundleEntry(out, 'config.redacted.json').toString('utf8'));
    assert.equal(cfg._unreadable, true);
    // OLD bug: the truthy error sentinel flowed through as a config, yielding a
    // near-empty projection that looked valid. Guard that it does NOT.
    assert.ok(!('bundleConfigured' in cfg) || cfg._unreadable,
      'must not masquerade as a valid (near-empty) config');
    const info = JSON.parse(_bundleEntry(out, 'info.json').toString('utf8'));
    assert.equal(info.configUnreadable, true);
    nodeFs.unlinkSync(out);
  });

  it('a bare token in a free-form log line is STILL scrubbed when config is corrupt (raw-harvest fallback)', () => {
    const token = 'tok_' + nodeCrypto.randomBytes(16).toString('hex');
    // Valid-shaped config bytes containing the token as a quoted JSON string
    // value, but deliberately corrupted so the keyed parse fails and the raw
    // harvest is the only path that can find the secret.
    _writeConfig('{ "apiKey": "' + token + '", CORRUPT');
    // A log line that mentions the token in free-form text b.redact won't catch.
    const logName = LOG_BASE + '.log';
    nodeFs.writeFileSync(
      nodePath.join(LOG_DIR, logName),
      JSON.stringify({ ts: 1, level: 'error', message: 'request failed for key ' + token }) + '\n');

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-45b.zip');
    diagnose.buildBundle(out);
    const logBuf = _bundleEntry(out, 'log/' + logName);
    assert.ok(logBuf, 'active log must be in the bundle');
    const logText = logBuf.toString('utf8');
    assert.ok(!logText.includes(token),
      'the secret literal must NOT survive into the bundle even with an unparseable config');
    nodeFs.unlinkSync(out);
  });

  it('valid config still drives the keyed literal scrub (no regression)', () => {
    const token = 'tok_' + nodeCrypto.randomBytes(16).toString('hex');
    _writeConfig({ server: 'https://example.test', apiKey: token });
    const logName = LOG_BASE + '.log';
    nodeFs.writeFileSync(
      nodePath.join(LOG_DIR, logName),
      JSON.stringify({ ts: 1, level: 'error', message: 'failure with ' + token }) + '\n');

    const out = nodePath.join(TMP_CONFIG_DIR, 'bundle-45c.zip');
    diagnose.buildBundle(out);
    const logText = _bundleEntry(out, 'log/' + logName).toString('utf8');
    assert.ok(!logText.includes(token), 'keyed literal scrub still fires for a valid config');
    nodeFs.unlinkSync(out);
  });
});
