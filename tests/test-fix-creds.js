'use strict';

// Pure-unit regression tests for the state+config+keychain audit fixes.
// No server harness, no network: each test drives the production lib modules
// directly against node:fs temp dirs. CONFIG_DIR is redirected to a temp dir
// via HERMITSTASH_SYNC_CONFIG_DIR BEFORE the lib modules are required, since
// lib/constants.js resolves the dir once at module load. state-db's open()
// takes an explicit dbPath so its tests use isolated temp DBs directly.
//
// Run standalone: node --test tests/test-fix-creds.js

const nodeFs = require('node:fs');
const nodeOs = require('node:os');
const nodePath = require('node:path');

// Redirect CONFIG_DIR before any lib require resolves constants.js.
const ROOT_CONFIG_DIR = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-fixcreds-'));
process.env.HERMITSTASH_SYNC_CONFIG_DIR = ROOT_CONFIG_DIR;

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const b = require('../vendor/blamejs');
const { CONFIG_DIR, CONFIG_FILE, CREDENTIALS_FILE } = require('../lib/constants');
const keychain = require('../lib/keychain');
const config = require('../lib/config');
const stateDb = require('../lib/state-db');
const logger = require('../lib/logger');

logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fixcreds-' + process.pid + '.log') });

const IS_WIN = process.platform === 'win32';

function tmpdir(prefix) {
  return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), prefix));
}

function rmFileQuiet(p) {
  try { nodeFs.unlinkSync(p); } catch { /* best-effort */ }
}

after(() => {
  try { nodeFs.rmSync(ROOT_CONFIG_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

// ---------------------------------------------------------------------------
// #25 — Symlink-following statSync/chmodSync removed; mode asserted off the
//       fstat of the inode-pinned, symlink-refused read (no TOCTOU chmod).
//       #26 is fixed-by-#25 (same code region): the hand-rolled mode-bit
//       check + path-chmod is replaced by the fdSafeReadSync withStat posture.
// ---------------------------------------------------------------------------
describe('state+config+keychain#25 / #26 — keychain credentials read is TOCTOU-safe and refuses loose perms', () => {
  before(() => { b.atomicFile.ensureDir(CONFIG_DIR, 0o700); });
  after(() => { rmFileQuiet(CREDENTIALS_FILE); });

  it('reads back a properly-tightened (0o600) credentials file', () => {
    rmFileQuiet(CREDENTIALS_FILE);
    b.atomicFile.writeSync(CREDENTIALS_FILE, 'GOOD-KEY-600', { fileMode: 0o600 });
    // Force the file fallback (apiKeyRef='file') so no native backend is probed.
    return keychain.retrieve('file').then((got) => {
      assert.equal(got, 'GOOD-KEY-600', 'a 0o600 fallback file must be served');
    });
  });

  it('REFUSES a group/world-readable credentials file instead of serving it (POSIX)', async () => {
    if (IS_WIN) return; // POSIX mode bits are not meaningful on Windows
    rmFileQuiet(CREDENTIALS_FILE);
    nodeFs.writeFileSync(CREDENTIALS_FILE, 'EXPOSED-KEY');
    nodeFs.chmodSync(CREDENTIALS_FILE, 0o644);
    await assert.rejects(
      () => keychain.retrieve('file'),
      (err) => {
        assert.match(err.message, /readable by other users|could not be read safely/,
          'a loose-perm fallback file must be refused with an actionable message');
        return true;
      },
      'retrieve() must fail closed on an exposed credentials file');
  });

  it('does NOT chmod a symlink target before refusing it (no TOCTOU arbitrary-chmod) (POSIX)', async () => {
    if (IS_WIN) return; // symlink creation is privileged on Windows
    rmFileQuiet(CREDENTIALS_FILE);
    // Plant a victim file with deliberately loose perms; the old code would
    // statSync+chmodSync(0o600) the symlink TARGET before the read refused it.
    const victimDir = tmpdir('hs-victim-');
    const victim = nodePath.join(victimDir, 'victim-inode');
    nodeFs.writeFileSync(victim, 'NOT-A-CREDENTIAL');
    nodeFs.chmodSync(victim, 0o666);
    const before = nodeFs.statSync(victim).mode & 0o777;
    try {
      nodeFs.symlinkSync(victim, CREDENTIALS_FILE);
    } catch {
      return; // symlink unsupported in this environment — skip
    }
    await assert.rejects(
      () => keychain.retrieve('file'),
      /symlink|could not be read safely/,
      'a symlinked credentials file must be refused');
    const afterMode = nodeFs.statSync(victim).mode & 0o777;
    assert.equal(afterMode, before,
      'the symlink target inode mode must be UNCHANGED — no chmod followed the symlink');
    rmFileQuiet(CREDENTIALS_FILE);
    nodeFs.rmSync(victimDir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// #28 — validate() type-checks mtls and enforces the cert/key/ca trio.
// ---------------------------------------------------------------------------
describe('state+config+keychain#28 — mtls shape + trio validation', () => {
  let dir, cert, key, ca;
  before(() => {
    dir = tmpdir('hs-mtls-');
    cert = nodePath.join(dir, 'client.pem');
    key = nodePath.join(dir, 'client.key');
    ca = nodePath.join(dir, 'ca.pem');
    for (const p of [cert, key, ca]) nodeFs.writeFileSync(p, 'PEM');
  });
  after(() => { try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });

  function base(extra) {
    return Object.assign({ server: 'https://h.example', syncFolder: dir, bundleId: 'b1' }, extra);
  }

  it('mtls:null is valid', () => {
    const errs = config.validate(base({ mtls: null }));
    assert.equal(errs.filter(e => /mtls/i.test(e)).length, 0);
  });

  it('a full cert/key/ca trio (all existing) is valid', () => {
    const errs = config.validate(base({ mtls: { cert, key, ca } }));
    assert.equal(errs.filter(e => /mtls/i.test(e)).length, 0, errs.join('; '));
  });

  it('a string mtls is rejected (old bug: passed validation, failed at handshake)', () => {
    const errs = config.validate(base({ mtls: '/some/path' }));
    assert.ok(errs.some(e => /mtls must be null or an object/.test(e)),
      'a non-object mtls must be rejected: ' + errs.join('; '));
  });

  it('an array mtls is rejected', () => {
    const errs = config.validate(base({ mtls: [cert, key, ca] }));
    assert.ok(errs.some(e => /mtls must be null or an object/.test(e)), errs.join('; '));
  });

  it('a partial trio { cert } is rejected with the missing fields named', () => {
    const errs = config.validate(base({ mtls: { cert } }));
    assert.ok(errs.some(e => /missing: key, ca/.test(e)),
      'a partial trio must be rejected naming key+ca: ' + errs.join('; '));
  });

  it('a non-string cert path is rejected', () => {
    const errs = config.validate(base({ mtls: { cert: 123, key, ca } }));
    assert.ok(errs.some(e => /mtls\.cert must be a string path/.test(e)), errs.join('; '));
  });
});

// ---------------------------------------------------------------------------
// #29 — env-overlay _int strictly parses; malformed values reach validate()
//       (and are rejected) instead of being silently dropped to the default.
// ---------------------------------------------------------------------------
describe('state+config+keychain#29 — strict integer env overlay', () => {
  const KEY = 'HERMITSTASH_DOWNLOAD_BYTES_PER_SEC';
  let saved;
  before(() => {
    saved = process.env[KEY];
    // Minimal valid config.json so load() succeeds and we exercise the overlay.
    b.atomicFile.ensureDir(CONFIG_DIR, 0o700);
    nodeFs.writeFileSync(CONFIG_FILE, JSON.stringify({
      server: 'https://h.example', syncFolder: CONFIG_DIR, bundleId: 'b1',
    }));
  });
  after(() => {
    if (saved === undefined) delete process.env[KEY]; else process.env[KEY] = saved;
    rmFileQuiet(CONFIG_FILE);
  });

  it('a non-numeric env value ("unlimited") is surfaced by validate(), not silently dropped', () => {
    process.env[KEY] = 'unlimited';
    const cfg = config.load();
    const errs = config.validate(cfg);
    assert.ok(errs.some(e => e.includes(KEY) && /non-negative integer/.test(e)),
      'malformed env value must be rejected by name: ' + errs.join('; '));
  });

  it('a trailing-garbage value ("10MB") is rejected, not coerced to 10', () => {
    process.env[KEY] = '10MB';
    const cfg = config.load();
    assert.notEqual(cfg.downloadBytesPerSec, 10, 'must not silently coerce 10MB -> 10');
    const errs = config.validate(cfg);
    assert.ok(errs.some(e => e.includes(KEY)), errs.join('; '));
  });

  it('a clean integer is accepted', () => {
    process.env[KEY] = '4096';
    const cfg = config.load();
    assert.equal(cfg.downloadBytesPerSec, 4096);
    assert.equal(config.validate(cfg).filter(e => e.includes(KEY)).length, 0);
  });

  it('an unset env var keeps the default (0 = unlimited)', () => {
    delete process.env[KEY];
    const cfg = config.load();
    assert.equal(cfg.downloadBytesPerSec, 0);
  });

  // Regression guard: a blank value is "unset", not "malformed". Container
  // platforms hand an empty string for any optional numeric left blank (Unraid
  // Default="", Compose `VAR=`), so blank must fall back to the default WITHOUT
  // a validation error — failing it here would refuse to boot an install that
  // leaves the documented-as-optional bandwidth/concurrency fields blank.
  it('an empty-string env value keeps the default and does NOT fail validation', () => {
    process.env[KEY] = '';
    const cfg = config.load();
    assert.equal(cfg.downloadBytesPerSec, 0, 'blank must resolve to the default, not ""');
    assert.equal(config.validate(cfg).filter(e => e.includes(KEY)).length, 0,
      'a blank optional numeric must not be a validation error');
  });

  it('a whitespace-only env value keeps the default and does NOT fail validation', () => {
    process.env[KEY] = '   ';
    const cfg = config.load();
    assert.equal(cfg.downloadBytesPerSec, 0, 'whitespace-only must resolve to the default');
    assert.equal(config.validate(cfg).filter(e => e.includes(KEY)).length, 0,
      'a whitespace-only optional numeric must not be a validation error');
  });
});

// ---------------------------------------------------------------------------
// #30 / #31 — pattern files read via fdSafeReadSync (symlink-refusing,
//             byte-capped, ENOENT -> [], fail-closed on other errors); load()
//             reads via fdSafeReadSync (no existsSync pre-flight) and still
//             throws the actionable "run init" message on a missing file.
// ---------------------------------------------------------------------------
describe('state+config+keychain#30 / #31 — TOCTOU-safe pattern files + config load', () => {
  let folder;
  before(() => { folder = tmpdir('hs-patterns-'); });
  after(() => { try { nodeFs.rmSync(folder, { recursive: true, force: true }); } catch { /* best-effort */ } });

  it('a missing .hermitstash-ignore yields just the defaults (ENOENT -> no extra patterns)', () => {
    rmFileQuiet(nodePath.join(folder, '.hermitstash-ignore'));
    const out = config.getIgnorePatterns({ syncFolder: folder, ignore: [] });
    assert.ok(Array.isArray(out) && out.length > 0, 'defaults must still be present');
  });

  it('a normal .hermitstash-ignore is parsed (comments + blanks stripped, deduped)', () => {
    const f = nodePath.join(folder, '.hermitstash-ignore');
    nodeFs.writeFileSync(f, '# a comment\n*.tmp\n\n  *.bak  \n*.tmp\n');
    const out = config.getIgnorePatterns({ syncFolder: folder, ignore: [] });
    assert.ok(out.includes('*.tmp'));
    assert.ok(out.includes('*.bak'));
    assert.equal(out.filter(p => p === '*.tmp').length, 1, 'deduped');
    assert.ok(!out.includes('# a comment'), 'comment lines stripped');
    rmFileQuiet(f);
  });

  it('a normal .hermitstash-include is parsed', () => {
    const f = nodePath.join(folder, '.hermitstash-include');
    nodeFs.writeFileSync(f, 'work/**\n');
    const out = config.getIncludePatterns({ syncFolder: folder, include: [] });
    assert.ok(out.includes('work/**'));
    rmFileQuiet(f);
  });

  it('a symlinked .hermitstash-ignore is refused (fail-closed), not silently read (POSIX)', () => {
    if (IS_WIN) return; // symlink creation is privileged on Windows
    const real = nodePath.join(folder, 'real-rules.txt');
    nodeFs.writeFileSync(real, '*.secret\n');
    const link = nodePath.join(folder, '.hermitstash-ignore');
    rmFileQuiet(link);
    try {
      nodeFs.symlinkSync(real, link);
    } catch {
      return; // symlink unsupported — skip
    }
    assert.throws(
      () => config.getIgnorePatterns({ syncFolder: folder, ignore: [] }),
      /Cannot read .*hermitstash-ignore|symlink/,
      'a symlinked pattern file must be refused with an actionable error');
    rmFileQuiet(link);
    rmFileQuiet(real);
  });

  it('an over-cap .hermitstash-ignore is refused (fail-closed)', () => {
    const f = nodePath.join(folder, '.hermitstash-ignore');
    // 256 KiB cap + 1 byte.
    nodeFs.writeFileSync(f, Buffer.alloc(b.constants.BYTES.kib(256) + 1, 0x61));
    assert.throws(
      () => config.getIgnorePatterns({ syncFolder: folder, ignore: [] }),
      /Cannot read .*hermitstash-ignore/,
      'an over-cap pattern file must be refused');
    rmFileQuiet(f);
  });

  it('load() throws the actionable "run init" message on a missing config (no existsSync gate)', () => {
    rmFileQuiet(CONFIG_FILE);
    assert.throws(
      () => config.load(),
      /Run 'hermitstash-sync init' first/,
      'a missing config must surface the actionable enoent message');
  });

  it('load() reads a present config without a separate existsSync round-trip', () => {
    b.atomicFile.ensureDir(CONFIG_DIR, 0o700);
    nodeFs.writeFileSync(CONFIG_FILE, JSON.stringify({ server: 'https://h.example', syncFolder: CONFIG_DIR, bundleId: 'b1' }));
    const cfg = config.load();
    assert.equal(cfg.server, 'https://h.example');
    rmFileQuiet(CONFIG_FILE);
  });
});

// ---------------------------------------------------------------------------
// #32 — dumpSchema validates table names against an identifier allowlist
//       before interpolating; a non-conforming name yields a null count
//       without throwing or executing against it.
// ---------------------------------------------------------------------------
describe('state+config+keychain#32 — dumpSchema identifier allowlist', () => {
  let dbPath;
  before(() => { dbPath = nodePath.join(tmpdir('hs-db32-'), 'state.db'); });
  after(() => { try { stateDb.close(); } catch { /* best-effort */ } });

  it('real tables (files, sync_state) report numeric counts', () => {
    stateDb.open(dbPath);
    const dump = stateDb.dumpSchema();
    assert.equal(typeof dump.counts.files, 'number');
    assert.equal(typeof dump.counts.sync_state, 'number');
    stateDb.close();
  });

  it('a table whose name contains a quote yields a null count, never an injection', () => {
    stateDb.open(dbPath);
    const d = stateDb.db();
    d.exec('CREATE TABLE IF NOT EXISTS "weird""name" (x INTEGER)');
    const dump = stateDb.dumpSchema();
    // The non-conforming name is recorded null (allowlist skip), and the real
    // tables survive — no DROP / breakout executed.
    assert.equal(dump.counts['weird"name'], null);
    assert.equal(typeof dump.counts.files, 'number', 'files table must still be countable');
    stateDb.close();
  });
});

// ---------------------------------------------------------------------------
// #33 — open() is idempotent: a second open() closes the prior handle instead
//       of orphaning it.
// ---------------------------------------------------------------------------
describe('state+config+keychain#33 — open() drops the prior handle', () => {
  after(() => { try { stateDb.close(); } catch { /* best-effort */ } });

  it('a second open() without an intervening close() does not throw and yields a working handle', () => {
    const dbPath = nodePath.join(tmpdir('hs-db33-'), 'state.db');
    stateDb.open(dbPath);
    stateDb.setMeta('k', 'v1');
    // Re-open in the SAME process with no explicit close() — the old singleton
    // would orphan the first handle; the fix closes it first.
    assert.doesNotThrow(() => stateDb.open(dbPath));
    // The re-opened handle is usable and sees the persisted row.
    assert.equal(stateDb.getMeta('k'), 'v1');
    stateDb.close();
  });
});

// ---------------------------------------------------------------------------
// #34 — _migrateNeedsBytes re-probe is guarded; the migration converges (the
//       needsBytes column exists after open) on both fresh and pre-existing
//       schemas, and a duplicate-column re-open is swallowed correctly.
// ---------------------------------------------------------------------------
describe('state+config+keychain#34 — needsBytes migration is robust on re-open', () => {
  after(() => { try { stateDb.close(); } catch { /* best-effort */ } });

  it('the needsBytes column is present after a fresh open', () => {
    const dbPath = nodePath.join(tmpdir('hs-db34a-'), 'state.db');
    stateDb.open(dbPath);
    const cols = stateDb.db().prepare('PRAGMA table_info(files)').all().map(c => c.name);
    assert.ok(cols.includes('needsBytes'));
    stateDb.close();
  });

  it('re-opening an already-migrated DB swallows the duplicate-column ALTER (no throw)', () => {
    const dbPath = nodePath.join(tmpdir('hs-db34b-'), 'state.db');
    stateDb.open(dbPath);
    stateDb.close();
    // Second open hits the ALTER again -> duplicate column -> re-probe confirms
    // present -> swallowed. The guarded re-probe must not let this surface.
    assert.doesNotThrow(() => stateDb.open(dbPath));
    const cols = stateDb.db().prepare('PRAGMA table_info(files)').all().map(c => c.name);
    assert.ok(cols.includes('needsBytes'));
    stateDb.close();
  });
});
