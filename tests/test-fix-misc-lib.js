'use strict';

// Pure-unit regression tests for the misc-lib lane fixes. No server harness,
// no network -- each test drives a real production module/method directly
// against a node:fs temp dir (or a spawned child process) and asserts the
// corrected behavior plus a guard against the pre-fix bug.
//
// Coverage:
//   watcher#22   lib/path-filter.js  -- classify/match lockstep for [ ] ? !
//   watcher#23   lib/watcher.js      -- over-cap ignore pattern dropped, not forwarded
//   watcher#24   lib/watcher.js      -- NFC + NFD subtree-ignore forms both forwarded
//   state-db#26  lib/checksum.js     -- oversize discriminator no longer fires on the path
//   keychain#35  lib/daemon.js       -- uncaughtException drains the log to disk before exit
//
// primitive-lens#52 (lib/metrics.js) is CONVERTED as of blamejs v0.17.9:
// b.metrics.snapshot.render now walks the labeled snap.metrics registry with
// the same family encoder the live exposition() uses, so renderPrometheus
// delegates to it (fields passed empty on the registry path — the vendored
// renderer would otherwise also emit prefix-qualified flat fields the sidecar
// never carries). Series-name convergence with the sidecar is guarded by
// tests/test-observability.js (F35).
//
// Run standalone:  node --test tests/test-fix-misc-lib.js

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const { spawnSync } = require('node:child_process');

const pathFilter = require('../lib/path-filter');
const checksum = require('../lib/checksum');
const Watcher = require('../lib/watcher');
const logger = require('../lib/logger');

const REPO_ROOT = nodePath.resolve(__dirname, '..');

// precomposed 'e' with acute accent (U+00E9); NFD decomposes to 'e' + U+0301.
// Pinned to the code point so the test is independent of this file's on-disk
// byte encoding (an NFD-normalized source would otherwise defeat the assertions).
const E_ACUTE = String.fromCharCode(0x00e9);

logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fix-misc-' + process.pid + '.log') });

function mkTmp(prefix) {
  return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), prefix));
}
function rm(dir) {
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// watcher#22 -- classifyPattern and _matchPattern must agree. A pattern
// containing '[', ']', '?' or '!' is classified 'unsupported' (config warns
// the operator it matches nothing), so the matcher must NOT honor those
// characters literally -- otherwise a real on-disk path containing them would
// be silently (non-)synced against the warning.
// ---------------------------------------------------------------------------
describe('watcher#22 -- [ ] ? ! patterns are inert in both classify and match', () => {
  const cases = [
    // [ real on-disk path, operator pattern ]
    ['data[cache]/x.txt', 'data[cache]/**'],
    ['secret[s]/a/b',     'secret[s]/**'],
    ['!foo/x',            '!foo/**'],
    ['a?/x',              'a?/**'],
    ['file?.txt',         'file?.txt'],
    ['data[cache]',       'data[cache]'],
    ['keep]me/x',         'keep]me'],
  ];
  it('classifyPattern reports unsupported AND the matcher refuses to match', () => {
    for (const [path, pattern] of cases) {
      assert.equal(pathFilter.classifyPattern(pattern), 'unsupported',
        "classifyPattern('" + pattern + "') must be unsupported");
      assert.equal(pathFilter.isIgnored(path, [pattern]), false,
        "matcher must NOT honor the literal '" + pattern + "' against '" + path + "' (lockstep with the warning)");
      assert.equal(pathFilter.shouldSync(path, { include: [pattern] }), false,
        "an unsupported include pattern must not selectively-include '" + path + "'");
    }
  });

  it('supported grammar still matches (no over-narrowing regression)', () => {
    assert.equal(pathFilter.isIgnored('node_modules/x/y', ['node_modules/**']), true, 'recursive-dir still matches');
    assert.equal(pathFilter.isIgnored('src/node_modules/a/b', ['src/node_modules']), true, 'path-qualified still matches');
    assert.equal(pathFilter.isIgnored('a/b/.DS_Store', ['.DS_Store']), true, 'basename still matches');
    assert.equal(pathFilter.isIgnored('a/b/x.tmp', ['*.tmp']), true, 'ext still matches');
    assert.equal(pathFilter.isIgnored('a/b/draft~', ['*~']), true, 'tilde still matches');
    assert.equal(pathFilter.isIgnored('a/b/c', ['a/b/c']), true, 'exact still matches');
    assert.equal(pathFilter.isIgnored('build/out/x', ['build/**']), true);
  });

  it('a non-string pattern is inert rather than throwing', () => {
    assert.doesNotThrow(() => pathFilter.isIgnored('a/b/c', [123, null, {}]));
    assert.equal(pathFilter.isIgnored('a/b/c', [123, null, {}]), false);
  });
});

// ---------------------------------------------------------------------------
// watcher#23 -- an ignore pattern longer than b.watcher's 256-code-unit cap
// (or past its 16-wildcard cap) must be DROPPED from the forwarded subset,
// not handed to b.watcher.create where it throws watcher/bad-ignore
// synchronously and takes down the whole watcher.
// ---------------------------------------------------------------------------
describe('watcher#23 -- over-cap ignore patterns are not forwarded to b.watcher', () => {
  const CAP = 256;
  const longSubtree = 'a'.repeat(CAP + 40) + '/**';   // classifies recursive-dir, exceeds the length cap
  const longPathQual = 'b'.repeat(CAP + 40) + '/c';    // classifies path-qualified, exceeds the length cap

  it('a >256-code-unit subtree pattern classifies as forwardable but is dropped from the forward set', () => {
    // Pre-fix this reached b.watcher.create and threw watcher/bad-ignore.
    assert.equal(pathFilter.classifyPattern(longSubtree), 'recursive-dir');
    assert.equal(pathFilter.classifyPattern(longPathQual), 'path-qualified');
    const w = new Watcher('/nonexistent', [longSubtree, longPathQual, 'good/**'], []);
    assert.ok(!w._dirIgnores.includes(longSubtree), 'over-cap recursive-dir is not forwarded');
    assert.ok(!w._dirIgnores.includes(longPathQual), 'over-cap path-qualified is not forwarded');
    assert.ok(w._dirIgnores.includes('good/**'), 'the in-cap subtree pattern is still forwarded');
    for (const p of w._dirIgnores) {
      assert.ok(p.length > 0 && p.length <= CAP, 'every forwarded form is within the ' + CAP + '-code-unit cap');
    }
  });

  it('start() no longer throws when an over-cap ignore pattern is present', () => {
    const tmp = mkTmp('hs-fix-cap-');
    try {
      const w = new Watcher(tmp, [longSubtree, 'good/**'], []);
      assert.doesNotThrow(() => w.start(), 'watcher boots even with an over-cap ignore pattern in config');
      assert.ok(w._handle, 'the watcher handle came up');
      w.stop();
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// watcher#24 -- a non-ASCII subtree-ignore pattern (stored NFC) must be
// forwarded in BOTH its composed (NFC) and decomposed (NFD) forms so
// b.watcher's poll walk prunes the ignored subtree whether the on-disk dir
// entry surfaces as NFC (most platforms) or NFD (macOS/APFS, some SMB mounts).
// ---------------------------------------------------------------------------
describe('watcher#24 -- NFC and NFD forms of a non-ASCII subtree ignore are both forwarded', () => {
  it('forwards both Unicode forms for a decomposable subtree pattern', () => {
    const nfc = 'caf' + E_ACUTE + '/**';        // "cafe'/**" precomposed
    const nfd = nfc.normalize('NFD');           // "cafe'/**" decomposed
    assert.notEqual(nfc, nfd, 'the pattern is genuinely decomposable');
    const w = new Watcher('/nonexistent', [nfc], []);
    assert.ok(w._dirIgnores.includes(nfc), 'the composed (NFC) form is forwarded');
    assert.ok(w._dirIgnores.includes(nfd), 'the decomposed (NFD) form is also forwarded (the fix)');
  });

  it('an ASCII subtree pattern is forwarded once (NFC/NFD collapse, no duplicate)', () => {
    const w = new Watcher('/nonexistent', ['node_modules/**'], []);
    assert.deepEqual(w._dirIgnores, ['node_modules/**'], 'ASCII patterns are not duplicated');
  });

  it('a form whose NFD expansion exceeds the cap is dropped while the NFC form survives', () => {
    // 200 x precomposed e-acute = 200 code units NFC (<=256) but 400 code units NFD (>256).
    const nfc = E_ACUTE.repeat(200) + '/**';
    const nfd = nfc.normalize('NFD');
    assert.ok(nfc.length <= 256 && nfd.length > 256, 'NFC within cap, NFD over cap');
    const w = new Watcher('/nonexistent', [nfc], []);
    assert.ok(w._dirIgnores.includes(nfc), 'the in-cap NFC form is forwarded');
    assert.ok(!w._dirIgnores.includes(nfd), 'the over-cap NFD form is dropped (would crash b.watcher)');
    for (const p of w._dirIgnores) assert.ok(p.length <= 256, 'no forwarded form exceeds the cap');
  });
});

// ---------------------------------------------------------------------------
// state-db#26 -- hashFile() must classify a blamejs reject as "oversize" only
// on the path-independent phrase the oversize branch alone emits. A
// non-oversize failure (ENOENT / EACCES / refused-symlink) on a file whose
// name merely contains the word "exceeded" must surface its REAL cause, not a
// bogus "raise the size limit" message.
// ---------------------------------------------------------------------------
describe('state-db#26 -- checksum error is not misclassified as oversize on the file path', () => {
  it('a missing file named with "exceeded" reports ENOENT, not a size-limit error', async () => {
    const tmp = mkTmp('hs-fix-hash-');
    try {
      const missing = nodePath.join(tmp, 'Report-exceeded-budget.xlsx'); // never created
      await assert.rejects(
        () => checksum.hashFile(missing),
        (err) => {
          assert.ok(!/sync size limit|HERMITSTASH_MAX_FILE_BYTES/i.test(err.message),
            'must NOT be reported as a size-limit error: ' + err.message);
          assert.ok(/ENOENT|stat failed/i.test(err.message),
            'the real ENOENT cause must survive: ' + err.message);
          return true;
        }
      );
    } finally { rm(tmp); }
  });

  it('a refused symlink named with "exceeded" reports the refusal, not a size error', async () => {
    const tmp = mkTmp('hs-fix-hashsym-');
    try {
      const target = nodePath.join(tmp, 'real.bin');
      nodeFs.writeFileSync(target, 'x');
      const link = nodePath.join(tmp, 'exceeded-link.bin');
      try {
        nodeFs.symlinkSync(target, link);
      } catch {
        return; // symlink creation not permitted (e.g. Windows without privilege) -- skip
      }
      await assert.rejects(
        () => checksum.hashFile(link),
        (err) => {
          assert.ok(!/sync size limit|HERMITSTASH_MAX_FILE_BYTES/i.test(err.message),
            'a refused symlink must NOT be masked as a size error: ' + err.message);
          assert.ok(/symlink/i.test(err.message),
            'the security-relevant symlink-refusal signal must survive: ' + err.message);
          return true;
        }
      );
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// keychain#35 -- the uncaughtException handler must drain the async
// b.logStream file sink before process.exit(1) so the crash record actually
// reaches the rotated log file (the durable post-mortem surface). Exercised
// end-to-end in a child process: install the real daemon handlers, throw,
// then read the log file back.
// ---------------------------------------------------------------------------
describe('keychain#35 -- the crash record is flushed to the log file before exit', () => {
  it('an uncaught exception in the daemon persists to the on-disk log', () => {
    const tmp = mkTmp('hs-fix-uncaught-');
    try {
      const logFile = nodePath.join(tmp, 'crash.log'); // sink writes <dir>/<base>.log -> tmp/crash.log
      const marker = 'boom-marker-' + process.pid;
      const child = [
        "'use strict';",
        'const log = require(' + JSON.stringify(nodePath.join(REPO_ROOT, 'lib', 'logger.js')) + ');',
        'const daemon = require(' + JSON.stringify(nodePath.join(REPO_ROOT, 'lib', 'daemon.js')) + ');',
        '(async () => {',
        '  await log.init({ level: "error", stdout: false, file: ' + JSON.stringify(logFile) + ' });',
        '  daemon.installSignalHandlers(async () => {}, null, null);',
        '  setTimeout(() => { throw new Error(' + JSON.stringify(marker) + '); }, 10);',
        '})();',
      ].join('\n');

      const res = spawnSync(process.execPath, ['-e', child], {
        env: Object.assign({}, process.env, { HERMITSTASH_SYNC_CONFIG_DIR: tmp }),
        encoding: 'utf8',
        timeout: 20000,
      });

      assert.equal(res.error, undefined, 'child spawned without error');
      assert.equal(res.status, 1, 'the crash path exits 1');
      const active = nodePath.join(tmp, 'crash.log');
      assert.ok(nodeFs.existsSync(active), 'the log file was created');
      const contents = nodeFs.readFileSync(active, 'utf8');
      assert.match(contents, /Uncaught exception/, 'the crash record reached the durable log file');
      assert.ok(contents.includes(marker), 'the error detail was flushed too, not just queued');
    } finally { rm(tmp); }
  });
});
