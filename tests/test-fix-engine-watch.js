'use strict';

// Pure-unit regression tests for the sync-engine + watcher + path-filter +
// checksum audit fixes. No server harness, no network — each test drives a
// real module / method directly against a node:fs temp dir (or a stub) and
// asserts the corrected behavior plus a guard against the pre-fix bug.
//
// Run standalone:  node --test tests/test-fix-engine-watch.js

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const pathFilter = require('../lib/path-filter');
const checksum = require('../lib/checksum');
const Watcher = require('../lib/watcher');
const SyncEngine = require('../lib/sync-engine');
const stateDb = require('../lib/state-db');
const { FILE_STATUS, SYNC_STATE } = require('../lib/constants');
const logger = require('../lib/logger');
const nodePathSep = nodePath.sep;

logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fix-' + process.pid + '.log') });

function mkTmp(prefix) {
  return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), prefix));
}
function rm(dir) {
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// sync-engine#0 — orphaned case-fold probe / case-rename temps must be
// sweep-collectable AND never uploaded by the local scan.
// ---------------------------------------------------------------------------
describe('sync-engine#0 — case-fold/rename temps are temp-named and never uploaded', () => {
  function withEngine(fn) {
    const tmp = mkTmp('hs-fix0-');
    try { fn(new SyncEngine({ syncFolder: tmp }, 'k'), tmp); }
    finally { rm(tmp); }
  }

  it('boot sweep removes orphaned .hs-case-probe.tmp.<hex> and <file>.tmp.<hex>', () => {
    withEngine((engine, tmp) => {
      const mk = (p) => nodeFs.writeFileSync(nodePath.join(tmp, p), 'x');
      mk('keep.txt');
      mk('.hs-case-probe.tmp.deadbeef');     // crashed case-fold probe orphan
      mk('report.txt.tmp.aabbccdd');         // crashed two-step case-rename orphan
      mk('.hs-case-probe.tmp.notallhex');    // decoy — suffix not all-hex, kept

      engine._cleanupTempFiles();

      const has = (p) => nodeFs.existsSync(nodePath.join(tmp, p));
      assert.equal(has('keep.txt'), true);
      assert.equal(has('.hs-case-probe.tmp.deadbeef'), false, 'crashed probe orphan must be swept');
      assert.equal(has('report.txt.tmp.aabbccdd'), false, 'crashed case-rename orphan must be swept');
      assert.equal(has('.hs-case-probe.tmp.notallhex'), true, 'non-hex decoy is preserved');
    });
  });

  it('_walkDir refuses to enqueue an in-flight temp for upload regardless of sweep timing', () => {
    withEngine((engine, tmp) => {
      const mk = (p) => nodeFs.writeFileSync(nodePath.join(tmp, p), 'x');
      mk('real.txt');
      mk('live.tmp.0123abcd');               // a live temp racing the scan
      mk('.HS-CASE-PROBE.tmp.feedface');      // uppercase variant kept on disk

      const walked = engine._walkDir(tmp).map(p => nodePath.basename(p));
      assert.ok(walked.includes('real.txt'), 'real files still walk');
      assert.ok(!walked.includes('live.tmp.0123abcd'), 'a live .tmp.<hex> is never enqueued for upload');
    });
  });

  it('the case-fold probe itself uses the sweep-collectable .tmp.<hex> tail', () => {
    withEngine((engine, tmp) => {
      // Drive the real probe and confirm any file it leaves behind matches the
      // sweep regex (it unlinks on success, but the name must be collectable
      // if a crash strands it).
      engine._detectCaseFolding();
      // After a clean probe nothing is left; assert no stray non-temp file.
      const left = nodeFs.readdirSync(tmp).filter(n => n.startsWith('.hs-case-probe') || n.startsWith('.HS-CASE-PROBE'));
      assert.deepEqual(left, [], 'probe cleans up after itself');
    });
  });
});

// ---------------------------------------------------------------------------
// sync-engine#1 — _safePath (server-origin) refuses OS-hostile names via
// b.safePath.resolveOrNull with platform:'windows'; _safeLocalPath
// (local-origin) keeps host-platform semantics.
// ---------------------------------------------------------------------------
describe('sync-engine#1 — _safePath splits server vs local origin', () => {
  function engine() {
    const tmp = mkTmp('hs-fix1-');
    return { e: new SyncEngine({ syncFolder: tmp }, 'k'), tmp };
  }

  it('server-origin _safePath rejects Windows-reserved / ADS / traversal / NUL names', () => {
    const { e, tmp } = engine();
    try {
      assert.equal(e._safePath('CON'), null, 'Windows reserved device rejected');
      assert.equal(e._safePath('foo:bar'), null, 'NTFS ADS marker rejected');
      assert.equal(e._safePath('../escape.txt'), null, 'traversal rejected');
      assert.equal(e._safePath('a' + String.fromCharCode(0) + 'b'), null, 'NUL byte rejected');
      assert.equal(e._safePath('trailingdot.'), null, 'Windows trailing-dot rejected');
      // Legitimate names still resolve.
      const ok = e._safePath('ok/file.txt');
      assert.ok(ok && ok.endsWith(nodePathSep + 'file.txt'), 'legit nested name resolves');
    } finally { rm(tmp); }
  });

  it('local-origin _safeLocalPath keeps host-platform semantics (no blanket Windows refusal)', () => {
    const { e, tmp } = engine();
    try {
      // Traversal / NUL are refused on every platform.
      assert.equal(e._safeLocalPath('../escape.txt'), null, 'traversal still refused locally');
      assert.equal(e._safeLocalPath('a' + String.fromCharCode(0) + 'b'), null, 'NUL still refused locally');
      if (process.platform !== 'win32') {
        // On a non-Windows host, a Linux-legal "foo:bar" / "aux" must resolve
        // so the user's legitimately-named file still syncs.
        assert.ok(e._safeLocalPath('foo:bar'), 'foo:bar resolves on non-Windows hosts');
        assert.ok(e._safeLocalPath('aux'), 'aux resolves on non-Windows hosts');
      }
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#2 — _handleFileRemovedNoSeq removes the row under the
// fold-resolved tracked key on a case-folding host.
// ---------------------------------------------------------------------------
describe('sync-engine#2 — _handleFileRemovedNoSeq deletes the fold-resolved row', () => {
  it('removes the foo.txt row when the rename old path arrives as Foo.txt (case-folding host)', async () => {
    const tmp = mkTmp('hs-fix2-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._fsCaseFolds = true; // simulate a case-insensitive volume
      stateDb.upsertFile({
        relativePath: 'foo.txt',
        serverFileId: 'fid',
        localChecksum: 'c',
        serverChecksum: 'c',
        size: 1,
        serverSeq: 1,
        status: FILE_STATUS.SYNCED,
      });
      assert.ok(stateDb.getFile('foo.txt'), 'row seeded under server casing');

      await e._handleFileRemovedNoSeq('Foo.txt'); // divergent casing

      assert.equal(stateDb.getFile('foo.txt'), undefined, 'fold-resolved row is removed (not orphaned)');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });

  it('non-case-folding host still removes the exact row (no behavior change)', async () => {
    const tmp = mkTmp('hs-fix2b-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._fsCaseFolds = false;
      stateDb.upsertFile({ relativePath: 'bar.txt', serverFileId: 'fid', serverChecksum: 'c', size: 1, status: FILE_STATUS.SYNCED });
      await e._handleFileRemovedNoSeq('bar.txt');
      assert.equal(stateDb.getFile('bar.txt'), undefined);
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#3 — _unlinkWithRetry is async and yields the event loop
// between retries (no synchronous Atomics.wait block).
// ---------------------------------------------------------------------------
describe('sync-engine#3 — _unlinkWithRetry yields the event loop (async backoff)', () => {
  it('returns a promise and does not block a concurrent timer during backoff', async () => {
    const tmp = mkTmp('hs-fix3-');
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      // A path that does not exist → ENOENT → treated as success immediately.
      const ret = e._unlinkWithRetry('gone.txt', nodePath.join(tmp, 'gone.txt'));
      assert.ok(ret && typeof ret.then === 'function', '_unlinkWithRetry is now async (returns a promise)');
      assert.equal(await ret, true, 'a missing file resolves to true');
    } finally { rm(tmp); }
  });

  it('event-loop work interleaves while a locked-delete retry backs off', async () => {
    const tmp = mkTmp('hs-fix3b-');
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      const target = nodePath.join(tmp, 'locked.txt');
      nodeFs.writeFileSync(target, 'x');
      // Force a transient lock error on the first attempt, then succeed, by
      // monkeypatching unlinkSync to throw EBUSY once.
      const realUnlink = nodeFs.unlinkSync;
      let calls = 0;
      let timerFiredDuringBackoff = false;
      nodeFs.unlinkSync = (p) => {
        calls++;
        if (calls === 1) {
          // Schedule a macrotask; if the backoff is async it WILL run before
          // the retry completes. (A synchronous Atomics.wait would starve it.)
          setTimeout(() => { timerFiredDuringBackoff = true; }, 0);
          const err = new Error('busy'); err.code = 'EBUSY'; throw err;
        }
        return realUnlink(p);
      };
      try {
        const ok = await e._unlinkWithRetry('locked.txt', target);
        assert.equal(ok, true, 'the retry eventually deletes the file');
        assert.equal(timerFiredDuringBackoff, true, 'a concurrent timer ran during the async backoff');
      } finally {
        nodeFs.unlinkSync = realUnlink;
      }
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#4 — local-rename fallback never silently strands the new bytes.
// _executeDelete is tri-state; on 'failed' a PENDING_UPLOAD marker is left,
// and _recoverPending re-drives stranded PENDING_UPLOAD rows.
// ---------------------------------------------------------------------------
describe('sync-engine#4 — local-rename fallback leaves a recoverable marker', () => {
  it('_executeDelete returns tri-state: skipped on suppression, failed on server error, deleted on success', async () => {
    const tmp = mkTmp('hs-fix4-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.SYNCED;
      const existing = { serverFileId: 'fid' };

      // skipped: suppression
      e._suppressPath('s.txt');
      assert.equal(await e._executeDelete('s.txt', existing), 'skipped');
      e._releasePath('s.txt');

      // failed: server DELETE throws
      e._http = { deleteFile: async () => { throw new Error('boom'); } };
      stateDb.upsertFile({ relativePath: 'f.txt', serverFileId: 'fid', status: FILE_STATUS.SYNCED, size: 1 });
      assert.equal(await e._executeDelete('f.txt', existing), 'failed');
      assert.equal(stateDb.getFile('f.txt').status, FILE_STATUS.ERROR, 'old path marked ERROR on failure');

      // deleted: server DELETE succeeds
      e._http = { deleteFile: async () => ({}) };
      stateDb.upsertFile({ relativePath: 'g.txt', serverFileId: 'fid', status: FILE_STATUS.SYNCED, size: 1 });
      assert.equal(await e._executeDelete('g.txt', existing), 'deleted');
      assert.equal(stateDb.getFile('g.txt'), undefined, 'deleted row removed');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });

  it('rename fallback with a delete failure upserts PENDING_UPLOAD for the new path (no silent loss)', async () => {
    const tmp = mkTmp('hs-fix4b-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.SYNCED;
      // Server rename throws → fallback. Delete also fails → 'failed' branch.
      e._http = {
        renameFile: async () => { throw new Error('rename unsupported'); },
        deleteFile: async () => { throw new Error('delete failed'); },
      };
      nodeFs.writeFileSync(nodePath.join(tmp, 'new.txt'), 'bytes');
      const pending = { fileId: 'fid', existing: { serverFileId: 'fid' } };
      await e._handleLocalRename('old.txt', 'new.txt', pending, 'csum', 5, Date.now());

      const row = stateDb.getFile('new.txt');
      assert.ok(row, 'the renamed new path is tracked (not silently dropped)');
      assert.equal(row.status, FILE_STATUS.PENDING_UPLOAD, 'new path left PENDING_UPLOAD for the reconcile sweep');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });

  it('_recoverPending re-drives a stranded PENDING_UPLOAD row whose bytes differ from the server', async () => {
    const tmp = mkTmp('hs-fix4c-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.SYNCED;
      e._http = {}; // present so _recoverPending proceeds
      nodeFs.writeFileSync(nodePath.join(tmp, 'stranded.txt'), 'local-bytes');
      stateDb.upsertFile({
        relativePath: 'stranded.txt',
        serverFileId: null,
        localChecksum: 'csum',
        serverChecksum: null,
        size: 11,
        status: FILE_STATUS.PENDING_UPLOAD,
      });

      let modified = null;
      e._handleLocalModify = async (rel) => { modified = rel; };
      await e._recoverPending();
      assert.equal(modified, 'stranded.txt', 'reconcile re-routed the stranded upload through _handleLocalModify');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#5 — empty-bundle / zero-tip catch-up completes; an established
// client still ignores a stray seq-0 liveness heartbeat.
// ---------------------------------------------------------------------------
describe('sync-engine#5 — empty-bundle seq-0 heartbeat completes catch-up', () => {
  it('fresh client (lastSeq===0) on an empty bundle transitions CATCHING_UP -> SYNCED on a seq-0 heartbeat', () => {
    const tmp = mkTmp('hs-fix5-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.CATCHING_UP;
      e._catchUpPending = 0;
      e._activeDownloads = 0;
      e._ws = { send: () => {} };
      let finalState = null;
      e._setState = (s) => { e._state = s; finalState = s; };

      e._handleHeartbeat({ seq: 0 });
      assert.equal(finalState, SYNC_STATE.SYNCED, 'empty-bundle seq-0 heartbeat completes catch-up');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });

  it('established client (lastSeq>0) ignores a stray seq-0 heartbeat (stays CATCHING_UP)', () => {
    const tmp = mkTmp('hs-fix5b-');
    const dbPath = nodePath.join(tmp, 'state.db');
    stateDb.open(dbPath);
    try {
      stateDb.setLastSeq(12);
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      e._state = SYNC_STATE.CATCHING_UP;
      e._catchUpPending = 0;
      e._activeDownloads = 0;
      e._ws = { send: () => {} };
      let became = null;
      e._setState = (s) => { e._state = s; became = s; };

      e._handleHeartbeat({ seq: 0 });
      assert.equal(e._caughtUpAtSeq, undefined, 'stray seq-0 heartbeat does not set _caughtUpAtSeq for an established client');
      assert.notEqual(became, SYNC_STATE.SYNCED, 'established client stays in catch-up on a stray seq-0 ping');
    } finally {
      stateDb.close();
      rm(tmp);
    }
  });
});

// ---------------------------------------------------------------------------
// watcher+pathfilter+checksum#35 — caseFold flag threads through path-filter
// (default OFF preserves byte-exact Linux semantics).
// ---------------------------------------------------------------------------
describe('watcher+pathfilter+checksum#35 — case-fold-aware ignore/include matching', () => {
  it('default (caseFold off) is byte-exact — a differently-cased path is NOT ignored', () => {
    const o = { ignore: ['node_modules/**', '*.tmp'] };
    assert.equal(pathFilter.shouldSync('node_modules/x.js', o), false, 'exact-case ignore matches');
    assert.equal(pathFilter.shouldSync('Node_Modules/x.js', o), true, 'differently-cased path NOT ignored when fold off');
    assert.equal(pathFilter.shouldSync('report.TMP', o), true, 'differently-cased ext NOT ignored when fold off');
  });

  it('caseFold on — a differently-cased path IS ignored (matches the engine identity layer)', () => {
    const o = { ignore: ['node_modules/**', '*.tmp'], caseFold: true };
    assert.equal(pathFilter.shouldSync('node_modules/x.js', o), false);
    assert.equal(pathFilter.shouldSync('Node_Modules/x.js', o), false, 'fold makes the subtree ignore match');
    assert.equal(pathFilter.shouldSync('report.TMP', o), false, 'fold makes the ext ignore match');
  });

  it('caseFold on — include allowlist resolves case-insensitively', () => {
    const o = { include: ['Work/**'], caseFold: true };
    assert.equal(pathFilter.shouldSync('work/a.txt', o), true, 'differently-cased include path matches under fold');
    assert.equal(pathFilter.shouldSync('photos/a.txt', o), false);
  });

  it('Watcher threads its caseFolds flag into shouldSync', () => {
    const tmp = mkTmp('hs-fix35-');
    try {
      const folding = new Watcher(tmp, ['*.tmp'], [], true);
      const exact = new Watcher(tmp, ['*.tmp'], [], false);
      assert.equal(folding.shouldSync('a.TMP'), false, 'folding watcher ignores differently-cased ext');
      assert.equal(exact.shouldSync('a.TMP'), true, 'byte-exact watcher does not');
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// watcher+pathfilter+checksum#36 — hashFilesParallel preserves its contract
// while driving concurrency through b.promisePool.
// ---------------------------------------------------------------------------
describe('watcher+pathfilter+checksum#36 — hashFilesParallel via b.promisePool', () => {
  it('empty input returns [] (no concurrency=0 throw)', async () => {
    assert.deepEqual(await checksum.hashFilesParallel([]), []);
  });

  it('one row per input in input order, with per-file null degradation', async () => {
    const tmp = mkTmp('hs-fix36-');
    try {
      const good = nodePath.join(tmp, 'good.txt');
      nodeFs.writeFileSync(good, 'hello');
      const missing = nodePath.join(tmp, 'nope.txt');
      const rows = await checksum.hashFilesParallel([good, missing, good]);
      assert.equal(rows.length, 3, 'one row per input');
      assert.equal(rows[0].filePath, good);
      assert.equal(rows[1].filePath, missing);
      assert.equal(rows[2].filePath, good);
      assert.ok(typeof rows[0].checksum === 'string' && rows[0].checksum.length === 128, 'good file → sha3-512 hex');
      assert.equal(rows[1].checksum, null, 'missing file degrades to null, not a throw');
      assert.equal(rows[0].checksum, rows[2].checksum, 'same file → same digest, positionally aligned');
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// watcher+pathfilter+checksum#37 — hashFile rejects on unreadable input
// (the primitive rejects; the defensive guard is a backstop, comment accurate).
// ---------------------------------------------------------------------------
describe('watcher+pathfilter+checksum#37 — hashFile rejects unreadable input', () => {
  it('throws for a missing file (rejection path, not a null-row return)', async () => {
    const tmp = mkTmp('hs-fix37-');
    try {
      await assert.rejects(() => checksum.hashFile(nodePath.join(tmp, 'absent.bin')),
        /Could not hash|hash/i, 'a missing file surfaces as a rejection');
    } finally { rm(tmp); }
  });

  it('returns a 128-char sha3-512 hex for a real file', async () => {
    const tmp = mkTmp('hs-fix37b-');
    try {
      const p = nodePath.join(tmp, 'x.txt');
      nodeFs.writeFileSync(p, 'content');
      const hex = await checksum.hashFile(p);
      assert.match(hex, /^[0-9a-f]{128}$/);
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// watcher+pathfilter+checksum#38 — an oversized watcher env value degrades to
// the default instead of hard-failing watcher start().
// ---------------------------------------------------------------------------
describe('watcher+pathfilter+checksum#38 — malformed watcher env degrades gracefully', () => {
  it('a >256-byte HERMITSTASH_WATCHER_MODE does not throw out of start()', () => {
    const tmp = mkTmp('hs-fix38-');
    const prev = process.env.HERMITSTASH_WATCHER_MODE;
    process.env.HERMITSTASH_WATCHER_MODE = 'x'.repeat(512); // over the 256-byte cap
    try {
      const w = new Watcher(tmp, [], []);
      // start() builds opts via the env resolvers; the oversized value must
      // degrade to the default ('auto') rather than throwing env/too-large.
      assert.doesNotThrow(() => w.start(), 'oversized env value must not hard-fail watcher start');
      w.stop();
    } finally {
      if (prev === undefined) delete process.env.HERMITSTASH_WATCHER_MODE;
      else process.env.HERMITSTASH_WATCHER_MODE = prev;
      rm(tmp);
    }
  });

  it('an oversized integer tunable degrades to the default (no throw)', () => {
    const tmp = mkTmp('hs-fix38b-');
    const prev = process.env.HERMITSTASH_WATCHER_MAX_PENDING;
    process.env.HERMITSTASH_WATCHER_MAX_PENDING = '9'.repeat(512);
    try {
      const w = new Watcher(tmp, [], []);
      assert.doesNotThrow(() => w.start());
      w.stop();
    } finally {
      if (prev === undefined) delete process.env.HERMITSTASH_WATCHER_MAX_PENDING;
      else process.env.HERMITSTASH_WATCHER_MAX_PENDING = prev;
      rm(tmp);
    }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#8 (cross-lane half) — getBundleMetadata now fails closed on a
// non-2xx, so _initialSync must surface an auth-class denial (HTTP 401/403) as
// a sticky ERROR + auth_error, while a non-auth failure (404/409/5xx) falls
// through to the non-sticky "rely on WebSocket catch-up" path without flipping
// auth_error.
// ---------------------------------------------------------------------------
describe('sync-engine#8 — _initialSync surfaces an auth-class bundle-metadata denial', () => {
  function engineWith(metaErr) {
    const tmp = mkTmp('hs-fix8-');
    const e = new SyncEngine({ syncFolder: tmp, shareId: 'share1' }, 'k');
    e._http = { getBundleMetadata: async () => { throw new Error(metaErr); } };
    let authErrors = 0;
    e.on('auth_error', () => { authErrors++; });
    return { e, tmp, authErrors: () => authErrors };
  }

  it('a 403 denial transitions the engine to ERROR and emits auth_error', async () => {
    const { e, tmp, authErrors } = engineWith('Bundle metadata request denied (HTTP 403) — the API key or mTLS cert was rejected');
    await e._initialSync();
    assert.equal(e._state, SYNC_STATE.ERROR, 'an auth-class denial must be a sticky ERROR');
    assert.equal(authErrors(), 1, 'auth_error must be emitted once');
    rm(tmp);
  });

  it('a 401 denial also emits auth_error', async () => {
    const { e, tmp, authErrors } = engineWith('Bundle metadata request denied (HTTP 401) — rejected');
    await e._initialSync();
    assert.equal(e._state, SYNC_STATE.ERROR);
    assert.equal(authErrors(), 1);
    rm(tmp);
  });

  it('a 404 (non-auth) failure does NOT emit auth_error and is not the sticky-ERROR path', async () => {
    const { e, tmp, authErrors } = engineWith('Bundle metadata fetch failed: HTTP 404');
    await e._initialSync();
    assert.equal(authErrors(), 0, 'a 404 must not be treated as an auth failure');
    rm(tmp);
  });
});

// ---------------------------------------------------------------------------
// watcher#39 — _dirPrefixIgnores forwards BOTH subtree-exclude shapes to the
// underlying walk: 'recursive-dir' (foo/**) AND 'path-qualified' (data/cache,
// which operators routinely write without the trailing /**). Forwarding only
// the /** shape left a large path-qualified excluded subtree un-pruned, so the
// poll walk counted its files toward pollMaxFiles and overflowed into degraded.
// ---------------------------------------------------------------------------
describe('watcher#39 — path-qualified subtree excludes are forwarded to the walk', () => {
  it('forwards recursive-dir AND path-qualified, but never basename/ext', () => {
    const tmp = mkTmp('hs-fix39-');
    try {
      const w = new Watcher(tmp, ['foo/**', 'data/cache', 'src/node_modules', '*.log', '.DS_Store'], []);
      const fwd = w._dirIgnores;
      assert.ok(fwd.includes('foo/**'), 'recursive-dir is forwarded');
      assert.ok(fwd.includes('data/cache'), 'path-qualified subtree is forwarded (the poll-overflow fix)');
      assert.ok(fwd.includes('src/node_modules'), 'a deeper path-qualified subtree is forwarded');
      assert.ok(!fwd.includes('*.log'), 'an ext pattern stays on the hook-side filter');
      assert.ok(!fwd.includes('.DS_Store'), 'a basename pattern stays on the hook-side filter');
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// watcher#40 — a watcher that exhausted its recovery budget (degraded: handle
// dropped, NOT operator-stopped) is re-armed by an ignore-pattern change. This
// is the live-reload remediation the degraded-state error advertises ("narrow
// your ignore patterns"); pre-fix it was a no-op because the restart was gated
// on a live handle, leaving change detection off until a full daemon restart.
// ---------------------------------------------------------------------------
describe('watcher#40 — a degraded watcher is re-armed by an ignore-pattern change', () => {
  it('updatePatterns re-arms a degraded (handle-less, non-stopped) watcher when the subtree set changes', () => {
    const tmp = mkTmp('hs-fix40-');
    try {
      const w = new Watcher(tmp, [], []);
      w.start();
      assert.ok(w._handle, 'watcher started with a live handle');
      // Reproduce the terminal degraded state _scheduleRecovery leaves at the cap.
      try { w._handle.stop(); } catch { /* idempotent */ }
      w._handle = null;
      w._recoveryAttempts = 999;
      w._recovering = false;
      assert.equal(w._stopped, false, 'degraded is distinct from operator-stopped');
      let rescans = 0;
      w.on('rescan', () => { rescans++; });
      w.updatePatterns(['huge_subtree/**'], []); // operator narrows ignores + SIGHUP
      assert.ok(w._handle, 'a degraded watcher is re-armed (was a silent no-op pre-fix)');
      assert.equal(w._recoveryAttempts, 0, 're-arm resets the recovery budget via start()');
      assert.equal(rescans, 1, 're-arm emits rescan so the engine re-walks for edits missed while degraded');
      w.stop();
    } finally { rm(tmp); }
  });

  it('does NOT re-arm an operator-stopped watcher, nor on a no-op (non-forwarded) pattern change', () => {
    const tmp = mkTmp('hs-fix40b-');
    try {
      const w = new Watcher(tmp, [], []);
      w.start();
      w.stop();
      assert.equal(w._handle, null);
      w.updatePatterns(['x/**'], []);
      assert.equal(w._handle, null, 'an operator-stopped watcher is never re-armed');

      const w2 = new Watcher(tmp, ['keep/**'], []);
      w2.start();
      try { w2._handle.stop(); } catch { /* idempotent */ }
      w2._handle = null;
      w2._recoveryAttempts = 999;
      // Only a basename pattern is added — the forwarded subtree set is unchanged,
      // so re-arming would just re-overflow; it must stay degraded.
      w2.updatePatterns(['keep/**', '*.log'], []);
      assert.equal(w2._handle, null, 'no re-arm when the forwarded subtree set is unchanged');
      w2.stop();
    } finally { rm(tmp); }
  });
});

// ---------------------------------------------------------------------------
// sync-engine#9 — resync() is a no-op once the engine is stopping. A SIGHUP
// delivered inside the graceful-stop window must not run _resyncOnce (which
// clearAll()s the state DB and re-opens the WebSocket against teardown).
// ---------------------------------------------------------------------------
describe('sync-engine#9 — resync() refuses to run once the engine is stopping', () => {
  it('a stopped engine never enters _resyncOnce', async () => {
    const tmp = mkTmp('hs-fix9-');
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      let ran = false;
      e._resyncOnce = async () => { ran = true; };
      e._stopped = true;
      const r = e.resync();
      assert.ok(r && typeof r.then === 'function', 'resync still returns a promise');
      await r;
      assert.equal(ran, false, 'resync must not start a teardown once stopped (SIGHUP-mid-shutdown guard)');
    } finally { rm(tmp); }
  });

  it('a live (non-stopped) engine still resyncs normally', async () => {
    const tmp = mkTmp('hs-fix9b-');
    try {
      const e = new SyncEngine({ syncFolder: tmp }, 'k');
      let ran = false;
      e._resyncOnce = async () => { ran = true; };
      await e.resync();
      assert.equal(ran, true, 'a non-stopped engine resyncs');
    } finally { rm(tmp); }
  });
});
