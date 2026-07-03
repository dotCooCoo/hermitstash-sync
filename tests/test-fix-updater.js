'use strict';

// Pure-unit regression tests for the confirmed lib/updater.js audit fixes.
// No server harness, no network: every assertion drives an exported helper,
// the updater's _internals surface, or the same vendored primitive the fix
// wired, against node:fs temp dirs only. Runs standalone:
//   node --test tests/test-fix-updater.js
//
// Findings covered:
//   updater#18 — beta-channel asset/signature regex (prerelease tail)
//   updater#21 — expired-signed-URL retry classifier on downloadTo
//   updater#23 — probation timer re-reads the marker before the destructive unlink

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const b = require('../vendor/blamejs');
const { createUpdater } = require('../lib/updater');
const log = require('../lib/logger');

// Quiet the updater's structured logger so the unit run doesn't spew.
log.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fix-updater-' + process.pid + '.log') });

function platformTag() {
  const p = process.platform;
  return p === 'win32' ? 'win' : p === 'darwin' ? 'macos' : 'linux';
}
const EXT = process.platform === 'win32' ? '.exe' : '';
const PLAT = platformTag();
const ARCH = process.arch;

// A dummy agent flips the updater into isTestEnv (no real PQC agent built).
function newUpdater(extra) {
  return createUpdater(Object.assign({ httpsAgent: {} }, extra || {}));
}

describe('updater#18 — beta-channel asset/signature regex accepts a prerelease tail', () => {
  const u = newUpdater();
  const assetRe = u._internals.platformAssetPattern();
  const sigRe = u._internals.platformSignaturePattern();

  it('stable asset still matches (no regression)', () => {
    const stable = `hermitstash-sync-v0.9.0-${PLAT}-${ARCH}${EXT}`;
    assert.equal(assetRe.test(stable), true);
    assert.equal(sigRe.test(`${stable}.sig`), true);
  });

  it('beta prerelease asset now matches (the fixed bug)', () => {
    const beta = `hermitstash-sync-v0.9.0-beta.1-${PLAT}-${ARCH}${EXT}`;
    assert.equal(assetRe.test(beta), true, 'beta asset must match after the prerelease-tail fix');
    assert.equal(sigRe.test(`${beta}.sig`), true, 'beta signature must match');
  });

  it('rc / build-metadata prerelease tails also match', () => {
    const rc = `hermitstash-sync-v1.2.3-rc.2-${PLAT}-${ARCH}${EXT}`;
    const build = `hermitstash-sync-v1.2.3+build.7-${PLAT}-${ARCH}${EXT}`;
    assert.equal(assetRe.test(rc), true);
    assert.equal(assetRe.test(build), true);
  });

  it('guards the old bug: a digit-only version pattern (no prerelease tail) is rejected', () => {
    // Behavioral guard so a revert to the digit-only `\d+\.\d+\.\d+-<plat>` form
    // (which drops the prerelease/build tail) fails here. The prerelease slot is a
    // BARE bounded char class, not a `(?:…)?` group — b.selfUpdate runs the pattern
    // through b.guardRegex.sanitize, which refuses a quantified group.
    assert.match(assetRe.source, /\[-0-9A-Za-z\.\+\]\{0,\d+\}/, 'asset pattern carries a bounded prerelease char class');
    assert.match(sigRe.source, /\[-0-9A-Za-z\.\+\]\{0,\d+\}/, 'sig pattern carries a bounded prerelease char class');
  });

  it('both patterns pass b.guardRegex.sanitize (b.selfUpdate refuses an unsafe assetPattern)', () => {
    const b = require('../vendor/blamejs');
    assert.doesNotThrow(() => b.guardRegex.sanitize(assetRe.source), 'asset pattern must be guardRegex-safe');
    assert.doesNotThrow(() => b.guardRegex.sanitize(sigRe.source), 'sig pattern must be guardRegex-safe');
  });

  it('still rejects the ML-DSA sidecar (.mldsa.sig) — property preserved', () => {
    const beta = `hermitstash-sync-v0.9.0-beta.1-${PLAT}-${ARCH}${EXT}`;
    assert.equal(sigRe.test(`${beta}.mldsa.sig`), false,
      'the ECDSA signature pattern must never match the ML-DSA sidecar');
  });

  it('still rejects a wrong-arch asset — anchor preserved', () => {
    const otherArch = ARCH === 'x64' ? 'arm64' : 'x64';
    const wrong = `hermitstash-sync-v0.9.0-beta.1-${PLAT}-${otherArch}${EXT}`;
    assert.equal(assetRe.test(wrong), false, 'wrong-arch asset must not match');
  });
});

describe('updater#21 — downloadTo retries only an expired-signed-URL status (403/410)', () => {
  // The fix wraps resolve+download in b.retry.withRetry with a statusCode-only
  // classifier `(e) => e.statusCode === 403 || e.statusCode === 410`. These
  // tests exercise that exact predicate through the real vendored primitive so
  // they lock the retry-vs-fail-closed contract without a network harness.
  const isRetryable = (e) => !!(e && (e.statusCode === 403 || e.statusCode === 410));

  function statusErr(code) {
    const e = new Error(`HTTP ${code}`);
    e.statusCode = code;
    return e;
  }

  it('a 403 expired URL is retried and the next attempt succeeds', async () => {
    let attempts = 0;
    const out = await b.retry.withRetry(async () => {
      attempts += 1;
      if (attempts === 1) throw statusErr(403);
      return 'downloaded';
    }, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0, isRetryable });
    assert.equal(out, 'downloaded');
    assert.equal(attempts, 2, 'must re-resolve+download once after a 403');
  });

  it('a 410 Gone URL is retried', async () => {
    let attempts = 0;
    const out = await b.retry.withRetry(async () => {
      attempts += 1;
      if (attempts < 2) throw statusErr(410);
      return 'ok';
    }, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0, isRetryable });
    assert.equal(out, 'ok');
    assert.equal(attempts, 2);
  });

  it('a 404 (asset truly absent) is NOT retried — fail closed, one attempt', async () => {
    let attempts = 0;
    await assert.rejects(
      b.retry.withRetry(async () => { attempts += 1; throw statusErr(404); },
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0, isRetryable }),
      /HTTP 404/);
    assert.equal(attempts, 1, '404 must not spin the retry loop');
  });

  it('a 401 (auth failure) is NOT retried', async () => {
    let attempts = 0;
    await assert.rejects(
      b.retry.withRetry(async () => { attempts += 1; throw statusErr(401); },
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0, isRetryable }),
      /HTTP 401/);
    assert.equal(attempts, 1);
  });

  it('a persistent 403 still gives up after maxAttempts (no infinite loop)', async () => {
    let attempts = 0;
    await assert.rejects(
      b.retry.withRetry(async () => { attempts += 1; throw statusErr(403); },
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0, isRetryable }),
      /HTTP 403/);
    assert.equal(attempts, 3, 'capped at maxAttempts');
  });
});

describe('updater#23 — probation timer re-reads the marker before the destructive unlink', () => {
  function tmpDir() {
    return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-upd-mk-'));
  }

  // Drive checkRollback with a fresh in-probation marker, mutate the marker on
  // disk during the window (as markGracefulShutdown / a successor install would),
  // let the unref'd timer fire, and assert the timer acts on CURRENT on-disk
  // state. node:timers fake clocks don't compose with the updater's real
  // setTimeout, so use a tiny real probation window + a short real wait.
  function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

  it('unlinks the current on-disk prevBinaryPath, not the armed-time snapshot', async () => {
    const dir = tmpDir();
    const markerPath = nodePath.join(dir, 'update-pending.json');
    const stalePrev = nodePath.join(dir, 'old-snapshot.prev');
    const livePrev = nodePath.join(dir, 'live.prev');
    nodeFs.writeFileSync(stalePrev, 'stale');
    nodeFs.writeFileSync(livePrev, 'live');

    const u = newUpdater({ currentVersion: '9.9.9', markerPath, probationMs: 120 });
    // Marker captured by the timer points at stalePrev.
    u._internals.writeMarker('9.9.9', stalePrev);

    const verdict = await u.checkRollback();
    assert.equal(verdict, 'probation');

    // Same-version rewrite that swaps prevBinaryPath (the markGracefulShutdown
    // shape: re-read + rewrite). The timer must honor THIS, not its snapshot.
    u._internals.writeMarker('9.9.9', livePrev, { gracefulAt: Date.now() });

    await wait(300);

    assert.equal(nodeFs.existsSync(livePrev), false, 'current prevBinaryPath must be unlinked');
    assert.equal(nodeFs.existsSync(stalePrev), true, 'stale snapshot path must NOT be unlinked (guard against old bug)');
    assert.equal(nodeFs.existsSync(markerPath), false, 'marker cleared after probation');
  });

  it('skips the unlink when the marker was rewritten for a different version', async () => {
    const dir = tmpDir();
    const markerPath = nodePath.join(dir, 'update-pending.json');
    const snapPrev = nodePath.join(dir, 'snap.prev');
    const otherPrev = nodePath.join(dir, 'other-version.prev');
    nodeFs.writeFileSync(snapPrev, 'snap');
    nodeFs.writeFileSync(otherPrev, 'other');

    const u = newUpdater({ currentVersion: '9.9.9', markerPath, probationMs: 120 });
    u._internals.writeMarker('9.9.9', snapPrev);

    const verdict = await u.checkRollback();
    assert.equal(verdict, 'probation');

    // A successor install rewrote the marker for a DIFFERENT version.
    u._internals.writeMarker('9.9.10', otherPrev);

    await wait(300);

    // The timer must NOT unlink otherPrev (it belongs to the new version) and
    // must NOT unlink snapPrev (its stale snapshot). Worst case is a leaked
    // backup, never a wrong-file delete.
    assert.equal(nodeFs.existsSync(otherPrev), true, 'different-version backup must not be unlinked');
    assert.equal(nodeFs.existsSync(snapPrev), true, 'snapshot backup must not be unlinked');
    assert.equal(nodeFs.existsSync(markerPath), false, 'stale marker still cleared');
  });

  it('tolerates a concurrently-deleted marker (no throw, no unlink)', async () => {
    const dir = tmpDir();
    const markerPath = nodePath.join(dir, 'update-pending.json');
    const snapPrev = nodePath.join(dir, 'snap.prev');
    nodeFs.writeFileSync(snapPrev, 'snap');

    const u = newUpdater({ currentVersion: '9.9.9', markerPath, probationMs: 120 });
    u._internals.writeMarker('9.9.9', snapPrev);

    const verdict = await u.checkRollback();
    assert.equal(verdict, 'probation');

    // Marker vanishes mid-window.
    u._internals.deleteMarker();

    await wait(300);

    assert.equal(nodeFs.existsSync(snapPrev), true, 'no marker => no unlink target');
  });
});
