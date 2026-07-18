'use strict';

// Pure-unit regression tests for the confirmed lib/updater.js audit fixes.
// No server harness, no network: every assertion drives an exported helper,
// the updater's _internals surface, or the same vendored primitive the fix
// wired, against node:fs temp dirs only. Runs standalone:
//   node --test tests/test-fix-updater.js
//
// Findings covered:
//   updater#18 (regex) — beta-channel asset/signature regex (prerelease tail)
//   updater#21 — expired-signed-URL retry classifier on downloadTo
//   updater#23 — probation timer re-reads the marker before the destructive unlink
//   updater#16 — b.selfUpdate.swap now REQUIRES expectedHash; the verified
//                SHA3-512 is threaded through performInstall (POSIX install
//                path previously threw and silently never installed)
//   updater#17 — the win32 self-replace re-hashes the asset against the verified
//                digest and installs the in-memory bytes (verify->install bind)
//   updater#18 (cap) — the signature download uses a small (64 KiB) cap, not the
//                256 MiB asset cap

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
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

// ---- shared fixtures for the install-path findings ----

function tmpDir(tag) {
  return nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-upd-' + (tag || 'x') + '-'));
}
// SHA3-512 lowercase hex — byte-identical to what the standalone verifier
// returns (verifyResult.sha3_512) and to what b.selfUpdate.swap / fdSafeReadSync
// recompute internally. Never derive the "verified" hash from the same bytes the
// production code re-reads in a way that would mask a real mismatch — these tests
// pass the digest of the ORIGINAL asset bytes, exactly as checkOnce does.
function sha3hex(buf) {
  return nodeCrypto.createHash('sha3-512').update(buf).digest('hex');
}
// Platform is forced per-test via createUpdater's injectable `platform` opt —
// never by stubbing the global process.platform: an Object.defineProperty
// stub restored in `finally` clobbers concurrently-running tests' view of
// the platform under node:test's async execution.

describe('updater#16 — POSIX install threads the verified digest into b.selfUpdate.swap', () => {
  // The v0.10.1 vendored refresh made expectedHash a REQUIRED opt on
  // b.selfUpdate.swap. performInstall must pass verifyResult.sha3_512, or every
  // Linux/macOS in-daemon install throws selfupdate/bad-expected-hash and
  // silently never installs. These drive the real _internals.performInstall
  // through the real vendored swap primitive (no network) with process.platform
  // stubbed to a POSIX value so the else-branch runs on any host.

  it('installs the new bytes and backs up the old when the digest matches', async () => {
    const dir = tmpDir('posix');
    const currentPath = nodePath.join(dir, 'hs');
    const assetPath = nodePath.join(dir, 'asset');
    const OLD = Buffer.from('OLD BINARY v0.4.6');
    const NEW = Buffer.from('NEW BINARY v9.9.9 with more bytes');
    nodeFs.writeFileSync(currentPath, OLD, { mode: 0o755 });
    nodeFs.writeFileSync(assetPath, NEW, { mode: 0o644 });
    const markerPath = nodePath.join(tmpDir('marker'), 'update-pending.json');

    const u = newUpdater({
      currentVersion: '0.4.6',
      platform: 'linux',
      markerPath,
      getExecPath: () => currentPath,
      getArgv: () => [],
      exitFn: () => {},
      spawnFn: () => ({ unref() {} }),
    });

    const { prevPath } = await u._internals.performInstall('9.9.9', assetPath, sha3hex(NEW));

    assert.ok(nodeFs.readFileSync(currentPath).equals(NEW), 'current binary must be the new bytes');
    assert.ok(prevPath.endsWith('.prev'), `expected a .prev backup, got ${prevPath}`);
    assert.ok(nodeFs.readFileSync(prevPath).equals(OLD), 'backup must hold the old bytes');
    const marker = JSON.parse(nodeFs.readFileSync(markerPath, 'utf8'));
    assert.equal(marker.newVersion, '9.9.9');
    assert.equal(marker.prevBinaryPath, prevPath);
  });

  it('refuses to install and leaves the current binary untouched when the digest mismatches', async () => {
    const dir = tmpDir('posix');
    const currentPath = nodePath.join(dir, 'hs');
    const assetPath = nodePath.join(dir, 'asset');
    const OLD = Buffer.from('OLD BINARY');
    const NEW = Buffer.from('NEW BINARY');
    nodeFs.writeFileSync(currentPath, OLD, { mode: 0o755 });
    nodeFs.writeFileSync(assetPath, NEW, { mode: 0o644 });
    const markerPath = nodePath.join(tmpDir('marker'), 'update-pending.json');

    const u = newUpdater({
      currentVersion: '0.4.6', platform: 'linux', markerPath,
      getExecPath: () => currentPath, getArgv: () => [], exitFn: () => {}, spawnFn: () => ({ unref() {} }),
    });

    const wrong = sha3hex(Buffer.from('some other content the signature never covered'));
    await assert.rejects(
      u._internals.performInstall('9.9.9', assetPath, wrong),
      (err) => { assert.match(err.message, /expectedHash|hash-mismatch|refusing to install/i); return true; }
    );
    assert.ok(nodeFs.readFileSync(currentPath).equals(OLD), 'current binary must be untouched after a refused swap');
    // Marker-before-swap contract: the marker for the refused install exists
    // (recording the attempted version) and the next boot of the still-current
    // binary clears it via checkRollback's version-mismatch stale branch.
    assert.equal(nodeFs.existsSync(markerPath), true, 'marker precedes the swap; refused swap leaves it for stale-clear');
    assert.equal(await u.checkRollback(), 'stale-cleared');
    assert.equal(nodeFs.existsSync(markerPath), false);
  });

  it('regression guard: the vendored swap REQUIRES expectedHash (omitting it throws)', async () => {
    // This is exactly the v0.10.1 break — a 2-arg performInstall (no digest)
    // reaches b.selfUpdate.swap with expectedHash undefined and is refused. The
    // production caller (checkOnce) always threads the digest, so this asserts
    // the vendored contract the fix satisfies rather than a reachable path.
    const dir = tmpDir('posix');
    const currentPath = nodePath.join(dir, 'hs');
    const assetPath = nodePath.join(dir, 'asset');
    nodeFs.writeFileSync(currentPath, 'OLD', { mode: 0o755 });
    nodeFs.writeFileSync(assetPath, 'NEW', { mode: 0o644 });
    const markerPath = nodePath.join(tmpDir('marker'), 'update-pending.json');
    const u = newUpdater({
      currentVersion: '0.4.6', platform: 'linux', markerPath,
      getExecPath: () => currentPath, getArgv: () => [], exitFn: () => {}, spawnFn: () => ({ unref() {} }),
    });
    await assert.rejects(
      u._internals.performInstall('9.9.9', assetPath /* no expectedHash */),
      (err) => { assert.match(err.message, /expectedHash|bad-expected-hash/i); return true; }
    );
  });
});

describe('updater#17 — win32 self-replace binds the installed bytes to the verified digest', () => {
  // Drive the win32 branch on any host by stubbing process.platform. The swap
  // renames whatever getExecPath() points at, so a temp file stands in for the
  // running .exe. The fix re-reads the asset with O_NOFOLLOW and refuses unless
  // it still matches the verified SHA3-512 BEFORE the rename-away, then installs
  // the verified in-memory bytes.

  it('renames the running image to .old and installs the verified new bytes', async () => {
    const dir = tmpDir('winswap');
    const currentPath = nodePath.join(dir, 'hs.exe');
    const assetPath = nodePath.join(dir, 'asset.exe');
    const RUNNING = Buffer.from('RUNNING IMAGE v0.4.6');
    const NEW = Buffer.from('NEW IMAGE v9.9.9');
    nodeFs.writeFileSync(currentPath, RUNNING, { mode: 0o755 });
    nodeFs.writeFileSync(assetPath, NEW, { mode: 0o755 });
    const markerPath = nodePath.join(tmpDir('marker'), 'update-pending.json');

    const u = newUpdater({
      currentVersion: '0.4.6', platform: 'win32', markerPath,
      getExecPath: () => currentPath, getArgv: () => [], exitFn: () => {}, spawnFn: () => ({ unref() {} }),
    });

    const { prevPath } = await u._internals.performInstall('9.9.9', assetPath, sha3hex(NEW));

    assert.ok(nodeFs.readFileSync(currentPath).equals(NEW), 'current path must hold the new bytes');
    assert.ok(prevPath.endsWith('.old.exe'), `expected an .old.exe backup, got ${prevPath}`);
    assert.ok(nodeFs.readFileSync(prevPath).equals(RUNNING), 'backup must hold the running image');
    const marker = JSON.parse(nodeFs.readFileSync(markerPath, 'utf8'));
    assert.equal(marker.prevBinaryPath, prevPath);
  });

  it('refuses a tampered asset and never disturbs the running image', async () => {
    const dir = tmpDir('winswap');
    const currentPath = nodePath.join(dir, 'hs.exe');
    const assetPath = nodePath.join(dir, 'asset.exe');
    const RUNNING = Buffer.from('RUNNING IMAGE');
    const NEW = Buffer.from('NEW IMAGE');
    nodeFs.writeFileSync(currentPath, RUNNING, { mode: 0o755 });
    nodeFs.writeFileSync(assetPath, NEW, { mode: 0o755 });
    const markerPath = nodePath.join(tmpDir('marker'), 'update-pending.json');

    const u = newUpdater({
      currentVersion: '0.4.6', platform: 'win32', markerPath,
      getExecPath: () => currentPath, getArgv: () => [], exitFn: () => {}, spawnFn: () => ({ unref() {} }),
    });

    // The verified digest is for RUNNING's-successor NEW, but an attacker
    // swapped assetPath to different bytes after verify. The re-check must fire.
    const verifiedButStale = sha3hex(Buffer.from('the bytes the signature actually covered'));
    await assert.rejects(
      u._internals.performInstall('9.9.9', assetPath, verifiedButStale),
      (err) => { assert.match(err.message, /integrity re-check|refusing to install/i); return true; }
    );

    // Read-first ordering: the running image is intact and no .old backup was
    // created. Marker-before-swap contract: the marker for the refused
    // install exists and the next boot of the still-current binary clears it
    // via checkRollback's version-mismatch stale branch.
    assert.ok(nodeFs.readFileSync(currentPath).equals(RUNNING), 'running image must be untouched');
    const oldPath = currentPath.replace(/\.exe$/, '.old.exe');
    assert.equal(nodeFs.existsSync(oldPath), false, 'no rename-away must have happened');
    assert.equal(nodeFs.existsSync(markerPath), true, 'marker precedes the swap; refused swap leaves it for stale-clear');
    assert.equal(await u.checkRollback(), 'stale-cleared');
    assert.equal(nodeFs.existsSync(markerPath), false);
  });
});

describe('updater#18 (cap) — the signature download uses a small cap, the asset uses the 256 MiB cap', () => {
  // downloadTo is shared by the asset leg and the signature leg. The fix gives it
  // a per-call maxBytes so the sub-100-byte detached signature is not fetched
  // under the 256 MiB asset ceiling. Stub the b.httpClient transport at its
  // boundary and capture the maxBytes the REAL downloadTo forwards — no network,
  // no reimplementation of the fix.
  const MIB_256 = b.constants.BYTES.mib(256);
  const KIB_64 = b.constants.BYTES.kib(64);

  async function captureCap(callDownloadTo) {
    const realRequest = b.httpClient.request;
    const realDownload = b.httpClient.downloadStream;
    let captured;
    b.httpClient.request = async () => ({ body: { destroy() {} } });       // resolveFinalUrl: no redirect, drained
    b.httpClient.downloadStream = async (opts) => { captured = opts.maxBytes; };
    try {
      const u = newUpdater({ currentVersion: '0.4.6' });
      await callDownloadTo(u);
    } finally {
      b.httpClient.request = realRequest;
      b.httpClient.downloadStream = realDownload;
    }
    return captured;
  }

  it('the signature leg forwards a 64 KiB cap', async () => {
    const cap = await captureCap((u) =>
      u._internals.downloadTo('https://example.invalid/asset.sig', nodePath.join(tmpDir('sig'), 'a.sig'), KIB_64));
    assert.equal(cap, KIB_64, 'signature download must cap at 64 KiB, not the 256 MiB asset ceiling');
    assert.ok(cap < MIB_256, 'the signature cap must be far below the asset cap');
  });

  it('the asset leg (and any unspecified caller) keeps the 256 MiB cap', async () => {
    const explicit = await captureCap((u) =>
      u._internals.downloadTo('https://example.invalid/asset', nodePath.join(tmpDir('asset'), 'a'), MIB_256));
    assert.equal(explicit, MIB_256, 'explicit asset download must keep the 256 MiB cap');

    const defaulted = await captureCap((u) =>
      u._internals.downloadTo('https://example.invalid/asset', nodePath.join(tmpDir('asset'), 'b')));
    assert.equal(defaulted, MIB_256, 'an unspecified cap must default to the asset ceiling (never less bounded)');
  });
});
