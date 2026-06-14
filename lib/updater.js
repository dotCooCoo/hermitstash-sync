'use strict';

// Auto-update for the sync daemon — built on b.selfUpdate primitives.
//
// Lifecycle:
//   1. b.selfUpdate.poll → fetches the GitHub /releases/latest feed,
//      semver-compares the latest tag to the running version, and
//      surfaces { available, asset, signature } when a newer build
//      exists. The poll itself handles SSRF posture (allowedHosts) and
//      response-size caps.
//   2. Download asset + signature to temp files via b.httpClient.request
//      (PQC TLS posture inherited from b.pqcAgent). Allowlist the same
//      GitHub-release host set on every fetch — a hostile redirect
//      cannot pivot us at a private IP.
//   3. b.selfUpdate.standaloneVerifier → ECDSA P-384 signature over the
//      asset bytes (DER, SHA3-512) verified against the pubkey embedded
//      in lib/autoupdate-pubkey.js. The standalone verifier is
//      SHA3-512-pinned, matching release.yml's signer; b.selfUpdate.verify
//      cannot be used here because its underlying crypto.verify(null, …)
//      call infers SHA-384 from the P-384 key and silently rejects our
//      SHA3-512-signed assets (latent v0.7.7+ bug — fixed at v0.7.9).
//   4. b.selfUpdate.swap → atomic copy-current-to-prev + rename
//      new-to-current with cross-device fallback. Probation marker
//      written by us, not the framework — it's the hermitstash-specific
//      contract that lets the next boot detect a crash-during-warmup.
//   5. Spawn detached child of the new binary, parent exits.
//
// Probation + rollback (next-boot path):
//   - checkRollback() reads ~/.hermitstash-sync/update-pending.json on
//     every startup. If marker is fresh (age < probationMs) we're
//     in-probation — arm a timer to clear the marker on success.
//   - If marker is stale (we're past probation but the marker is still
//     there → previous boot crashed) → b.selfUpdate.rollback restores
//     .prev → spawn restored binary → exit.
//
// Source installs (not SEA): poll + log a notice, never swap.

// codebase-patterns:allow-file process-exit — updater.exitFn defaults to process.exit so post-swap the parent terminates and the detached child takes over (tests inject a stub).

const nodeFs = require('node:fs');
const nodeFsPromises = require('node:fs/promises');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const log = require('./logger');
const b = require('../vendor/blamejs');
// Standalone verifier (SHA3-512-pinned). Bypasses b.selfUpdate.verify's
// SHA-384 inference that would silently reject our SHA3-512-signed
// assets — see verify-call-site below for context.
const standaloneVerifier = require('../scripts/standalone-verifier');
// Reused only for its negotiated-group observer. The updater's TLS path is
// OBSERVE-ONLY: api.github.com / objects.githubusercontent.com don't offer
// the ML-KEM hybrid groups, so a hard-fail would brick self-update. We log a
// WARN on a classical negotiation but never destroy the socket — separate
// agent from http-client's, so http-client's hard-fail can't bleed onto it.
const { assertNegotiatedGroupPqc } = require('./http-client');
const {
  VERSION,
  AUTOUPDATE_REPO,
  AUTOUPDATE_POLL_MS,
  AUTOUPDATE_PROBATION_MS,
  AUTOUPDATE_PUBKEY_PEM,
  CONFIG_DIR,
  TLS_GROUPS,
  TLS_MIN_VERSION,
} = require('./constants');

const C = b.constants;

const DEFAULT_INITIAL_CHECK_DELAY_MS = C.TIME.minutes(1);
const MAX_ASSET_BYTES = C.BYTES.mib(256);

function defaultIsSeaBinary() {
  try { return require('node:sea').isSea(); } catch { return false; }
}

function platformTag() {
  const p = process.platform;
  return p === 'win32' ? 'win' : p === 'darwin' ? 'macos' : 'linux';
}

function assetName(version) {
  const ext = process.platform === 'win32' ? '.exe' : '';
  return `hermitstash-sync-v${version}-${platformTag()}-${process.arch}${ext}`;
}

// Delegates to b.selfUpdate.compareTags (v0.9.47+ public-surface
// exposure of the internal _compareTags). Kept as a local re-export so
// existing tests that import `compareVersions` from `lib/updater` don't
// have to be rewritten. Same -1 / 0 / +1 semantics; same leading-`v`
// stripping; full SemVer prefix handling (`1.10.0` > `1.9.0`).
function compareVersions(a, c) {
  return b.selfUpdate.compareTags(a, c);
}

function createUpdater(opts = {}) {
  const currentVersion = opts.currentVersion || VERSION;
  const repo = opts.repo || AUTOUPDATE_REPO;
  const apiBase = opts.apiBase || 'https://api.github.com';
  const pubkeyPem = opts.pubkeyPem !== undefined ? opts.pubkeyPem : AUTOUPDATE_PUBKEY_PEM;
  const pollMs = opts.pollMs || AUTOUPDATE_POLL_MS;
  const probationMs = opts.probationMs || AUTOUPDATE_PROBATION_MS;
  const initialDelayMs = opts.initialDelayMs != null ? opts.initialDelayMs : DEFAULT_INITIAL_CHECK_DELAY_MS;
  const markerPath = opts.markerPath || nodePath.join(CONFIG_DIR, 'update-pending.json');
  const getExecPath = opts.getExecPath || (() => process.execPath);
  const getArgv = opts.getArgv || (() => process.argv.slice(2));
  const isSeaBinary = opts.isSeaBinary || defaultIsSeaBinary;
  const exitFn = opts.exitFn || ((code) => process.exit(code));
  const spawnFn = opts.spawnFn || b.processSpawn.spawn;
  const userAgent = `hermitstash-sync/${currentVersion}`;

  // Auto-update channel — "stable" (default) pins to /releases/latest
  // which by GitHub's contract excludes prereleases. "beta" lists
  // /releases and lets b.selfUpdate.poll pick the highest by tag
  // (semver-aware), so a v0.9.0-beta.1 prerelease beats a v0.8.5
  // stable. Operators set config.autoUpdateChannel; the cmdStart
  // path passes it through here.
  const channel = (opts.channel === 'beta') ? 'beta' : 'stable';
  const releasesUrl = channel === 'beta'
    ? `${apiBase}/repos/${repo}/releases?per_page=10`                          // allow:raw-byte-literal — page size (count, not bytes)
    : `${apiBase}/repos/${repo}/releases/latest`;

  // Tests inject httpsAgent + isTestEnv; production builds the PQC agent.
  let httpsAgent = opts.httpsAgent;
  const isTestEnv = !!opts.httpsAgent;
  if (!httpsAgent) {
    httpsAgent = b.pqcAgent.create({ keepAlive: true, maxSockets: 4 });
    httpsAgent.options.ecdhCurve = TLS_GROUPS;
    httpsAgent.options.groups    = TLS_GROUPS;
    httpsAgent.options.minVersion = TLS_MIN_VERSION;
    // Observe-only post-quantum check on the self-update TLS path. The
    // GitHub release CDN legitimately speaks no ML-KEM hybrid, so a classical
    // negotiation here is expected, not an attack — log it (so the PQC posture
    // is visible) but never fail. enforce:false routes through the same logger
    // line the enforced sync transport uses without destroying the socket.
    // This is a DIFFERENT agent from http-client's, so the sync transport's
    // hard-fail cannot reach the updater.
    const _origCreateConnection = httpsAgent.createConnection.bind(httpsAgent);
    httpsAgent.createConnection = function (options, cb) {
      const socket = _origCreateConnection(options, cb);
      if (socket && typeof socket.once === 'function') {
        const host = (options && (options.servername || options.host)) || 'github release CDN';
        socket.once('secureConnect', function () {
          assertNegotiatedGroupPqc(socket, host, { enforce: false });
        });
      }
      return socket;
    };
  }
  const allowInternal = isTestEnv;

  // Production-only egress allowlist. Tests bypass via isTestEnv.
  const allowedHosts = isTestEnv ? undefined : ['api.github.com', 'github.com', 'objects.githubusercontent.com'];

  function platformAssetPattern() {
    const ext = process.platform === 'win32' ? '\\.exe$' : '$';
    // allow:dynamic-regex — pattern built from local platform / arch / extension only (no operator input); the runtime values come from process.platform and process.arch.
    return new RegExp(
      'hermitstash-sync-v\\d+\\.\\d+\\.\\d+-' +
      platformTag() + '-' + process.arch + ext
    );
  }

  // GitHub release-asset URLs 302 to a signed objects.githubusercontent.com
  // location, and b.httpClient.downloadStream composes through request()'s
  // no-follow default — it throws on a 3xx rather than chasing it. So we
  // resolve the final landing URL first: a stream-mode request that follows
  // up to 5 hops and records each Location via the onRedirect hook. The
  // last `to` is the resolved URL; the response body is drained + destroyed
  // immediately since we only wanted the URL. A direct 200 (no redirect)
  // leaves resolved === url.
  async function resolveFinalUrl(url) {
    let resolved = url;
    let resp;
    try {
      resp = await b.httpClient.request({
        url, method: 'GET',
        headers: { 'User-Agent': userAgent },
        agent: httpsAgent,
        allowInternal,
        allowedHosts,
        responseMode: 'stream',
        maxRedirects: 5,
        timeoutMs: C.TIME.minutes(2),
        idleTimeoutMs: C.TIME.minutes(1),
        onRedirect: (e) => { if (e && e.to) resolved = e.to; },
      });
    } catch (err) {
      if (err && err.code === 'HTTP_ERROR' && err.statusCode) {
        throw new Error(`HTTP ${err.statusCode} from ${url}`);
      }
      throw err;
    }
    // We have the resolved URL — discard the body without buffering it.
    const body = resp && resp.body;
    if (body && typeof body.destroy === 'function') {
      try { body.destroy(); } catch { /* best-effort teardown */ }
    } else if (body && typeof body.resume === 'function') {
      body.resume();
    }
    return resolved;
  }

  // Stream an asset to disk instead of buffering it into memory. Routes
  // through the same b.httpClient + b.pqcAgent the rest of the client uses
  // (SSRF / TLS / allowedHosts posture unchanged), hashes the bytes in
  // flight, and atomically renames into place — the on-disk file is then
  // re-verified by the SHA3-512-pinned standalone verifier before any swap.
  // The resolved URL is computed first so downloadStream never sees the
  // GitHub 302 it would refuse.
  async function downloadTo(url, destPath) {
    const resolvedUrl = await resolveFinalUrl(url);
    try {
      await b.httpClient.downloadStream({
        url: resolvedUrl,
        dest: destPath,
        agent: httpsAgent,
        allowInternal,
        allowedHosts,
        headers: { 'User-Agent': userAgent },
        hash: 'sha3-512',
        maxBytes: MAX_ASSET_BYTES,
        timeoutMs: C.TIME.minutes(2),
        idleTimeoutMs: C.TIME.minutes(1),
      });
    } catch (err) {
      if (err && err.statusCode) {
        throw new Error(`HTTP ${err.statusCode} from ${resolvedUrl}`);
      }
      throw err;
    }
    return destPath;
  }

  function writeMarker(newVersion, prevBinaryPath) {
    const data = { newVersion, prevBinaryPath, installedAt: Date.now() };
    // Atomic write: temp + fsync + rename + parent-dir fsync, with the
    // Windows transient-lock retry on the rename, and the parent dir
    // created internally. A crash in the swap window can never leave a
    // torn JSON that readMarker() would silently treat as "no pending
    // update", abandoning rollback. fileMode keeps the marker world-
    // readable (it carries no secret — only version + prev-binary path).
    b.atomicFile.writeSync(markerPath, JSON.stringify(data), { fileMode: 0o644 });
  }

  function readMarker() {
    try { return b.safeJson.parse(nodeFs.readFileSync(markerPath, 'utf8'), { maxBytes: C.BYTES.kib(64) }); } catch { return null; }
  }

  function deleteMarker() {
    try { nodeFs.unlinkSync(markerPath); } catch {}
  }

  function prevPathFor(currentPath) {
    const ext = nodePath.extname(currentPath);
    const base = currentPath.slice(0, currentPath.length - ext.length);
    return `${base}.prev${ext}`;
  }

  // Windows holds an exclusive lock on a running image, so renaming the
  // NEW binary ONTO the running .exe (what b.selfUpdate.swap does) fails
  // with EBUSY/EPERM. Windows does, however, permit renaming the running
  // image away from its own path. The backup of the current binary is
  // therefore that rename target — `<exec>.old` — which stays locked
  // until this process exits and is unlinked on the next boot.
  function oldPathFor(currentPath) {
    const ext = nodePath.extname(currentPath);
    const base = currentPath.slice(0, currentPath.length - ext.length);
    return `${base}.old${ext}`;
  }

  // win32 in-use swap: rename the running image to `<exec>.old` (allowed
  // even while running), then drop the new binary at the now-free original
  // path. Returns the backup path so the marker records it for next-boot
  // cleanup. EPERM/EACCES/EBUSY here means even the rename-away is blocked
  // (locked-down ACLs, an AV scanner holding a handle) — surface an
  // actionable error pointing the operator at the external updater rather
  // than failing opaquely.
  function _windowsSwap(assetPath, currentPath, oldPath) {
    try { nodeFs.unlinkSync(oldPath); } catch { /* no stale .old to clear */ }
    try {
      nodeFs.renameSync(currentPath, oldPath);
    } catch (err) {
      if (err && (err.code === 'EPERM' || err.code === 'EACCES' || err.code === 'EBUSY')) {
        throw new Error(
          `Auto-update: in-daemon self-replace is not supported here — Windows ` +
          `blocked renaming the running executable (${err.code}). Re-run the ` +
          `installer manually, or run the external updater / "docker pull" ` +
          `for your deployment to upgrade.`
        );
      }
      throw err;
    }
    try {
      // The original path is now free — move the verified asset into it.
      // renameSync stays atomic when asset + exec share a volume; fall
      // back to copy on a cross-device temp dir.
      try {
        nodeFs.renameSync(assetPath, currentPath);
      } catch (mvErr) {
        if (mvErr && mvErr.code === 'EXDEV') {
          nodeFs.copyFileSync(assetPath, currentPath);
          try { nodeFs.unlinkSync(assetPath); } catch { /* temp asset leak — operator-cleanable */ }
        } else {
          throw mvErr;
        }
      }
    } catch (err) {
      // Install failed after the rename-away — restore the old image so
      // the daemon isn't left with no binary at currentPath.
      try { nodeFs.renameSync(oldPath, currentPath); } catch { /* best-effort restore */ }
      throw err;
    }
  }

  // win32 in-use rollback: rename the running (new, crashed) image away,
  // then move `<exec>.old` (the backup recorded at install) back to the
  // original path. The `.new-failed` rename target stays locked until this
  // process exits; the next boot's stale-marker / probation cleanup leaves
  // it for the operator (or a later install's unlink) — it never blocks
  // the restore. Throws an actionable error if even the rename-away fails.
  function _windowsRollback(currentPath, backupPath) {
    const failedPath = `${currentPath}.new-failed`;
    try { nodeFs.unlinkSync(failedPath); } catch { /* no stale failed image */ }
    try {
      nodeFs.renameSync(currentPath, failedPath);
    } catch (err) {
      if (err && (err.code === 'EPERM' || err.code === 'EACCES' || err.code === 'EBUSY')) {
        throw new Error(
          `Windows blocked renaming the running executable (${err.code}) — ` +
          `manual recovery required: restore ${backupPath} to ${currentPath}.`
        );
      }
      throw err;
    }
    try {
      nodeFs.renameSync(backupPath, currentPath);
    } catch (mvErr) {
      if (mvErr && mvErr.code === 'EXDEV') {
        nodeFs.copyFileSync(backupPath, currentPath);
        try { nodeFs.unlinkSync(backupPath); } catch { /* backup leak — operator-cleanable */ }
      } else {
        // Restore failed — put the running image back so we aren't left
        // with no binary at currentPath, then surface the error.
        try { nodeFs.renameSync(failedPath, currentPath); } catch { /* best-effort */ }
        throw mvErr;
      }
    }
  }

  async function performInstall(version, assetPath) {
    const currentPath = getExecPath();
    let prevPath;

    if (process.platform === 'win32') {
      prevPath = oldPathFor(currentPath);
      _windowsSwap(assetPath, currentPath, prevPath);
    } else {
      prevPath = prevPathFor(currentPath);
      try { nodeFs.unlinkSync(prevPath); } catch {}
      await b.selfUpdate.swap({
        from:     assetPath,
        to:       currentPath,
        backupTo: prevPath,
      });
      try { nodeFs.chmodSync(currentPath, 0o755); } catch {}
    }

    writeMarker(version, prevPath);

    // Mark the successor so its cmdStart tolerates THIS still-exiting process's
    // pidfile during the brief handoff window instead of die()-ing on it.
    const child = spawnFn(currentPath, getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, HERMITSTASH_SELF_REPLACE: '1' },
    });
    if (child && typeof child.unref === 'function') child.unref();
    return { currentPath, prevPath };
  }

  async function checkOnce(onUpdateReady) {
    if (!pubkeyPem) {
      log.debug('Auto-update: no pubkey embedded, skipping check');
      return { status: 'disabled' };
    }
    let pollResult;
    try {
      pollResult = await b.selfUpdate.poll({
        releasesUrl,
        currentVersion,
        assetPattern:     platformAssetPattern(),
        signaturePattern: /\.sig$/,
        allowedHosts,
        allowInternal,
        timeoutMs:        C.TIME.seconds(15),
        headers:          { 'User-Agent': userAgent, 'Accept': 'application/vnd.github+json' },
      });
    } catch (err) {
      log.warn(`Auto-update poll failed: ${err.message}`);
      return { status: 'error', error: err };
    }

    if (!pollResult.available) {
      log.debug(`Auto-update: on latest (${currentVersion})`);
      return { status: 'up-to-date', version: pollResult.latestTag };
    }

    const newVersion = String(pollResult.latestTag || '').replace(/^v/, '');
    if (!isSeaBinary()) {
      log.warn(`Auto-update: v${newVersion} available — running from source, update manually with "git pull"`);
      return { status: 'source-notify', version: newVersion };
    }

    if (!pollResult.asset || !pollResult.signature) {
      const err = new Error(`Missing asset or signature for ${assetName(newVersion)} (asset=${!!pollResult.asset} sig=${!!pollResult.signature})`);
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }

    const tmp = await nodeFsPromises.mkdtemp(nodePath.join(nodeOs.tmpdir(), 'hs-update-'));
    const cleanup = async () => {
      try { await nodeFsPromises.rm(tmp, { recursive: true, force: true }); } catch {}
    };

    try {
      log.info(`Auto-update: v${newVersion} available (running ${currentVersion}) — downloading + verifying`);
      const assetPath = nodePath.join(tmp, pollResult.asset.name);
      const sigPath   = nodePath.join(tmp, pollResult.signature.name);
      await downloadTo(pollResult.asset.url, assetPath);
      await downloadTo(pollResult.signature.url, sigPath);

      // Verify via the SHA3-512-pinned standalone verifier — matches the
      // release.yml signer's hash choice. b.selfUpdate.verify would
      // wrongly reject SHA3-512 sigs because it goes through
      // crypto.verify(null, …) which infers SHA-384 from the curve.
      let verifyResult;
      try {
        verifyResult = standaloneVerifier.verify(assetPath, sigPath, pubkeyPem);
      } catch (vErr) {
        throw new Error(`Auto-update: signature verification failed for v${newVersion}: ${vErr.message}`);
      }
      log.info(`Auto-update: v${newVersion} verified (sha3-512=${verifyResult.sha3_512.slice(0, 16)}…, alg=${verifyResult.alg}), handing off for install`);

      if (onUpdateReady) {
        await onUpdateReady(async () => {
          try {
            return await performInstall(newVersion, assetPath);
          } finally {
            await cleanup();
          }
        });
      } else {
        await cleanup();
      }
      return { status: 'ready', version: newVersion };
    } catch (err) {
      await cleanup();
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }
  }

  function start(onUpdateReady) {
    if (!pubkeyPem) {
      log.info('Auto-update disabled: no pubkey embedded in this build');
      return () => {};
    }
    if (!isSeaBinary()) {
      log.info('Auto-update: source install — will notify on new versions but not self-replace');
    }

    let running = false;
    const runCheck = async () => {
      if (running) return;
      running = true;
      try { await checkOnce(onUpdateReady); } finally { running = false; }
    };

    const kickoff = setTimeout(runCheck, initialDelayMs);
    if (kickoff && typeof kickoff.unref === 'function') kickoff.unref();

    const repeater = b.safeAsync.repeating(runCheck, pollMs, {
      onError: function (err) {
        log.warn('Auto-update poll failed: ' + (err && err.message ? err.message : String(err)));
      },
    });

    return () => { clearTimeout(kickoff); repeater.stop(); };
  }

  // Returns one of: 'no-marker', 'stale-cleared', 'probation',
  // 'rolled-back', 'rollback-failed'. The caller (cli.js cmdStart) must
  // not continue startup when 'rolled-back' is returned — exitFn fires.
  async function checkRollback() {
    const marker = readMarker();
    if (!marker) return 'no-marker';

    if (marker.newVersion !== currentVersion) {
      log.warn(`Auto-update: stale marker (newVersion=${marker.newVersion}, running=${currentVersion}) — clearing`);
      deleteMarker();
      return 'stale-cleared';
    }

    const age = Date.now() - (marker.installedAt || 0);

    if (age < probationMs) {
      log.info(`Auto-update: v${currentVersion} in probation (${Math.round(age/1000)}s / ${Math.round(probationMs/1000)}s)`);
      const remaining = probationMs - age;
      const timer = setTimeout(() => {
        if (marker.prevBinaryPath) {
          try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {}
        }
        deleteMarker();
        log.info(`Auto-update: v${currentVersion} completed probation`);
      }, remaining);
      if (timer && typeof timer.unref === 'function') timer.unref();
      return 'probation';
    }

    log.error(`Auto-update: v${currentVersion} did not complete probation — rolling back`);
    try {
      if (!marker.prevBinaryPath || !nodeFs.existsSync(marker.prevBinaryPath)) {
        throw new Error(`prev binary not found at ${marker.prevBinaryPath}`);
      }
      if (process.platform === 'win32') {
        // Symmetric in-use restore: copying the backup ONTO the running
        // (new, crashed) image fails with EPERM, so rename the running
        // image away to `<exec>.new-failed`, then rename `<exec>.old`
        // back to the original path. The stranded `.new-failed` stays
        // locked until this process exits and is cleared next boot.
        _windowsRollback(getExecPath(), marker.prevBinaryPath);
      } else {
        await b.selfUpdate.rollback({
          to:       getExecPath(),
          backupTo: marker.prevBinaryPath,
        });
        try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {}
        try { nodeFs.chmodSync(getExecPath(), 0o755); } catch {}
      }
    } catch (err) {
      log.error(`Auto-update: rollback failed: ${err.message} — manual recovery required`);
      deleteMarker();
      return 'rollback-failed';
    }

    deleteMarker();

    // Same self-replace handoff as performInstall: the restored binary's
    // cmdStart must tolerate this exiting process's pidfile during the window.
    const child = spawnFn(getExecPath(), getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, HERMITSTASH_SELF_REPLACE: '1' },
    });
    if (child && typeof child.unref === 'function') child.unref();
    exitFn(0);
    return 'rolled-back';
  }

  return {
    start,
    checkRollback,
    checkOnce,
    isSeaBinary,
    _internals: { performInstall, downloadTo, compareVersions, assetName, prevPathFor, readMarker, writeMarker, deleteMarker },
  };
}

const _default = createUpdater();

module.exports = {
  start: _default.start,
  checkRollback: _default.checkRollback,
  checkOnce: _default.checkOnce,
  isSeaBinary: _default.isSeaBinary,
  createUpdater,
  assetName,
  compareVersions,
};
