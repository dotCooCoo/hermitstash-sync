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
//   3. b.selfUpdate.verify → ECDSA P-384 signature over the asset bytes
//      (DER, sha384) verified against the pubkey embedded in
//      lib/constants.js. Verify reports the SHA3-512 of the asset for
//      audit correlation; the signature itself is the integrity gate.
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

function compareVersions(a, c) {
  const pa = a.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
  const pb = c.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
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

  // Tests inject httpsAgent + isTestEnv; production builds the PQC agent.
  let httpsAgent = opts.httpsAgent;
  const isTestEnv = !!opts.httpsAgent;
  if (!httpsAgent) {
    httpsAgent = b.pqcAgent.create({ keepAlive: true, maxSockets: 4 });
    httpsAgent.options.ecdhCurve = TLS_GROUPS;
    httpsAgent.options.groups    = TLS_GROUPS;
    httpsAgent.options.minVersion = TLS_MIN_VERSION;
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

  // Manual download (the .verify primitive reads from disk, so we
  // stream both asset + sig into a per-update temp dir first). Routes
  // through the same b.httpClient + b.pqcAgent the rest of the client
  // uses, so the SSRF / TLS / size-cap defaults stay uniform.
  async function downloadTo(url, destPath) {
    const headers = { 'User-Agent': userAgent };
    let resp;
    try {
      resp = await b.httpClient.request({
        url, method: 'GET', headers,
        agent: httpsAgent,
        allowInternal,
        allowedHosts,
        timeoutMs: C.TIME.minutes(2),
        idleTimeoutMs: C.TIME.minutes(1),
        maxResponseBytes: MAX_ASSET_BYTES,
        followRedirects: true,
        maxRedirects: 5,
      });
    } catch (err) {
      if (err && err.code === 'HTTP_ERROR' && err.statusCode) {
        throw new Error(`HTTP ${err.statusCode} from ${url}`);
      }
      throw err;
    }
    if (resp.statusCode !== 200) {
      throw new Error(`HTTP ${resp.statusCode} from ${url}`);
    }
    const buf = Buffer.isBuffer(resp.body) ? resp.body : Buffer.from(resp.body || '');
    await nodeFsPromises.writeFile(destPath, buf, { mode: 0o644 });
    return destPath;
  }

  function writeMarker(newVersion, prevBinaryPath) {
    nodeFs.mkdirSync(nodePath.dirname(markerPath), { recursive: true });
    const data = { newVersion, prevBinaryPath, installedAt: Date.now() };
    nodeFs.writeFileSync(markerPath, JSON.stringify(data), { mode: 0o644 });
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

  async function performInstall(version, assetPath) {
    const currentPath = getExecPath();
    const prevPath = prevPathFor(currentPath);

    try { nodeFs.unlinkSync(prevPath); } catch {}

    await b.selfUpdate.swap({
      from:     assetPath,
      to:       currentPath,
      backupTo: prevPath,
    });

    if (process.platform !== 'win32') {
      try { nodeFs.chmodSync(currentPath, 0o755); } catch {}
    }

    writeMarker(version, prevPath);

    const child = spawnFn(currentPath, getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: process.env,
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
        releasesUrl:      `${apiBase}/repos/${repo}/releases/latest`,
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

      const verifyResult = await b.selfUpdate.verify({
        assetPath,
        signaturePath: sigPath,
        pubkeyPem,
        hashAlgo: 'sha3-512',
      });
      log.info(`Auto-update: v${newVersion} verified (sha3-512=${verifyResult.hash.slice(0, 16)}…), handing off for install`);

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
      await b.selfUpdate.rollback({
        to:       getExecPath(),
        backupTo: marker.prevBinaryPath,
      });
      try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {}
      if (process.platform !== 'win32') {
        try { nodeFs.chmodSync(getExecPath(), 0o755); } catch {}
      }
    } catch (err) {
      log.error(`Auto-update: rollback failed: ${err.message} — manual recovery required`);
      deleteMarker();
      return 'rollback-failed';
    }

    deleteMarker();

    const child = spawnFn(getExecPath(), getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: process.env,
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
