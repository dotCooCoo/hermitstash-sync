'use strict';

// Auto-update for the sync daemon.
//
// Flow (SEA binary only):
//   1. Poll GitHub Releases every pollMs.
//   2. If a newer version exists, download binary + .sha3-512 + .sig for this
//      platform/arch.
//   3. Verify SHA3-512 checksum matches.
//   4. Verify raw P-384 ECDSA signature over the SHA3-512 digest using the
//      embedded AUTOUPDATE_PUBKEY_PEM.
//   5. Hand off to caller via onUpdateReady(install) — caller stops engine,
//      calls install(), then exits. install() writes update-pending marker,
//      renames current binary → .prev, writes new binary → current path,
//      spawns new detached child.
//
// Probation + rollback:
//   - On every startup, checkRollback() inspects ~/.hermitstash-sync/update-pending.json.
//   - If marker's newVersion matches current version and installedAt < probationMs
//     ago: we're in probation — arm a timer. On fire, delete .prev and marker.
//   - If marker's newVersion matches current version and installedAt >= probationMs
//     ago: the previous startup crashed before completing probation. Restore
//     .prev, delete marker, spawn restored binary, exit.
//
// Source installs (not SEA): log a notice only; never swap.
//
// The `createUpdater(opts)` factory exists primarily for tests: it lets the
// test harness swap in a mock HTTPS endpoint, a different version/pubkey, a
// fake execPath, a fake marker path, and so on. The default export wires
// constants straight through for the production CLI path.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const { spawn } = require('node:child_process');
const log = require('./logger');
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

const DEFAULT_INITIAL_CHECK_DELAY_MS = 60 * 1000;

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

function compareVersions(a, b) {
  const pa = a.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
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
  const markerPath = opts.markerPath || path.join(CONFIG_DIR, 'update-pending.json');
  const getExecPath = opts.getExecPath || (() => process.execPath);
  const getArgv = opts.getArgv || (() => process.argv.slice(2));
  const isSeaBinary = opts.isSeaBinary || defaultIsSeaBinary;
  const tlsOpts = opts.tlsOpts || { ecdhCurve: TLS_GROUPS, groups: TLS_GROUPS, minVersion: TLS_MIN_VERSION };
  const httpsAgent = opts.httpsAgent;
  const exitFn = opts.exitFn || ((code) => process.exit(code));
  const spawnFn = opts.spawnFn || spawn;
  const userAgent = `hermitstash-sync/${currentVersion}`;

  function httpsGet(url, getOpts = {}, redirects = 0) {
    return new Promise((resolve, reject) => {
      if (redirects > 5) return reject(new Error('Too many redirects'));
      const reqOpts = {
        headers: { 'User-Agent': userAgent, ...(getOpts.headers || {}) },
        ...tlsOpts,
      };
      if (httpsAgent) reqOpts.agent = httpsAgent;
      const req = https.get(url, reqOpts, res => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(httpsGet(res.headers.location, getOpts, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        }
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(120000, () => req.destroy(new Error('Timeout')));
    });
  }

  async function getLatestRelease() {
    const url = `${apiBase}/repos/${repo}/releases/latest`;
    const body = await httpsGet(url, { headers: { 'Accept': 'application/vnd.github+json' } });
    const data = JSON.parse(body.toString('utf8'));
    const assets = {};
    for (const a of (data.assets || [])) assets[a.name] = a.browser_download_url;
    return { version: String(data.tag_name || '').replace(/^v/, ''), assets };
  }

  function parseShaFile(text) {
    const m = text.trim().match(/^([0-9a-f]+)/i);
    return m ? m[1].toLowerCase() : null;
  }

  function verifySignature(binary, sig) {
    if (!pubkeyPem) {
      throw new Error('AUTOUPDATE_PUBKEY_PEM not configured — cannot verify update');
    }
    const digest = crypto.createHash('sha3-512').update(binary).digest();
    const pubkey = crypto.createPublicKey(pubkeyPem);
    return crypto.verify('sha512', digest, { key: pubkey, dsaEncoding: 'ieee-p1363' }, sig);
  }

  async function downloadAndVerify(version) {
    const name = assetName(version);
    const release = await getLatestRelease();
    if (release.version !== version) {
      throw new Error(`Release tag mismatch: expected ${version}, got ${release.version}`);
    }
    const binUrl = release.assets[name];
    const sumUrl = release.assets[`${name}.sha3-512`];
    const sigUrl = release.assets[`${name}.sig`];
    if (!binUrl || !sumUrl || !sigUrl) {
      throw new Error(`Missing assets for ${name} (bin=${!!binUrl} sum=${!!sumUrl} sig=${!!sigUrl})`);
    }
    const [binary, sumText, sig] = await Promise.all([
      httpsGet(binUrl), httpsGet(sumUrl), httpsGet(sigUrl),
    ]);
    const expected = parseShaFile(sumText.toString('utf8'));
    const actual = crypto.createHash('sha3-512').update(binary).digest('hex');
    if (expected !== actual) {
      throw new Error(`SHA3-512 mismatch: expected ${expected}, got ${actual}`);
    }
    if (!verifySignature(binary, sig)) {
      throw new Error('ECDSA signature verification failed — refusing to install');
    }
    return binary;
  }

  function prevPathFor(currentPath) {
    const ext = path.extname(currentPath);
    const base = currentPath.slice(0, currentPath.length - ext.length);
    return `${base}.prev${ext}`;
  }

  function writeMarker(newVersion, prevBinaryPath) {
    fs.mkdirSync(path.dirname(markerPath), { recursive: true });
    const data = { newVersion, prevBinaryPath, installedAt: Date.now() };
    fs.writeFileSync(markerPath, JSON.stringify(data), { mode: 0o644 });
  }

  function readMarker() {
    try { return JSON.parse(fs.readFileSync(markerPath, 'utf8')); } catch { return null; }
  }

  function deleteMarker() {
    try { fs.unlinkSync(markerPath); } catch {}
  }

  function installBinary(newBinary, newVersion) {
    const currentPath = getExecPath();
    const prevPath = prevPathFor(currentPath);

    try { fs.unlinkSync(prevPath); } catch {}

    fs.renameSync(currentPath, prevPath);

    try {
      fs.writeFileSync(currentPath, newBinary, { mode: 0o755 });
      if (process.platform !== 'win32') fs.chmodSync(currentPath, 0o755);
    } catch (err) {
      try { fs.renameSync(prevPath, currentPath); } catch {}
      throw err;
    }

    writeMarker(newVersion, prevPath);

    const child = spawnFn(currentPath, getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: process.env,
    });
    child.unref && child.unref();
    return { currentPath, prevPath };
  }

  async function checkOnce(onUpdateReady) {
    if (!pubkeyPem) {
      log.debug('Auto-update: no pubkey embedded, skipping check');
      return { status: 'disabled' };
    }
    try {
      const { version } = await getLatestRelease();
      if (compareVersions(version, currentVersion) <= 0) {
        log.debug(`Auto-update: on latest (${currentVersion})`);
        return { status: 'up-to-date', version };
      }
      if (!isSeaBinary()) {
        log.warn(`Auto-update: v${version} available — running from source, update manually with "git pull"`);
        return { status: 'source-notify', version };
      }
      log.info(`Auto-update: v${version} available (running ${currentVersion}) — downloading + verifying`);
      const binary = await downloadAndVerify(version);
      log.info(`Auto-update: v${version} verified, handing off for install`);
      if (onUpdateReady) await onUpdateReady(() => installBinary(binary, version));
      return { status: 'ready', version, binary };
    } catch (err) {
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
    kickoff.unref && kickoff.unref();
    const interval = setInterval(runCheck, pollMs);
    interval.unref && interval.unref();

    return () => { clearTimeout(kickoff); clearInterval(interval); };
  }

  // Returns one of: 'no-marker', 'stale-cleared', 'probation', 'rolled-back',
  // 'rollback-failed'. Caller should NOT continue startup if we returned
  // 'rolled-back' (unless exitFn was overridden for testing — in which case
  // the caller may ignore).
  function checkRollback() {
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
          try { fs.unlinkSync(marker.prevBinaryPath); } catch {}
        }
        deleteMarker();
        log.info(`Auto-update: v${currentVersion} completed probation`);
      }, remaining);
      timer.unref && timer.unref();
      return 'probation';
    }

    log.error(`Auto-update: v${currentVersion} did not complete probation — rolling back`);
    try {
      if (!marker.prevBinaryPath || !fs.existsSync(marker.prevBinaryPath)) {
        throw new Error(`prev binary not found at ${marker.prevBinaryPath}`);
      }
      const currentPath = getExecPath();
      try { fs.unlinkSync(currentPath); } catch {}
      fs.renameSync(marker.prevBinaryPath, currentPath);
      if (process.platform !== 'win32') fs.chmodSync(currentPath, 0o755);
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
    child.unref && child.unref();
    exitFn(0);
    return 'rolled-back';
  }

  return {
    start,
    checkRollback,
    checkOnce,
    isSeaBinary,
    // Exposed for tests
    _internals: { installBinary, downloadAndVerify, verifySignature, compareVersions, assetName, prevPathFor, readMarker, writeMarker, deleteMarker },
  };
}

// Production singleton wired to the real constants.
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
