'use strict';

// Docker e2e — builds the sync-client image, runs it as a container against
// the local test HermitStash server (started by run-all.js), and exercises
// the full enrollment + bidirectional-sync + restart-persistence + graceful-
// shutdown flow end-to-end.
//
// Skips if `docker` isn't on PATH. Skips if the image build fails (e.g. no
// network access to GitHub Releases for the verify stage).
//
// On Linux the container uses --network=host so it can reach the test
// server on 127.0.0.1. On Mac/Windows Docker Desktop we rewrite 127.0.0.1
// in the URL to host.docker.internal — that's the Docker Desktop convention
// for container-to-host connectivity.
//
// Run via:
//   node tests/run-all.js
// or, targeting just this suite:
//   HS_ONLY=test-docker-e2e.js node tests/run-all.js

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');

const {
  createTempDir, rmrf, sleep, ApiClient,
  runDbScript, uploadFile, countBundleFiles,
  httpRequest,
} = require('./test-helpers');
const { VERSION: LOCAL_VERSION } = require('../lib/constants');

// Resolve the GH-published version the image build will pull. The container's
// SEA binary is downloaded by the Dockerfile based on the VERSION build-arg.
// Pinning to lib/constants.js's local version drifts: a fix committed but not
// yet tagged would mean we test against a stale published SEA. Asking the GH
// API for the latest release each time keeps the test honest — if a release
// is out, exercise that one.
function resolveLatestSyncTag() {
  try {
    var out = execFileSync('gh', ['release', 'view', '--repo', 'dotCooCoo/hermitstash-sync', '--json', 'tagName', '-q', '.tagName'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    var tag = String(out).trim().replace(/^v/, '');
    if (/^\d+\.\d+\.\d+/.test(tag)) return tag;
  } catch (_e) { /* gh CLI not installed or unauthenticated — fall through */ }
  return LOCAL_VERSION;
}
const VERSION = resolveLatestSyncTag();

const CTX = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  clientCertPath: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKeyPath: process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCertPath: process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!CTX.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

const HAS_DOCKER = (() => {
  try { execFileSync('docker', ['version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
})();

const PROJECT_ROOT = path.resolve(__dirname, '..');
const IMAGE_TAG = 'hermitstash-sync-e2e:test-' + process.pid;
const CONTAINER = 'hs-sync-e2e-' + process.pid;

// Host-relative URL the container should use to reach the test server.
function containerServerUrl() {
  const u = new URL(CTX.url);
  if (process.platform !== 'linux' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost')) {
    u.hostname = 'host.docker.internal';
  }
  return u.toString().replace(/\/$/, '');
}

// Network flag for `docker run`. --network=host is Linux-only; Docker Desktop
// on Mac/Windows exposes host.docker.internal by default.
function networkFlag() {
  return process.platform === 'linux' ? ['--network=host'] : [];
}

function docker(args, opts = {}) {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
}

// `docker logs` splits container stdout/stderr across the host's
// stdout/stderr streams. The default execFileSync returns only stdout,
// so any container error written via console.error (e.g.
// `[init] Failed: ...`) is silently dropped from waitUntilLogContains
// matching. Combine both streams here so the watch loop sees every
// log line the container emits.
function dockerLogs(container) {
  const r = require('node:child_process').spawnSync('docker', ['logs', container], {
    encoding: 'utf8',
  });
  return (r.stdout || '') + (r.stderr || '');
}

// Provision a sync-enabled stash + enrollment code through the production
// HTTP flow. Driving the public admin endpoints exercises the same
// primitives (b.mtlsCa, field-crypto, hashCertFingerprint) that
// production callers go through — field-crypto sealing, mtls-CA cert
// issuance, the api_keys row, and the cert-fingerprint binding all
// fire as they would in a real customer-stash provisioning. Catches
// auth-stack regressions that a dialect-only seed-by-SQL shape would
// miss (the WS handshake auth-rejects without the cert binding).
async function seedEnrollmentCode() {
  const slug = 'docker-e2e-' + b.crypto.generateToken(4);
  const client = new ApiClient(CTX.url, CTX.apiKey, {
    clientCert: CTX.clientCertPath,
    clientKey:  CTX.clientKeyPath,
    ca:         CTX.caCertPath,
  });

  // 1. Create the stash via the admin API.
  let resp = await client.request('/admin/stash/create', 'POST', { name: 'Docker e2e', slug: slug });
  if (resp.statusCode !== 200 || !resp.json || !resp.json.stash) {
    throw new Error('admin/stash/create failed: HTTP ' + resp.statusCode + ' ' + (resp.body || ''));
  }
  const stashId = resp.json.stash._id;

  // 2. Toggle syncEnabled so the stash participates in the shared persistent
  //    sync channel.
  resp = await client.request('/admin/stash/' + stashId + '/update', 'POST', { syncEnabled: true });
  if (resp.statusCode !== 200) {
    throw new Error('admin/stash/:id/update failed: HTTP ' + resp.statusCode + ' ' + (resp.body || ''));
  }

  // 3. Mint the first sync-token. On a sync-enabled stash with no bundle yet,
  //    the server provisions the shared persistent sync bundle and records it
  //    as stash.syncBundleId at this admin-provisioning step, so /sync/enroll
  //    can hand the client a resolvable bundleId. Redeeming the code here also
  //    yields the stash-bound sync principal (API key + issued client cert)
  //    used below for the "server -> host" push — the shared sync bundle
  //    refuses an anonymous/browser caller. This drives the real production
  //    provisioning + enrollment path end to end: bundle creation, cert
  //    issuance (b.mtlsCa.generateClientCert), and cert-fingerprint binding.
  resp = await client.request('/admin/stash/' + stashId + '/sync-token', 'POST', {});
  if (resp.statusCode !== 200 || !resp.json || !resp.json.enrollmentCode) {
    throw new Error('admin/stash/:id/sync-token (push identity) failed: HTTP ' + resp.statusCode + ' ' + (resp.body || ''));
  }
  const pushEnroll = await httpRequest(CTX.url + '/sync/enroll', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: resp.json.enrollmentCode }),
    timeout: 15000,
  });
  if (pushEnroll.statusCode !== 200 || !pushEnroll.json || !pushEnroll.json.clientCert) {
    throw new Error('push-identity /sync/enroll failed: HTTP ' + pushEnroll.statusCode + ' ' + (pushEnroll.body || ''));
  }
  // The server resolved the provisioned sync bundle onto the enroll response —
  // this is the bundle the container syncs against. A null bundleId means the
  // admin sync-token step did not provision stash.syncBundleId.
  const bundleId = pushEnroll.json.bundleId;
  if (!bundleId) {
    throw new Error('enroll response carried no bundleId — stash.syncBundleId was not provisioned: ' + (pushEnroll.body || ''));
  }
  const push = {
    key:    pushEnroll.json.apiKey,
    cert:   pushEnroll.json.clientCert,
    keyPem: pushEnroll.json.clientKey,
    ca:     pushEnroll.json.caCert,
  };

  // 4. Mint the enrollment code the container redeems on its first boot.
  resp = await client.request('/admin/stash/' + stashId + '/sync-token', 'POST', {});
  if (resp.statusCode !== 200 || !resp.json || !resp.json.enrollmentCode) {
    throw new Error('admin/stash/:id/sync-token (container) failed: HTTP ' + resp.statusCode + ' ' + (resp.body || ''));
  }

  return { code: resp.json.enrollmentCode, bundleId: bundleId, stashId: stashId, slug: slug, push: push };
}

// Push a file through /stash/:slug/file/:bundleId — the only path that's
// allowed to write into a stash-bound bundle (by design; /drop/* refuses
// stash bundles to keep per-stash caps + access checks effective).
async function uploadFileViaStash(slug, bundleId, name, content, push) {
  const u = new URL(CTX.url + '/stash/' + slug + '/file/' + bundleId);
  const boundary = '----boundary' + b.crypto.generateToken(8);
  const payload = Buffer.concat([
    Buffer.from('--' + boundary + '\r\n', 'utf8'),
    Buffer.from('Content-Disposition: form-data; name="relativePath"\r\n\r\n' + name + '\r\n', 'utf8'),
    Buffer.from('--' + boundary + '\r\n', 'utf8'),
    Buffer.from('Content-Disposition: form-data; name="file"; filename="' + name + '"\r\n', 'utf8'),
    Buffer.from('Content-Type: application/octet-stream\r\n\r\n', 'utf8'),
    Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'),
    Buffer.from('\r\n--' + boundary + '--\r\n', 'utf8'),
  ]);
  return new Promise(function (resolve, reject) {
    // The shared sync bundle only accepts writes from the stash's sync
    // principal (Bearer sync key + its bound client cert), so present the
    // redeemed push identity — not the admin cert, which is not a sync
    // principal for this stash and would be refused with a 404.
    const req = require('https').request({
      hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
      rejectUnauthorized: false,
      ca: push.ca,
      cert: push.cert,
      key: push.keyPem,
      headers: {
        'Content-Type':   'multipart/form-data; boundary=' + boundary,
        'Content-Length': payload.length,
        'Authorization':  'Bearer ' + push.key,
      },
    }, function (res) {
      const chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () { resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); });
    });
    req.on('error', reject);
    req.write(payload); req.end();
  });
}

function dockerRmf(target, kind) {
  try { docker([kind, 'rm', '-f', target], { stdio: 'ignore' }); } catch {}
}

async function waitUntilLogContains(container, needle, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const logs = dockerLogs(container);
      if (logs.includes(needle)) return logs;
    } catch {}
    await sleep(500);
  }
  const lastLogs = (() => { try { return dockerLogs(container); } catch { return '<no logs>'; } })();
  throw new Error(`Timed out waiting for "${needle}" in container ${container} logs\n---\n${lastLogs}`);
}

async function waitForServerToSeeFile(bundleId, relativePath, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const count = countBundleFiles(CTX.dbPath, bundleId);
    // files.relativePath is sealed at rest with no derived hash, so a raw
    // SQL equality check can't match it. Each bundle is freshly minted per
    // test, so any new row in this bundle is necessarily the file under
    // test — count > 0 is a sufficient probe.
    if (count > 0) return;
    await sleep(500);
  }
  // Dump container logs on failure so the next bisection round has signal.
  // Surfacing watcher mode + any sync failures saves a manual `docker logs`.
  var logs;
  try { logs = require("child_process").execFileSync("docker", ["logs", CONTAINER], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); } catch (_e) { logs = "<no logs: " + _e.message + ">"; }
  throw new Error(`Server never saw ${relativePath} in bundle ${bundleId}\n--- container logs ---\n${logs}`);
}

async function waitForHostFile(filePath, expectedContent, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) {
      const body = fs.readFileSync(filePath, 'utf8');
      if (body === expectedContent) return;
    }
    await sleep(500);
  }
  var logs;
  try { logs = require("child_process").execFileSync("docker", ["logs", CONTAINER], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); } catch (_e) { logs = "<no logs: " + _e.message + ">"; }
  throw new Error(`Host never received ${filePath} with expected content\n--- container logs ---\n${logs}`);
}

describe('Docker client — end-to-end', { timeout: 300000 }, function () {
  if (!HAS_DOCKER) {
    it('skipped — docker not available', { skip: true }, () => {});
    return;
  }

  let hostSyncDir;
  let configVolume;
  let enrollmentCode;
  let bundleId;
  let stashSlug;
  let pushIdentity;

  before(async function () {
    console.log('[docker-e2e] Building image ' + IMAGE_TAG + ' for linux/amd64 ...');
    try {
      docker([
        'buildx', 'build', '--load',
        '--platform', 'linux/amd64',
        '--build-arg', `VERSION=${VERSION}`,
        '-t', IMAGE_TAG,
        PROJECT_ROOT,
      ], { stdio: 'inherit' });
    } catch (err) {
      console.log('[docker-e2e] Image build failed — skipping suite:', err.message);
      this.skip();
      return;
    }

    hostSyncDir = createTempDir('docker-sync');
    configVolume = 'hs-sync-e2e-config-' + process.pid;

    const seeded = await seedEnrollmentCode();
    enrollmentCode = seeded.code;
    bundleId = seeded.bundleId;
    stashSlug = seeded.slug;
    pushIdentity = seeded.push;
    console.log('[docker-e2e] Seeded enrollment code for bundle ' + bundleId);
  });

  after(async function () {
    dockerRmf(CONTAINER, 'container');
    dockerRmf(configVolume, 'volume');
    try { docker(['rmi', '-f', IMAGE_TAG], { stdio: 'ignore' }); } catch {}
    if (hostSyncDir) rmrf(hostSyncDir);
  });

  it('container starts, enrolls, reaches RUNNING', async function () {
    const url = containerServerUrl();
    console.log('[docker-e2e] Container → server URL: ' + url);
    docker([
      'run', '-d',
      '--name', CONTAINER,
      ...networkFlag(),
      '-e', `HERMITSTASH_SERVER_URL=${url}`,
      '-e', `HERMITSTASH_ENROLLMENT_CODE=${enrollmentCode}`,
      '-e', 'HERMITSTASH_LOG_LEVEL=debug',
      '-e', 'HERMITSTASH_WATCHER_MODE=poll',
      '-e', 'HERMITSTASH_WATCHER_POLL_INTERVAL_MS=500',
      '-v', `${configVolume}:/config`,
      '-v', `${hostSyncDir}:/data`,
      IMAGE_TAG,
    ]);
    await waitUntilLogContains(CONTAINER, 'Sync engine running', 60000);
  });

  it('host → server: file written on host appears in server bundle', async function () {
    const name = 'from-host.txt';
    fs.writeFileSync(path.join(hostSyncDir, name), 'written in the container host dir');
    await waitForServerToSeeFile(bundleId, name, 20000);
    assert.ok(countBundleFiles(CTX.dbPath, bundleId) >= 1);
  });

  it('server → host: file uploaded to server appears on host', async function () {
    const name = 'from-server.txt';
    // Stash-bound bundles only accept writes through /stash/:slug/file/:bundleId.
    // /drop/* refuses by design (per-stash caps + access checks live on the
    // stash route, including for admin keys — see test-stash-drop-bypass.js).
    const res = await uploadFileViaStash(stashSlug, bundleId, name, 'pushed by server', pushIdentity);
    assert.equal(res.statusCode, 200, 'upload failed: ' + res.body);
    await waitForHostFile(path.join(hostSyncDir, name), 'pushed by server', 20000);
  });

  it('restart does not re-enroll — persisted config is reused', async function () {
    docker(['restart', CONTAINER]);
    await waitUntilLogContains(CONTAINER, 'Sync engine running', 60000);
    const logs = docker(['logs', CONTAINER]);
    // Entrypoint only prints "Running first-time enrollment" on the first
    // boot when no config exists.
    const enrollments = (logs.match(/Running first-time enrollment/g) || []).length;
    assert.equal(enrollments, 1, 'Expected exactly 1 enrollment across both boots');
  });

  it('SIGTERM shuts down gracefully (exit 0)', async function () {
    docker(['stop', '--time', '15', CONTAINER]);
    const code = docker(['inspect', '-f', '{{.State.ExitCode}}', CONTAINER]).trim();
    assert.equal(code, '0');
  });
});
