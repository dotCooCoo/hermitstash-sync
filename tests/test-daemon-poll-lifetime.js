'use strict';
// The daemon keeps running while its server is unreachable. With the poll file
// watcher (the container default) every timer the daemon holds is unref'd, and
// without a ref'd handle of its own the process exited with status 0 right
// after its first failed connection instead of reconnecting.
//
// Runs `hermitstash-sync start` in the foreground against a local port nothing
// listens on. Needs no HermitStash server.
//
// Run standalone:
//   node --test tests/test-daemon-poll-lifetime.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'bin', 'hermitstash-sync.js');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
  });
}

test('the daemon keeps reconnecting with the poll watcher while the server is unreachable', async () => {
  const port = await freePort();
  const cfgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-poll-lifetime-cfg-'));
  const syncDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-poll-lifetime-data-'));
  fs.writeFileSync(path.join(cfgDir, 'credentials'), 'test-api-key-not-real\n', { mode: 0o600 });
  fs.writeFileSync(path.join(cfgDir, 'config.json'), JSON.stringify({
    server: 'https://127.0.0.1:' + port,
    bundleId: 'bundle-poll-lifetime',
    shareId: 'share-poll-lifetime',
    syncFolder: syncDir,
    apiKeyRef: 'file',
    autoUpdate: false,
    logLevel: 'info',
  }, null, 2), { mode: 0o600 });

  const child = spawn(process.execPath, [BIN, 'start'], {
    env: Object.assign({}, process.env, {
      HERMITSTASH_SYNC_CONFIG_DIR: cfgDir,
      HERMITSTASH_WATCHER_MODE: 'poll',
      HERMITSTASH_NTP_DISABLE: '1',
      HERMITSTASH_AUTO_UPDATE: 'false',
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (d) => { output += d; });
  child.stderr.on('data', (d) => { output += d; });
  let exited = null;
  const exitedPromise = new Promise((resolve) => {
    child.on('exit', (code, signal) => { exited = { code, signal }; resolve(); });
  });

  try {
    // Wait for the second reconnect attempt, which only a daemon that survived
    // its first failed connection can reach, or for the process to end.
    const deadline = Date.now() + 30_000;                                        // allow:raw-byte-literal — test wait ceiling
    while (!exited && !/Reconnecting in ~\d+s \(attempt 2\)/.test(output) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));                              // allow:raw-byte-literal — poll interval
    }
    assert.equal(exited, null, 'the daemon exited while the server was unreachable:\n' + output);
    assert.match(output, /Reconnecting in ~\d+s \(attempt 2\)/, 'the daemon reached a second reconnect attempt:\n' + output);
    assert.doesNotMatch(output, /The event loop drained/);
  } finally {
    if (!exited) {
      child.kill();
      await exitedPromise;
    }
    fs.rmSync(cfgDir, { recursive: true, force: true });
    fs.rmSync(syncDir, { recursive: true, force: true });
  }
});
