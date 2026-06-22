'use strict';

/**
 * Exit-code contract for `hermitstash-sync status`.
 *
 * `status` is a process-exit health probe: it must exit 0 when the daemon is
 * RUNNING/healthy and exit 3 (LSB "program not running") when STOPPED, so a
 * Docker HEALTHCHECK / Kubernetes liveness exec / systemd probe detects a dead
 * daemon by exit code alone rather than grepping the human-readable banner.
 *
 * The STOPPED cases drive the real bin entry point in a child process (the
 * faithful exit-code path). The RUNNING case runs cli.run() in-process with
 * daemon.isRunning() stubbed, since spinning a real daemon is unnecessary to
 * assert the exit code stays 0.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const BIN = path.join(REPO_ROOT, 'bin', 'hermitstash-sync.js');

// Spawn the real CLI `status` with an isolated CONFIG_DIR (so no real daemon
// or config is in scope) and return { stdout, exitCode }. A fresh temp dir
// guarantees no PID file → daemon.isRunning() returns false → STOPPED path.
function runStatus(configObj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-status-exit-'));
  try {
    if (configObj) {
      // The STOPPED+configured branch reads server/syncFolder from config.json.
      // Point syncFolder at a real dir so config.load() doesn't fault on it.
      const syncFolder = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-status-folder-'));
      fs.writeFileSync(
        path.join(dir, 'config.json'),
        JSON.stringify(Object.assign({ syncFolder }, configObj)),
      );
    }
    const env = Object.assign({}, process.env, { HERMITSTASH_SYNC_CONFIG_DIR: dir });
    let stdout = '';
    let exitCode = 0;
    try {
      stdout = execFileSync(process.execPath, [BIN, 'status'], {
        cwd: REPO_ROOT,
        env,
        encoding: 'utf8',
        timeout: 30000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      exitCode = err.status == null ? 1 : err.status;
      stdout = (err.stdout || '') + (err.stderr || '');
    }
    return { stdout, exitCode };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('status exit-code contract', () => {

  it('exits 3 (not-running) when STOPPED and configured', () => {
    const { stdout, exitCode } = runStatus({ server: 'https://example.com', bundleId: 'b1' });
    assert.equal(exitCode, 3, 'STOPPED must exit 3 (LSB program-not-running)');
    // stdout stays human-readable + backward-compatible.
    assert.match(stdout, /Status: STOPPED/, 'banner must still print: ' + stdout);
    assert.match(stdout, /Server: https:\/\/example\.com/, 'config summary must still print: ' + stdout);
  });

  it('exits 3 (not-running) when STOPPED and not configured', () => {
    const { stdout, exitCode } = runStatus(null);
    assert.equal(exitCode, 3, 'STOPPED+unconfigured must exit 3');
    assert.match(stdout, /Status: STOPPED/, 'banner must still print: ' + stdout);
    assert.match(stdout, /Not configured/, 'unconfigured hint must still print: ' + stdout);
  });

  it('keeps the human-readable banner greppable for legacy probes', () => {
    // Backward-compat guard for consumers still matching the banner text while
    // they migrate to the exit code.
    const { stdout } = runStatus({ server: 'https://example.com', bundleId: 'b1' });
    assert.ok(stdout.includes('Status: STOPPED'), 'legacy banner-grep must still match');
  });

  it('exits 0 when RUNNING (daemon.isRunning stubbed)', () => {
    // Drive the production cmdStatus path via cli.run() with isRunning stubbed
    // to a live PID and config absent (so the RUNNING branch short-circuits
    // before opening the state DB). The RUNNING/healthy contract is exit 0.
    const daemon = require('../lib/daemon');
    const config = require('../lib/config');
    const cli = require('../lib/cli');

    const origIsRunning = daemon.isRunning;
    const origExists = config.exists;
    const origExitCode = process.exitCode;
    // Silence the RUNNING banner so the test output stays clean.
    const origLog = console.log;
    console.log = () => {};
    try {
      process.exitCode = undefined;
      daemon.isRunning = () => 4242;
      config.exists = () => false;
      const ret = cli.run(['status']);
      // cmdStatus is synchronous, but run() returns its value (may be a
      // resolved value, not a promise) — guard for both.
      if (ret && typeof ret.then === 'function') {
        return ret.then(() => {
          assert.ok(process.exitCode === 0 || process.exitCode === undefined,
            'RUNNING must leave exit code 0, got: ' + process.exitCode);
        });
      }
      assert.ok(process.exitCode === 0 || process.exitCode === undefined,
        'RUNNING must leave exit code 0, got: ' + process.exitCode);
      return undefined;
    } finally {
      console.log = origLog;
      daemon.isRunning = origIsRunning;
      config.exists = origExists;
      process.exitCode = origExitCode;
    }
  });
});
