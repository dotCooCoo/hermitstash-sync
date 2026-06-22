'use strict';

// F3 / F4 regression: the secrets directory (CONFIG_DIR) and the log directory
// must be created 0o700 — not the umask-default 0o755 — so the dir holding
// credentials, state.db, mTLS material, and logs is not world-traversable, and
// a non-owner cannot plant a symlink in the log dir to redirect the log stream.
// Also asserts the daemon-boot upgrade-path remediation tightens an existing
// loose dir, and that logger.init leaves the active log as a regular file.
//
// POSIX mode bits only; the whole suite skips on Windows. CONFIG_DIR is
// resolved from HERMITSTASH_SYNC_CONFIG_DIR at constants.js load, so it is
// pointed at a fresh tmpdir before any lib require. Self-contained.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const TMP_ROOT = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-secrets-dir-'));
const CONFIG_DIR = nodePath.join(TMP_ROOT, '.hermitstash-sync');
process.env.HERMITSTASH_SYNC_CONFIG_DIR = CONFIG_DIR;

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');

const daemon = require('../lib/daemon');
const logger = require('../lib/logger');
const { LOG_FILE } = require('../lib/constants');

const POSIX = process.platform !== 'win32';

after(() => {
  try { logger.close(); } catch { /* idempotent */ }
  try { daemon.removePid(); } catch { /* idempotent */ }
  try { nodeFs.rmSync(TMP_ROOT, { recursive: true, force: true }); } catch { /* best-effort */ }
});

describe('Secrets dir + log dir hardening (F3 / F4)', { skip: POSIX ? false : 'POSIX-only mode bits' }, () => {
  it('daemon.writePid creates CONFIG_DIR 0o700 on a fresh install', () => {
    nodeFs.rmSync(CONFIG_DIR, { recursive: true, force: true });
    daemon.writePid();
    try {
      const mode = nodeFs.statSync(CONFIG_DIR).mode & 0o777;
      assert.equal(mode, 0o700, `CONFIG_DIR should be 0700, got ${mode.toString(8)}`);
    } finally {
      daemon.removePid();
    }
  });

  it('daemon boot tightens an existing world-traversable CONFIG_DIR to 0o700', () => {
    nodeFs.rmSync(CONFIG_DIR, { recursive: true, force: true });
    // Simulate an install created loosely by an older version.
    nodeFs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o755 });
    nodeFs.chmodSync(CONFIG_DIR, 0o755); // mkdir mode is umask-masked; force it
    assert.notEqual(nodeFs.statSync(CONFIG_DIR).mode & 0o077, 0, 'precondition: dir is group/world accessible');

    daemon.writePid();
    try {
      const mode = nodeFs.statSync(CONFIG_DIR).mode & 0o777;
      assert.equal(mode, 0o700, `boot should remediate loose CONFIG_DIR to 0700, got ${mode.toString(8)}`);
    } finally {
      daemon.removePid();
    }
  });

  it('logger.init creates the log dir 0o700 and leaves the active log a regular file', () => {
    nodeFs.rmSync(CONFIG_DIR, { recursive: true, force: true });
    logger.init({ level: 'error', stdout: false });
    try {
      const dirMode = nodeFs.statSync(CONFIG_DIR).mode & 0o777;
      assert.equal(dirMode, 0o700, `log dir should be 0700, got ${dirMode.toString(8)}`);
      const active = nodeFs.lstatSync(LOG_FILE);
      assert.equal(active.isSymbolicLink(), false, 'active log path must not be a symlink after init');
      assert.equal(active.isFile(), true, 'active log path must be a regular file after init');
    } finally {
      logger.close();
    }
  });

  it('logger.init drops a pre-planted symlink at the active log path', () => {
    nodeFs.rmSync(CONFIG_DIR, { recursive: true, force: true });
    nodeFs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    const target = nodePath.join(TMP_ROOT, 'attacker-target.txt');
    nodeFs.writeFileSync(target, 'pre-existing\n');
    // Plant a symlink where the sink will open the active log.
    try {
      nodeFs.symlinkSync(target, LOG_FILE);
    } catch (e) {
      // Some CI sandboxes forbid symlink creation; skip rather than fail.
      return;
    }
    logger.init({ level: 'error', stdout: false });
    logger.info('post-init line');
    logger.close();
    const active = nodeFs.lstatSync(LOG_FILE);
    assert.equal(active.isSymbolicLink(), false, 'symlink must be removed before the sink opens the log');
    // The attacker target must not have grown — logs went to the regular file.
    assert.equal(nodeFs.readFileSync(target, 'utf8'), 'pre-existing\n',
      'logs must not have been redirected into the symlink target');
  });
});
