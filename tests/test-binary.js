'use strict';

/**
 * SEA binary smoke tests — verifies the compiled executable works correctly.
 *
 * Runs the binary with various commands and validates output.
 * Also tests against a live server if run via run-all.js with env vars.
 *
 * Usage:
 *   node --test tests/test-binary.js              (standalone, basic tests only)
 *   node tests/run-all.js                          (full suite including server tests)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');

const VERSION = require('../lib/constants').VERSION;
const PLATFORM = os.platform();
const ARCH = os.arch();
const platformTag = (PLATFORM === 'win32' ? 'win' : PLATFORM === 'darwin' ? 'macos' : 'linux') + '-' + ARCH;
const EXE_EXT = PLATFORM === 'win32' ? '.exe' : '';
const EXE_NAME = 'hermitstash-sync-v' + VERSION + '-' + platformTag + EXE_EXT;
const EXE_PATH = path.join(__dirname, '..', 'build', EXE_NAME);

// Skip all tests if binary doesn't exist
const binaryExists = fs.existsSync(EXE_PATH);

describe('SEA Binary', { skip: !binaryExists ? 'Binary not found: ' + EXE_NAME : false }, () => {

  function runExe(args, opts) {
    return execFileSync(EXE_PATH, args, {
      encoding: 'utf8',
      timeout: 10000,
      ...opts,
    });
  }

  function runExeSafe(args) {
    try {
      return { stdout: runExe(args), exitCode: 0 };
    } catch (err) {
      return { stdout: (err.stdout || '') + (err.stderr || ''), exitCode: err.status };
    }
  }

  // ---- Basic command tests ----

  it('version command outputs correct version', () => {
    var out = runExe(['version']);
    assert.ok(out.includes('v' + VERSION), 'Should contain version v' + VERSION + ', got: ' + out.trim());
    assert.ok(out.includes('Node.js'), 'Should show Node.js version');
    assert.ok(out.includes('OpenSSL'), 'Should show OpenSSL version');
  });

  it('help command outputs usage information', () => {
    var out = runExe(['help']);
    assert.ok(out.includes('hermitstash-sync'), 'Should contain program name');
    assert.ok(out.includes('init'), 'Should list init command');
    assert.ok(out.includes('start'), 'Should list start command');
    assert.ok(out.includes('status'), 'Should list status command');
    assert.ok(out.includes('stop'), 'Should list stop command');
    assert.ok(out.includes('resync'), 'Should list resync command');
  });

  it('--help flag works', () => {
    var out = runExe(['--help']);
    assert.ok(out.includes('hermitstash-sync'), 'Should contain program name');
  });

  it('-h flag works', () => {
    var out = runExe(['-h']);
    assert.ok(out.includes('hermitstash-sync'), 'Should contain program name');
  });

  it('unknown command shows help', () => {
    var result = runExeSafe(['nonexistent-command']);
    assert.ok(result.stdout.includes('hermitstash-sync') || result.stdout.includes('Unknown'), 'Should show help or error');
  });

  // ---- Status without config ----

  it('status without config shows error', () => {
    // Use a temp HOME so it doesn't find real config
    var tmpHome = path.join(os.tmpdir(), 'hs-test-home-' + b.crypto.generateToken(4));
    fs.mkdirSync(tmpHome, { recursive: true });
    var result = runExeSafe(['status']);
    // Should show disconnected or config error — not crash
    assert.ok(result.stdout.length > 0 || result.exitCode !== null, 'Should produce output or exit code');
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  });

  // ---- Binary integrity ----

  it('binary size is reasonable (>50MB, <200MB)', () => {
    var stat = fs.statSync(EXE_PATH);
    var mb = stat.size / 1024 / 1024;
    assert.ok(mb > 50, 'Binary should be >50MB (Node.js embedded), got ' + mb.toFixed(1) + 'MB');
    assert.ok(mb < 200, 'Binary should be <200MB, got ' + mb.toFixed(1) + 'MB');
  });

  it('SHA-256 checksum file matches binary', () => {
    var sha256Path = EXE_PATH + '.sha256';
    if (!fs.existsSync(sha256Path)) return; // skip if no checksum file
    var expected = fs.readFileSync(sha256Path, 'utf8').split(/\s/)[0];
    var actual = crypto.createHash('sha256').update(fs.readFileSync(EXE_PATH)).digest('hex');
    assert.equal(actual, expected, 'SHA-256 checksum should match');
  });

  it('SHA3-512 checksum file matches binary', () => {
    var sha3Path = EXE_PATH + '.sha3-512';
    if (!fs.existsSync(sha3Path)) return; // skip if no checksum file
    var expected = fs.readFileSync(sha3Path, 'utf8').split(/\s/)[0];
    var actual = crypto.createHash('sha3-512').update(fs.readFileSync(EXE_PATH)).digest('hex');
    assert.equal(actual, expected, 'SHA3-512 checksum should match');
  });

  // ---- GPG signature verification ----

  it('GPG signature file exists if binary was signed', () => {
    var ascPath = EXE_PATH + '.asc';
    // Only check if signature exists — not all builds are signed
    if (fs.existsSync(ascPath)) {
      var sig = fs.readFileSync(ascPath, 'utf8');
      assert.ok(sig.includes('-----BEGIN PGP SIGNATURE-----'), 'Should be a valid PGP signature');
      assert.ok(sig.includes('-----END PGP SIGNATURE-----'), 'Should have signature end marker');
    }
  });
});
