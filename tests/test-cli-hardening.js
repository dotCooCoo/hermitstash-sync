'use strict';

/**
 * Hardening tests for the CLI + config surface that do not need a running
 * server: config-load validation, env-overlay semantics, and enrollment-URL
 * parsing. These exercise the production lib modules directly.
 *
 * The config-load cases run in a child process because lib/constants.js reads
 * HERMITSTASH_SYNC_CONFIG_DIR once at module-load time — a fresh child with the
 * env pointed at a temp dir is the only way to redirect CONFIG_FILE per case
 * without poisoning the parent's module cache.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');

// Write a config.json into a fresh temp CONFIG_DIR and run a snippet against
// the production config lib with that dir active. Returns { stdout } or throws
// with the child's stderr attached so an assertion failure is legible.
function runWithConfig(configObj, env, snippet) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-cli-hardening-'));
  try {
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(configObj));
    const childEnv = Object.assign({}, process.env, { HERMITSTASH_SYNC_CONFIG_DIR: dir }, env || {});
    const out = execFileSync(process.execPath, ['-e', snippet], {
      cwd: REPO_ROOT,
      env: childEnv,
      encoding: 'utf8',
    });
    return { stdout: out };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('config.load() + validate() env-overlay hardening', () => {

  it('flags an invalid env-overlaid value with an actionable, env-named error', () => {
    // A container operator sets a bad concurrency via env; the error must name
    // the env var, not the config field they never touched.
    const { stdout } = runWithConfig(
      { server: 'https://example.com', syncFolder: os.tmpdir(), bundleId: 'b1' },
      { HERMITSTASH_UPLOAD_CONCURRENCY: '-5' },
      "const c = require('./lib/config'); const cfg = c.load(); const errs = c.validate(cfg); process.stdout.write(JSON.stringify(errs));",
    );
    const errs = JSON.parse(stdout);
    assert.ok(Array.isArray(errs) && errs.length > 0, 'validate should report at least one error');
    const named = errs.find(e => e.includes('HERMITSTASH_UPLOAD_CONCURRENCY'));
    assert.ok(named, 'error should name the env var, got: ' + JSON.stringify(errs));
    assert.ok(/non-negative integer/.test(named), 'error should describe the constraint: ' + named);
  });

  it('empty HERMITSTASH_PINNED_SERVER_SPKI does NOT clear configured pins', () => {
    const pin = 'sha256/' + 'A'.repeat(43) + '=';
    const { stdout } = runWithConfig(
      { server: 'https://example.com', syncFolder: os.tmpdir(), bundleId: 'b1', pinnedServerSpki: [pin] },
      { HERMITSTASH_PINNED_SERVER_SPKI: '' },
      "const c = require('./lib/config'); process.stdout.write(JSON.stringify(c.load().pinnedServerSpki));",
    );
    const pins = JSON.parse(stdout);
    assert.deepEqual(pins, [pin], 'empty env var must preserve config.json pins, not clear them');
  });

  it('whitespace-only HERMITSTASH_INCLUDE does NOT clear the selective-sync allowlist', () => {
    const { stdout } = runWithConfig(
      { server: 'https://example.com', syncFolder: os.tmpdir(), bundleId: 'b1', include: ['docs/'] },
      { HERMITSTASH_INCLUDE: '   ' },
      "const c = require('./lib/config'); process.stdout.write(JSON.stringify(c.load().include));",
    );
    const include = JSON.parse(stdout);
    assert.deepEqual(include, ['docs/'], 'whitespace-only env var must preserve the allowlist');
  });

  it('a non-empty HERMITSTASH_PINNED_SERVER_SPKI still overlays config.json', () => {
    const envPin = 'sha256/' + 'B'.repeat(43) + '=';
    const { stdout } = runWithConfig(
      { server: 'https://example.com', syncFolder: os.tmpdir(), bundleId: 'b1', pinnedServerSpki: ['sha256/' + 'A'.repeat(43) + '='] },
      { HERMITSTASH_PINNED_SERVER_SPKI: envPin },
      "const c = require('./lib/config'); process.stdout.write(JSON.stringify(c.load().pinnedServerSpki));",
    );
    assert.deepEqual(JSON.parse(stdout), [envPin], 'a real env value should still override');
  });
});

describe('enrollment URL parsing', () => {

  it('accepts an http:// enrollment origin (cleartext opt-in)', () => {
    // F22 regression: the parse must use { allowedProtocols } so the
    // ALLOW_HTTP_ALL preset takes effect and http:// is not rejected.
    const b = require('../vendor/blamejs');
    const parsed = b.safeUrl.parse('http://hermit.local:8080', { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL });
    assert.equal(parsed.protocol, 'http:');
    assert.equal(parsed.host, 'hermit.local:8080');
  });

  it('still accepts https:// enrollment origins', () => {
    const b = require('../vendor/blamejs');
    const parsed = b.safeUrl.parse('https://hermitstash.example', { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL });
    assert.equal(parsed.protocol, 'https:');
  });

  it('cmdInitFromEnv reaches the request stage for an http:// server (parse does not reject)', () => {
    // Drive the real cmdInitFromEnv with an http:// server and an unreachable
    // host. The init must FAIL past URL parsing — a connection/HTTP error, not
    // a "protocol-disallowed" / "not a valid URL" parse rejection. A reserved
    // TEST-NET-1 address (RFC 5737) guarantees no real listener.
    let exitCode = 0;
    let stderr = '';
    try {
      execFileSync(process.execPath, ['-e',
        "const cli = require('./lib/cli'); cli.run(['init','--non-interactive']).catch(()=>process.exit(7));",
      ], {
        cwd: REPO_ROOT,
        env: Object.assign({}, process.env, {
          HERMITSTASH_SERVER_URL: 'http://192.0.2.1:9',
          HERMITSTASH_ENROLLMENT_CODE: 'HSTASH-TEST-TEST-TEST',
          HERMITSTASH_SYNC_FOLDER: fs.mkdtempSync(path.join(os.tmpdir(), 'hs-init-folder-')),
          HERMITSTASH_NTP_DISABLE: '1',
        }),
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 30000,
      });
    } catch (err) {
      exitCode = err.status || 1;
      stderr = (err.stderr || '') + (err.stdout || '');
    }
    // The command should fail (no reachable server), but NOT because http://
    // was rejected at parse. Assert the failure is a transport/HTTP failure.
    assert.notEqual(exitCode, 0, 'init against an unreachable http server should fail');
    assert.ok(
      !/not a valid url|protocol-disallowed|safe-url\/protocol/i.test(stderr),
      'failure must not be an http:// parse rejection, got: ' + stderr.slice(0, 400),
    );
  });
});
