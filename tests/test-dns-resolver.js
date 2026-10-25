'use strict';
// Hostname resolution for the server and release hosts.
//   1. bin/hermitstash-sync.js switches blamejs to the operating system's
//      resolver at boot, so Docker service names, /etc/hosts entries and
//      LAN-only names resolve. An operator-set BLAMEJS_DNS_TRANSPORT is kept.
//   2. A dns/* failure on the WebSocket dial is not terminal: the wrapper
//      redials with backoff instead of stopping until a restart.
// Needs no HermitStash server.
//
// Run standalone:
//   node --test tests/test-dns-resolver.js
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const WsClient = require('../lib/ws-client');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'hermitstash-sync.js');
const MARKER = 'USE_SYSTEM_RESOLVER_CALLED';

// A preload that records whether boot calls b.network.dns.useSystemResolver().
// It loads the same vendor/blamejs module instance that bin/ requires.
function writePreload(dir) {
  const file = path.join(dir, 'record-resolver.js');
  fs.writeFileSync(file, [
    "'use strict';",
    'const dns = require(' + JSON.stringify(path.join(ROOT, 'vendor', 'blamejs')) + ').network.dns;',
    'const original = dns.useSystemResolver;',
    'dns.useSystemResolver = function () {',
    '  process.stdout.write(' + JSON.stringify(MARKER + '\n') + ');',
    '  return original.apply(this, arguments);',
    '};',
    '',
  ].join('\n'));
  return file;
}

function runVersion(preload, extraEnv) {
  const env = Object.assign({}, process.env, extraEnv);
  delete env.BLAMEJS_DNS_TRANSPORT;
  Object.assign(env, extraEnv);
  return spawnSync(process.execPath, ['--require', preload, BIN, 'version'], { env, encoding: 'utf8', timeout: 60_000 }); // allow:raw-byte-literal — test ceiling
}

describe('DNS resolver selected at boot', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-dns-resolver-'));
  const preload = writePreload(dir);
  process.on('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });

  it('uses the system resolver when BLAMEJS_DNS_TRANSPORT is not set', () => {
    const r = runVersion(preload, {});
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(MARKER));
    assert.match(r.stdout, /hermitstash-sync v\d+\.\d+\.\d+/);
  });

  it('keeps the transport the operator set in BLAMEJS_DNS_TRANSPORT', () => {
    const r = runVersion(preload, { BLAMEJS_DNS_TRANSPORT: 'doh' });
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stdout, new RegExp(MARKER));
  });
});

describe('WebSocket dial failures from DNS', () => {
  const ws = new WsClient({ server: 'https://sync.example.test' }, 'test-api-key');

  it('treats a dns/* failure as retryable even when the framework marks it permanent', () => {
    assert.equal(ws._isTerminalWsError({ code: 'dns/no-result', permanent: true }), false);
    assert.equal(ws._isTerminalWsError({ code: 'dns/doh-failed', permanent: false }), false);
  });

  it('still treats an outbound-URL guard refusal as terminal', () => {
    assert.equal(ws._isTerminalWsError({ code: 'ssrf-guard/blocked-cloud-metadata', permanent: true }), true);
  });
});
