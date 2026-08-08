'use strict';

// Unit tests for the post-quantum negotiated-group floor.
//
// lib/http-client.js#assertNegotiatedGroupPqc is the single enforcement
// point: it reads a TLS socket's negotiated key-exchange group via
// getEphemeralKeyInfo() and, on the HermitStash sync transport + WebSocket
// control channel, HARD-FAILS a classical fallback (destroys the socket).
// The auto-update GitHub-release downloader calls it OBSERVE-ONLY
// (enforce:false) — it logs a classical negotiation but never fails, since
// the release CDN legitimately offers no ML-KEM hybrid.
//
// node:tls reports getEphemeralKeyInfo() as a non-empty
// { name:'X25519', type:'ECDH' } for a CLASSICAL group and as {} (no name)
// for an ML-KEM hybrid. The tests drive synthetic sockets that stub
// getEphemeralKeyInfo() so we exercise the production assertion directly,
// without needing a server that can be coerced into a classical handshake.
//
// The escape hatch HERMITSTASH_ALLOW_CLASSICAL_TLS is read once at module
// load, so the case that flips it runs in a child process with the env var
// set, asserting the hard-fail downgrades to a non-fatal warning.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const { execFileSync } = require('node:child_process');

const logger = require('../lib/logger');
const HttpClient = require('../lib/http-client');

const REPO_ROOT = nodePath.resolve(__dirname, '..');

// Quiet the library logger — the assertion emits a WARN on every classical
// negotiation and we don't want it spewing into the test output.
logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-pqc-' + process.pid + '.log') });

// A synthetic TLS socket: stubs getEphemeralKeyInfo() to a fixed value and
// records destroy(err) so the test can assert whether enforcement fired.
function fakeSocket(keyInfo) {
  return {
    destroyed: false,
    destroyErr: null,
    getEphemeralKeyInfo() { return keyInfo; },
    once() { /* not used — we call the assertion directly */ },
    destroy(err) { this.destroyed = true; this.destroyErr = err || null; },
  };
}

const CLASSICAL = { name: 'X25519', type: 'ECDH' };
// Node 24.19+ reports an ML-KEM hybrid POSITIVELY as { type: 'TLSGroup', name }.
const HYBRID_TLSGROUP = { name: 'X25519MLKEM768', type: 'TLSGroup' };
const HYBRID_NAMED = { name: 'X25519MLKEM768' };    // name-only, still recognised
// An empty key-info no longer means "hybrid". Per the tls docs it means the key
// exchange was NOT EPHEMERAL — neither post-quantum nor forward-secret — so the
// floor refuses it under enforcement instead of reading it as a hybrid.
const NO_EPHEMERAL = {};

// Run the enforce:true assertion against a classical socket in a CHILD
// process so the module-level HERMITSTASH_ALLOW_CLASSICAL_TLS read happens
// fresh under the chosen env. The child quiets its logger to a temp file
// (stdout off) so the only thing on stdout is the DESTROYED / ALLOWED marker.
function _runChildAssertion(envOverlay) {
  const childSrc = [
    "const logger = require('./lib/logger');",
    "logger.init({ level: 'error', stdout: false, file: require('node:path').join(require('node:os').tmpdir(), 'hs-pqc-child-' + process.pid + '.log') });",
    "const HttpClient = require('./lib/http-client');",
    "let destroyed = false;",
    "const sock = {",
    "  getEphemeralKeyInfo() { return { name: 'X25519', type: 'ECDH' }; },",
    "  destroy() { destroyed = true; },",
    "};",
    "HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });",
    "process.stdout.write(destroyed ? 'DESTROYED' : 'ALLOWED');",
  ].join('\n');

  const env = Object.assign({}, process.env);
  for (const k in envOverlay) {
    if (k === '__delete_HERMITSTASH_ALLOW_CLASSICAL_TLS') { delete env.HERMITSTASH_ALLOW_CLASSICAL_TLS; continue; }
    env[k] = envOverlay[k];
  }

  return execFileSync(process.execPath, ['-e', childSrc], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env,
  }).trim();
}

describe('PQC floor — enforced sync transport (enforce:true, escape hatch OFF)', () => {
  it('hard-fails a classical negotiation by destroying the socket with an actionable error', () => {
    const sock = fakeSocket(CLASSICAL);
    HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });
    assert.equal(sock.destroyed, true, 'a classical group must destroy the socket');
    assert.ok(sock.destroyErr instanceof Error, 'destroy must carry an Error');
    const msg = sock.destroyErr.message;
    assert.match(msg, /classical TLS group X25519/, 'error names the negotiated group');
    assert.match(msg, /sync\.example\.test/, 'error names the server host');
    assert.match(msg, /HERMITSTASH_ALLOW_CLASSICAL_TLS=1/, 'error points at the documented override');
  });

  it('passes a hybrid reported as type TLSGroup (Node 24.19+ shape)', () => {
    const sock = fakeSocket(HYBRID_TLSGROUP);
    HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });
    assert.equal(sock.destroyed, false, 'a positively-identified hybrid must not fail');
  });

  it('REFUSES a non-ephemeral key exchange (empty key-info) under enforcement', () => {
    // Previously read as "hybrid, therefore fine" — a fail-open that a
    // non-post-quantum, non-forward-secret negotiation slipped through.
    const sock = fakeSocket(NO_EPHEMERAL);
    const blocked = HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });
    assert.equal(blocked, true, 'an unreported key exchange must be refused, not assumed post-quantum');
    assert.equal(sock.destroyed, true, 'the socket must be torn down');
    assert.match(String(sock.destroyErr && sock.destroyErr.message), /non-ephemeral|post-quantum/i,
      'the error must name why it was refused');
  });

  it('passes a hybrid negotiation reported with an MLKEM name', () => {
    const sock = fakeSocket(HYBRID_NAMED);
    HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });
    assert.equal(sock.destroyed, false, 'an MLKEM-named group must not fail');
  });

  it('does not throw when the socket cannot report a key info', () => {
    const sock = { destroyed: false, destroy() { this.destroyed = true; } };
    // No getEphemeralKeyInfo — best-effort path returns without touching the socket.
    HttpClient.assertNegotiatedGroupPqc(sock, 'sync.example.test', { enforce: true });
    assert.equal(sock.destroyed, false, 'a socket with no key-info reporter is left alone');
  });
});

describe('PQC floor — observe-only updater path (enforce:false)', () => {
  it('warns but does NOT fail on a classical negotiation', () => {
    const sock = fakeSocket(CLASSICAL);
    HttpClient.assertNegotiatedGroupPqc(sock, 'objects.githubusercontent.com', { enforce: false });
    assert.equal(sock.destroyed, false, 'the updater path must never destroy the socket on classical');
  });

  it('passes a hybrid negotiation without failing', () => {
    const sock = fakeSocket(HYBRID_TLSGROUP);
    HttpClient.assertNegotiatedGroupPqc(sock, 'objects.githubusercontent.com', { enforce: false });
    assert.equal(sock.destroyed, false);
  });
});

describe('PQC floor — escape hatch (HERMITSTASH_ALLOW_CLASSICAL_TLS=1)', () => {
  it('downgrades the enforced hard-fail to a non-fatal warning when set', () => {
    // The escape hatch is read once at module load, so flip it in a child
    // process. The child drives the production assertion with enforce:true on
    // a classical socket and prints whether the socket was destroyed.
    const out = _runChildAssertion({ HERMITSTASH_ALLOW_CLASSICAL_TLS: '1' });
    assert.equal(out, 'ALLOWED', 'with the escape hatch set, a classical group must NOT be hard-failed');
  });

  it('still hard-fails when the escape hatch is unset (control)', () => {
    const out = _runChildAssertion({ __delete_HERMITSTASH_ALLOW_CLASSICAL_TLS: true });
    assert.equal(out, 'DESTROYED', 'without the escape hatch, a classical group is hard-failed');
  });
});
