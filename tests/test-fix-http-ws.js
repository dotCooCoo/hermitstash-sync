'use strict';

// Pure-unit regression tests for the http+ws lane audit fixes. No server
// harness, no network: every assertion drives a production method directly with
// fabricated sockets / streams / stubbed transports, mirroring the style of
// tests/test-unit-features.js. Run standalone:
//
//   node --test tests/test-fix-http-ws.js
//
// One describe block per finding id, each asserting the corrected behavior AND
// guarding against the old bug where feasible.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const { PassThrough } = require('node:stream');
const { EventEmitter } = require('node:events');

const logger = require('./../lib/logger');
const b = require('../vendor/blamejs');

// Quiet the structured logger so unit runs don't spew (the WS open handler and
// the PQC assertion both log).
logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-fix-httpws-' + process.pid + '.log') });

const HttpClient = require('../lib/http-client');
const WsClient = require('../lib/ws-client');

// A socket stub that reports a given negotiated TLS group and records whether
// destroy() was called.
function fakeTlsSocket(groupName) {
  const s = {
    destroyed: false,
    destroyErr: null,
    getEphemeralKeyInfo() { return groupName ? { name: groupName } : {}; },
    destroy(err) { this.destroyed = true; this.destroyErr = err || null; },
  };
  return s;
}

describe('http+ws#6 — WebSocket classical-TLS downgrade fails closed', () => {
  it('assertNegotiatedGroupPqc returns true AND destroys on an enforced classical group', () => {
    const sock = fakeTlsSocket('X25519');   // classical ECDH, no MLKEM
    const blocked = HttpClient.assertNegotiatedGroupPqc(sock, 'example.test', { enforce: true });
    assert.equal(blocked, true, 'enforced classical negotiation must report that it blocked the socket');
    assert.equal(sock.destroyed, true, 'the socket must be destroyed on the enforced floor violation');
    assert.ok(sock.destroyErr instanceof Error, 'destroy must carry an actionable error');
  });

  it('returns false (and does not destroy) for an ML-KEM hybrid group', () => {
    const sock = fakeTlsSocket('X25519MLKEM768');
    const blocked = HttpClient.assertNegotiatedGroupPqc(sock, 'example.test', { enforce: true });
    assert.equal(blocked, false, 'an at-floor hybrid is not a downgrade');
    assert.equal(sock.destroyed, false, 'an at-floor hybrid must never be destroyed');
  });

  it('returns false for the observe-only (enforce:false) path even on a classical group', () => {
    const sock = fakeTlsSocket('P-256');
    sock.destroy = () => { throw new Error('observe-only must not destroy'); };
    const blocked = HttpClient.assertNegotiatedGroupPqc(sock, 'example.test', { enforce: false });
    assert.equal(blocked, false, 'observe-only never blocks');
  });

  it('returns false for a missing / unreadable socket', () => {
    assert.equal(HttpClient.assertNegotiatedGroupPqc(null, 'h', { enforce: true }), false);
    assert.equal(HttpClient.assertNegotiatedGroupPqc({}, 'h', { enforce: true }), false);
  });

  it('WsClient does NOT emit open when the PQC floor enforcement destroyed the socket', () => {
    const origConnect = b.wsClient.connect;
    let fake;
    b.wsClient.connect = function () {
      fake = new EventEmitter();
      fake.readyState = 'connecting';
      fake.close = () => {};
      fake.cancelReconnect = () => {};
      return fake;
    };
    try {
      const ws = new WsClient({ server: 'https://localhost:8443', reconnect: true, tls: { rejectUnauthorized: false } }, 'apikey');
      let opened = false;
      ws.on('open', () => { opened = true; });
      ws.connect('bundle-1', 0);
      // Reset the backoff counter to a non-zero value so we can prove the fail-
      // closed path leaves it intact (does not run `this._reconnectAttempt = 0`).
      ws._reconnectAttempt = 3;
      // Classical group -> assertNegotiatedGroupPqc destroys + returns true.
      fake._socket = fakeTlsSocket('X25519');
      fake.emit('open');
      assert.equal(opened, false, 'a destroyed (downgraded) socket must NOT surface as a live channel');
      assert.equal(ws._reconnectAttempt, 3, 'backoff must NOT be reset on the fail-closed path');
    } finally {
      b.wsClient.connect = origConnect;
    }
  });

  it('WsClient DOES emit open on an at-floor (hybrid) socket', () => {
    const origConnect = b.wsClient.connect;
    let fake;
    b.wsClient.connect = function () {
      fake = new EventEmitter();
      fake.readyState = 'connecting';
      fake.close = () => {};
      fake.cancelReconnect = () => {};
      return fake;
    };
    try {
      const ws = new WsClient({ server: 'https://localhost:8443', reconnect: true, tls: { rejectUnauthorized: false } }, 'apikey');
      let opened = false;
      ws.on('open', () => { opened = true; });
      ws.connect('bundle-1', 0);
      ws._reconnectAttempt = 5;
      fake._socket = fakeTlsSocket('SecP384r1MLKEM1024');
      fake.emit('open');
      assert.equal(opened, true, 'an at-floor PQC negotiation must emit open');
      assert.equal(ws._reconnectAttempt, 0, 'a successful open resets the backoff counter');
    } finally {
      b.wsClient.connect = origConnect;
    }
  });
});

describe('http+ws#8 — getBundleMetadata fails closed on non-2xx', () => {
  function clientWithStub(respByCall) {
    const c = new HttpClient({ server: 'http://127.0.0.1:9' }, 'apikey');
    c._jsonRequest = async () => respByCall;
    return c;
  }

  it('returns the parsed body on a 200', async () => {
    const c = clientWithStub({ statusCode: 200, json: { files: [], totalSize: 0 } });
    const meta = await c.getBundleMetadata('share-1');
    assert.deepEqual(meta, { files: [], totalSize: 0 });
  });

  it('throws an actionable auth error on 401/403 (does NOT mask as empty bundle)', async () => {
    for (const status of [401, 403]) {
      const c = clientWithStub({ statusCode: status, json: { error: 'forbidden' } });
      await assert.rejects(
        () => c.getBundleMetadata('share-1'),
        (err) => {
          assert.match(err.message, new RegExp('HTTP ' + status));
          assert.match(err.message, /re-enroll|Re-enroll/);
          return true;
        },
        `HTTP ${status} must throw, not return an empty bundle`,
      );
    }
  });

  it('throws on a 404 JSON error body (no silent 0-files)', async () => {
    const c = clientWithStub({ statusCode: 404, json: { detail: 'no such bundle' } });
    await assert.rejects(() => c.getBundleMetadata('share-x'), /no such bundle/);
  });

  it('throws on a 409 JSON error body (the genuine fail-open case)', async () => {
    const c = clientWithStub({ statusCode: 409, json: { error: 'sync disabled' } });
    await assert.rejects(() => c.getBundleMetadata('share-x'), /sync disabled/);
  });

  it('throws on a 5xx with a non-JSON body (resp.json null)', async () => {
    const c = clientWithStub({ statusCode: 503, json: null });
    await assert.rejects(() => c.getBundleMetadata('share-x'), /HTTP 503/);
  });
});

describe('http+ws#9 — streaming transfers pin DNS through the SSRF guard', () => {
  it('_pinnedServerLookup returns a Node lookup pinned to the guard-validated IP', async () => {
    const c = new HttpClient({ server: 'http://127.0.0.1:9999' }, 'apikey');
    const lookup = await c._pinnedServerLookup();
    assert.equal(typeof lookup, 'function', 'a resolvable host must yield a pinned lookup');

    // options.all === true returns the full family list.
    await new Promise((resolve, reject) => {
      lookup('127.0.0.1', { all: true }, (err, addrs) => {
        try {
          assert.ifError(err);
          assert.ok(Array.isArray(addrs) && addrs.length >= 1);
          assert.equal(addrs[0].address, '127.0.0.1');
          assert.equal(addrs[0].family, 4);
          resolve();
        } catch (e) { reject(e); }
      });
    });

    // Single-address form (options omitted -> callback as 2nd arg).
    await new Promise((resolve, reject) => {
      lookup('127.0.0.1', (err, address, family) => {
        try {
          assert.ifError(err);
          assert.equal(address, '127.0.0.1');
          assert.equal(family, 4);
          resolve();
        } catch (e) { reject(e); }
      });
    });
  });

  it('_pinnedServerLookup re-throws (fails closed) on an SSRF-guard refusal', async () => {
    // 169.254.169.254 is the cloud-metadata IP — an UNCONDITIONAL hard-deny
    // that allowInternal:true does not override. The transfer must fail closed
    // rather than fall through to an unpinned connect the guard would block.
    const c = new HttpClient({ server: 'http://169.254.169.254' }, 'apikey');
    await assert.rejects(
      () => c._pinnedServerLookup(),
      (err) => {
        assert.ok(typeof err.code === 'string' && err.code.startsWith('ssrf-guard/'),
          'a guard refusal must surface with its ssrf-guard/* code, not be swallowed');
        return true;
      },
    );
  });

  it('the stale "builds multipart fully in memory" comment is gone from the transport JSDoc', () => {
    const src = require('node:fs').readFileSync(nodePath.join(__dirname, '..', 'lib', 'http-client.js'), 'utf8');
    assert.ok(!/builds multipart fully in memory/.test(src),
      'the stale blocker comment must be removed once the DNS pin is applied');
  });
});

describe('http+ws#10 — body collectors enforce a true byte cap', () => {
  it('collectTextBody resolves a body under the cap', async () => {
    const s = new PassThrough();
    const p = HttpClient.collectTextBody(s, 64);
    s.write(Buffer.from('hello world'));
    s.end();
    assert.equal(await p, 'hello world');
  });

  it('collectTextBody rejects (and destroys the stream) on a body over the BYTE cap', async () => {
    const s = new PassThrough();
    const p = HttpClient.collectTextBody(s, 10);
    s.write(Buffer.from('abcdefghijklmnopqrstuvwxyz'));   // 26 bytes > 10
    s.end();
    await assert.rejects(p, (err) => {
      assert.equal(err.code, 'buffer/too-large', 'overflow must surface the framework too-large code');
      return true;
    });
  });

  it('enforces a BYTE cap, not a UTF-16 code-unit cap (the old bug)', async () => {
    // 6 multibyte chars (each 3 UTF-8 bytes = 18 bytes) under a 10-char string
    // length but over a 10-BYTE cap. The old `body.length` guard counted code
    // units and would have accepted this; the byte cap must reject it.
    const s = new PassThrough();
    const p = HttpClient.collectTextBody(s, 10);
    s.write(Buffer.from('中文测试'));   // 4 CJK chars = 12 UTF-8 bytes, 4 code units
    s.end();
    await assert.rejects(p, /too-large|maxBytes/i,
      'a 12-byte / 4-code-unit body must trip a 10-byte cap');
  });
});
