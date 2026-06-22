'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const nodeFs = require('node:fs');
const nodeOs = require('node:os');
const nodePath = require('node:path');
const b = require('../vendor/blamejs');
const WsClient = require('../lib/ws-client');

/**
 * Since-aware reconnect contract + dial-URL coverage for lib/ws-client.js.
 *
 * The wrapper sets reconnect:false on b.wsClient and drives reconnect itself
 * for ONE reason: each redial must carry the latest applied `seq` so the
 * server's catch-up flow does not re-emit events the client already
 * processed. blamejs's built-in reconnect would re-use the original URL and
 * replay those events. These tests stub b.wsClient.connect with a transport
 * that CAPTURES the dial URL, so the `since` query param a redial actually
 * carries is observed — not just whether _closing/reconnecting fire.
 *
 * Self-contained (no server): run directly with
 *   node --test tests/test-ws-reconnect.js
 */

const WsClientError = b.wsClient.WsClientError;

// Stand up a production WsClient whose underlying b.wsClient.connect is
// replaced by a controllable peer-contract emitter that RECORDS every dial
// URL into `urls`. Returns the wrapper, the live stub, the captured-URL
// array, and a restore() to undo the monkeypatch.
//
// Each call to connect() returns a FRESH emitter so a redial after a 'close'
// gets its own transport (matching blamejs, which builds a new socket per
// dial). `stub` always references the most recent transport.
function withCapturingTransport(initialSince) {
  const realConnect = b.wsClient.connect;
  const urls = [];
  let stub = null;

  b.wsClient.connect = (url) => {
    urls.push(url);
    stub = new EventEmitter();
    stub.readyState = 'connecting';
    stub.send = () => {};
    stub.close = () => {};
    stub.cancelReconnect = () => {};
    return stub;
  };

  // reconnect enabled (omit reconnect:false) so a transient drop arms the
  // wrapper's own _scheduleReconnect. The host is never contacted — connect
  // is stubbed, so the dial is fully synthetic. RECONNECT_DELAYS[0] in
  // constants.js is short enough that the redial fires within the test window.
  const ws = new WsClient({ server: 'https://stub.invalid:443', reconnect: true }, 'hs_stub_key');
  ws.connect('stub-bundle', initialSince === undefined ? 0 : initialSince);

  return {
    ws,
    get stub() { return stub; },
    urls,
    restore() { b.wsClient.connect = realConnect; },
  };
}

// blamejs emits 'error' then 'close' on a socket failure; the wrapper decides
// terminality on 'error' and acts on 'close'. Replay that order against the
// CURRENT stub transport.
function driveError(stub, err) {
  stub.emit('error', err);
  stub.emit('close', 1006, err.message || 'error');
}

function waitForEvent(emitter, name, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${name}`)), timeoutMs);
    emitter.once(name, (...args) => { clearTimeout(timer); resolve(args); });
  });
}

function sinceParam(url) {
  // The wrapper builds .../sync/ws?bundleId=...&since=N — pull N back out.
  const m = /[?&]since=([^&]*)/.exec(url || '');
  return m ? decodeURIComponent(m[1]) : null;
}

describe('WsClient since-aware reconnect dials with the latest since', () => {

  it('initial dial carries the since passed to connect()', () => {
    const h = withCapturingTransport(0);
    try {
      assert.equal(h.urls.length, 1, 'connect() dials exactly once');
      assert.equal(sinceParam(h.urls[0]), '0', 'first dial carries since=0');
      assert.match(h.urls[0], /^wss:\/\/stub\.invalid\/sync\/ws\?/,
        'dial URL is the wss upgrade endpoint derived from the https server URL');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

  it('a transient drop redials, and the redial carries the since from connect()', async () => {
    const h = withCapturingTransport(7);
    try {
      h.ws.on('error', () => {}); // swallow the re-emitted transient 'error'
      const reconnectingP = waitForEvent(h.ws, 'reconnecting', 3000);

      // pong-timeout is the canonical transient: a dead peer the wrapper must
      // recover from with a fresh dial.
      driveError(h.stub, new WsClientError('ws-client/pong-timeout',
        'no pong received within 90000ms'));

      await reconnectingP;
      assert.equal(h.urls.length, 2, 'a transient drop schedules and fires a redial');
      assert.equal(sinceParam(h.urls[1]), '7',
        'the redial carries the since the client connected with');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

  it('updateSince() between dials is reflected in the redial URL', async () => {
    const h = withCapturingTransport(0);
    try {
      h.ws.on('error', () => {});
      assert.equal(sinceParam(h.urls[0]), '0', 'first dial is since=0');

      // The daemon applies events and advances the cursor while connected.
      h.ws.updateSince(42);

      const reconnectingP = waitForEvent(h.ws, 'reconnecting', 3000);
      driveError(h.stub, new WsClientError('ws-client/pong-timeout',
        'no pong received within 90000ms'));
      await reconnectingP;

      assert.equal(h.urls.length, 2, 'the drop fires a redial');
      assert.equal(sinceParam(h.urls[1]), '42',
        'the redial carries the LATEST applied seq, not the original since — ' +
        'this is the whole reason the wrapper drives reconnect itself');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

  it('a negative or non-integer since is clamped to 0 in the dial URL', () => {
    // A corrupt cursor must never produce since=<garbage> or a negative value
    // the server would treat as "replay everything". The wrapper clamps to 0
    // (full catch-up) rather than emitting an invalid param.
    for (const bad of [-1, 1.5, NaN, '5', null, undefined]) {
      const h = withCapturingTransport(0);
      try {
        h.ws.updateSince(bad);
        // Force a fresh dial so the clamp is observed in a URL. Drive a
        // transient drop synchronously and read the captured URL after the
        // reconnect timer fires.
        h.ws.on('error', () => {});
        // Re-dial directly via the private dialer so the assertion stays
        // synchronous and deterministic (no reliance on the reconnect timer).
        h.ws._dial();
        const last = h.urls[h.urls.length - 1];
        assert.equal(sinceParam(last), '0',
          `since=${String(bad)} must clamp to 0 in the dial URL, got ${sinceParam(last)}`);
      } finally {
        h.ws.close();
        h.restore();
      }
    }
  });

});

describe('WsClient SSRF-guard refusals are terminal, not a reconnect storm', () => {

  it('a cloud-metadata SSRF refusal stops reconnecting and surfaces upgrade_rejected', async () => {
    const h = withCapturingTransport(0);
    try {
      let reconnected = false;
      h.ws.on('reconnecting', () => { reconnected = true; });
      // The wrapper must NOT also emit a generic 'error' for an SSRF refusal —
      // the rejection path owns the operator signal. Fail loudly if it does.
      h.ws.on('error', (e) => {
        assert.fail('SSRF refusal must route through upgrade_rejected, not generic error: ' + (e && e.message));
      });

      const rejectedP = waitForEvent(h.ws, 'upgrade_rejected', 3000);
      const err = new WsClientError('ssrf-guard/blocked-cloud-metadata',
        "URL resolves to 169.254.169.254 (cloud-metadata) — blocked unconditionally");
      driveError(h.stub, err);

      const [info] = await rejectedP;
      assert.equal(info.status, 0,
        'an SSRF refusal has no HTTP exchange — synthetic status 0 maps to a sticky ERROR, not an auth retry');
      assert.match(info.body, /cloud-metadata/, 'the guard message is carried as the body');
      assert.equal(h.ws._closing, true,
        'an SSRF refusal is terminal — _closing must be set so reconnect is suppressed');

      // Give any erroneously-scheduled reconnect a beat to fire.
      await new Promise(r => setTimeout(r, 50));
      assert.equal(reconnected, false, 'a terminal SSRF refusal must NOT schedule a reconnect');
      assert.equal(h.urls.length, 1, 'no redial after a terminal SSRF refusal');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

  it('any ssrf-guard/* code (e.g. blocked-private) is treated as terminal', async () => {
    const h = withCapturingTransport(0);
    try {
      let reconnected = false;
      h.ws.on('reconnecting', () => { reconnected = true; });
      h.ws.on('error', () => { assert.fail('SSRF refusal must not emit generic error'); });

      const rejectedP = waitForEvent(h.ws, 'upgrade_rejected', 3000);
      driveError(h.stub, new WsClientError('ssrf-guard/blocked-private',
        'URL resolves to 10.0.0.5 in the private range'));

      await rejectedP;
      assert.equal(h.ws._closing, true, 'blocked-private is terminal');
      await new Promise(r => setTimeout(r, 50));
      assert.equal(reconnected, false, 'a terminal SSRF refusal must NOT reconnect');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

});

describe('WsClient refuses a symlinked mTLS cert/key/CA path', () => {

  // The private key is the highest-value secret the client holds. A planted
  // symlink at the configured key path would otherwise let an attacker with
  // write access to the cert directory substitute or exfiltrate key material
  // the daemon then presents to the server. fdSafeReadSync(refuseSymlink:true)
  // refuses to follow it. Symlink creation needs privilege on Windows (and
  // Developer Mode); skip the assertion if the OS refuses to create one.
  function makeSymlinkOrSkip(target, linkPath) {
    try {
      nodeFs.symlinkSync(target, linkPath);
      return true;
    } catch (e) {
      if (e && (e.code === 'EPERM' || e.code === 'ENOSYS' || e.code === 'EACCES')) return false;
      throw e;
    }
  }

  it('a symlinked private key is refused at construction (not followed)', (t) => {
    const dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-ws-mtls-'));
    try {
      const realKey = nodePath.join(dir, 'real-secret.key');
      nodeFs.writeFileSync(realKey, 'SECRET-KEY-MATERIAL', { mode: 0o600 });
      const linkKey = nodePath.join(dir, 'client.key');
      if (!makeSymlinkOrSkip(realKey, linkKey)) {
        t.skip('symlink creation not permitted on this host');
        return;
      }

      assert.throws(
        () => new WsClient({ server: 'https://stub.invalid', mtls: { key: linkKey } }, 'hs_stub_key'),
        /symlink/i,
        'constructing with a symlinked key path must throw rather than read the link target',
      );
    } finally {
      nodeFs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a regular-file private key reads normally', () => {
    const dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-ws-mtls-'));
    try {
      const keyPath = nodePath.join(dir, 'client.key');
      nodeFs.writeFileSync(keyPath, 'PEM-KEY-BYTES', { mode: 0o600 });
      const ws = new WsClient({ server: 'https://stub.invalid', mtls: { key: keyPath } }, 'hs_stub_key');
      assert.ok(Buffer.isBuffer(ws._cachedKey), 'a regular file is read into the cache as a Buffer');
      assert.equal(ws._cachedKey.toString('utf8'), 'PEM-KEY-BYTES',
        'the cached bytes match the on-disk file (byte-identical to the prior readFileSync)');
    } finally {
      nodeFs.rmSync(dir, { recursive: true, force: true });
    }
  });

});

describe('WsClient drops a late open that wins the race against close()', () => {

  it('an open that arrives after close() does not re-emit open', async () => {
    const h = withCapturingTransport(0);
    try {
      const stub = h.stub;
      let opened = false;
      h.ws.on('open', () => { opened = true; });

      // Consumer asks to close while the handshake is still connecting.
      h.ws.close();

      // The in-flight handshake completes and blamejs emits 'open' before its
      // deferred teardown fires.
      stub.emit('open');

      await new Promise(r => setTimeout(r, 20));
      assert.equal(opened, false,
        'an open after close() must be dropped — it would otherwise flip the engine back to CATCHING_UP');
    } finally {
      h.ws.close();
      h.restore();
    }
  });

});
