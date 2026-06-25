'use strict';

// Server-independent regression test for the two WebSocket terminal-error
// behaviours in lib/ws-client.js. Exercises the REAL production WsClient against a plain
// loopback TCP server (no HTTPS, no mTLS certs, no HermitStash harness) that
// returns a non-101 handshake response, driving blamejs's async handshake-
// error classifier into the wrapper's 'error' handler.
//
// What this pins:
//   1. A terminal handshake failure with no HTTP status (bad-status-line) now
//      routes through emit('upgrade_rejected', { status: 0 }) — the new async
//      branch — instead of the generic emit('error'). It must set _closing,
//      must NOT arm a reconnect, and must NOT also emit 'error'.
//   2. A 4xx handshake rejection (bad-status) still emits upgrade_rejected with
//      the real status and fails closed (regression guard on the pre-existing
//      bad-status path).
//   3. A 5xx handshake rejection stays TRANSIENT: no upgrade_rejected, _closing
//      stays false, the wrapper self-heals by arming a reconnect. This is the
//      availability path the fix must not break.

const net = require('node:net');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const WsClient = require('../lib/ws-client');

// A loopback TCP server that, on the first inbound handshake bytes, writes back
// `responseBytes` and then leaves the socket for the client to tear down.
function startFakeWsServer(responseBytes) {
  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      let answered = false;
      sock.on('data', () => {
        if (answered) return;
        answered = true;
        try { sock.write(responseBytes); } catch { /* peer may have gone */ }
      });
      sock.on('error', () => { /* client teardown noise */ });
    });
    server.on('error', () => { /* ignore */ });
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port });
    });
  });
}

// Drive a single dial against a fake server and capture the wrapper's emitted
// terminal signals. Resolves after the handshake has had time to fail.
function runDial(port, config) {
  return new Promise((resolve) => {
    const ws = new WsClient(Object.assign({ server: 'http://127.0.0.1:' + port }, config), 'test-api-key');
    const captured = { upgradeRejected: null, errorEmitted: false, reconnecting: false };
    ws.on('upgrade_rejected', (info) => { if (!captured.upgradeRejected) captured.upgradeRejected = info; });
    ws.on('error', () => { captured.errorEmitted = true; });
    ws.on('reconnecting', () => { captured.reconnecting = true; });
    ws.connect('bundle-test', 0);
    setTimeout(() => {
      captured.closing = ws._closing;
      captured.reconnectTimerArmed = ws._reconnectTimer !== null || captured.reconnecting;
      try { ws.close(); } catch { /* idempotent */ }
      resolve(captured);
    }, 400);
  });
}

describe('ws-client terminal-error routing (server-independent)', () => {
  let badStatusLine, notFound, unavailable;

  before(async () => {
    // Malformed status line -> ws-client/bad-status-line (terminal, no HTTP status).
    badStatusLine = await startFakeWsServer('GARBAGE NOT HTTP\r\n\r\n');
    // 4xx handshake rejection -> ws-client/bad-status, status 404 (terminal).
    notFound = await startFakeWsServer('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n');
    // 5xx handshake rejection -> ws-client/bad-status, status 503 (TRANSIENT).
    unavailable = await startFakeWsServer('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n');
  });

  after(() => {
    for (const s of [badStatusLine, notFound, unavailable]) {
      if (s && s.server) { try { s.server.close(); } catch { /* ignore */ } }
    }
  });

  it('routes a status-less terminal handshake failure through upgrade_rejected{status:0}, fails closed, no reconnect', async () => {
    const r = await runDial(badStatusLine.port, { reconnect: false });
    assert.ok(r.upgradeRejected, 'expected an upgrade_rejected emission');
    assert.equal(r.upgradeRejected.status, 0, 'status must be the synthetic 0 for a status-less terminal failure');
    assert.equal(typeof r.upgradeRejected.body, 'string');
    assert.ok(r.upgradeRejected.body.length > 0, 'body should carry the framework error message');
    assert.equal(r.errorEmitted, false, 'must NOT also emit a generic error (rejection path owns the terminal signal)');
    assert.equal(r.closing, true, '_closing must be set so the close handler skips reconnect');
    assert.equal(r.reconnectTimerArmed, false, 'no reconnect may be armed for a terminal failure');
  });

  it('still emits upgrade_rejected with the real status for a 4xx handshake rejection (no regression)', async () => {
    const r = await runDial(notFound.port, { reconnect: false });
    assert.ok(r.upgradeRejected, 'expected an upgrade_rejected emission');
    assert.equal(r.upgradeRejected.status, 404, '4xx status must be surfaced, not flattened to 0');
    assert.equal(r.errorEmitted, false, 'a 4xx rejection must not also emit a generic error');
    assert.equal(r.closing, true, 'a 4xx handshake rejection fails closed');
    assert.equal(r.reconnectTimerArmed, false, 'a 4xx handshake rejection does not reconnect');
  });

  it('keeps a 5xx handshake rejection TRANSIENT — no upgrade_rejected, self-heals via reconnect (availability guard)', async () => {
    // reconnect left enabled (omit reconnect:false) so the wrapper arms its timer.
    const r = await runDial(unavailable.port, {});
    assert.equal(r.upgradeRejected, null, 'a 5xx must NOT emit upgrade_rejected (that would pin a sticky ERROR)');
    assert.equal(r.closing, false, '_closing must stay false so the close handler can reconnect');
    assert.equal(r.reconnectTimerArmed, true, 'a 5xx must self-heal by scheduling a reconnect');
  });
});
