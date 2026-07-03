'use strict';

// Server-independent regression tests for three lib/ws-client.js defects,
// all driving the REAL production WsClient (and the REAL vendored b.wsClient
// wire layer) against a minimal loopback TCP server that speaks just enough
// RFC 6455 to complete a handshake. No HTTPS / mTLS / HermitStash harness —
// same posture as tests/test-ws-terminal-errors.js.
//
// Covers:
//   #13 close() teardown leak — close() must let b.wsClient's deferred
//       teardown run to completion (destroy the socket + stop the 30s ping
//       interval) instead of poisoning it with cancelReconnect(), AND must
//       not disturb the session a resync dials synchronously afterwards.
//   #14 message-after-close leak — a frame delivered while _closing is set
//       (the state a PQC-floor classical-TLS rejection leaves post-open)
//       must NOT reach consumers.
//   #15 non-4xx bad-status — a 200 / 3xx handshake response must fail closed
//       via upgrade_rejected{status} instead of reconnecting forever with no
//       operator-visible signal. 5xx must stay transient (availability guard).

const net = require('node:net');
const crypto = require('node:crypto');
const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');

const WsClient = require('../lib/ws-client');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'; // RFC 6455 §1.3

function sleep(ms) {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}

function computeAccept(secKey) {
  return crypto.createHash('sha1').update(secKey + WS_GUID).digest('base64');
}

// Unmasked server->client text frame (FIN=1, opcode 0x1). Payload assumed
// < 126 bytes so the 7-bit length field is used directly (RFC 6455 §5.2).
function encodeTextFrame(str) {
  const payload = Buffer.from(str, 'utf8');
  return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
}

// A loopback server that completes the RFC 6455 handshake for the first inbound
// request on each connection (computing the real Sec-WebSocket-Accept so blamejs
// reaches readyState 'open'), then leaves the socket open. When opts.coalescedFrame
// is set it is written in the SAME segment as the 101 response, so blamejs drains
// it via the _consumeHandshake -> _consumeFrames tail path (the #14 scenario).
function startWsHandshakeServer(opts) {
  opts = opts || {};
  const conns = [];
  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      conns.push(sock);
      let buf = Buffer.alloc(0);
      let handshaked = false;
      sock.on('data', (chunk) => {
        if (handshaked) return;
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        handshaked = true;
        const header = buf.subarray(0, idx).toString('utf8');
        let key = '';
        for (const line of header.split('\r\n')) {
          const m = /^sec-websocket-key:\s*(.+)$/i.exec(line);
          if (m) { key = m[1].trim(); break; }
        }
        const resp =
          'HTTP/1.1 101 Switching Protocols\r\n' +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          'Sec-WebSocket-Accept: ' + computeAccept(key) + '\r\n\r\n';
        let out = Buffer.from(resp, 'utf8');
        if (opts.coalescedFrame) out = Buffer.concat([out, opts.coalescedFrame]);
        try { sock.write(out); } catch { /* peer may have gone */ }
      });
      sock.on('error', () => { /* client teardown noise */ });
    });
    server.on('error', () => { /* ignore */ });
    server.listen(0, '127.0.0.1', () => {
      resolve({
        server,
        port: server.address().port,
        close() {
          for (const s of conns) { try { s.destroy(); } catch { /* ignore */ } }
          try { server.close(); } catch { /* ignore */ }
        },
      });
    });
  });
}

// A loopback server that, on the first inbound handshake bytes, writes back a
// fixed non-101 response and leaves the client to tear down. Mirrors
// tests/test-ws-terminal-errors.js#startFakeWsServer.
function startRawServer(responseBytes) {
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
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function openOnce(ws, trigger) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('WebSocket did not open within 3s')), 3000);
    ws.once('open', () => { clearTimeout(t); resolve(); });
    trigger();
  });
}

// Drive a single dial against a raw non-101 server and capture the wrapper's
// terminal signals. Mirrors tests/test-ws-terminal-errors.js#runDial.
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

describe('ws-client fix: close() teardown leak (#13)', () => {
  const servers = [];
  after(() => { for (const s of servers) { try { s.close(); } catch { /* ignore */ } } });

  it('close() lets the outgoing client fully tear down — socket destroyed, ping interval stopped', async () => {
    const srv = await startWsHandshakeServer({});
    servers.push(srv);
    const ws = new WsClient({ server: 'http://127.0.0.1:' + srv.port, reconnect: false }, 'k');
    await openOnce(ws, () => ws.connect('bundle', 0));

    const deadB = ws._b;
    assert.ok(deadB, 'internal b.wsClient is present after open');
    assert.notEqual(deadB._pingTimer, null, 'pre-close sanity: heartbeat interval started on open');

    ws.close();
    assert.equal(ws._b, null, 'wrapper drops its client reference on close');

    // Wait past b.wsClient's hardcoded 1s close grace window so the deferred
    // _teardown fires. With the bug it early-returned (poisoned by the wrapper's
    // cancelReconnect() setting _closed=true) and left the socket + interval alive.
    await sleep(1400);

    assert.equal(deadB._pingTimer, null, 'ping interval stopped by the completed teardown (leak fixed)');
    assert.ok(deadB._socket && deadB._socket.destroyed, 'underlying socket destroyed by the completed teardown');
  });

  it('close() + immediate connect() (resync) does not clobber the freshly-dialled session', async () => {
    const srv = await startWsHandshakeServer({});
    servers.push(srv);
    const ws = new WsClient({ server: 'http://127.0.0.1:' + srv.port, reconnect: false }, 'k');

    await openOnce(ws, () => ws.connect('bundle', 0));
    const b1 = ws._b;

    let closeEvents = 0;
    let reconnecting = 0;
    ws.on('close', () => { closeEvents += 1; });
    ws.on('reconnecting', () => { reconnecting += 1; });

    // Resync: close() then connect() synchronously, mirroring sync-engine._resyncOnce.
    ws.close();
    await openOnce(ws, () => ws.connect('bundle', 0));
    const b2 = ws._b;
    assert.notEqual(b1, b2, 'resync dialled a fresh client');

    // Wait past b1's 1s teardown grace so its late 'close'/'error' would fire
    // if the old client were still wired to the wrapper's handlers.
    await sleep(1400);

    assert.equal(ws._b, b2, 'the resynced client was NOT nulled by the retired client teardown');
    assert.equal(closeEvents, 0, 'no spurious wrapper close emitted after resync');
    assert.equal(reconnecting, 0, 'no spurious reconnect scheduled after resync');
    ws.close();
  });
});

describe('ws-client fix: message delivered after _closing is dropped (#14)', () => {
  const servers = [];
  after(() => { for (const s of servers) { try { s.close(); } catch { /* ignore */ } } });

  it('a frame drained after the wrapper set _closing (PQC-floor rejection state) is NOT delivered', async () => {
    const frame = encodeTextFrame('{"type":"heartbeat"}');
    const srv = await startWsHandshakeServer({ coalescedFrame: frame });
    servers.push(srv);
    const ws = new WsClient({ server: 'http://127.0.0.1:' + srv.port, reconnect: false }, 'k');

    let messages = 0;
    ws.on('message', () => { messages += 1; });
    // Reproduce the exact synchronous ordering of the bug: the wrapper 'open'
    // handler runs (here we set _closing, mirroring the classical-TLS-downgrade
    // rejection that sets it in production), then b.wsClient synchronously drains
    // the handshake-tail frame via _consumeFrames.
    ws.on('open', () => { ws._closing = true; });
    ws.connect('bundle', 0);

    await sleep(500);
    assert.equal(messages, 0, 'no message delivered over a connection the wrapper is tearing down');
    ws.close();
  });

  it('positive control: the same coalesced frame IS delivered on a live connection', async () => {
    const frame = encodeTextFrame('{"type":"heartbeat"}');
    const srv = await startWsHandshakeServer({ coalescedFrame: frame });
    servers.push(srv);
    const ws = new WsClient({ server: 'http://127.0.0.1:' + srv.port, reconnect: false }, 'k');

    const got = [];
    ws.on('message', (m) => { got.push(m); });
    ws.connect('bundle', 0);

    await sleep(500);
    assert.equal(got.length, 1, 'the frame is delivered when the wrapper is NOT closing (guard is the sole suppressor)');
    assert.equal(got[0] && got[0].type, 'heartbeat', 'the delivered message is the parsed server frame');
    ws.close();
  });
});

describe('ws-client fix: non-4xx bad-status fails closed (#15)', () => {
  let ok200;
  let redirect302;
  let unavailable503;

  it('setup fake servers', async () => {
    // Reverse proxy answering the Upgrade with a non-101 status instead of 101.
    ok200 = await startRawServer('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
    redirect302 = await startRawServer('HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n');
    unavailable503 = await startRawServer('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n');
  });

  after(() => {
    for (const s of [ok200, redirect302, unavailable503]) {
      if (s && s.server) { try { s.server.close(); } catch { /* ignore */ } }
    }
  });

  it('a 200 handshake response is terminal: upgrade_rejected{200}, fails closed, no infinite reconnect', async () => {
    // reconnect enabled so a mis-classification (the bug) would arm a reconnect
    // timer — the assertion below would then catch the silent-reconnect regression.
    const r = await runDial(ok200.port, {});
    assert.ok(r.upgradeRejected, 'a 200 upgrade response must surface upgrade_rejected');
    assert.equal(r.upgradeRejected.status, 200, 'the real 200 status is surfaced, not flattened to 0');
    assert.equal(r.closing, true, '_closing must be set so the close handler skips reconnect');
    assert.equal(r.reconnectTimerArmed, false, 'a 200 must NOT reconnect forever');
  });

  it('a 302 redirect handshake response is terminal: upgrade_rejected{302}, fails closed, no reconnect', async () => {
    const r = await runDial(redirect302.port, {});
    assert.ok(r.upgradeRejected, 'a 302 upgrade response must surface upgrade_rejected');
    assert.equal(r.upgradeRejected.status, 302, 'the real 302 status is surfaced');
    assert.equal(r.closing, true, '_closing must be set for a 3xx misconfiguration');
    assert.equal(r.reconnectTimerArmed, false, 'a 302 must NOT reconnect forever');
  });

  it('a 503 handshake response stays TRANSIENT — self-heals via reconnect (availability guard, no regression)', async () => {
    const r = await runDial(unavailable503.port, {});
    assert.equal(r.upgradeRejected, null, 'a 5xx must NOT emit upgrade_rejected (that would pin a sticky ERROR)');
    assert.equal(r.closing, false, '_closing must stay false so the close handler can reconnect');
    assert.equal(r.reconnectTimerArmed, true, 'a 5xx must self-heal by scheduling a reconnect');
  });
});
