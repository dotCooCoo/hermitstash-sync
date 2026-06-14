'use strict';

/**
 * Thin wrapper around blamejs `b.wsClient.connect()`.
 *
 * Delegates the entire RFC 6455 wire layer — handshake, frame parsing,
 * masking, control-frame validation, permessage-deflate negotiation +
 * decompression-bomb defence (`zlib.inflateRawSync` with maxOutputLength),
 * UTF-8 fatal validation on text + close-reason, RSV1-on-continuation
 * rejection, control-frame ≤125-byte cap + FIN=1 enforcement, permanent-
 * vs-transient error classifier, TLSv1.3 pin — to blamejs. The handshake
 * GUID is the framework default (the RFC 6455 §1.3 standard
 * `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`), since `hermitstash-private`
 * has migrated to the standard GUID; no `handshakeGuid` opt needed.
 *
 * What we still layer on top:
 *
 *   - `since`-aware reconnect: each reconnect must dial with the latest
 *     applied `seq` so the server's catch-up flow doesn't re-emit events
 *     the client has already processed. blamejs's built-in reconnect
 *     re-uses the original URL, so we set `reconnect: false` and drive
 *     reconnects ourselves — re-running connect(bundleId, this._since)
 *     with the freshly-updated `since`.
 *
 * Public surface preserved (sync-engine.js + tests rely on it):
 *   constructor(config, apiKey)
 *   connect(bundleId, since=0)
 *   send(obj)              -> bool
 *   updateSince(seq)       -> void
 *   reloadMtlsCerts()      -> void
 *   close()                -> void
 *
 * Events: open, message (parsed JSON object), close, error,
 *         reconnecting (attempt#), upgrade_rejected ({status, body}),
 *         auth_error ({status, body}).
 */

const nodeFs = require('node:fs');
const nodeNet = require('node:net');
const { EventEmitter } = require('node:events');
const { VERSION, RECONNECT_DELAYS, HEARTBEAT_TIMEOUT_MS, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
const log = require('./logger');
const metrics = require('./metrics');

const b = require('../vendor/blamejs');

const C = b.constants;

// Cap on JSON message bodies we'll accept on the wire. blamejs already
// caps at 8 MiB by default; pin it explicitly so a server-side bump
// doesn't silently widen the client's exposure.
const MAX_MESSAGE_BYTES = C.BYTES.mib(8);
// allow:raw-byte-literal — RFC 6455 §7.4.1 close code "normal closure", protocol literal not a byte size
const WS_NORMAL_CLOSE = 1000;
const WS_LOG_PREVIEW_CHARS = 200; // truncation cap for malformed-JSON debug logging

// Codes that no amount of redialling will fix: a bad URL, a server that
// isn't speaking the WebSocket handshake, or a credentialed 4xx rejection.
// For these we suppress reconnect so the daemon doesn't hammer the server.
//
// blamejs constructs every WsClientError as `alwaysPermanent`, so its
// `err.permanent` flag is true for transient drops too — including the
// pong-timeout the heartbeat fires when a peer goes silent, which is
// precisely the signal that SHOULD trigger a fresh dial. We therefore
// classify terminality from the error code ourselves rather than trusting
// that flag. `ws-client/bad-status` is conditionally terminal: only a 4xx
// handshake rejection is hopeless; 5xx and everything unlisted (protocol /
// UTF-8 / decompression drops, pong-timeout, handshake-timeout) are treated
// as transient because a reconnect recovers them.
const WS_TERMINAL_CODES = new Set([
  'ws-client/bad-url',
  'ws-client/accept-mismatch',
  'ws-client/bad-upgrade',
  'ws-client/bad-status-line',
  'ws-client/bad-subprotocol',
  'ws-client/bad-header',
]);

// Pull the HTTP status out of a blamejs ws-client error. bad-status carries
// it directly on `err.status`; fall back to parsing the message tail
// ("handshake response status was N ...") for resilience against a future
// wire-format tweak.
function _wsErrorStatus(err) {
  if (err && Number.isInteger(err.status)) return err.status;
  const m = /status was (\d+)/.exec((err && err.message) || '');
  return m ? parseInt(m[1], 10) : 0;
}

// Decide whether a ws-client error permanently rules out reconnect.
function _isTerminalWsError(err) {
  const code = err && err.code;
  if (!code) return false;
  if (WS_TERMINAL_CODES.has(code)) return true;
  // bad-status is terminal only for a 4xx handshake rejection; a 5xx is a
  // server-side blip a reconnect can ride out.
  if (code === 'ws-client/bad-status') {
    const status = _wsErrorStatus(err);
    return status >= 400 && status < 500;
  }
  return false;
}

// PQC group preference + TLS-1.3 pin — pass through to blamejs's tlsOpts.
// blamejs already enforces TLSv1.3 inside ws-client; we additionally
// supply the curve preference so the ClientHello advertises the
// HermitStash server's expected PQC groups before any blamejs default
// would override.
function _pqcTlsOpts(extra) {
  return Object.assign({
    ecdhCurve: TLS_GROUPS,
    groups:    TLS_GROUPS,
    minVersion: TLS_MIN_VERSION,
  }, extra || {});
}

class WsClient extends EventEmitter {
  constructor(config, apiKey) {
    super();
    this._config = config;
    this._apiKey = apiKey;
    this._b = null;             // active b.wsClient instance, if any
    this._bundleId = null;
    this._since = 0;
    this._closing = false;
    this._reconnectAttempt = 0;
    this._reconnectTimer = null;

    // Cache mTLS material on construction so reconnects don't re-read disk.
    this._cachedCert = null;
    this._cachedKey  = null;
    this._cachedCa   = null;
    if (config.mtls) {
      if (config.mtls.cert) this._cachedCert = nodeFs.readFileSync(config.mtls.cert);
      if (config.mtls.key)  this._cachedKey  = nodeFs.readFileSync(config.mtls.key);
      if (config.mtls.ca)   this._cachedCa   = nodeFs.readFileSync(config.mtls.ca);
    }
  }

  connect(bundleId, since = 0) {
    this._bundleId = bundleId;
    this._since = since;
    this._closing = false;
    this._dial();
  }

  send(obj) {
    if (!this._b || this._b.readyState !== 'open') {
      log.warn('Cannot send — not connected');
      return false;
    }
    try {
      // b.wsClient.send accepts string|Buffer|object — JSON.stringifies
      // objects internally with the same UTF-8 encoding we used before.
      this._b.send(obj);
      return true;
    } catch (err) {
      log.error('Failed to send WebSocket frame', err);
      return false;
    }
  }

  // Test-only escape hatch — sends a raw frame at the chosen opcode.
  // tests/test-websocket.js's "malformed JSON message is handled without
  // crashing" case feeds an invalid-JSON TEXT frame this way to verify
  // the receive parser doesn't bring down the connection. Production code
  // should always use send().
  _sendFrame(opcode, payload) {
    if (!this._b || this._b.readyState !== 'open') return;
    const TEXT = 0x01, BINARY = 0x02;
    if (opcode === TEXT) {
      this._b.send(Buffer.isBuffer(payload) ? payload.toString('utf8') : String(payload));
    } else if (opcode === BINARY) {
      this._b.send(Buffer.isBuffer(payload) ? payload : Buffer.from(payload));
    }
  }

  updateSince(seq) {
    this._since = seq;
  }

  reloadMtlsCerts() {
    if (!this._config.mtls) return;
    try {
      if (this._config.mtls.cert) this._cachedCert = nodeFs.readFileSync(this._config.mtls.cert);
      if (this._config.mtls.key)  this._cachedKey  = nodeFs.readFileSync(this._config.mtls.key);
      if (this._config.mtls.ca)   this._cachedCa   = nodeFs.readFileSync(this._config.mtls.ca);
      log.info('mTLS cert cache reloaded from disk');
    } catch (err) {
      log.error('Failed to reload mTLS certs', err);
    }
  }

  close() {
    this._closing = true;
    this._cancelReconnectTimer();
    if (this._b) {
      // allow:silent-catch — graceful close on an already-half-closed socket is fine; the b.wsClient destructor finalises regardless
      try { this._b.close(WS_NORMAL_CLOSE, 'client-close'); } catch (_e) {}
      // allow:silent-catch — cancelReconnect is a no-op when reconnect already disarmed
      try { this._b.cancelReconnect(); } catch (_e) {}
      this._b = null;
    }
  }

  _dial() {
    const serverUrl = b.safeUrl.parse(this._config.server, { allowedProtocols: ['http:', 'https:'] });
    const isHttps = serverUrl.protocol === 'https:';
    const wsScheme = isHttps ? 'wss:' : 'ws:';
    const since = (Number.isInteger(this._since) && this._since >= 0) ? this._since : 0;
    const wsUrl = `${wsScheme}//${serverUrl.host}/sync/ws?` +
                  `bundleId=${encodeURIComponent(this._bundleId)}&since=${encodeURIComponent(String(since))}`;

    // Node refuses SNI when the host is an IP literal (RFC 6066 §3). blamejs
    // defaults `servername: host`, so override with undefined when dialling
    // an IP — leaves SNI unset, which Node accepts.
    const sni = nodeNet.isIP(serverUrl.hostname) ? undefined : serverUrl.hostname;

    // Build a CA bundle that ADDS the mTLS CA to system roots + any
    // NODE_EXTRA_CA_CERTS file — passing `ca` to Node TLS otherwise
    // REPLACES the trust store, which breaks server-cert validation
    // for production deployments served via Let's Encrypt or system
    // CAs. HttpClient.buildCaBundle owns the bundling so both
    // transports stay in lockstep.
    const HttpClient = require('./http-client');                                // allow:inline-require — avoids circular load order with the wrapper; cold path
    // SPKI pinning when config.pinnedServerSpki is set — runs on top
    // of the default chain + hostname checks.
    const pinCheck = HttpClient.buildCheckServerIdentity(this._config.pinnedServerSpki);
    const assertPqcGroup = HttpClient.assertNegotiatedGroupPqc;
    const wsHost = serverUrl.hostname;
    const tlsOpts = isHttps ? _pqcTlsOpts({
      cert: this._cachedCert || undefined,
      key:  this._cachedKey  || undefined,
      ca:   this._cachedCa ? HttpClient.buildCaBundle(this._cachedCa) : undefined,
      servername: sni,
      ...(pinCheck ? { checkServerIdentity: pinCheck } : {}),
      // Tests pass { rejectUnauthorized: false } on this._config.tls so a
      // self-signed test CA is accepted at the TLS layer. Production
      // leaves it unset → blamejs's default rejectUnauthorized:true wins.
      ...((this._config.tls) || {}),
    }) : null;

    log.debug('WebSocket connecting', { url: wsUrl });

    let client;
    try {
      client = b.wsClient.connect(wsUrl, {
        headers: {
          'Authorization': `Bearer ${this._apiKey}`,
          'User-Agent':    `hermitstash-sync/${VERSION}`,
        },
        tlsOpts:           tlsOpts,
        // The user explicitly configured this server URL, so blamejs's
        // default SSRF gate (which would block 127.0.0.1, 10.x, etc.)
        // doesn't apply — same posture as our http-client.js sync paths.
        // The gate's value here is closing the DNS-rebinding TOCTOU
        // window on the resolved host.
        allowInternal:     true,
        // handshakeGuid omitted — server uses the RFC 6455 §1.3 standard
        // GUID, which is also blamejs's default.
        // Server pings every 30s; the client allows 90s (= 3 missed
        // heartbeats) before treating the connection as dead and
        // reconnecting. See HEARTBEAT_TIMEOUT_MS in lib/constants.js.
        pingMs:            C.TIME.seconds(30),
        pongMs:            HEARTBEAT_TIMEOUT_MS,
        maxMessageBytes:   MAX_MESSAGE_BYTES,
        // We drive reconnect ourselves so each redial picks up the latest
        // `since` value (blamejs's built-in reconnect re-uses the original
        // URL, which would replay events the client has already processed).
        reconnect:         false,
        // No audit subsystem in the CLI; suppress safeEmit calls.
        audit:             false,
        permessageDeflate: true,
      });
    } catch (err) {
      log.error('WebSocket connect threw at config time', err);
      this.emit('error', err);
      if (!this._closing) this._scheduleReconnect();
      return;
    }

    this._b = client;

    client.on('open', () => {
      // Post-handshake post-quantum floor enforcement for the control
      // channel. b.wsClient owns the raw TLS socket (it dials via
      // tls.connect, not the HTTPS agent), so the agent-level assertion in
      // http-client can't reach it — we read the negotiated group off the
      // exposed socket here instead. By 'open' the TLS handshake and the WS
      // upgrade are both complete, so getEphemeralKeyInfo() reports the
      // settled key exchange. A classical negotiation destroys the socket
      // (enforce: true) unless HERMITSTASH_ALLOW_CLASSICAL_TLS is set; either
      // way the downgrade is logged. Plain ws: (test/loopback) has no TLS
      // socket and is skipped.
      if (isHttps && client._socket && typeof assertPqcGroup === 'function') {
        assertPqcGroup(client._socket, wsHost, { enforce: true });
      }
      this._reconnectAttempt = 0;
      log.info('WebSocket connected');
      this.emit('open');
    });

    client.on('message', (data, isBinary) => {
      // Server frames are JSON text. safeJson.parse applies size + depth
      // + prototype-pollution caps on the untrusted server body. Log
      // preview truncates at WS_LOG_PREVIEW_CHARS on parse failure.
      if (isBinary) {
        log.warn('Unexpected binary frame from server');
        return;
      }
      let msg;
      try {
        msg = b.safeJson.parse(data, { maxBytes: MAX_MESSAGE_BYTES });
      } catch (err) {
        log.warn('Invalid JSON from server', { err: err.message, head: String(data).slice(0, WS_LOG_PREVIEW_CHARS) });
        return;
      }
      this.emit('message', msg);
    });

    client.on('close', (code, reason) => {
      log.info('WebSocket closed', { code, reason });
      this._b = null;
      this.emit('close', code, reason);
      if (!this._closing) this._scheduleReconnect();
    });

    client.on('error', (err) => {
      // Once we've initiated close, swallow follow-up socket errors
      // (ECONNRESET from the server tearing down its end after a 4xx, etc.)
      // — they're noise, not actionable, and would otherwise become
      // uncaughtException for any consumer that already detached its
      // .once('error') listener. Check _closing BEFORE we set it on this
      // error so the very first permanent error still gets surfaced.
      if (this._closing) {
        log.debug('WebSocket post-close error (swallowed)', { code: err && err.code, msg: err && err.message });
        return;
      }
      // Suppress our own reconnect (before the close handler fires) only
      // for genuinely terminal failures — a bad URL, a non-WebSocket peer,
      // or a 4xx handshake rejection. Transient drops, including the
      // pong-timeout / handshake-timeout that signal a dead peer, fall
      // through to the close handler's reconnect path so a fresh dial can
      // recover. See _isTerminalWsError for why we don't trust
      // err.permanent (blamejs marks every error permanent).
      if (_isTerminalWsError(err)) {
        this._closing = true;
      }
      const code = err && err.code;
      if (code === 'ws-client/bad-status') {
        // blamejs's bad-status message is "handshake response status was
        // N (expected 101 Switching Protocols)" — recover N so the
        // upgrade_rejected listener sees the real HTTP status code.
        const status = _wsErrorStatus(err);
        // Match the legacy contract: handshake-rejection paths emit
        // upgrade_rejected (+ auth_error for 401/403) and DO NOT also
        // emit a generic 'error' — consumers wire the rejection paths
        // separately from socket errors.
        //
        // Only a TERMINAL bad-status (4xx) emits upgrade_rejected — the
        // engine treats a non-4xx upgrade_rejected as PERMANENT ("restart
        // the daemon"), which contradicts the self-healing reconnect a 5xx
        // takes (for a 5xx, _closing stays false and the close handler
        // reconnects). A non-terminal 5xx therefore stays silent here and
        // is handled entirely by the close+reconnect path.
        if (_isTerminalWsError(err)) {
          this.emit('upgrade_rejected', { status, body: err.message || '' });
          if (status === 401 || status === 403) {
            metrics.record.authError();
            this.emit('auth_error', { status, body: err.message || '' });
          }
        }
        return;
      }
      log.error('WebSocket error', err);
      this.emit('error', err);
    });
  }

  _scheduleReconnect() {
    if (this._closing) return;
    if (this._config.reconnect === false) return;
    const delay = RECONNECT_DELAYS[Math.min(this._reconnectAttempt, RECONNECT_DELAYS.length - 1)];
    this._reconnectAttempt += 1;
    log.info(`Reconnecting in ${delay / 1000}s (attempt ${this._reconnectAttempt})`);
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      if (this._closing) return;
      metrics.record.reconnect();
      this.emit('reconnecting', this._reconnectAttempt);
      this._dial();
    }, delay);
    if (typeof this._reconnectTimer.unref === 'function') this._reconnectTimer.unref();
  }

  _cancelReconnectTimer() {
    if (this._reconnectTimer) {
      // allow:silent-catch — clearTimeout is forgiving but defensive against a stub/mock that throws
      try { clearTimeout(this._reconnectTimer); } catch (_e) {}
      this._reconnectTimer = null;
    }
  }
}

module.exports = WsClient;
