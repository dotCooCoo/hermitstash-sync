'use strict';

/**
 * The WebSocket control channel. The whole RFC 6455 wire layer belongs to the
 * framework; what this adds is a `since`-aware reconnect.
 *
 * Each reconnect has to dial with the latest applied seq, or the server's
 * catch-up re-emits events already processed. The framework's own reconnect
 * reuses the original URL, so it is turned off and reconnects are driven here.
 *
 * Emits: open, message, close, error, reconnecting, upgrade_rejected,
 * auth_error.
 */

const nodeNet = require('node:net');
const nodeFs = require('node:fs');
const { EventEmitter } = require('node:events');
const { VERSION, RECONNECT_DELAYS, HEARTBEAT_TIMEOUT_MS, TLS_GROUPS, TLS_MIN_VERSION, INSTANCE_ID_FILE } = require('./constants');
const log = require('./logger');
const metrics = require('./metrics');

const b = require('../vendor/blamejs');

const C = b.constants;

// Cap on the mTLS cert/key/CA files read off disk. A PEM cert/key/CA bundle
// is well under 1 MiB; the cap is a guard against a swapped-in oversized file,
// not a tuning knob.
const MTLS_PEM_MAX_BYTES = C.BYTES.mib(1);

// Read an mTLS file (the client cert, the 0o600 private key, or the CA
// bundle) refusing to follow a symlink at the final path component. The
// private key is the highest-value secret the client holds; a planted
// symlink at the configured path would otherwise let an attacker with write
// access to the cert directory substitute or exfiltrate key material the
// daemon then presents to the server. fdSafeReadSync binds the read to the
// inode it opened (O_NOFOLLOW + inode-equality) so a swap between stat and
// read can't change which bytes come back. Returns a Buffer (no encoding),
// byte-identical to the readFileSync(path) the TLS layer previously consumed.
function _readMtlsFile(path, kind) {
  return b.atomicFile.fdSafeReadSync(path, {
    refuseSymlink: true,
    inodeCheck:    true,
    maxBytes:      MTLS_PEM_MAX_BYTES,
    errorFor(errKind, detail) {
      if (errKind === 'symlink') {
        return new Error(
          `Refusing to read mTLS ${kind} from ${path}: it is a symlink. ` +
          'Replace it with a regular file (re-enroll to reissue the client certificate).');
      }
      if (errKind === 'too-large') {
        return new Error(
          `mTLS ${kind} at ${path} is ${detail.size} bytes, larger than the ${MTLS_PEM_MAX_BYTES}-byte ` +
          'cap — the file is not a PEM cert/key. Re-enroll to reissue the client certificate.');
      }
      return new Error(
        `Failed to read mTLS ${kind} from ${path} (${errKind}). ` +
        'Re-enroll to reissue the client certificate.');
    },
  });
}

// Cap on JSON message bodies we'll accept on the wire. blamejs already
// caps at 8 MiB by default; pin it explicitly so a server-side bump
// doesn't silently widen the client's exposure.
const MAX_MESSAGE_BYTES = C.BYTES.mib(8);
// allow:raw-byte-literal — RFC 6455 §7.4.1 close code "normal closure", protocol literal not a byte size
const WS_NORMAL_CLOSE = 1000;
const WS_LOG_PREVIEW_CHARS = 200; // truncation cap for malformed-JSON debug logging

// The framework's own transience verdict is used rather than a taxonomy
// maintained here — but only during the handshake. A mid-stream protocol or
// frame error is marked permanent too, and yet a fresh dial recovers it, so
// those self-heal instead of failing closed. _handshakeComplete draws the line.

// Pull the HTTP status out of a blamejs ws-client error. 0.15.23 exposes it
// directly on `err.statusCode`; fall back to the legacy `err.status` alias and
// then to parsing the message tail ("handshake response status was N ...") for
// resilience against a future wire-format tweak.
function _wsErrorStatus(err) {
  if (err && Number.isInteger(err.statusCode)) return err.statusCode;
  if (err && Number.isInteger(err.status)) return err.status;
  const m = /status was (\d+)/.exec((err && err.message) || '');
  return m ? parseInt(m[1], 10) : 0;
}

// Detect a blamejs SSRF-guard refusal (private / loopback / link-local /
// reserved / cloud-metadata destination). The guard throws via its SsrfError
// convention (message, code, ctx), but b.wsClient passes errorClass:
// WsClientError whose signature is (code, message, statusCode), so the args land
// swapped — err.code holds the human message and err.message holds the
// 'ssrf-guard/...' slug (filed upstream). Check BOTH fields so the refusal is
// detected whichever one carries the slug, until the upstream arg-order is fixed.
function _isSsrfError(err) {
  const code = err && err.code;
  const msg = err && err.message;
  return (typeof code === 'string' && code.startsWith('ssrf-guard/')) ||
         (typeof msg === 'string' && msg.startsWith('ssrf-guard/'));
}

// `config.tls` is an undeclared passthrough: absent from the defaults, with no
// validation rule, so any such key travels from the config file straight into
// the dial. Spread last, a `rejectUnauthorized: false` there disables chain
// validation — and since Node only calls checkServerIdentity once the chain
// verified, it voids the SPKI pin along with it. That would turn write access
// to the config file into full interception of the control channel, API key
// included, which on macOS and Windows otherwise lives in the OS keychain.
function _allowInsecureTls() {
  const raw = b.safeEnv.readVar('HERMITSTASH_ALLOW_INSECURE_TLS', { type: 'string', default: '' }).trim();
  return /^(1|true|yes|on)$/i.test(raw);
}

// The whole bag is ignored by default rather than filtered. A denylist is the
// wrong shape: nearly every option here can defeat server identity, and the
// object is spread last, so anything left un-stripped wins. `ca` replaces the
// trust store outright, `servername` retargets the name the identity check runs
// against, and a version or cipher floor drops the connection to TLS 1.2 — which
// the post-quantum check then reads as at-floor, because a static-RSA handshake
// reports no ephemeral group at all. Nothing in the client sets this; only the
// test harness does.
function _configTlsOverrides(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const keys = Object.keys(raw);
  if (keys.length === 0) return {};
  if (_allowInsecureTls()) return raw;
  log.warn('Ignoring the TLS options in config (' + keys.join(', ') +
    ') — server verification stays on. Set HERMITSTASH_ALLOW_INSECURE_TLS=1 to apply them deliberately ' +
    '(intended for a self-signed test server).');
  return {};
}

// Header the server reads to recognise THIS client across reconnects.
const INSTANCE_HEADER = 'X-HermitStash-Instance';

// A stable id for this installation, sent on every upgrade so the server can
// drop the connection this same client left behind rather than counting a
// not-yet-reaped socket against the per-key ceiling and refusing the reconnect.
// Persisted, so a restarted daemon still supersedes its previous run's
// connections — a per-process id would strand exactly those ghosts.
//
// It identifies and does not authenticate: the API key and client certificate
// do that, and the server only uses this to choose among connections already
// belonging to one key. Unreadable or unwritable, the client sends no header
// and the server behaves as it did before.
let _instanceId;
function instanceId() {
  if (_instanceId !== undefined) return _instanceId;
  _instanceId = null;
  try {
    const existing = nodeFs.readFileSync(INSTANCE_ID_FILE, 'utf8').trim();
    // Re-validate on read: the file is on disk and could have been edited.
    // Anything unexpected is replaced rather than sent.
    if (/^[A-Za-z0-9_-]{8,64}$/.test(existing)) { _instanceId = existing; return _instanceId; }
  } catch { /* not created yet, or unreadable — fall through and mint one */ }
  try {
    const fresh = b.crypto.generateToken(16).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32); // allow:raw-byte-literal — 16 bytes of entropy and a 32-CHARACTER cap, not buffer sizes
    if (fresh.length >= 8) {                                                               // allow:raw-byte-literal — minimum id length in characters, not a byte size
      b.atomicFile.writeSync(INSTANCE_ID_FILE, fresh + '\n', { mode: 0o600 });
      _instanceId = fresh;
    }
  } catch (err) {
    log.debug('Could not persist an instance id; reconnects will not supersede early', { err: err && err.message });
  }
  return _instanceId;
}

// The framework already pins TLS 1.3; this supplies the group preference, so
// the ClientHello advertises the server's expected post-quantum groups.
//
// `ecdhCurve` only. Node has no `groups` option, so a key by that name is
// accepted and discarded — it reads as insurance and is not consulted, and
// only `ecdhCurve` is validated.
function _pqcTlsOpts(extra) {
  return Object.assign({
    ecdhCurve: TLS_GROUPS,
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
    // Identifies this client to the server across reconnects. Defaults to the
    // installation-wide persisted id, which is what a daemon wants: one process,
    // one connection per bundle, and a reconnect that should displace its own
    // predecessor. `config.instanceId` overrides it for the case that breaks
    // that assumption — several WsClients alive at once in a single process,
    // which is two distinct subscribers rather than one client reconnecting.
    // They must not share an id, or the second would displace the first.
    this._instanceId = (config && typeof config.instanceId === 'string' && config.instanceId)
      ? config.instanceId
      : instanceId();
    this._closing = false;
    this._reconnectAttempt = 0;
    this._reconnectTimer = null;
    // True once the current dial's handshake has completed ('open' fired and the
    // PQC floor passed). Terminal-vs-transient classification only applies to a
    // handshake-phase failure; a post-open error self-heals via a fresh dial.
    this._handshakeComplete = false;

    // Cache mTLS material on construction so reconnects don't re-read disk.
    this._cachedCert = null;
    this._cachedKey  = null;
    this._cachedCa   = null;
    if (config.mtls) {
      if (config.mtls.cert) this._cachedCert = _readMtlsFile(config.mtls.cert, 'certificate');
      if (config.mtls.key)  this._cachedKey  = _readMtlsFile(config.mtls.key, 'private key');
      if (config.mtls.ca)   this._cachedCa   = _readMtlsFile(config.mtls.ca, 'CA bundle');
    }
  }

  connect(bundleId, since = 0) {
    // Make connect() self-contained: cancel any pending reconnect timer and
    // tear down an existing live client before dialing. sync-engine calls
    // close() first by convention, but a caller that invokes connect()
    // directly on a live/reconnecting instance would otherwise leave the
    // pending timer to fire a SECOND _dial() — two live clients both wired to
    // this wrapper, every server event delivered twice, and a self-sustaining
    // multi-connection storm as each teardown clobbers the other. Reuse
    // close()'s teardown dance, then reset the lifecycle state.
    this._cancelReconnectTimer();
    if (this._b) {
      const dead = this._b;
      this._b = null;
      try {
        dead.removeAllListeners();
        dead.on('error', () => {});           // swallow a post-close socket error
        dead.close(WS_NORMAL_CLOSE, 'client-reconnect');
      } catch (_e) { /* allow:silent-catch — best-effort teardown of the superseded client */ }
    }
    this._bundleId = bundleId;
    this._since = since;
    this._closing = false;
    // An explicit connect() begins a fresh connection lifecycle — restart the
    // backoff ladder so a resync re-dial (close() then connect() on the same
    // instance while mid-backoff) doesn't inherit a climbed _reconnectAttempt
    // and schedule its first retry at a far-out ladder step.
    this._reconnectAttempt = 0;
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
      if (this._config.mtls.cert) this._cachedCert = _readMtlsFile(this._config.mtls.cert, 'certificate');
      if (this._config.mtls.key)  this._cachedKey  = _readMtlsFile(this._config.mtls.key, 'private key');
      if (this._config.mtls.ca)   this._cachedCa   = _readMtlsFile(this._config.mtls.ca, 'CA bundle');
      log.info('mTLS cert cache reloaded from disk');
    } catch (err) {
      log.error('Failed to reload mTLS certs', err);
    }
  }

  close() {
    this._closing = true;
    this._cancelReconnectTimer();
    if (this._b) {
      // Detach the wrapper's listeners from the outgoing client and let its
      // OWN deferred teardown run to completion. b.wsClient.close() on an open
      // socket only sends a CLOSE frame and schedules socket.destroy() + the
      // 30s ping-interval stop on a 1s grace timer, leaving the client's
      // internal _closed flag false. The previous cancelReconnect() call here
      // set that flag true, which made the deferred teardown early-return
      // BEFORE it destroyed the socket or stopped the ping interval — leaking a
      // half-open TLS socket, a live interval timer, and the whole client on
      // every close / resync / stop. cancelReconnect() is therefore gone: with
      // reconnect:false there is never a framework reconnect timer to cancel,
      // and close() already cancels one internally, so the call was pure poison.
      //
      // A resync calls connect() synchronously right after close(), so we null
      // and detach the outgoing client here — otherwise its late teardown
      // 'close'/'error' would reach the wrapper's handlers and clobber the
      // freshly-dialled session (null the new client, emit a spurious 'close',
      // schedule a spurious reconnect). The re-armed no-op 'error' listener is
      // mandatory: after removeAllListeners a socket error during the 1s grace
      // window (e.g. the server ECONNRESETs its end after our CLOSE frame) would
      // emit 'error' with no listener and crash the process as an
      // uncaughtException — the exact case the wrapper's post-close swallow guards.
      const dead = this._b;
      this._b = null;
      try {
        dead.removeAllListeners();
        dead.on('error', () => {});
        dead.close(WS_NORMAL_CLOSE, 'client-close');
      } catch (_e) {}   // allow:silent-catch — best-effort teardown of the outgoing client; the deferred _teardown finalises the socket + ping interval regardless
    }
  }

  _dial() {
    // Each dial starts a fresh handshake; clear the completion latch so a
    // failure before 'open' is classified as a handshake-phase (terminal-vs-
    // transient) error rather than a self-healing post-open one.
    this._handshakeComplete = false;
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
    // SPKI pinning when config.pinnedServerSpki is set — runs on top of the
    // default chain + hostname checks. In tunnel mode the hostname/SAN match is
    // skipped (tunnel + pin + mTLS bind identity) while the pin + chain stay on.
    const pinCheck = HttpClient.buildCheckServerIdentity(this._config.pinnedServerSpki, { relaxHostname: !!this._config.tunnelMode });
    const assertPqcGroup = HttpClient.assertNegotiatedGroupPqc;
    const wsHost = serverUrl.hostname;
    const tlsOpts = isHttps ? _pqcTlsOpts({
      cert: this._cachedCert || undefined,
      key:  this._cachedKey  || undefined,
      ca:   this._cachedCa ? HttpClient.buildCaBundle(this._cachedCa) : undefined,
      servername: sni,
      ...(pinCheck ? { checkServerIdentity: pinCheck } : {}),
      // config.tls is a test-harness passthrough and is ignored entirely unless
      // HERMITSTASH_ALLOW_INSECURE_TLS is set, so nothing in config.json can
      // displace the trust anchors, the SNI/hostname the identity check uses,
      // the TLS floor, or the pin verifier installed above.
      ..._configTlsOverrides(this._config.tls),
    }) : null;

    log.debug('WebSocket connecting', { url: wsUrl });

    let client;
    try {
      client = b.wsClient.connect(wsUrl, {
        headers: Object.assign({
          'Authorization': `Bearer ${this._apiKey}`,
          'User-Agent':    `hermitstash-sync/${VERSION}`,
        }, this._instanceId ? { [INSTANCE_HEADER]: this._instanceId } : {}),
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
      // b.wsClient.connect() throws synchronously for a config-time terminal
      // failure (a bad URL or a bad subprotocol). Treat those exactly like an
      // async terminal handshake error: fail closed (no reconnect) and
      // surface them on the rejection path with a synthetic status 0, so the
      // engine maps them to a sticky ERROR with an actionable "fix the server
      // URL, restart the daemon" message instead of redialing a hopeless target
      // forever on the backoff ladder. A genuinely transient throw still
      // schedules a reconnect. (connect() only throws pre-open config-time
      // codes, all err.permanent===true, so the handshake-phase gate passes.)
      if (this._isTerminalWsError(err)) {
        log.error('WebSocket dial permanently failed at config time (' + (err && err.code) +
          ') — fix the server URL/config, then restart the daemon (it will NOT reconnect on its own)',
        { code: err && err.code, msg: err && err.message });
        this._closing = true;
        this.emit('upgrade_rejected', { status: 0, body: (err && err.message) || '' });
        return;
      }
      log.error('WebSocket connect threw at config time', err);
      this.emit('error', err);
      if (!this._closing) this._scheduleReconnect();
      return;
    }

    this._b = client;

    client.on('open', () => {
      // A handshake already in flight when close() was called can still
      // complete and emit 'open' before blamejs's deferred teardown fires.
      // Once the consumer has asked to close, drop that late 'open' so we
      // don't flip the engine back into CATCHING_UP or reset the reconnect
      // counter against a daemon that just stopped — mirrors the _closing
      // check in the 'error' handler below.
      if (this._closing) {
        log.debug('WebSocket open after close (ignored)');
        return;
      }
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
      //
      // assertPqcGroup returns true when it destroyed the socket on an
      // enforced classical downgrade. A PQC-floor violation is a PERMANENT
      // server-posture failure, not a transient drop — redialling just
      // re-negotiates the same classical group forever. So we FAIL CLOSED: set
      // _closing (so the destroy-driven 'close'/'error' do NOT reconnect) and
      // surface the actionable terminal signal on the rejection path (synthetic
      // status 0 -> engine sticky ERROR), exactly like the ssrf-guard and
      // config-time-throw branches. The follow-up destroy 'error' carries no
      // code and arrives with _closing already set, so the 'error' handler's
      // _closing guard swallows it. We do NOT emit 'open' (which would flip the
      // engine into CATCHING_UP on a socket being torn down). When the socket
      // survives (at-floor PQC, allowed-classical, or plain ws:) the return is
      // false and we complete the handshake below.
      if (isHttps && client._socket && typeof assertPqcGroup === 'function') {
        if (assertPqcGroup(client._socket, wsHost, { enforce: true })) {
          log.error('WebSocket PQC floor enforcement destroyed the connection (classical group negotiated) — ' +
            'upgrade the HermitStash server to a PQC build or set HERMITSTASH_ALLOW_CLASSICAL_TLS=1, then restart ' +
            'the daemon (it will NOT reconnect on its own)');
          this._closing = true;
          this.emit('upgrade_rejected', { status: 0, body: 'server negotiated a classical TLS group — post-quantum key exchange required' });
          return;
        }
      }
      // Handshake complete: a later error is now a post-open drop (self-heal),
      // not a handshake-phase terminal failure.
      this._handshakeComplete = true;
      this._reconnectAttempt = 0;
      log.info('WebSocket connected');
      this.emit('open');
    });

    client.on('message', (data, isBinary) => {
      // Drop any frame delivered after the consumer asked to close — symmetric
      // with the 'open' and 'error' handlers' _closing guards. blamejs drains
      // frames piggybacked on the handshake tail SYNCHRONOUSLY right after
      // emit('open') (_consumeHandshake -> _consumeFrames), so a PQC-floor
      // classical-TLS rejection in the 'open' handler (which sets _closing and
      // destroys the socket asynchronously) would otherwise still let one
      // coalesced server frame — e.g. a file_removed — reach the sync engine
      // over a connection the post-quantum gate just refused fail-closed.
      // connect() resets _closing=false per dial, so live + since-aware-
      // reconnect traffic is unaffected.
      if (this._closing) return;
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
      // Suppress our own reconnect (before the close handler fires) only for a
      // genuinely terminal HANDSHAKE failure — a bad URL, a non-WebSocket peer,
      // or a 4xx rejection (err.permanent===true, pre-open). Transient drops
      // (5xx, pong-timeout, handshake-timeout) and any post-open error (a
      // mid-stream protocol/frame violation) fall through to the close handler's
      // reconnect path so a fresh dial can recover. _isTerminalWsError now reads
      // the framework's err.permanent (0.15.23), gated on the handshake phase.
      if (this._isTerminalWsError(err)) {
        this._closing = true;
      }
      const code = err && err.code;
      // A blamejs SSRF-guard refusal (private / loopback / link-local /
      // reserved / cloud-metadata destination) is permanent — the gate runs
      // on every dial, so each reconnect would refuse the same target. There
      // is no HTTP exchange behind it, so surface it on the handshake-
      // rejection path with a synthetic status of 0 (which the engine maps to
      // a sticky ERROR, not an auth retry) and carry the guard's own message
      // as the body. Do not also emit a generic 'error' — the rejection path
      // owns the operator signal, same as a 4xx bad-status.
      if (_isSsrfError(err)) {
        log.error('WebSocket dial refused by the outbound-URL guard — fix the server URL, then restart the daemon (it will NOT reconnect on its own)', { code, msg: err && err.message });
        this.emit('upgrade_rejected', { status: 0, body: (err && err.message) || '' });
        return;
      }
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
        if (this._isTerminalWsError(err)) {
          this.emit('upgrade_rejected', { status, body: err.message || '' });
          if (status === 401 || status === 403) {
            metrics.record.authError();
            this.emit('auth_error', { status, body: err.message || '' });
          }
        } else if (status === 429 || status === 408) {
          // Retry-later handshake status (rate-limited upgrade / server-side
          // timeout). NOT terminal: _closing stays false above, so the close
          // handler self-heals via _scheduleReconnect once the throttle window
          // resets or the server reaps the ghost connection. Log it so the
          // backoff is attributable rather than a silent mystery drop. (A 5xx
          // stays silent — the close+reconnect log tail already narrates it.)
          log.warn(`WebSocket upgrade throttled (HTTP ${status}) — backing off; will reconnect once the limit clears`);
        }
        return;
      }
      // Any remaining terminal handshake failure (accept-mismatch, bad-upgrade,
      // bad-status-line) arrives here with _closing already set above but with
      // no HTTP status. Surface it on the rejection path with a synthetic
      // status 0 — the same as the ssrf and config-time-throw branches — so the
      // engine sets a sticky ERROR with an actionable "restart" message instead
      // of flipping to RECONNECTING forever against a socket this wrapper will
      // never redial. The generic 'error' emit below stays for genuinely
      // transient / unclassified failures only.
      if (this._isTerminalWsError(err)) {
        log.error('WebSocket dial permanently failed (' + code +
          ') — fix the server URL/config, then restart the daemon (it will NOT reconnect on its own)',
        { code, msg: err && err.message });
        this.emit('upgrade_rejected', { status: 0, body: (err && err.message) || '' });
        return;
      }
      log.error('WebSocket error', err);
      this.emit('error', err);
    });
  }

  // Decide whether a ws-client error permanently rules out reconnect. Consumes
  // the framework's err.permanent (0.15.23+, which reflects real transience),
  // but ONLY for a handshake-phase failure: once the handshake completed, the
  // framework still marks a mid-stream protocol/frame error permanent, yet a
  // fresh dial recovers it — so a post-open error is always treated as transient
  // (self-heal). A missing code (e.g. a raw socket Error) is not terminal.
  _isTerminalWsError(err) {
    if (!err || !err.code) return false;
    if (this._handshakeComplete) return false;
    // bad-status: terminal iff 4xx, transient iff 5xx. Decide by the recovered
    // HTTP status (err.statusCode -> err.status -> message tail) rather than
    // err.permanent: the status is the authoritative signal, and an error that
    // reaches us without a populated statusCode (the classifier then defaults
    // permanent=true) would otherwise mis-classify a transient 5xx as terminal
    // and wedge the daemon offline instead of reconnecting.
    if (err.code === 'ws-client/bad-status') {
      const status = _wsErrorStatus(err);
      // Transient (self-heal via reconnect): a 5xx (a momentarily overloaded
      // server), PLUS 408 Request Timeout and 429 Too Many Requests — the two
      // 4xx "retry later" statuses. The HermitStash server answers the /sync/ws
      // upgrade with 429 when a per-IP handshake throttle window is saturated, or
      // when the per-key connection ceiling is momentarily full (a reconnect
      // arriving before the server has reaped the prior, now-dead socket). Both
      // clear on their own — the throttle window resets, the ghost connection is
      // reaped — so treating a 429 as terminal wedged the daemon into a sticky
      // ERROR that never recovered after the limit reset and required a manual
      // restart. http-client.js classifies 408/429 as retryable for the same
      // reason, so the two transports stay consistent.
      //
      // Every OTHER non-5xx status is terminal: a 4xx caller error the server
      // rejects again on every retry (401/403/404/...), and a 1xx/2xx/3xx (a
      // misrouted reverse proxy answering the Upgrade with 200, or a 302 redirect
      // instead of 101) is a permanent misconfiguration — without this the wrapper
      // classified it neither terminal nor transient-with-signal and reconnected
      // forever with no upgrade_rejected and no operator-visible ERROR. An
      // unparseable status (0) also fails closed here rather than looping silently.
      const retryable = (status >= 500 && status < 600) || status === 408 || status === 429;
      return !retryable;
    }
    // Every other code: trust the framework's per-code transience verdict
    // (handshake-timeout / pong-timeout transient; bad-url / accept-mismatch /
    // bad-upgrade / bad-status-line / bad-subprotocol / bad-header / ssrf /
    // unknown terminal). 0.15.23+.
    return err.permanent === true;
  }

  _scheduleReconnect() {
    if (this._closing) return;
    if (this._config.reconnect === false) return;
    const base = RECONNECT_DELAYS[Math.min(this._reconnectAttempt, RECONNECT_DELAYS.length - 1)];
    // Half-jitter [base/2, base] with crypto-strength randomness so a fleet that
    // drops at the same instant (server restart/deploy/network blip) doesn't
    // redial in lockstep and stampede the server — matching the project's
    // crypto-jitter posture for upload retries. blamejs's built-in reconnect
    // jitters the same way; we drive our own since-aware loop but keep the jitter.
    const half = Math.floor(base / 2);
    const delay = half + b.crypto.randomInt(0, half + 1);
    this._reconnectAttempt += 1;
    log.info(`Reconnecting in ~${Math.round(delay / 1000)}s (attempt ${this._reconnectAttempt})`);
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
