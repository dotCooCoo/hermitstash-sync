'use strict';

/**
 * Server-independent unit coverage for the Tailscale/WireGuard TUNNEL MODE
 * security decisions in lib/http-client.js + lib/config.js.
 *
 * Tunnel mode reaches the HermitStash server inside a tunnel where the server's
 * external TLS leaf won't carry the tunnel (MagicDNS) hostname, so the client
 * SKIPS the leaf's hostname/SAN match — but ONLY while it still pins the
 * server's SPKI (+ the mTLS chain + the PQC floor). The two things that MUST
 * hold, and are exercised here:
 *   1. Relaxing the hostname is fail-closed: NEVER skip the SAN check without a
 *      pin (config.validate refuses it AND the TLS-layer verifier refuses it).
 *   2. With a pin, relax mode passes a cert whose SAN does NOT match the dialed
 *      host but whose SPKI matches the pin, and rejects a pin mismatch.
 *
 * The relax path deliberately skips node:tls.checkServerIdentity, so a minimal
 * `{ raw: <DER> }` cert (the shape spkiPin accepts) is enough to drive it — no
 * TLS handshake needed. A real DER comes from any node:tls root cert.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeTls = require('node:tls');
const nodeCrypto = require('node:crypto');

const HttpClient = require('../lib/http-client');
const config = require('../lib/config');
const cli = require('../lib/cli');

// A real certificate (any of the bundled roots) gives us valid DER to derive a
// genuine SPKI pin from; we present it as a peer cert to the verifier.
const anyRootPem = nodeTls.rootCertificates[0];
const x509 = new nodeCrypto.X509Certificate(anyRootPem);
const peerCert = { raw: x509.raw };                 // the shape spkiPin accepts
const realPin = HttpClient.spkiPin(peerCert);       // "sha256/<base64>"
const wrongPin = 'sha256/' + 'A'.repeat(43) + '=';  // valid shape, never matches

describe('tunnel mode — checkServerIdentity relaxation (lib/http-client.js)', () => {

  it('no pins + no relax → undefined (default trust path, no override installed)', () => {
    assert.equal(HttpClient.buildCheckServerIdentity([]), undefined);
    assert.equal(HttpClient.buildCheckServerIdentity([], { relaxHostname: false }), undefined);
    assert.equal(HttpClient.buildCheckServerIdentity(undefined), undefined);
  });

  it('relax + a matching pin → PASS despite a non-matching hostname (SAN check skipped)', () => {
    const fn = HttpClient.buildCheckServerIdentity([realPin], { relaxHostname: true });
    // The dialed host is a MagicDNS name the external leaf never carries; relax
    // mode must not consult the SAN, only the pin — which matches → undefined.
    assert.equal(fn('hs.tailnet-abc.ts.net', peerCert), undefined,
      'relax mode with a matching pin must accept a cert whose SAN does not match the dialed host');
  });

  it('relax + a WRONG pin → rejected with a pin-mismatch error', () => {
    const fn = HttpClient.buildCheckServerIdentity([wrongPin], { relaxHostname: true });
    const err = fn('hs.tailnet-abc.ts.net', peerCert);
    assert.ok(err instanceof Error, 'a pin mismatch must be rejected');
    assert.match(err.message, /SPKI pin mismatch/, 'the error names the pin mismatch');
  });

  it('relax + NO pin → FAIL CLOSED (never skip the hostname check without a pin)', () => {
    const fn = HttpClient.buildCheckServerIdentity([], { relaxHostname: true });
    assert.ok(typeof fn === 'function', 'relax mode installs a verifier even with no pins');
    const err = fn('any.host', peerCert);
    assert.ok(err instanceof Error, 'relaxing the hostname with no pin must be refused');
    assert.match(err.message, /refusing to skip|no pinned server SPKI|pinnedServerSpki is empty/i,
      'the error explains the fail-closed refusal');
  });

  it('non-relax + a pin still enforces the hostname/SAN check (no regression)', () => {
    const fn = HttpClient.buildCheckServerIdentity([realPin], { relaxHostname: false });
    // A root-CA cert has no SAN matching this host, so node:tls.checkServerIdentity
    // must reject — proving the default hostname check still runs when NOT relaxed.
    const err = fn('definitely-not-this-cert.invalid', peerCert);
    assert.ok(err instanceof Error, 'non-relax mode must keep enforcing the hostname/SAN match');
  });

});

describe('tunnel mode — config.validate fail-closed policy (lib/config.js)', () => {

  // A minimal otherwise-valid config; we toggle tunnelMode / pinnedServerSpki
  // and assert only on whether the tunnel-specific error is present, so other
  // unrelated validation output can't mask the result.
  function baseCfg(extra) {
    return Object.assign({
      server: 'https://hs.tailnet-abc.ts.net',
      bundleId: '',
      shareId: '',
      syncFolder: '/tmp/hs-tunnel-test',
      apiKeyRef: 'keychain:hermitstash-sync',
      mtls: null,
      ignore: [],
      logLevel: 'info',
    }, extra || {});
  }
  const tunnelErr = (errs) => errs.some(e => /tunnel/i.test(e) && /pin/i.test(e));

  it('tunnelMode ON with an EMPTY pin list → rejected (must pin the server SPKI)', () => {
    const errs = config.validate(baseCfg({ tunnelMode: true, pinnedServerSpki: [] }));
    assert.ok(tunnelErr(errs), 'tunnelMode without a pin must be a validation error:\n' + errs.join('\n'));
  });

  it('tunnelMode ON with a valid pin → the tunnel policy passes', () => {
    const errs = config.validate(baseCfg({ tunnelMode: true, pinnedServerSpki: [realPin] }));
    assert.equal(tunnelErr(errs), false, 'tunnelMode + a valid pin must satisfy the policy:\n' + errs.join('\n'));
  });

  it('tunnelMode OFF with no pin → the tunnel policy does not fire', () => {
    const errs = config.validate(baseCfg({ tunnelMode: false }));
    assert.equal(tunnelErr(errs), false, 'tunnelMode off must not require a pin');
  });

  it('a non-boolean tunnelMode is rejected', () => {
    const errs = config.validate(baseCfg({ tunnelMode: 'yes', pinnedServerSpki: [realPin] }));
    assert.ok(errs.some(e => /tunnelMode/i.test(e) && /boolean/i.test(e)),
      'tunnelMode must be a boolean:\n' + errs.join('\n'));
  });

});

describe('tunnel mode — probeServerLeafSpki (SPKI capture)', () => {

  it('refuses to capture a pin over http:// (a pin is meaningless without TLS)', async () => {
    await assert.rejects(
      HttpClient.probeServerLeafSpki('http://hs.tailnet-abc.ts.net'),
      /https:\/\/|without TLS|plaintext|serve-terminated/i,
      'capturing an SPKI pin over http:// must be refused');
  });

});

describe('tunnel mode — prefers an out-of-band pin over trust-on-first-use', () => {

  // An operator-supplied pin arrived over a channel the network attacker does
  // not control, so it must be used VERBATIM and must suppress the probe
  // entirely — probing would re-open the window the supplied pin exists to
  // close. The server URL below is unroutable: if the probe ran at all, the
  // call would reject instead of resolving.
  const ENV = 'HERMITSTASH_PINNED_SERVER_SPKI';
  const saved = process.env[ENV];                                               // allow:raw-process-env — test fixture toggling the documented operator env var
  const restore = () => {
    if (saved === undefined) delete process.env[ENV];                           // allow:raw-process-env — test fixture cleanup
    else process.env[ENV] = saved;                                              // allow:raw-process-env — test fixture cleanup
  };

  it('uses the supplied pin(s) and never probes the network', async () => {
    process.env[ENV] = realPin;                                                 // allow:raw-process-env — test fixture
    try {
      const pins = await cli.resolveTunnelPins('https://unroutable.invalid:9', { interactive: false });
      assert.deepEqual(pins, [realPin], 'the out-of-band pin must be used verbatim');
    } finally { restore(); }
  });

  it('accepts multiple comma-separated supplied pins (rotation)', async () => {
    process.env[ENV] = `${realPin}, ${wrongPin}`;                               // allow:raw-process-env — test fixture
    try {
      const pins = await cli.resolveTunnelPins('https://unroutable.invalid:9', { interactive: false });
      assert.deepEqual(pins, [realPin, wrongPin], 'both pins carry through, trimmed');
    } finally { restore(); }
  });

});

describe('tunnel mode — config.tls cannot disable TLS verification (ws transport)', () => {

  // `config.tls` is an undeclared passthrough: absent from config DEFAULTS and
  // unvalidated, so config.load()'s {...DEFAULTS, ...parsed} hands it straight
  // to the dial. Spread last it would disable chain validation AND — because
  // Node only calls checkServerIdentity when the chain verified — silently void
  // the SPKI pin, turning config-file write access into full interception of the
  // control channel. Capture the real dial options to prove it cannot.
  const WsClient = require('../lib/ws-client');
  const b = require('../vendor/blamejs');

  function capturedTlsOpts(cfg, env) {
    const realConnect = b.wsClient.connect;
    const savedEnv = process.env.HERMITSTASH_ALLOW_INSECURE_TLS;                // allow:raw-process-env — test fixture
    if (env === undefined) delete process.env.HERMITSTASH_ALLOW_INSECURE_TLS;   // allow:raw-process-env — test fixture
    else process.env.HERMITSTASH_ALLOW_INSECURE_TLS = env;                      // allow:raw-process-env — test fixture
    let seen = null;
    b.wsClient.connect = (_url, opts) => {
      seen = opts && opts.tlsOpts;
      const { EventEmitter } = require('node:events');
      const stub = new EventEmitter();
      stub.readyState = 'connecting';
      stub.send = () => {}; stub.close = () => {}; stub.cancelReconnect = () => {};
      return stub;
    };
    try {
      const ws = new WsClient(Object.assign({ server: 'https://stub.invalid:443', reconnect: false }, cfg), 'hs_stub_key');
      ws.connect('stub-bundle', 0);
      try { ws.close(); } catch { /* teardown */ }
    } finally {
      b.wsClient.connect = realConnect;
      if (savedEnv === undefined) delete process.env.HERMITSTASH_ALLOW_INSECURE_TLS;  // allow:raw-process-env — test fixture cleanup
      else process.env.HERMITSTASH_ALLOW_INSECURE_TLS = savedEnv;                     // allow:raw-process-env — test fixture cleanup
    }
    return seen;
  }

  it('ignores rejectUnauthorized:false coming from config.tls', () => {
    const opts = capturedTlsOpts({ tls: { rejectUnauthorized: false } }, undefined);
    assert.ok(opts, 'expected to capture the dial TLS options');
    assert.notEqual(opts.rejectUnauthorized, false,
      'config.tls must NOT be able to disable chain validation on the WebSocket transport');
  });

  it('ignores a checkServerIdentity override so it cannot displace the SPKI pin', () => {
    const opts = capturedTlsOpts(
      { tls: { checkServerIdentity: () => undefined }, pinnedServerSpki: [realPin] }, undefined);
    assert.ok(opts, 'expected to capture the dial TLS options');
    assert.equal(typeof opts.checkServerIdentity, 'function', 'the pin verifier must still be installed');
    // The surviving verifier must be OURS — it rejects a cert whose pin doesn't
    // match — not the config-supplied stub that would accept anything.
    const err = opts.checkServerIdentity('stub.invalid', peerCert);
    assert.ok(err instanceof Error,
      'the surviving checkServerIdentity must be the pin verifier, not the config-supplied stub');
  });

  // A denylist of "obviously dangerous" keys is not enough: this object is
  // spread LAST, so ANY surviving key overrides what the client just set. These
  // three are the ones that defeat server identity without ever touching
  // rejectUnauthorized/checkServerIdentity, so they are pinned as regressions.
  it('ignores config.tls "ca" — it would REPLACE the trust anchors with an attacker root', () => {
    const attackerRoot = '-----BEGIN CERTIFICATE-----\nattacker\n-----END CERTIFICATE-----';
    const opts = capturedTlsOpts({ tls: { ca: attackerRoot }, mtls: null }, undefined);
    assert.notEqual(opts.ca, attackerRoot,
      'config.tls.ca must not replace the trust store — a chain-valid intercept would follow');
  });

  it('ignores config.tls "servername" — it would retarget the hostname/SAN check', () => {
    const opts = capturedTlsOpts({ tls: { servername: 'attacker.tld' } }, undefined);
    assert.notEqual(opts.servername, 'attacker.tld',
      'config.tls.servername must not choose the name the identity check validates against');
  });

  it('ignores config.tls TLS-floor overrides — they would allow a TLS 1.2 downgrade', () => {
    const opts = capturedTlsOpts({ tls: { maxVersion: 'TLSv1.2', minVersion: 'TLSv1.2', ciphers: 'DEFAULT:@SECLEVEL=0' } }, undefined);
    assert.notEqual(opts.maxVersion, 'TLSv1.2', 'config.tls must not cap the TLS version');
    assert.equal(opts.minVersion, 'TLSv1.3', 'the TLS 1.3 floor stands');
    assert.notEqual(opts.ciphers, 'DEFAULT:@SECLEVEL=0', 'config.tls must not weaken the cipher policy');
  });

  it('honors the explicit HERMITSTASH_ALLOW_INSECURE_TLS escape hatch (test harnesses)', () => {
    const opts = capturedTlsOpts({ tls: { rejectUnauthorized: false } }, '1');
    assert.equal(opts.rejectUnauthorized, false,
      'with the documented escape hatch set, the override is honored deliberately');
  });

});
