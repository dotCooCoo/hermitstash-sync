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
