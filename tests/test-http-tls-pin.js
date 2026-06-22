'use strict';

/**
 * Runtime enforcement tests for SPKI server-certificate pinning.
 *
 * config.validate() already checks the pin STRING SHAPE (`sha256/<43-char>=`),
 * but the security control is the callback `buildCheckServerIdentity` returns:
 * when pins are configured it must REJECT a server cert whose SPKI SHA-256 is
 * not in the pin list and ACCEPT one that is. A regression that made the
 * callback always-accept (a base64 mislabel, an early return, a SHA swap)
 * would silently downgrade the connection to no-pin TLS, and every shape-only
 * test would still pass. These tests invoke the returned callback against real
 * cert material so the accept/reject decision is exercised end-to-end.
 *
 * The same callback is reused by the WebSocket transport
 * (lib/ws-client.js -> HttpClient.buildCheckServerIdentity), so this coverage
 * guards both the HTTP and WS pinning paths.
 *
 * Self-contained: generates a CA + two distinct server certs via b.mtlsCa
 * (OpenSSL-free) and computes the real pins itself. Skips if cert generation
 * is unavailable.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const nodeFs = require('node:fs');
const b = require('../vendor/blamejs');
const { createTempDir, rmrf } = require('./test-helpers');

const HttpClient = require('../lib/http-client');

// Compute the `sha256/<base64>` SPKI pin for a PEM cert exactly the way the
// production code derives the observed pin from the leaf cert's DER.
function pinForPem(pem) {
  const x509 = new nodeCrypto.X509Certificate(pem);
  const spkiDer = x509.publicKey.export({ format: 'der', type: 'spki' });
  return 'sha256/' + nodeCrypto.createHash('sha256').update(spkiDer).digest('base64');
}

// A peer-cert object shaped the way Node hands one to checkServerIdentity:
// `.raw` is the DER of the leaf cert; subjectaltname carries the SANs the
// default hostname check consults.
function peerCertFromPem(pem) {
  const x509 = new nodeCrypto.X509Certificate(pem);
  return {
    raw: x509.raw,
    subject: { CN: x509.subject },
    subjectaltname: 'DNS:localhost, IP Address:127.0.0.1',
  };
}

describe('SPKI pin runtime enforcement (buildCheckServerIdentity)', () => {
  let certA = null;   // the pinned server cert
  let certB = null;   // a different server cert (distinct keypair -> distinct pin)
  let dir = null;

  before(async () => {
    dir = createTempDir('tls-pin-certs');
    try {
      const ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: 'disabled', generation: 1 });
      await ca.initCA();
      const a = await ca.generateClientCert({
        cn: 'localhost', usage: 'server',
        sans: ['DNS:localhost', 'IP:127.0.0.1'], validityDays: 3650,
      });
      const b2 = await ca.generateClientCert({
        cn: 'localhost', usage: 'server',
        sans: ['DNS:localhost', 'IP:127.0.0.1'], validityDays: 3650,
      });
      certA = a.cert;
      certB = b2.cert;
    } catch (_e) {
      certA = null;
      certB = null;
    }
  });

  it('null / empty pin list returns undefined so default chain validation is unchanged', () => {
    assert.strictEqual(HttpClient.buildCheckServerIdentity(null), undefined);
    assert.strictEqual(HttpClient.buildCheckServerIdentity([]), undefined);
    assert.strictEqual(HttpClient.buildCheckServerIdentity('sha256/x='), undefined);
  });

  it('accepts a server cert whose SPKI matches a configured pin', (t) => {
    if (!certA) return t.skip('test PKI unavailable (b.mtlsCa cert generation failed)');
    const cb = HttpClient.buildCheckServerIdentity([pinForPem(certA)]);
    assert.strictEqual(typeof cb, 'function');
    const result = cb('localhost', peerCertFromPem(certA));
    // undefined === accepted (the contract Node's checkServerIdentity uses)
    assert.strictEqual(result, undefined, result && result.message);
  });

  it('accepts when the matching pin is one of several configured pins', (t) => {
    if (!certA || !certB) return t.skip('test PKI unavailable');
    const cb = HttpClient.buildCheckServerIdentity([pinForPem(certB), pinForPem(certA)]);
    const result = cb('localhost', peerCertFromPem(certA));
    assert.strictEqual(result, undefined, result && result.message);
  });

  it('rejects a server cert whose SPKI is NOT in the pin list', (t) => {
    if (!certA || !certB) return t.skip('test PKI unavailable');
    // Pin certB, present certA — distinct keypairs, so the SPKI differs.
    const cb = HttpClient.buildCheckServerIdentity([pinForPem(certB)]);
    const result = cb('localhost', peerCertFromPem(certA));
    assert.ok(result instanceof Error, 'expected an Error rejection, got ' + result);
    assert.match(result.message, /SPKI pin mismatch/);
    // The actionable message names the observed pin and the expected set.
    assert.match(result.message, /observed sha256\//);
  });

  it('rejects (never accepts) when the leaf cert cannot be parsed', () => {
    const cb = HttpClient.buildCheckServerIdentity(['sha256/' + 'A'.repeat(43) + '=']);
    // A peer object with no usable DER is rejected by whichever gate fires
    // first — the default chain/hostname check or the SPKI-extraction guard.
    // The security-relevant invariant is that it is NEVER accepted (undefined).
    const result = cb('localhost', { raw: Buffer.from('not-a-cert') });
    assert.ok(result instanceof Error, 'expected an Error rejection, got ' + result);
  });

  it('rejects when the default chain/hostname check fails even if the pin would match', (t) => {
    if (!certA) return t.skip('test PKI unavailable');
    const cb = HttpClient.buildCheckServerIdentity([pinForPem(certA)]);
    // Hostname the cert does not cover -> default checkServerIdentity returns an
    // Error first; the pin layer must NOT paper over a failed hostname check.
    const peer = peerCertFromPem(certA);
    peer.subjectaltname = 'DNS:other.example';
    const result = cb('attacker.example', peer);
    assert.ok(result instanceof Error, 'expected an Error rejection, got ' + result);
    // The hostname failure surfaces, not the pin layer's mismatch message.
    assert.doesNotMatch(result.message, /SPKI pin mismatch/);
  });

  it('teardown', () => {
    if (dir) rmrf(dir);
  });
});
