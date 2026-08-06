'use strict';

/**
 * Integration coverage for tunnel-mode SPKI capture against the REAL running
 * HermitStash server (PQC-TLS). Unit coverage of the relax/verify decision
 * lives in test-tunnel-mode.js (server-independent); this proves the capture
 * mechanics — a PQC-group TLS probe that reads the server's leaf and derives its
 * SPKI pin — actually work end-to-end against a live server, since `init
 * --tunnel` depends on it to bootstrap the pin.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const HttpClient = require('../lib/http-client');

const ctx = { url: process.env.HERMITSTASH_TEST_URL };
if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

describe('tunnel mode — probeServerLeafSpki against the live server', () => {

  it('captures a well-formed, config-shaped SPKI pin from the running server', async () => {
    const pin = await HttpClient.probeServerLeafSpki(ctx.url);
    // Exactly the shape config.pinnedServerSpki accepts, so what the probe
    // captures at enrollment can be persisted + verified verbatim on connect.
    assert.match(pin, /^sha256\/[A-Za-z0-9+/]{43}=$/,
      'the probe must return a "sha256/<43-char-base64>=" pin, got ' + JSON.stringify(pin));
  });

  it('is deterministic — the same leaf yields the same pin across probes', async () => {
    const [a, b] = await Promise.all([
      HttpClient.probeServerLeafSpki(ctx.url),
      HttpClient.probeServerLeafSpki(ctx.url),
    ]);
    assert.equal(a, b, 'two probes of the same server leaf must derive the identical pin');
  });

});
