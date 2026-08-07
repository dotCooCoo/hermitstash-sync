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

describe('tunnel mode — a captured pin must be acknowledged before it is trusted', () => {

  // Trust-on-first-use is only safe if accepting the observed leaf is a
  // deliberate act. An attacker on-path at setup answers the probe with a cert
  // they own; because tunnel mode also skips the hostname check, that pin would
  // make their interception permanent and silent. Headless setup therefore
  // refuses to proceed on an unacknowledged capture. Needs the live server so
  // the probe actually succeeds and we reach the acknowledgement gate.
  const cli = require('../lib/cli');
  const PIN_ENV = 'HERMITSTASH_PINNED_SERVER_SPKI';
  const ACK_ENV = 'HERMITSTASH_TUNNEL_PIN_ACK';

  function withEnv(vals, fn) {
    const saved = {};
    for (const k of Object.keys(vals)) {
      saved[k] = process.env[k];                                                // allow:raw-process-env — test fixture
      if (vals[k] === undefined) delete process.env[k];                         // allow:raw-process-env — test fixture
      else process.env[k] = vals[k];                                            // allow:raw-process-env — test fixture
    }
    const restore = () => {
      for (const k of Object.keys(saved)) {
        if (saved[k] === undefined) delete process.env[k];                      // allow:raw-process-env — test fixture cleanup
        else process.env[k] = saved[k];                                         // allow:raw-process-env — test fixture cleanup
      }
    };
    return Promise.resolve().then(fn).finally(restore);
  }

  it('headless setup REFUSES to capture a pin — it has no way to confirm one', async () => {
    await withEnv({ [PIN_ENV]: undefined, [ACK_ENV]: undefined }, async () => {
      await assert.rejects(
        cli.resolveTunnelPins(ctx.url, { interactive: false }),
        /HERMITSTASH_PINNED_SERVER_SPKI|out-of-band|cannot confirm/i,
        'unattended setup must not trust-on-first-use; it must demand the pin out-of-band');
    });
  });

  it('no "proceed anyway" flag can substitute for the pin in a headless setup', async () => {
    // A flag would only assert "pin whatever answers" — it names no value, so it
    // cannot distinguish the real server from an interceptor. Setting the old
    // acknowledgement variable (or anything like it) must NOT unlock capture.
    await withEnv({ [PIN_ENV]: undefined, [ACK_ENV]: '1' }, async () => {
      await assert.rejects(
        cli.resolveTunnelPins(ctx.url, { interactive: false }),
        /HERMITSTASH_PINNED_SERVER_SPKI|out-of-band|cannot confirm/i,
        'a value-less acknowledgement flag must not unlock unattended trust-on-first-use');
    });
  });

  it('headless setup succeeds when the pin is supplied out-of-band', async () => {
    const realPin = await HttpClient.probeServerLeafSpki(ctx.url);
    await withEnv({ [PIN_ENV]: realPin, [ACK_ENV]: undefined }, async () => {
      const pins = await cli.resolveTunnelPins(ctx.url, { interactive: false });
      assert.deepEqual(pins, [realPin], 'the supplied pin is used verbatim');
    });
  });

});
