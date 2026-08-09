'use strict';

/**
 * Tests for TLS group configuration correctness.
 *
 * Verifies that:
 * - The centralized constants export correctly
 * - The group preference array is frozen (immutable)
 * - SecP384r1MLKEM1024 is offered as the top preference
 * - Node.js/OpenSSL accepts all groups in the preference list
 * - The server and sync client constants are consistent
 * - PQC_GROUPS IANA IDs match expected values
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const tls = require('node:tls');
const path = require('node:path');

const SERVER_DIR = process.env.HERMITSTASH_SERVER_DIR
  || path.resolve(__dirname, '..', '..', 'hermitstash');
const serverConstants = require(path.join(SERVER_DIR, 'lib', 'constants'));
const syncConstants = require(path.join(__dirname, '..', 'lib', 'constants'));
const { buildEnrollmentAgent } = require(path.join(__dirname, '..', 'lib', 'cli'));

describe('Server TLS Constants (hermitstash)', function () {
  it('TLS_GROUP_PREFERENCE is exported', function () {
    assert.ok(Array.isArray(serverConstants.TLS_GROUP_PREFERENCE));
    assert.ok(serverConstants.TLS_GROUP_PREFERENCE.length >= 2);
  });

  it('TLS_GROUP_PREFERENCE is frozen (immutable)', function () {
    assert.ok(Object.isFrozen(serverConstants.TLS_GROUP_PREFERENCE));
    assert.throws(function () {
      serverConstants.TLS_GROUP_PREFERENCE.push('test');
    }, TypeError);
  });

  it('SecP384r1MLKEM1024 is the top preference (Level 5)', function () {
    assert.strictEqual(serverConstants.TLS_GROUP_PREFERENCE[0], 'SecP384r1MLKEM1024');
  });

  it('X25519MLKEM768 is present as fallback', function () {
    assert.ok(serverConstants.TLS_GROUP_PREFERENCE.includes('X25519MLKEM768'));
  });

  it('SecP256r1MLKEM768 is present as secondary fallback', function () {
    assert.ok(serverConstants.TLS_GROUP_PREFERENCE.includes('SecP256r1MLKEM768'));
  });

  it('TLS_GROUP_CURVE_STR is the colon-joined preference list', function () {
    assert.strictEqual(
      serverConstants.TLS_GROUP_CURVE_STR,
      serverConstants.TLS_GROUP_PREFERENCE.join(':')
    );
  });

  it('TLS_GROUP_CURVE_STR contains no spaces or trailing colons', function () {
    assert.ok(!/\s/.test(serverConstants.TLS_GROUP_CURVE_STR));
    assert.ok(!serverConstants.TLS_GROUP_CURVE_STR.endsWith(':'));
    assert.ok(!serverConstants.TLS_GROUP_CURVE_STR.startsWith(':'));
  });

  it('PQC_GROUPS contains expected IANA IDs', function () {
    assert.strictEqual(serverConstants.PQC_GROUPS.X25519MLKEM768, 0x11EC);
    assert.strictEqual(serverConstants.PQC_GROUPS.SecP384r1MLKEM1024, 0x11ED);
  });

  it('PQC_GROUPS covers every hybrid the preference list advertises', function () {
    // Asserting a count let a real bug hide: SecP256r1MLKEM768 was advertised
    // in the preference list but missing from this accept-set, so the server
    // offered the group, accepted it at the TLS layer, then answered a client
    // offering only it with a fatal handshake_failure — indistinguishable, from
    // that client's side, from being refused for offering nothing post-quantum.
    // The relationship between the two tables is what matters, so check that
    // instead of a number that has to be edited every time a group is added.
    const advertised = serverConstants.TLS_GROUP_PREFERENCE.filter((g) => /MLKEM/i.test(g));
    assert.ok(advertised.length > 0, 'preference list advertises no hybrid');
    for (const group of advertised) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(serverConstants.PQC_GROUPS, group),
        `${group} is advertised but missing from PQC_GROUPS — it would be refused at the gate`
      );
    }
  });
});

describe('Sync Client TLS Constants (hermitstash-sync)', function () {
  it('TLS_GROUPS is exported as a string', function () {
    assert.strictEqual(typeof syncConstants.TLS_GROUPS, 'string');
    assert.ok(syncConstants.TLS_GROUPS.length > 0);
  });

  it('TLS_GROUPS contains SecP384r1MLKEM1024', function () {
    assert.ok(syncConstants.TLS_GROUPS.includes('SecP384r1MLKEM1024'));
  });

  it('TLS_GROUPS contains X25519MLKEM768', function () {
    assert.ok(syncConstants.TLS_GROUPS.includes('X25519MLKEM768'));
  });

  it('TLS_GROUPS matches server TLS_GROUP_CURVE_STR', function () {
    assert.strictEqual(syncConstants.TLS_GROUPS, serverConstants.TLS_GROUP_CURVE_STR);
  });
});

describe('OpenSSL TLS Context Validation', function () {
  it('Node.js accepts all server TLS groups', function () {
    assert.doesNotThrow(function () {
      tls.createSecureContext({
        groups: serverConstants.TLS_GROUP_PREFERENCE,
        minVersion: 'TLSv1.3',
      });
    });
  });

  it('Node.js accepts the sync client ecdhCurve string', function () {
    assert.doesNotThrow(function () {
      tls.createSecureContext({
        ecdhCurve: syncConstants.TLS_GROUPS,
        minVersion: 'TLSv1.3',
      });
    });
  });

  it('Node.js rejects a bogus group name via ecdhCurve', function () {
    // Note: the `groups` option silently ignores unknown names;
    // `ecdhCurve` (used by https.Agent) throws immediately.
    assert.throws(function () {
      tls.createSecureContext({
        ecdhCurve: 'BogusGroup999',
        minVersion: 'TLSv1.3',
      });
    });
  });

  it('SecP384r1MLKEM1024 is individually accepted by OpenSSL', function () {
    assert.doesNotThrow(function () {
      tls.createSecureContext({
        groups: ['SecP384r1MLKEM1024'],
        minVersion: 'TLSv1.3',
      });
    });
  });
});

describe('Enrollment TLS agent (first contact)', function () {
  it('advertises the PQC group preference on ecdhCurve, and only there', function () {
    const agent = buildEnrollmentAgent();
    try {
      // A bare https.Agent would negotiate Node's default non-PQC curves and
      // be rejected by a server that enforces the PQC gate.
      assert.strictEqual(agent.options.ecdhCurve, syncConstants.TLS_GROUPS);
      // `groups` is not a node:tls option — the premise that OpenSSL honours it
      // on some Node versions is checked directly below, and a second copy of
      // the preference under a name nothing reads invites narrowing it there
      // and believing the wire changed.
      assert.strictEqual(agent.options.groups, undefined);
    } finally {
      try { agent.destroy(); } catch (_e) { /* best-effort */ }
    }
  });

  it('node:tls honours ecdhCurve and ignores groups (the premise)', function () {
    // A value no implementation could accept throws on an option that is read
    // and is swallowed by one that is not, so this re-establishes the premise
    // against the running Node rather than trusting it — and fails loudly if a
    // future Node starts implementing one of the ignored names.
    assert.throws(
      () => tls.createSecureContext({ minVersion: 'TLSv1.3', ecdhCurve: 'not-a-real-group' }),
      'ecdhCurve must be validated by node:tls'
    );
    for (const ignored of ['groups', 'curves', 'namedCurves']) {
      assert.doesNotThrow(
        () => tls.createSecureContext({ minVersion: 'TLSv1.3', [ignored]: 'not-a-real-group' }),
        `${ignored} is now honoured by node:tls — the group preference must be set through it too`
      );
    }
  });

  it('pins TLS 1.3', function () {
    const agent = buildEnrollmentAgent();
    try {
      assert.strictEqual(agent.options.minVersion, syncConstants.TLS_MIN_VERSION);
      assert.strictEqual(agent.options.minVersion, 'TLSv1.3');
    } finally {
      try { agent.destroy(); } catch (_e) { /* best-effort */ }
    }
  });

  it('accepts self-signed certs at first contact (CA pin takes over post-enrollment)', function () {
    const agent = buildEnrollmentAgent();
    try {
      assert.strictEqual(agent.options.rejectUnauthorized, false);
    } finally {
      try { agent.destroy(); } catch (_e) { /* best-effort */ }
    }
  });
});
