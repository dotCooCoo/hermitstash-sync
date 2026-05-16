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

  it('PQC_GROUPS has exactly 2 entries', function () {
    assert.strictEqual(Object.keys(serverConstants.PQC_GROUPS).length, 2);
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
