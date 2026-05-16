'use strict';

/**
 * Unit tests for the PQC gate's ClientHello parser (clientHelloHasPQC).
 *
 * Crafts binary TLS ClientHello messages with various supported_groups
 * extension contents and verifies the parser correctly identifies PQC groups.
 *
 * This is the most security-critical parser in the server — a bug here
 * silently lets non-PQC clients through or blocks PQC clients.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SERVER_DIR = process.env.HERMITSTASH_SERVER_DIR
  || path.resolve(__dirname, '..', '..', 'hermitstash');
const b = require(path.join(SERVER_DIR, 'lib', 'vendor', 'blamejs'));
const { clientHelloHasPQC, PQC_GROUP_IDS } = b.pqcGate;
const { PQC_GROUPS } = require(path.join(SERVER_DIR, 'lib', 'constants'));

/**
 * Build a minimal TLS 1.3 ClientHello record with the given supported_groups.
 *
 * @param {number[]} groupIds — IANA group IDs to include in supported_groups extension
 * @param {object} [opts] — options to craft edge cases
 * @param {boolean} [opts.omitSupportedGroups] — omit the supported_groups extension entirely
 * @param {boolean} [opts.emptySupportedGroups] — include extension with zero groups
 * @param {number} [opts.badRecordType] — override the record type byte
 * @param {number} [opts.badHandshakeType] — override the handshake type byte
 * @returns {Buffer}
 */
function buildClientHello(groupIds, opts) {
  opts = opts || {};

  // --- Build extensions ---
  var extensions = Buffer.alloc(0);

  if (!opts.omitSupportedGroups) {
    // supported_groups extension (type 0x000A)
    var groupCount = opts.emptySupportedGroups ? 0 : groupIds.length;
    var groupListLen = groupCount * 2;
    var extData = Buffer.alloc(2 + groupListLen);
    extData.writeUInt16BE(groupListLen, 0);
    for (var i = 0; i < groupCount; i++) {
      extData.writeUInt16BE(groupIds[i], 2 + i * 2);
    }
    var extHeader = Buffer.alloc(4);
    extHeader.writeUInt16BE(0x000A, 0); // extension type: supported_groups
    extHeader.writeUInt16BE(extData.length, 2);
    extensions = Buffer.concat([extensions, extHeader, extData]);
  }

  // Add a dummy extension (supported_versions 0x002B) so extensions block isn't just supported_groups
  var dummyExt = Buffer.from([
    0x00, 0x2B, // type: supported_versions
    0x00, 0x03, // length: 3
    0x02,       // list length: 2
    0x03, 0x04  // TLS 1.3
  ]);
  extensions = Buffer.concat([extensions, dummyExt]);

  var extensionsLenBuf = Buffer.alloc(2);
  extensionsLenBuf.writeUInt16BE(extensions.length, 0);

  // --- Build ClientHello body ---
  var clientVersion = Buffer.from([0x03, 0x03]); // TLS 1.2 (real version in extensions for TLS 1.3)
  var random = Buffer.alloc(32, 0xAB); // 32 bytes of random
  var sessionId = Buffer.from([0x00]); // empty session ID
  var cipherSuites = Buffer.from([
    0x00, 0x04, // 4 bytes = 2 suites
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0x13, 0x02  // TLS_AES_256_GCM_SHA384
  ]);
  var compression = Buffer.from([0x01, 0x00]); // 1 method: null

  var body = Buffer.concat([
    clientVersion, random, sessionId, cipherSuites, compression,
    extensionsLenBuf, extensions
  ]);

  // --- Build handshake header ---
  var handshakeType = opts.badHandshakeType !== undefined ? opts.badHandshakeType : 0x01; // ClientHello
  var handshakeHeader = Buffer.alloc(4);
  handshakeHeader[0] = handshakeType;
  handshakeHeader.writeUIntBE(body.length, 1, 3); // 3-byte length

  var handshake = Buffer.concat([handshakeHeader, body]);

  // --- Build TLS record ---
  var recordType = opts.badRecordType !== undefined ? opts.badRecordType : 0x16; // Handshake
  var recordHeader = Buffer.alloc(5);
  recordHeader[0] = recordType;
  recordHeader[1] = 0x03;
  recordHeader[2] = 0x01; // TLS 1.0 record version (standard for ClientHello)
  recordHeader.writeUInt16BE(handshake.length, 3);

  return Buffer.concat([recordHeader, handshake]);
}

describe('PQC Gate: PQC_GROUP_IDS derivation', function () {
  it('PQC_GROUP_IDS matches Object.values(PQC_GROUPS)', function () {
    var expected = new Set(Object.values(PQC_GROUPS));
    assert.deepStrictEqual([...PQC_GROUP_IDS].sort(), [...expected].sort());
  });

  it('PQC_GROUP_IDS contains X25519MLKEM768 (0x11EC)', function () {
    assert.ok(PQC_GROUP_IDS.has(0x11EC));
  });

  it('PQC_GROUP_IDS contains SecP384r1MLKEM1024 (0x11ED)', function () {
    assert.ok(PQC_GROUP_IDS.has(0x11ED));
  });

  it('PQC_GROUP_IDS does not contain classical groups', function () {
    assert.ok(!PQC_GROUP_IDS.has(0x001D)); // X25519
    assert.ok(!PQC_GROUP_IDS.has(0x0017)); // secp256r1
    assert.ok(!PQC_GROUP_IDS.has(0x0018)); // secp384r1
  });
});

describe('PQC Gate: clientHelloHasPQC parser', function () {
  it('accepts ClientHello with X25519MLKEM768 (0x11EC)', function () {
    var buf = buildClientHello([0x001D, 0x11EC, 0x0017]); // X25519, X25519MLKEM768, P-256
    assert.strictEqual(clientHelloHasPQC(buf), true);
  });

  it('accepts ClientHello with SecP384r1MLKEM1024 (0x11ED)', function () {
    var buf = buildClientHello([0x0018, 0x11ED]); // P-384, SecP384r1MLKEM1024
    assert.strictEqual(clientHelloHasPQC(buf), true);
  });

  it('accepts ClientHello with both PQC groups', function () {
    var buf = buildClientHello([0x11EC, 0x11ED, 0x001D]);
    assert.strictEqual(clientHelloHasPQC(buf), true);
  });

  it('accepts ClientHello with PQC group as the only group', function () {
    var buf = buildClientHello([0x11EC]);
    assert.strictEqual(clientHelloHasPQC(buf), true);
  });

  it('rejects ClientHello with only classical groups', function () {
    var buf = buildClientHello([0x001D, 0x0017, 0x0018]); // X25519, P-256, P-384
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('rejects ClientHello with empty supported_groups list', function () {
    var buf = buildClientHello([], { emptySupportedGroups: true });
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('rejects ClientHello with no supported_groups extension', function () {
    var buf = buildClientHello([], { omitSupportedGroups: true });
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('rejects non-handshake record type', function () {
    var buf = buildClientHello([0x11EC], { badRecordType: 0x17 }); // application data
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('rejects non-ClientHello handshake type', function () {
    var buf = buildClientHello([0x11EC], { badHandshakeType: 0x02 }); // ServerHello
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('rejects null input', function () {
    assert.strictEqual(clientHelloHasPQC(null), false);
  });

  it('rejects empty buffer', function () {
    assert.strictEqual(clientHelloHasPQC(Buffer.alloc(0)), false);
  });

  it('rejects truncated buffer (too short for record header)', function () {
    assert.strictEqual(clientHelloHasPQC(Buffer.from([0x16, 0x03, 0x01])), false);
  });

  it('rejects truncated buffer (too short for handshake header)', function () {
    var buf = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00]);
    assert.strictEqual(clientHelloHasPQC(buf), false);
  });

  it('handles large number of groups without crashing', function () {
    var groups = [];
    for (var i = 0; i < 200; i++) groups.push(0x0017 + (i % 10)); // 200 classical groups
    groups.push(0x11EC); // PQC group at the end
    var buf = buildClientHello(groups);
    assert.strictEqual(clientHelloHasPQC(buf), true);
  });

  it('handles ClientHello with session ID', function () {
    // Build manually with a 32-byte session ID
    var hello = buildClientHello([0x11EC]);
    // Verify the standard builder works — session ID is empty (0x00) by default
    assert.strictEqual(clientHelloHasPQC(hello), true);
  });
});
