'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { httpRequest, runDbScript } = require('./test-helpers');

var url = process.env.HERMITSTASH_TEST_URL;
var dbPath = process.env.HERMITSTASH_TEST_DB_PATH;

if (!url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

var VAULT_PREFIX = 'vault:';
var VAULT_AAD_PREFIX = 'vault.aad:';

/**
 * Helper: check if a value looks vault-sealed — either the legacy "vault:"
 * envelope or the AAD-bound "vault.aad:" form. The server AEAD-binds sealed
 * columns to their row identity (table + primary key + column); legacy "vault:"
 * rows still read via dual-read until rewritten.
 */
function isSealed(value) {
  return typeof value === 'string' &&
    (value.startsWith(VAULT_AAD_PREFIX) || value.startsWith(VAULT_PREFIX));
}

/**
 * Vault operations tests.
 *
 * Vault requires WebAuthn (passkey) authentication which cannot be easily
 * automated in E2E tests. These tests verify access control and that
 * vault-related user fields are sealed at rest in the database.
 */
describe('Vault: Access Control', { timeout: 30000 }, function () {

  // The vault routes live under /vault/{status,files,upload,...}. Earlier
  // assertions hit /vault and /vault/api/files which aren't real routes —
  // the server 404'd them and the test accidentally validated bot-guard
  // (which used to fingerprint /vault*) rather than requireAuth. Now /vault/*
  // is in bot-guard skipPaths (Bearer-authed API surface), so the test must
  // hit an actual route to exercise the auth gate.
  it('GET /vault/status without authentication returns 401 or redirect', async function () {
    var res = await httpRequest(url + '/vault/status');
    assert.ok(
      res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 302 || res.statusCode === 303,
      'Unauthenticated vault access should be rejected, got ' + res.statusCode
    );
  });

  it('GET /vault/files without authentication returns 401 or redirect', async function () {
    var res = await httpRequest(url + '/vault/files', {
      headers: { 'Content-Type': 'application/json' },
    });
    assert.ok(
      res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 302 || res.statusCode === 303,
      'Unauthenticated vault API access should be rejected, got ' + res.statusCode
    );
  });
});

describe('Vault: User Field Encryption', { timeout: 30000 }, function () {

  it('vaultEnabled field is sealed in the raw DB', function () {
    var script = [
      'var rows = db.prepare("SELECT vaultEnabled FROM users ORDER BY createdAt ASC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one user');

    var val = rows[0].vaultEnabled;
    // vaultEnabled is in the sealed fields list for users table.
    // If the user has never enabled vault, the value may be null.
    // If it exists, it should be sealed.
    if (val !== null && val !== undefined) {
      assert.ok(isSealed(val),
        'vaultEnabled should be vault-sealed when set, got: ' + String(val).substring(0, 40));
    }
    // If null, that is fine -- user has not enabled vault
  });

  it('vaultPublicKey field is sealed in the raw DB', function () {
    var script = [
      'var rows = db.prepare("SELECT vaultPublicKey FROM users ORDER BY createdAt ASC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one user');

    var val = rows[0].vaultPublicKey;
    // If set, should be sealed. If null, user hasn't set up vault keys.
    if (val !== null && val !== undefined) {
      assert.ok(isSealed(val),
        'vaultPublicKey should be vault-sealed when set, got: ' + String(val).substring(0, 40));
    }
  });

  it('vaultSeed field is sealed in the raw DB (if present)', function () {
    var script = [
      'var rows = db.prepare("SELECT vaultSeed FROM users ORDER BY createdAt ASC LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));
    assert.ok(rows.length >= 1, 'Should have at least one user');

    var val = rows[0].vaultSeed;
    if (val !== null && val !== undefined) {
      assert.ok(isSealed(val),
        'vaultSeed should be vault-sealed when set, got: ' + String(val).substring(0, 40));
    }
  });
});

describe('Vault: Credential Fields', { timeout: 30000 }, function () {

  it('credential records have sealed fields in the raw DB', function () {
    // Credentials may or may not exist in the test DB (depends on whether
    // passkeys have been registered). This test checks the schema is correct
    // when records exist.
    var script = [
      'var rows = db.prepare("SELECT credentialId, publicKey, deviceType FROM credentials LIMIT 1").all();',
      'process.stdout.write(JSON.stringify(rows));',
    ].join('\n');
    var rows = JSON.parse(runDbScript(dbPath, script));

    if (rows.length === 0) {
      // No credentials registered -- that is expected in a test env
      assert.ok(true, 'No credential records to verify (expected in test environment)');
      return;
    }

    var cred = rows[0];
    if (cred.credentialId) {
      assert.ok(isSealed(cred.credentialId),
        'credentialId should be vault-sealed, got: ' + String(cred.credentialId).substring(0, 40));
    }
    if (cred.publicKey) {
      assert.ok(isSealed(cred.publicKey),
        'publicKey should be vault-sealed, got: ' + String(cred.publicKey).substring(0, 40));
    }
  });
});
