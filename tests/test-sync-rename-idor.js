'use strict';

/**
 * Cross-bundle IDOR tests for /sync/rename.
 *
 * test-bundle-ownership.js already covers cross-USER rename (user A rejects
 * user B's key). This suite targets the cross-BUNDLE gap: given a single
 * user who owns multiple sync bundles, can a rename request against
 * bundle A accidentally mutate a file in bundle B that happens to share
 * the same relativePath?
 *
 * The server's handleSyncFileRename() scopes the file lookup by
 * bundleId, so the happy-path answer is "no" — but this has three
 * independent scoping gates (bundleId DB filter, boundBundleId key
 * scope, sync bundleType check) and one regression in any of them
 * would silently reintroduce the vulnerability.
 *
 * Coverage:
 *   - Same relativePath in two bundles → rename of bundle A's copy
 *     leaves bundle B's copy unchanged
 *   - boundBundleId-scoped key can't rename files in other bundles
 *   - Non-sync bundles reject rename entirely
 *   - oldRelativePath that doesn't exist in the bundle → 404
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  httpRequest, encryptedRequest, sleep, sha3, runDbScript, createBundleViaDb,
} = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
  // mTLS materials for blamejs apiEncrypt — POST /sync/rename requires
  // a Bearer-authed mTLS client (per server v1.9.15).
  clientCert: process.env.HERMITSTASH_TEST_CLIENT_CERT,
  clientKey:  process.env.HERMITSTASH_TEST_CLIENT_KEY,
  caCert:     process.env.HERMITSTASH_TEST_CA_CERT,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * Seed a file row in a given bundle. Returns { fileId, relativePath }.
 * Uses the real files-table schema seen in lib/db.js COLUMNS.
 */
function seedFile(bundleId, relativePath) {
  var fileId = b.crypto.generateToken(32);
  var now = new Date().toISOString();
  var script = [
    'db.prepare("INSERT INTO files (_id, bundleId, originalName, relativePath, storagePath, size, mimeType, checksum, encryptionKey, seq, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(fileId) + ',',
    '    ' + JSON.stringify(bundleId) + ',',
    '    ' + JSON.stringify(require('node:path').basename(relativePath)) + ',',
    '    ' + JSON.stringify(relativePath) + ',',
    '    ' + JSON.stringify('nowhere/' + fileId) + ',',
    '    0, "text/plain",',
    '    ' + JSON.stringify('0'.repeat(128)) + ',',
    '    ' + JSON.stringify('') + ',',
    '    1, "complete", ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to seed file: ' + out);
  return { fileId: fileId, relativePath: relativePath };
}

// Files.relativePath is vault-sealed at rest, so we can't compare it by
// reading the column directly. Instead we probe by ATTEMPTING a rename
// against the expected path — if it still resolves (200), the file is
// still there; if the server returns 404, the file has been moved/removed.
async function fileStillAtPath(bundleId, relativePath) {
  var res = await renameReq(ctx.apiKey, {
    bundleId: bundleId,
    oldRelativePath: relativePath,
    // We don't want to actually rename during the probe — so pick a fresh
    // name and then rename it back if the probe succeeded. Tests are
    // sequenced so this round-trip is safe per-test.
    newRelativePath: '__probe_' + b.crypto.generateToken(4) + '.txt',
  });
  if (res.statusCode === 200) {
    // Restore the original path so the test's follow-up assertions see a clean state.
    // Extract the probed name back out of the response's decrypted body if present;
    // otherwise just leave the probe rename — the test only needs the boolean result.
    return true;
  }
  return false;
}

/**
 * Insert a sync-scoped key bound to a specific bundleId. Returns the raw
 * token. Use to test boundBundleId enforcement independently of ownerId.
 */
function createBoundSyncKey(bundleId) {
  var raw = 'hs_' + b.crypto.generateToken(32);
  var keyHash = sha3(raw);
  var prefix = raw.substring(0, 7);
  var id = b.crypto.generateToken(32);
  var now = new Date().toISOString();
  var script = [
    // Bind to the oldest user (same ownerId as createBundleViaDb uses)
    'var users = db.prepare("SELECT _id FROM users ORDER BY createdAt ASC LIMIT 1").all();',
    'var userId = users.length > 0 ? users[0]._id : "system";',
    'db.prepare("INSERT INTO api_keys (_id, name, keyHash, prefix, permissions, userId, boundBundleId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(' + JSON.stringify(id) + ', "e2e-bound", ' + JSON.stringify(keyHash) + ', ' + JSON.stringify(prefix) + ', "sync", userId, ' + JSON.stringify(bundleId) + ', ' + JSON.stringify(now) + ');',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to create bound key: ' + out);
  return raw;
}

function renameReq(bearerToken, body) {
  return encryptedRequest(ctx, '/sync/rename', { body: body, apiKey: bearerToken });
}

describe('Sync rename cross-bundle IDOR', { timeout: 15000 }, function () {

  it('renaming a path in bundle A does not affect the same path in bundle B', async function () {
    // Same user owns both bundles, both have a file at "shared.txt".
    // Rename the one in bundle A; bundle B's file must be untouched.
    var bundleA = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var bundleB = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var fileA = seedFile(bundleA.bundleId, 'shared.txt');
    var fileB = seedFile(bundleB.bundleId, 'shared.txt');
    await sleep(100);

    var res = await renameReq(ctx.apiKey, {
      bundleId: bundleA.bundleId,
      oldRelativePath: 'shared.txt',
      newRelativePath: 'renamed-in-A.txt',
    });
    assert.equal(res.statusCode, 200, 'rename in A should succeed, got ' + res.statusCode + ' ' + (res.body || ''));

    // Probe: bundle A should NO LONGER have shared.txt (the rename worked)
    // and bundle B SHOULD still have shared.txt (unaffected by A's rename).
    var aStillThere = await fileStillAtPath(bundleA.bundleId, 'shared.txt');
    assert.equal(aStillThere, false, 'bundle A shared.txt should be gone after rename');
    var bStillThere = await fileStillAtPath(bundleB.bundleId, 'shared.txt');
    assert.equal(bStillThere, true, 'bundle B shared.txt should still exist (NOT renamed by A\'s request)');
    // fileA and fileB references silence lint — used for clarity + future debugging
    void fileA; void fileB;
  });

  it('rename request from a bundle-A-bound key targeting bundle B is rejected', async function () {
    // Key is sync-scoped AND boundBundleId-locked to bundle A.
    // Attempts against bundle B must fail regardless of ownership.
    var bundleA = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var bundleB = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    seedFile(bundleB.bundleId, 'target.txt');
    var keyForA = createBoundSyncKey(bundleA.bundleId);
    await sleep(100);

    var res = await renameReq(keyForA, {
      bundleId: bundleB.bundleId,
      oldRelativePath: 'target.txt',
      newRelativePath: 'pwned.txt',
    });
    // Either 403 (scope mismatch) or 404 (bundle not found from this key's view)
    assert.ok(res.statusCode === 403 || res.statusCode === 404,
      'bound-to-A key → bundle B rename should be 403/404, got ' + res.statusCode + ' ' + (res.body || ''));
  });

  it('rename on a non-sync (snapshot) bundle is rejected', async function () {
    var bundle = createBundleViaDb(ctx.dbPath, { bundleType: 'default' });
    seedFile(bundle.bundleId, 'cant-rename.txt');
    await sleep(100);

    var res = await renameReq(ctx.apiKey, {
      bundleId: bundle.bundleId,
      oldRelativePath: 'cant-rename.txt',
      newRelativePath: 'whatever.txt',
    });
    assert.ok(res.statusCode >= 400 && res.statusCode < 500,
      'non-sync bundle rename → 4xx, got ' + res.statusCode);
  });

  it('rename of a path that does not exist in the targeted bundle returns 404', async function () {
    // A path that happens to exist in one bundle should not be findable via
    // another bundle's rename request.
    var bundleA = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    var bundleB = createBundleViaDb(ctx.dbPath, { bundleType: 'sync' });
    seedFile(bundleA.bundleId, 'only-in-A.txt');
    await sleep(100);

    var res = await renameReq(ctx.apiKey, {
      bundleId: bundleB.bundleId,
      oldRelativePath: 'only-in-A.txt',
      newRelativePath: 'moved.txt',
    });
    assert.equal(res.statusCode, 404, 'path not in bundle B → 404, got ' + res.statusCode);
  });
});
