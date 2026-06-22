#!/usr/bin/env node
'use strict';
/**
 * One-time setup: generate the ML-DSA-65 release-signing keypair
 * that the release workflow uses to sign every SEA binary as a
 * PQC-first sidecar (`<binary>.mldsa.sig`).
 *
 * Run this ONCE locally before the first PQC-signed release. The
 * script:
 *   - Writes the PUBLIC key to `keys/release-pqc-pub.json` (commit
 *     this file — operators verify against the in-tree pubkey).
 *   - Prints the PRIVATE key (base64url) to stdout. Store as the
 *     `RELEASE_PQC_SIGNING_KEY` secret on the GitHub Actions
 *     repository (or in the release environment if one is in use).
 *   - Prints the public-key fingerprint (SHA3-512 of the raw
 *     public-key bytes). Add to SECURITY.md / README.md so operators
 *     can verify the in-tree pubkey out of band against the
 *     commit-signed reference.
 *
 * Re-running this script ROTATES the key. To rotate:
 *   1. Run this script (overwrites keys/release-pqc-pub.json).
 *   2. Update `RELEASE_PQC_SIGNING_KEY` secret.
 *   3. Update SECURITY.md / README.md with the new fingerprint.
 *   4. Commit + ship a release.
 *   Previously-signed releases remain verifiable against the OLD
 *   public key — operators can `git log keys/release-pqc-pub.json`
 *   to walk the history.
 *
 * Algorithm: ML-DSA-65 (FIPS 204) — NIST PQC security category 3
 * (~192-bit classical, ~96-bit post-quantum). Independent of the
 * existing P-384 ECDSA auto-update signature — both sigs ship per
 * release; the daemon's in-binary auto-update verifier uses the
 * ECDSA sig (verified with only node:crypto), while operators who
 * want a PQC-only verification posture use the .mldsa.sig sidecar.
 */

var b      = require('../vendor/blamejs');
var fs     = require('node:fs');
var path   = require('node:path');
var crypto = require('node:crypto');

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sha3_512_hex(buf) {
  return crypto.createHash('sha3-512').update(buf).digest('hex');
}

function main() {
  var pair = b.pqcSoftware.ml_dsa_65.keygen();
  var pubBytes = Buffer.from(pair.publicKey);
  var secBytes = Buffer.from(pair.secretKey);
  var fingerprint = sha3_512_hex(pubBytes);
  var pubJson = {
    algorithm:             'ml-dsa-65',
    publicKey:             b64url(pubBytes),
    fingerprint_sha3_512:  fingerprint,
    createdAt:             new Date().toISOString().slice(0, 10),
    rotation_note:         'Re-running scripts/generate-release-signing-key.js rotates the key. Update RELEASE_PQC_SIGNING_KEY secret + the README/SECURITY fingerprint in the same commit.',
  };

  var pubPath = path.resolve(__dirname, '..', 'keys', 'release-pqc-pub.json');
  fs.mkdirSync(path.dirname(pubPath), { recursive: true });
  fs.writeFileSync(pubPath, JSON.stringify(pubJson, null, 2) + '\n');

  process.stderr.write('\n=== ML-DSA-65 release-signing keypair ===\n\n');
  process.stderr.write('Public key written to: ' + pubPath + '\n');
  process.stderr.write('Fingerprint (SHA3-512): ' + fingerprint + '\n\n');
  process.stderr.write('Private key (base64url, paste into RELEASE_PQC_SIGNING_KEY secret):\n');
  process.stderr.write('------------------------\n');
  process.stdout.write(b64url(secBytes) + '\n');
  process.stderr.write('------------------------\n\n');
  process.stderr.write('Next steps:\n');
  process.stderr.write('  1. Verify the public-key write:\n');
  process.stderr.write('       cat ' + pubPath + '\n');
  process.stderr.write('  2. Set the secret on the repo:\n');
  process.stderr.write('       gh secret set RELEASE_PQC_SIGNING_KEY --body "<paste from above>"\n');
  process.stderr.write('  3. Add the fingerprint to the README / SECURITY notes so operators can verify\n');
  process.stderr.write('     the in-tree pubkey out of band.\n');
  process.stderr.write('  4. Commit keys/release-pqc-pub.json, ship a release.\n');
}

main();
