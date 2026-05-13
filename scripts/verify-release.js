'use strict';

// verify-release.js — standalone verifier used by the Docker build,
// the deploy/install.sh installer, and the deploy/update.sh updater.
//
// Given a binary and its .sig file, verify the ECDSA P-384 signature
// over the binary bytes (DER) using the pubkey embedded in
// lib/autoupdate-pubkey.js. Mirrors what `b.selfUpdate.verify` does at
// runtime. Exits 0 on success, nonzero with a message on any failure.
// No npm deps — node:crypto + node:fs only. Critically: this script
// must require ONLY zero-dep modules so contexts that don't ship
// vendor/blamejs (the Dockerfile verify stage, deploy/install.sh,
// deploy/update.sh) can still run it.
//
// The .sha3-512 sidecar argument is preserved for backward compatibility
// with existing Dockerfile / install.sh / update.sh callers, but is
// only used as an informational digest cross-check; the signature is
// the integrity gate. Pass `-` (a dash) when no checksum file is
// available.
//
// Usage: node scripts/verify-release.js <binary> <binary.sha3-512|-> <binary.sig>

const fs = require('node:fs');
const crypto = require('node:crypto');
const { AUTOUPDATE_PUBKEY_PEM } = require('../lib/autoupdate-pubkey');

function die(msg) {
  console.error(`[verify] ${msg}`);
  process.exit(1);
}

const [, , binPath, sumPath, sigPath] = process.argv;
if (!binPath || !sumPath || !sigPath) {
  die('usage: verify-release.js <binary> <binary.sha3-512|-> <binary.sig>');
}
if (!AUTOUPDATE_PUBKEY_PEM) {
  die('AUTOUPDATE_PUBKEY_PEM not embedded in lib/autoupdate-pubkey.js — cannot verify');
}

const binary = fs.readFileSync(binPath);
const sig = fs.readFileSync(sigPath);

const ok = crypto.verify(
  null,
  binary,
  crypto.createPublicKey(AUTOUPDATE_PUBKEY_PEM),
  sig,
);
if (!ok) die('ECDSA signature verification failed');

if (sumPath !== '-' && fs.existsSync(sumPath)) {
  const sumText = fs.readFileSync(sumPath, 'utf8');
  const expected = (sumText.trim().match(/^([0-9a-f]+)/i) || [])[1];
  if (expected) {
    const actual = crypto.createHash('sha3-512').update(binary).digest('hex');
    if (expected.toLowerCase() !== actual.toLowerCase()) {
      die(`SHA3-512 cross-check mismatch: expected ${expected}, got ${actual}`);
    }
  }
}

console.log(`[verify] OK — ${binPath} passes ECDSA P-384 (DER) signature check`);
