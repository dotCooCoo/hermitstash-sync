'use strict';

// verify-release.js — standalone verifier used by the Docker build.
//
// Given a binary, its .sha3-512 checksum file, and its ECDSA .sig file,
// verify both against the pubkey embedded in lib/constants.js. Exits 0 on
// success, nonzero with a message on any failure. No npm deps.
//
// Usage: node scripts/verify-release.js <binary> <binary.sha3-512> <binary.sig>

const fs = require('node:fs');
const crypto = require('node:crypto');
const { AUTOUPDATE_PUBKEY_PEM } = require('../lib/constants');

function die(msg) {
  console.error(`[verify] ${msg}`);
  process.exit(1);
}

const [, , binPath, sumPath, sigPath] = process.argv;
if (!binPath || !sumPath || !sigPath) {
  die('usage: verify-release.js <binary> <binary.sha3-512> <binary.sig>');
}
if (!AUTOUPDATE_PUBKEY_PEM) {
  die('AUTOUPDATE_PUBKEY_PEM not embedded in lib/constants.js — cannot verify');
}

const binary = fs.readFileSync(binPath);
const sumText = fs.readFileSync(sumPath, 'utf8');
const sig = fs.readFileSync(sigPath);

const expected = (sumText.trim().match(/^([0-9a-f]+)/i) || [])[1];
if (!expected) die(`could not parse checksum from ${sumPath}`);
const actual = crypto.createHash('sha3-512').update(binary).digest('hex');
if (expected.toLowerCase() !== actual.toLowerCase()) {
  die(`SHA3-512 mismatch: expected ${expected}, got ${actual}`);
}

const digest = crypto.createHash('sha3-512').update(binary).digest();
const ok = crypto.verify(
  'sha512',
  digest,
  { key: crypto.createPublicKey(AUTOUPDATE_PUBKEY_PEM), dsaEncoding: 'ieee-p1363' },
  sig,
);
if (!ok) die('ECDSA signature verification failed');

console.log(`[verify] OK — ${binPath} passes SHA3-512 + ECDSA P-384 checks`);
