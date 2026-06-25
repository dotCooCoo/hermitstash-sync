'use strict';

// verify-release.js — release-asset CLI shim around blamejs's node:-builtins-only
// `b.selfUpdate.standaloneVerifier`. Used by the Docker verify stage,
// `deploy/install.sh`, and `deploy/update.sh` — all contexts that run
// BEFORE vendor/blamejs is on disk. The verifier itself lives at
// `scripts/standalone-verifier.js`, vendored verbatim from
// `vendor/blamejs/lib/self-update-standalone-verifier.js` so we can
// ship it alongside this CLI without dragging the full b.* surface
// into the install pipeline. The pubkey at `lib/autoupdate-pubkey.js`
// is operator-owned (this repo's release key).
//
// Algorithm + format are detected by the standalone verifier from the
// signature's ASN.1 structure, not its byte length: an ECDSA signature that
// parses as a DER SEQUENCE{INTEGER r, INTEGER s} is verified as DER; otherwise
// an exactly-96-byte pair is verified as IEEE-P1363 r||s; anything else fails
// closed. The digest is SHA3-512.
//   - ECDSA P-384 (DER over SHA3-512) — what release.yml emits
//   - ECDSA P-384 (IEEE-P1363 r||s, 96 bytes) — also accepted
//   - Ed25519, ML-DSA-87 — accepted if the pubkey SPKI matches
//
// The .sha3-512 sidecar argument is preserved for backward compat with
// the old Dockerfile / install.sh / update.sh callers, but is only used
// as an informational digest cross-check; the signature is the integrity
// gate. Pass `-` (a dash) when no checksum file is available.
//
// Usage: node scripts/verify-release.js <binary> <binary.sha3-512|-> <binary.sig>

const fs = require('node:fs');
const verifier = require('./standalone-verifier');
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

let result;
try {
  result = verifier.verify(binPath, sigPath, AUTOUPDATE_PUBKEY_PEM);
} catch (err) {
  die(`signature verification failed: ${err && err.message ? err.message : String(err)}`);
}
if (!result || !result.ok) die('ECDSA signature verification failed');

if (sumPath !== '-' && fs.existsSync(sumPath)) {
  const sumText = fs.readFileSync(sumPath, 'utf8');
  const expected = (sumText.trim().match(/^([0-9a-f]+)/i) || [])[1];
  // The caller named a checksum file (it is not the `-` sentinel) and the
  // file exists, so it MUST yield a hex digest to compare against. A sidecar
  // that parses to nothing — corrupted, BOM-prefixed, an error page saved by
  // a failed download, a leading-whitespace line — is a fail-closed error,
  // not a silent skip; collapsing it into the no-checksum path would tell the
  // operator the digest was cross-checked when it never was. The signature is
  // still the primary gate, but a malformed sidecar means the artifact set is
  // not what was published — refuse it.
  if (!expected) {
    die(`SHA3-512 sidecar ${sumPath} contains no parseable hex digest — ` +
        `re-download the .sha3-512 file or pass '-' if no checksum is available`);
  }
  if (expected.toLowerCase() !== result.sha3_512.toLowerCase()) {
    die(`SHA3-512 cross-check mismatch: expected ${expected}, got ${result.sha3_512}`);
  }
}

console.log(`[verify] OK — ${binPath} passes ${result.alg} signature check`);
