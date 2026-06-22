#!/usr/bin/env node
'use strict';
/**
 * Workflow-side helper: compute classical (SHA-256) AND PQC-first
 * (SHA3-512) digests of a release artifact (typically a SEA binary)
 * and write each to a sidecar file in `sha256sum` / `sha3sum -a 512`
 * compatible format:
 *
 *   <artifact>.sha256     — `<hex>  <filename>` (one line)
 *   <artifact>.sha3-512   — `<hex>  <filename>` (one line)
 *
 * SHA-256 is the conventional release-checksum operators expect to
 * find on a release page; verify via:
 *
 *   sha256sum -c hermitstash-sync-vX.Y.Z-linux-x64.sha256
 *
 * SHA3-512 is the project's PQC-first hash choice — the auto-update
 * verifier (lib/updater.js) hashes the downloaded binary with
 * SHA3-512 before verifying the embedded P-384 ECDSA signature, so
 * this sidecar matches what the daemon checks against. Verify via:
 *
 *   openssl dgst -sha3-512 hermitstash-sync-vX.Y.Z-linux-x64
 *
 * Invoked from `.github/workflows/release.yml` per matrix job:
 *
 *   node scripts/sha3-digest.js build/hermitstash-sync-vX.Y.Z-linux-x64
 */

var fs     = require('node:fs');
var path   = require('node:path');
var crypto = require('node:crypto');

function fail(msg) {
  process.stderr.write('[release-digests] ' + msg + '\n');
  process.exit(1);
}

// Algorithms emitted, in sidecar order. SHA-256 is the conventional
// release checksum operators run with `sha256sum -c`; SHA3-512 is the
// PQC-first hash the auto-update verifier checks against. The classical
// SHA-256 sidecar must stay, so the file is streamed through node:crypto
// hashers directly — the framework's b.crypto.hashFile only emits the
// SHA-3 family + SHA-512, not SHA-256.
var ALGORITHMS = [
  { name: 'sha256',   ext: 'sha256' },
  { name: 'sha3-512', ext: 'sha3-512' },
];

// Stream the artifact through every hasher in a single pass rather than
// reading the whole binary into memory — SEA bundles are hundreds of MB
// and the workflow runner has a bounded heap. One read stream feeds all
// hashers so the file is read from disk exactly once.
function computeDigests(artifactPath) {
  return new Promise(function (resolve, reject) {
    var hashers = ALGORITHMS.map(function (a) { return crypto.createHash(a.name); });
    var rs = fs.createReadStream(artifactPath);
    rs.on('error', function (e) { reject(e); });
    rs.on('data', function (chunk) {
      for (var i = 0; i < hashers.length; i++) hashers[i].update(chunk);
    });
    rs.on('end', function () {
      resolve(hashers.map(function (h) { return h.digest('hex'); }));
    });
  });
}

function main() {
  var artifactPath = process.argv[2];
  if (!artifactPath) fail('usage: node scripts/sha3-digest.js <artifact-path>');
  try { fs.accessSync(artifactPath, fs.constants.R_OK); }
  catch (e) { fail('cannot read ' + artifactPath + ': ' + (e && e.message || e)); }
  var base = path.basename(artifactPath);
  // Emit BOTH sidecars from one streamed pass so the workflow only has
  // to invoke one script per artifact.
  computeDigests(artifactPath).then(function (digests) {
    for (var i = 0; i < ALGORITHMS.length; i++) {
      var digest = digests[i];
      var sidecarPath = artifactPath + '.' + ALGORITHMS[i].ext;
      fs.writeFileSync(sidecarPath, digest + '  ' + base + '\n');
      process.stderr.write('[release-digests] OK — wrote ' + sidecarPath + '\n');
      process.stderr.write('[release-digests] ' + ALGORITHMS[i].name + ':  ' + digest + '  ' + base + '\n');
    }
  }).catch(function (e) { fail('digest failed: ' + (e && e.message || e)); });
}

if (require.main === module) main();

module.exports = { computeDigests: computeDigests, ALGORITHMS: ALGORITHMS };
