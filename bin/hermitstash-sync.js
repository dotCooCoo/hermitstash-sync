#!/usr/bin/env node
'use strict';

// Node version gate. Floor is 24.14.1 — npm engines is advisory only, so
// check at runtime to fail fast with an actionable error instead of leaking
// a cryptic stack from a 24.14+ API call deep in vendored blamejs (or one of
// the security backports between 24.4 and 24.14.1 we now rely on). SEA users
// carry the embedded Node with them so this only fires for from-source
// installs on a stale runtime.
(function _enforceNodeFloor() {
  var FLOOR = { major: 24, minor: 14, patch: 1 };
  var m = /^v(\d+)\.(\d+)\.(\d+)/.exec(process.versions.node);
  if (!m) return;                                   // unparseable — let it through
  var major = parseInt(m[1], 10);
  var minor = parseInt(m[2], 10);
  var patch = parseInt(m[3], 10);
  // Strict semver-greater-or-equal compare: major > floor, OR equal major
  // with minor > floor, OR equal major+minor with patch >= floor patch.
  if (major > FLOOR.major) return;
  if (major === FLOOR.major) {
    if (minor > FLOOR.minor) return;
    if (minor === FLOOR.minor && patch >= FLOOR.patch) return;
  }
  process.stderr.write(
    'hermitstash-sync requires Node.js 24.14.1 or newer (current: ' +
    process.version + ').\n' +
    'Upgrade Node, then re-run. The SEA binary releases ship with their own\n' +
    'embedded Node and are not affected by your system Node version.\n'
  );
  process.exit(78); // EX_CONFIG (sysexits)
})();

// Boot-time PQC Known-Answer Test. Validates the vendored ML-KEM-1024
// keygen → encapsulate → decapsulate round-trip produces matching 32-byte
// shared secrets before the daemon performs any real crypto. If the
// vendored noble-post-quantum bundle is corrupted or the build truncated
// it (vendor-tree refresh gone wrong, partial download, etc.) we fail
// here instead of inside the first apiEncrypt envelope decapsulation
// where the failure mode would be a confusing "session-unknown" loop.
(function _runPqcKAT() {
  try {
    var b = require('../vendor/blamejs');
    var r = b.pqcSoftware.runKnownAnswerTest();
    if (!r || !r.ok) {
      process.stderr.write(
        'hermitstash-sync: PQC self-test failed (' +
        (r && r.reason ? r.reason : 'unknown') + ').\n' +
        'The vendored cryptographic bundle in vendor/blamejs/ may be\n' +
        'corrupted. Re-clone the repository or refresh vendor/blamejs/.\n'
      );
      process.exit(70); // EX_SOFTWARE
    }
  } catch (e) {
    process.stderr.write(
      'hermitstash-sync: PQC self-test threw (' + e.message + ').\n'
    );
    process.exit(70);
  }
})();

// Vendor-tree integrity check. Re-hash every consumed blamejs entry
// point against the recorded SHA256s in vendor/MANIFEST.json and refuse
// to start on mismatch. Catches a half-applied vendor refresh, a
// corrupted clone, or post-commit tampering with a vendored cjs that
// would silently swap a primitive's behavior. The manifest is populated
// by `node scripts/vendor-hash.js` after every vendor refresh; CI / the
// release workflow should run that script's output against HEAD to
// detect drift.
//
// SEA bypass: when running as a Single Executable Application (Node ≥21
// `node:sea`), the vendor tree is bundled into the binary and there's no
// vendor/ sibling directory on disk to re-hash. SEA integrity is
// established at release time via the P-384 ECDSA signature over the
// SHA3-512 of the binary, verified by `lib/updater.js` before any swap.
// Running this gate on an SEA would always fail with "MANIFEST.json
// missing", which is exactly what broke v0.6.6 → v0.6.8 docker smoke
// tests. Skip the gate in SEA mode; the from-source integrity check
// remains active for `node bin/hermitstash-sync.js`.
(function _verifyVendorIntegrity() {
  try {
    // node:sea is only available on Node ≥21; older Nodes throw on
    // require. Wrap so a non-SEA Node without the module still proceeds
    // to the gate (the Node-floor gate above already enforces ≥24.14).
    var sea;
    try { sea = require('node:sea'); } catch (_e) { sea = null; }
    if (sea && typeof sea.isSea === 'function' && sea.isSea()) return;

    var b = require('../vendor/blamejs');
    var path = require('node:path');
    // Resolve relative to the bin/ entry, not cwd — the daemon may be
    // launched from any working directory.
    var manifestPath = path.join(__dirname, '..', 'vendor', 'MANIFEST.json');
    var r = b.configDrift.verifyVendorIntegrity({
      manifestPath: manifestPath,
      libVendorDir: path.join(__dirname, '..'),
    });
    if (!r.ok) {
      process.stderr.write(
        'hermitstash-sync: vendor integrity check failed.\n' +
        '  ' + r.mismatches.length + ' file(s) do not match the recorded SHA256 in\n' +
        '  vendor/MANIFEST.json. Mismatches:\n'
      );
      for (var i = 0; i < r.mismatches.length && i < 5; i += 1) {
        var m = r.mismatches[i];
        process.stderr.write('    - ' + m.path + '\n');
      }
      process.stderr.write(
        '  Re-clone the repository or run `node scripts/vendor-hash.js`\n' +
        '  if the vendor was deliberately refreshed.\n'
      );
      process.exit(70); // EX_SOFTWARE
    }
  } catch (e) {
    process.stderr.write(
      'hermitstash-sync: vendor integrity check threw (' + e.message + ').\n'
    );
    process.exit(70);
  }
})();

const { run } = require('../lib/cli');
run(process.argv.slice(2));
