#!/usr/bin/env node
'use strict';

// codebase-patterns:allow-file process-exit — boot-time gates terminate via process.exit() to surface fail-fast diagnostics before any side effects.
// codebase-patterns:allow-file inline-require — each IIFE gate cold-loads the blamejs vendor lazily; hoisting would run unrelated boot code before the Node-floor check.

// Node version gate. Floor is 24.18.0 — npm engines is advisory only, so
// check at runtime to fail fast with an actionable error instead of leaking
// a cryptic stack from a 24.18+ API call deep in vendored blamejs (or one of
// the security backports between 24.4 and 24.18.0 we now rely on). SEA users
// carry the embedded Node with them so this only fires for from-source
// installs on a stale runtime.
(function _enforceNodeFloor() {
  var FLOOR = { major: 24, minor: 18, patch: 0 }; // allow:raw-byte-literal — semver triple (Node 24.18.0), not byte sizes
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
    'hermitstash-sync requires Node.js 24.18.0 or newer (current: ' +
    process.version + ').\n' +
    'Upgrade Node, then re-run. The SEA binary releases ship with their own\n' +
    'embedded Node and are not affected by your system Node version.\n'
  );
  process.exit(78); // EX_CONFIG (sysexits)
})();

// Vendor-tree integrity PRECHECK — must run before any vendored code is
// loaded. The PQC self-test below require()s vendor/blamejs, which executes the
// vendored bundle's import-time code (including noble-post-quantum.cjs); the
// configDrift-based integrity gate further down is itself part of blamejs, so
// by the time it runs the very modules it validates have already executed. A
// tampered *.cjs would therefore get one boot-time arbitrary-code execution
// before the after-the-fact check could refuse it. This pass uses ONLY node:fs
// + node:crypto + node:path — no vendored code — to re-hash every consumed file
// against the recorded SHA256s FIRST, making the integrity check a true
// precondition for loading the bundle. SEA bypass mirrors the gate below (the
// vendor tree is embedded in the binary, not on disk to re-hash).
(function _verifyVendorIntegrityPreload() {
  try {
    var sea;
    try { sea = require('node:sea'); } catch (_e) { sea = null; }
    if (sea && typeof sea.isSea === 'function' && sea.isSea()) return;

    var nodeFs = require('node:fs');
    var nodeCrypto = require('node:crypto');
    var nodePath = require('node:path');
    var root = nodePath.join(__dirname, '..');
    // The manifest is a trusted in-repo file; cap the read defensively anyway,
    // mirroring b.safeJson's ceiling (which isn't loadable this early).
    var manifestRaw = nodeFs.readFileSync(nodePath.join(root, 'vendor', 'MANIFEST.json'), 'utf8');
    if (manifestRaw.length > 1048576) {                                          // allow:raw-byte-literal — 1 MiB manifest ceiling
      process.stderr.write('hermitstash-sync: vendor/MANIFEST.json is implausibly large — refusing.\n');
      process.exit(70);
    }
    // b.safeJson is unavailable before the vendored bundle is loaded + verified;
    // JSON.parse on this trusted, size-capped in-repo manifest is the bootstrap
    // exception this whole precheck exists to enable.
    var manifest = JSON.parse(manifestRaw);                                      // allow:bare-json-parse — pre-vendor-load precheck; b.safeJson not yet loadable; trusted size-capped in-repo manifest
    var pkgs = (manifest && manifest.packages) || {};
    var mismatches = [];
    var checkedCount = 0;
    function _checkFiles(files, hashes, baseDir) {
      for (var kind in files) {
        if (!Object.prototype.hasOwnProperty.call(files, kind)) continue;
        var rel = files[kind];
        var expected = hashes && hashes[kind];
        if (typeof rel !== 'string' || typeof expected !== 'string') continue;
        var actual;
        try {
          actual = 'sha256:' + nodeCrypto.createHash('sha256').update(nodeFs.readFileSync(nodePath.join(baseDir, rel))).digest('hex');
        } catch (_e) {
          actual = '<read-failed>';
        }
        checkedCount += 1;
        if (actual !== expected) mismatches.push(rel);
      }
    }
    for (var name in pkgs) {
      if (!Object.prototype.hasOwnProperty.call(pkgs, name)) continue;
      var pkg = pkgs[name];
      if (!pkg || !pkg.files || !pkg.hashes) continue;
      // Top-level files.<kind> are paths from the repo root (e.g.
      // "vendor/blamejs/lib/ws-client.js"); transitive files.server are
      // relative to the package directory (e.g. "lib/vendor/noble-curves.cjs").
      _checkFiles(pkg.files, pkg.hashes, root);
      var transitiveBase = nodePath.join(root, (typeof pkg.directory === 'string' ? pkg.directory : ('vendor/' + name)));
      // Also verify the transitive bundles (noble-curves, peculiar-pki,
      // simplewebauthn-server, …) that blamejs require()s at load time. Their
      // per-file hashes live under transitive.packages (projected for the
      // SBOM); without this they would execute at boot BEFORE any integrity
      // check — the exact boot-time arbitrary-code-execution window this
      // preload precheck exists to close. The .cjs bundles run on require; the
      // data payloads (.txt) get the same hash coverage for free.
      var tp = pkg.transitive && pkg.transitive.packages;
      if (tp && typeof tp === 'object') {
        for (var tk in tp) {
          if (!Object.prototype.hasOwnProperty.call(tp, tk)) continue;
          var tpkg = tp[tk];
          if (tpkg && tpkg.files && tpkg.hashes) _checkFiles(tpkg.files, tpkg.hashes, transitiveBase);
        }
      }
    }
    // Coverage floor: a manifest stripped of its files/hashes maps (a botched
    // refresh, a partial clone, or tampering) would otherwise verify ZERO files
    // and pass silently. The gate's job is to verify the vendored tree —
    // verifying nothing is a failure, not a success.
    if (checkedCount === 0) {
      process.stderr.write(
        'hermitstash-sync: vendor integrity precheck verified 0 files —\n' +
        '  vendor/MANIFEST.json has no files/hashes to check. Refusing.\n' +
        '  Re-clone the repository or run `node scripts/vendor-hash.js`.\n'
      );
      process.exit(70);
    }
    if (mismatches.length > 0) {
      process.stderr.write(
        'hermitstash-sync: vendor integrity precheck failed.\n' +
        '  ' + mismatches.length + ' file(s) do not match the recorded SHA256 in\n' +
        '  vendor/MANIFEST.json. Mismatches:\n'
      );
      for (var i = 0; i < mismatches.length && i < 5; i += 1) {
        process.stderr.write('    - ' + mismatches[i] + '\n');
      }
      process.stderr.write(
        '  Re-clone the repository or run `node scripts/vendor-hash.js`\n' +
        '  if the vendor was deliberately refreshed.\n'
      );
      process.exit(70); // EX_SOFTWARE
    }
  } catch (e) {
    process.stderr.write('hermitstash-sync: vendor integrity precheck threw (' + e.message + ').\n');
    process.exit(70);
  }
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
    var nodePath = require('node:path');
    // Resolve relative to the bin/ entry, not cwd — the daemon may be
    // launched from any working directory.
    var manifestPath = nodePath.join(__dirname, '..', 'vendor', 'MANIFEST.json');
    var r = b.configDrift.verifyVendorIntegrity({
      manifestPath: manifestPath,
      libVendorDir: nodePath.join(__dirname, '..'),
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

// Vendor-data integrity gate. blamejs v0.9.8+ ships its three vendored data
// files (PSL, common-passwords, BIMI trust anchors) as `require()`-resolved
// CJS modules with four orthogonal trust layers: SHA-256 + SHA3-512 +
// SLH-DSA-SHAKE-256f signature + in-payload canary. `b.vendorData.verifyAll`
// forces eager verification of every registered entry up front, so a
// tampered install fails at boot instead of at first PSL lookup. This is
// orthogonal to the JS-file integrity check above — that one re-hashes the
// consumed source files, this one verifies the bundled data payloads. Both
// run on every boot; mismatches in either are EX_SOFTWARE.
(function _verifyVendorData() {
  try {
    var b = require('../vendor/blamejs');
    if (b.vendorData && typeof b.vendorData.verifyAll === 'function') {
      b.vendorData.verifyAll();
    }
  } catch (e) {
    process.stderr.write(
      'hermitstash-sync: vendor data integrity check failed (' +
      (e && e.message ? e.message : 'unknown') + ').\n' +
      '  One of the bundled data files (PSL / common-passwords / BIMI\n' +
      '  anchors) failed dual-hash + SLH-DSA + canary verification.\n' +
      '  Re-clone the repository or refresh vendor/blamejs/.\n'
    );
    process.exit(70); // EX_SOFTWARE
  }
})();

const { run } = require('../lib/cli');
// Backstop any async command path that rejects before it installs its own
// handlers (e.g. a corrupt config.json read deep in a command). Without this
// such a rejection escapes as a raw stack + unhandledRejection. Surface the
// message and preserve exit code 1.
run(process.argv.slice(2)).catch((err) => {
  process.stderr.write((err && err.message ? err.message : String(err)) + '\n');
  process.exit(1);                                                              // allow:process-exit — top-level rejection backstop; exit 1 mirrors die()
});
