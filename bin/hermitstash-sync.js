#!/usr/bin/env node
'use strict';

// Node version gate. Vendored blamejs (`vendor/blamejs/package.json` engines)
// requires >=24.4.0 — npm engines is advisory only, so check at runtime to
// fail fast with an actionable error instead of leaking a cryptic stack from
// a 24.4+ API call deep in the framework. SEA users carry the embedded Node
// with them so this only fires for from-source installs on a stale runtime.
(function _enforceNodeFloor() {
  var m = /^v(\d+)\.(\d+)\./.exec(process.versions.node);
  if (!m) return;                                   // unparseable — let it through
  var major = parseInt(m[1], 10);
  var minor = parseInt(m[2], 10);
  if (major > 24 || (major === 24 && minor >= 4)) return;
  process.stderr.write(
    'hermitstash-sync requires Node.js 24.4.0 or newer (current: ' +
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

const { run } = require('../lib/cli');
run(process.argv.slice(2));
