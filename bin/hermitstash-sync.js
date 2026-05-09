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

const { run } = require('../lib/cli');
run(process.argv.slice(2));
