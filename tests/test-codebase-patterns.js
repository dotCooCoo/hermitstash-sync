'use strict';

// Thin shim — the canonical suite lives at scripts/test-codebase-patterns.js
// so docker-e2e.yml can run it without `tests/` on its checkout context.
// `node tests/run-all.js` auto-discovers `tests/test-*.js`, so this file
// re-exports the canonical suite. Edit the scripts/ copy, not this one.
require('../scripts/test-codebase-patterns');
