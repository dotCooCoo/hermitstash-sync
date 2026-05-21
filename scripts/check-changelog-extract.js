#!/usr/bin/env node
'use strict';
/**
 * Pre-push static gate — confirm the current version has a
 * structured release-notes entry AND that CHANGELOG.md matches the
 * full JSON tree.
 *
 * Two failure modes catch the common drift cases:
 *   - release-notes/v<version>.json missing for the version that
 *     `lib/constants.js` currently advertises (the workflow's
 *     release-page markdown step would fail on tag push).
 *   - CHANGELOG.md drifts from the JSON tree (someone hand-edited
 *     the markdown rather than the JSON, OR added a JSON entry but
 *     forgot to run `--rebuild`).
 *
 * Exit codes:
 *   0  — both gates pass
 *   1  — release notes missing OR CHANGELOG drift
 *
 * Usage:
 *   node scripts/check-changelog-extract.js          # uses lib/constants.js VERSION
 *   node scripts/check-changelog-extract.js 0.8.23   # explicit version
 *
 * Intended for the test runner and as a pre-tag local sanity check.
 */

var child = require('node:child_process');
var path  = require('node:path');

var GEN = path.resolve(__dirname, 'generate-changelog-entry.js');

function _run(args) {
  var res = child.spawnSync(process.execPath, [GEN].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] });
  return {
    code:   res.status === null ? 1 : res.status,
    stdout: res.stdout ? res.stdout.toString('utf8') : '',
    stderr: res.stderr ? res.stderr.toString('utf8') : '',
  };
}

function main() {
  var explicit = process.argv[2];

  // Gate 1: the current version's JSON exists + validates + renders.
  var renderArgs = explicit ? [explicit, '--release-page'] : ['--release-page'];
  var render = _run(renderArgs);
  if (render.code !== 0) {
    process.stderr.write(render.stderr);
    process.stderr.write('[check-changelog-extract] FAIL — current version has no valid release-notes entry\n');
    process.exit(1);
  }
  if (render.stdout.length < 64) {                                                      // allow:raw-byte-literal — minimum-bytes render-output sanity floor
    process.stderr.write('[check-changelog-extract] FAIL — generator produced suspiciously small release-page markdown (' +
      render.stdout.length + ' bytes); the JSON validated but rendered empty\n');
    process.exit(1);
  }

  // Gate 2: full CHANGELOG.md matches the JSON tree rebuild.
  var check = _run(['--check']);
  process.stderr.write(check.stderr);
  if (check.code !== 0) process.exit(1);

  process.stderr.write('[check-changelog-extract] OK — release notes present + CHANGELOG.md in sync\n');
}

main();
