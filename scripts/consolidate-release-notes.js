#!/usr/bin/env node
'use strict';
/**
 * Roll up per-patch `release-notes/v<X>.<Y>.<Z>.json` files for any
 * MINOR line OTHER than the current one into a single consolidated
 * `release-notes/v<X>.<Y>.x.json` file. The current minor (derived
 * from `lib/constants.js#VERSION`) stays as per-patch files so the
 * release flow keeps editing one small JSON for the live line.
 *
 * Operate as a MAINTAINER-SIDE step, NOT inside the release flow.
 * Reorganising release-notes/ mid-release would shift the input set
 * after the workflow's release-page-markdown step had already
 * rendered. Run consolidation only between releases.
 *
 * Consolidated file shape:
 *   {
 *     "minor":    "0.8",
 *     "releases": [
 *       { ...same shape as a single v<V>.json... },
 *       ...                    // newest first
 *     ]
 *   }
 *
 * The `generate-changelog-entry.js` lookup falls back to the
 * consolidated file when the per-patch file is absent, so deleting
 * per-patch files after rollup (via `--prune`) keeps the generator
 * working for the historical line.
 *
 * Usage:
 *   node scripts/consolidate-release-notes.js              # preview — writes consolidated files but keeps per-patch
 *   node scripts/consolidate-release-notes.js --prune      # also delete per-patch files after writing consolidated
 *   node scripts/consolidate-release-notes.js --check      # exit non-zero if any rollup is needed (CI use)
 *
 * Idempotent: re-running is safe.
 */

var fs   = require('node:fs');
var path = require('node:path');

var ROOT         = path.resolve(__dirname, '..');
var NOTES_DIR    = path.join(ROOT, 'release-notes');
var CONSTANTS_JS = path.join(ROOT, 'lib', 'constants.js');

function _exit(msg) {
  process.stderr.write('[consolidate-release-notes] ' + msg + '\n');
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) { _exit('cannot read ' + label + ' (' + filePath + '): ' + (e && e.message || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit('malformed JSON in ' + label + ' (' + filePath + '): ' + (e && e.message || e)); }
}

function _currentMinor() {
  var raw;
  try { raw = fs.readFileSync(CONSTANTS_JS, 'utf8'); }
  catch (e) { _exit('cannot read ' + CONSTANTS_JS + ': ' + (e && e.message || e)); }
  var m = raw.match(/VERSION\s*[:=]\s*['"](\d+\.\d+)\.\d+['"]/);
  if (!m) _exit('could not parse VERSION from lib/constants.js');
  return m[1];
}

function _compareVersionsDesc(a, b) {
  var ap = a.split('.').map(Number);
  var bp = b.split('.').map(Number);
  for (var i = 0; i < 3; i += 1) {
    if (ap[i] !== bp[i]) return bp[i] - ap[i];
  }
  return 0;
}

function _scan() {
  if (!fs.existsSync(NOTES_DIR)) _exit('release-notes/ directory missing');
  var entries = fs.readdirSync(NOTES_DIR);
  var perPatchByMinor = {};
  var consolidatedByMinor = {};
  for (var i = 0; i < entries.length; i += 1) {
    var name = entries[i];
    var conMatch = name.match(/^v(\d+\.\d+)\.x\.json$/);
    if (conMatch) {
      consolidatedByMinor[conMatch[1]] = name;
      continue;
    }
    var verMatch = name.match(/^v(\d+\.\d+\.\d+)\.json$/);
    if (!verMatch) continue;
    var version = verMatch[1];
    var minor = version.replace(/\.\d+$/, '');
    if (!perPatchByMinor[minor]) perPatchByMinor[minor] = [];
    var payload = _readJson(path.join(NOTES_DIR, name), 'release-notes/' + name);
    perPatchByMinor[minor].push({ version: version, file: name, payload: payload });
  }
  return { perPatchByMinor: perPatchByMinor, consolidatedByMinor: consolidatedByMinor };
}

function main() {
  var argv      = process.argv.slice(2);
  var pruneMode = argv.indexOf('--prune') !== -1;
  var checkMode = argv.indexOf('--check') !== -1;
  if (pruneMode && checkMode) _exit('--prune and --check are mutually exclusive');

  var currentMinor = _currentMinor();
  var scanned = _scan();
  var needWork = false;
  var summary = [];

  var minors = Object.keys(scanned.perPatchByMinor).sort();
  for (var i = 0; i < minors.length; i += 1) {
    var minor = minors[i];
    if (minor === currentMinor) {
      summary.push('  ' + minor + '.x — current line, leave per-patch (' + scanned.perPatchByMinor[minor].length + ' files)');
      continue;
    }
    var perPatch = scanned.perPatchByMinor[minor];
    perPatch.sort(function (a, b) { return _compareVersionsDesc(a.version, b.version); });
    needWork = true;
    var conName = 'v' + minor + '.x.json';
    var conPath = path.join(NOTES_DIR, conName);

    if (checkMode) {
      summary.push('  ' + minor + '.x — ' + perPatch.length + ' per-patch file(s) need consolidation into ' + conName);
      continue;
    }

    var doc = {
      minor:    minor,
      releases: perPatch.map(function (p) { return p.payload; }),
    };
    fs.writeFileSync(conPath, JSON.stringify(doc, null, 2) + '\n');
    summary.push('  ' + minor + '.x — wrote ' + conName + ' with ' + perPatch.length + ' release(s)');

    if (pruneMode) {
      for (var j = 0; j < perPatch.length; j += 1) {
        fs.unlinkSync(path.join(NOTES_DIR, perPatch[j].file));
        summary.push('             pruned ' + perPatch[j].file);
      }
    }
  }

  process.stderr.write('[consolidate-release-notes] scan:\n' + summary.join('\n') + '\n');

  if (checkMode && needWork) {
    process.stderr.write('[consolidate-release-notes] FAIL — historical minor lines have un-rolled per-patch files\n');
    process.exit(1);
  }
  if (!needWork) {
    process.stderr.write('[consolidate-release-notes] nothing to do\n');
  }
}

main();
