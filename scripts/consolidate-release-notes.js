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
 * Writing a consolidated file MERGES the per-patch payloads on disk
 * with any release entries already present in an existing
 * `v<minor>.x.json`. Per-patch wins on a version collision; entries
 * the rollup already holds but that no longer have a per-patch source
 * are preserved, never overwritten. A single per-patch file
 * reappearing on a historical line (a backport, a hand-restored note,
 * a revert) therefore extends the rollup instead of replacing it.
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
  // Anchor to the exact `const VERSION = '<semver>'` declaration. An
  // unanchored `VERSION[:=]...` also matches an unrelated `*_VERSION`
  // constant (e.g. `const TLS_MIN_VERSION = 'TLSv1.3'`) and `.match()`
  // returns the FIRST hit, so declaration order would decide which string
  // is extracted. Capturing major + minor from a single-quoted semver
  // triple refuses a non-version literal at the boundary. Sibling
  // generate-changelog-entry.js#_readProjectVersion hardened the identical
  // pattern for the same reason.
  var m = raw.match(/\bconst VERSION\s*=\s*'(\d+)\.(\d+)\.\d+'/);
  if (!m) _exit('could not find `const VERSION = \'<semver>\'` literal in lib/constants.js');
  return m[1] + '.' + m[2];
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

    // Merge, never clobber. Seed a version-keyed map from any existing
    // consolidated rollup so release entries already collapsed into
    // v<minor>.x.json (whose per-patch sources were pruned in a prior
    // run) survive when a single per-patch file reappears on this line.
    // Per-patch payloads then overlay the map — a per-patch file wins
    // on a version collision (it is the live-edited source).
    var byVersion = {};
    var existingCount = 0;
    if (scanned.consolidatedByMinor[minor]) {
      var existing = _readJson(conPath, 'release-notes/' + conName);
      if (!Array.isArray(existing.releases)) {
        _exit('existing ' + conName + ' has no `releases` array — refusing to overwrite a malformed rollup');
      }
      for (var e = 0; e < existing.releases.length; e += 1) {
        var rel = existing.releases[e];
        if (!rel || typeof rel.version !== 'string') {
          _exit('existing ' + conName + ' releases[' + e + '] has no string `version` — refusing to overwrite');
        }
        byVersion[rel.version] = rel;
        existingCount += 1;
      }
    }
    for (var p = 0; p < perPatch.length; p += 1) {
      byVersion[perPatch[p].version] = perPatch[p].payload;
    }
    var mergedVersions = Object.keys(byVersion).sort(_compareVersionsDesc);
    var doc = {
      minor:    minor,
      releases: mergedVersions.map(function (v) { return byVersion[v]; }),
    };
    fs.writeFileSync(conPath, JSON.stringify(doc, null, 2) + '\n');
    summary.push('  ' + minor + '.x — wrote ' + conName + ' with ' + mergedVersions.length +
      ' release(s) (' + perPatch.length + ' per-patch + ' + existingCount + ' already in rollup, merged)');

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
