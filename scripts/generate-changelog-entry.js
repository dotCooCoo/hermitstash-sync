#!/usr/bin/env node
'use strict';
/**
 * Generate the CHANGELOG.md section for a release from a structured
 * JSON source at `release-notes/v<version>.json`.
 *
 * The structured source enforces operator-facing shape — every field
 * has a known semantic (headline, summary, sections[].items[], etc.)
 * and runs through a leak-vocabulary validator before the markdown
 * emitter. Hand-written prose can drift into internal-process
 * narrative (`phase`, `sweep`, `tier`, AI co-authorship trailers,
 * conversation residue); the JSON pipeline refuses such input at
 * validation time so the discipline holds by construction.
 *
 * Usage:
 *   node scripts/generate-changelog-entry.js               # version from lib/constants.js
 *   node scripts/generate-changelog-entry.js 0.8.23        # explicit version
 *   node scripts/generate-changelog-entry.js --release-page         # multi-section GH-release-page markdown
 *   node scripts/generate-changelog-entry.js --rebuild              # rewrite CHANGELOG.md from release-notes/
 *   node scripts/generate-changelog-entry.js --check                # gate that CHANGELOG.md matches the JSON tree
 *
 * Validation refusals — the generator exits non-zero when:
 *   - The JSON is missing required fields.
 *   - Any string field contains a leak-vocabulary token from the
 *     LEAK_PATTERNS list below.
 *   - The version in the JSON doesn't match the requested version.
 */

var fs   = require('node:fs');
var path = require('node:path');
// Vendored framework — release ordering delegates to b.selfUpdate.compareTags
// so the repo has ONE semver comparator (lib/updater.js and
// consolidate-release-notes.js use the same one). In-repo script: vendor/ is
// always present, both locally and in release.yml after checkout.
var b    = require('../vendor/blamejs');

var ROOT          = path.resolve(__dirname, '..');
var CONSTANTS_JS  = path.join(ROOT, 'lib', 'constants.js');
var CHANGELOG     = path.join(ROOT, 'CHANGELOG.md');
var NOTES_DIR     = path.join(ROOT, 'release-notes');

// LEAK_PATTERNS — tokens that signal internal-process narrative instead of
// operator-facing description: internal sequencing numbers (phase / pass /
// slice / batch / sweep / tier), AI-tooling vocabulary and co-authorship
// trailers, conversation residue, and audit-attribution shorthand. Every
// release-notes string field is swept against this list before the markdown
// emitter, so that vocabulary can never reach the operator-facing CHANGELOG or
// release page.
//
// This function is exported (see `module.exports` at the foot of the file) so
// the `docs-leak-vocab` check in scripts/test-codebase-patterns.js can import
// the SAME list as its single source of truth, instead of keeping a second
// hand-copied array that could silently drift out of sync with this one.
function _leakPatterns() {
  return [
    // Phase / sweep / tier numbering — internal sequencing the
    // operator doesn't share. The digit-anchored forms catch both the
    // spaced and hyphenated spellings ("phase 9" AND "phase-9", "slice 4"
    // AND "slice-4") via [\s-]+, matching how the tier pattern already
    // tolerates a hyphen; the noun-anchored forms below catch un-numbered
    // sequencing like "the cleanup sweep" / "across the slice" / "a second
    // drift-audit pass".
    /\bphase[\s-]+\d/i,
    /\bsweep[\s-]+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch[\s-]+\d/i,
    /\bgroup\s+[a-h]\s+remainder\b/i,
    /\bslice[\s-]+\d/i,
    /\bpass[\s-]+\d/i,
    // Un-numbered internal-sequencing phrasings. "sweep" is anchored to the
    // drift-audit qualifier (the unambiguous internal-process sense) so
    // everyday technical English — "the startup sweep that removes temp
    // files", "a compliance audit sweep", "a single pass over the file" — is
    // not flagged.
    /\bdrift[- ]?audit\s+sweep\b/i,
    /\bacross\s+the\s+slice\b/i,
    /\bdrift[- ]audit\s+pass\b/i,
    /\b\d+[- ]gap\s+closure\b/i,
    // "audit-derived" / "post-audit" — internal-process attribution.
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
    // Pre-merge / review residue — how a change arrived, not what it is.
    /\bfolded in pre-merge\b/i,
    /\bcaught by (?:the )?reviewer\b/i,
    // Multi-agent tooling narrative.
    /\b(?:multi-agent|agent)\s+fan-?out\b/i,
    // AI-tooling vocabulary that should never reach operator-facing.
    /\b(?:anthropic|chatgpt|openai|copilot|claude|sonnet|opus|haiku|gemini|co[- ]authored[- ]by|llm[- ]generated|ai[- ]generated)\b/i,
    // AI-process adjectives — "AI-assisted", "AI-discovered", "AI-derived".
    /\bai[- ](?:assisted|discovered|derived)\b/i,
    // Conversation residue.
    /\bas\s+discussed\b/i,
    /\bper\s+(?:your|the)\s+earlier\s+note\b/i,
    /\boperator[- ]confirmed\b/i,
    // Tautological pass/green claims.
    /\ball\s+tests\s+passing\b/i,
    /\bci\s+green\b/i,
    // CLAUDE.md / rule-shorthand variants.
    /\bclaude\.md\b/i,
    /\bper\s+rule\s+§\d/i,
    /\bper\s+project\s+rule\s+§/i,
  ];
}

function _exit(msg) {
  process.stderr.write('[generate-changelog-entry] ' + msg + '\n');
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) { _exit('cannot read ' + label + ' (' + filePath + '): ' + (e && e.message || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit('malformed JSON in ' + label + ' (' + filePath + '): ' + (e && e.message || e)); }
}

function _scanString(value, fieldPath, patterns) {
  var hits = [];
  for (var i = 0; i < patterns.length; i += 1) {
    if (patterns[i].test(value)) {
      hits.push({ path: fieldPath, pattern: patterns[i].source });
    }
  }
  return hits;
}

function _walkForLeaks(node, basePath, patterns, out) {
  if (typeof node === 'string') {
    var hits = _scanString(node, basePath, patterns);
    for (var i = 0; i < hits.length; i += 1) out.push(hits[i]);
    // A C0 / DEL control character (newline, tab, …) in an operator-facing
    // string breaks the single-line CHANGELOG bullet that --rebuild emits and
    // the awk/grep per-line extract contract (scripts/test-codebase-patterns.js
    // scans CHANGELOG.md line by line). It round-trips cleanly through --check,
    // so only this gate catches it. Reject it here alongside the leak sweep.
    if (/[\u0000-\u001f\u007f]/.test(node)) {  // C0/DEL controls: an operator-facing field must be single-line (see comment above)
      out.push({ path: basePath, pattern: 'embedded control character (newline/tab) — operator-facing fields must be single-line' });
    }
    return;
  }
  if (Array.isArray(node)) {
    for (var j = 0; j < node.length; j += 1) {
      _walkForLeaks(node[j], basePath + '[' + j + ']', patterns, out);
    }
    return;
  }
  if (node && typeof node === 'object') {
    var keys = Object.keys(node);
    for (var k = 0; k < keys.length; k += 1) {
      if (keys[k] === '$schema') continue;
      _walkForLeaks(node[keys[k]], basePath + '.' + keys[k], patterns, out);
    }
  }
}

// Section heading allowlist + canonical ordering. Modeled on the
// Keep-a-Changelog conventions plus a `Supply chain` slot for the
// signing/SBOM/VEX/provenance entries this project ships often.
// Order at render-time follows this list regardless of the JSON's
// declaration order, so generated entries are structurally identical
// across releases.
var SECTION_ALLOWLIST_ORDER = [
  'Added',
  'Changed',
  'Deprecated',
  'Removed',
  'Fixed',
  'Security',
  'Supply chain',
  'Migration',
];

function _fail(errors) {
  process.stderr.write('[generate-changelog-entry] FAIL:\n');
  for (var i = 0; i < errors.length; i += 1) {
    process.stderr.write('  - ' + errors[i] + '\n');
  }
  process.exit(1);
}

function validate(notes, version) {
  var errs = [];

  // ---- Required top-level fields ----

  if (notes.version !== version) {
    errs.push('`version` is ' + JSON.stringify(notes.version) +
      ' but expected ' + JSON.stringify(version));
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(notes.date || '')) {
    errs.push('`date` must be `YYYY-MM-DD`; got ' + JSON.stringify(notes.date));
  }
  if (typeof notes.headline !== 'string' || notes.headline.length < 8) {                // allow:raw-byte-literal — min headline length floor
    errs.push('`headline` missing or shorter than 8 characters');
  } else {
    if (/[.!?]$/.test(notes.headline)) {
      errs.push('`headline` must not end with sentence punctuation (the renderer adds the period)');
    }
    if (notes.headline !== notes.headline.trim()) {
      errs.push('`headline` has leading/trailing whitespace');
    }
    if (!/^[A-Z`]/.test(notes.headline)) {
      errs.push('`headline` must start with a capital letter or backtick (current: ' +
        JSON.stringify(notes.headline.slice(0, 16)) + '...)');
    }
  }
  if (notes.summary !== undefined) {
    if (typeof notes.summary !== 'string') errs.push('`summary` must be a string when present');
    else if (notes.summary !== notes.summary.trim()) errs.push('`summary` has leading/trailing whitespace');
    else if (notes.summary.length > 0 && !/[.!?]$/.test(notes.summary)) {
      errs.push('`summary` must end with sentence punctuation');
    }
  }

  // ---- Sections ----

  if (!Array.isArray(notes.sections) || notes.sections.length === 0) {
    errs.push('`sections` must be a non-empty array');
  } else {
    // Null-prototype so a heading colliding with an inherited object member
    // ('constructor') can't read truthy and add a spurious duplicate-heading
    // diagnostic on top of the allowlist error it already gets.
    var seenHeadings = Object.create(null);
    for (var s = 0; s < notes.sections.length; s += 1) {
      var sec = notes.sections[s];
      var pfx = 'sections[' + s + ']';
      if (typeof sec.heading !== 'string') {
        errs.push(pfx + '.heading missing');
        continue;
      }
      if (SECTION_ALLOWLIST_ORDER.indexOf(sec.heading) === -1) {
        errs.push(pfx + '.heading ' + JSON.stringify(sec.heading) +
          ' not in allowlist: ' + SECTION_ALLOWLIST_ORDER.join(' / '));
      }
      if (seenHeadings[sec.heading]) {
        errs.push(pfx + '.heading ' + JSON.stringify(sec.heading) +
          ' duplicates an earlier section — consolidate items under one section');
      }
      seenHeadings[sec.heading] = true;
      if (!Array.isArray(sec.items) || sec.items.length === 0) {
        errs.push(pfx + ' (' + sec.heading + ') `items` missing/empty');
        continue;
      }
      for (var t = 0; t < sec.items.length; t += 1) {
        var it  = sec.items[t];
        var ipx = pfx + '.items[' + t + ']';
        if (typeof it.title !== 'string' || it.title.length === 0) {
          errs.push(ipx + '.title missing');
        } else {
          if (it.title !== it.title.trim()) errs.push(ipx + '.title has leading/trailing whitespace');
          if (/[.!?]$/.test(it.title))      errs.push(ipx + '.title must not end with sentence punctuation');
          if (!/^[A-Za-z`]/.test(it.title)) errs.push(ipx + '.title must start with a letter or backtick');
        }
        if (typeof it.body !== 'string' || it.body.length === 0) {
          errs.push(ipx + '.body missing');
        } else {
          if (it.body !== it.body.trim()) errs.push(ipx + '.body has leading/trailing whitespace');
          if (!/[.!?]$/.test(it.body))    errs.push(ipx + '.body must end with sentence punctuation');
          if (it.body.length < 16) {                                                    // allow:raw-byte-literal — min body length floor
            errs.push(ipx + '.body shorter than 16 characters (under-described — operators need context)');
          }
        }
      }
    }
  }

  // ---- References ----

  if (notes.references !== undefined) {
    if (!Array.isArray(notes.references)) {
      errs.push('`references` must be an array when present');
    } else {
      for (var r = 0; r < notes.references.length; r += 1) {
        var ref = notes.references[r];
        var rpx = 'references[' + r + ']';
        if (typeof ref.label !== 'string' || ref.label.length === 0) {
          errs.push(rpx + '.label missing');
        }
        if (typeof ref.url !== 'string' || !/^https:\/\//.test(ref.url)) {
          errs.push(rpx + '.url must be an https:// URL');
        }
      }
    }
  }

  // ---- Leak-vocabulary sweep ----

  var hits = [];
  _walkForLeaks(notes, '$', _leakPatterns(), hits);
  if (hits.length > 0) {
    process.stderr.write('[generate-changelog-entry] FAIL: leak-vocabulary tokens found in release-notes JSON:\n');
    for (var h = 0; h < hits.length; h += 1) {
      process.stderr.write('  ' + hits[h].path + '  ←  pattern /' + hits[h].pattern + '/\n');
    }
    process.stderr.write('[generate-changelog-entry] Each field must be operator-facing. Strip internal-process narrative + rewrite.\n');
    if (errs.length > 0) _fail(errs);
    process.exit(1);
  }

  if (errs.length > 0) _fail(errs);
}

// Re-order sections to the canonical sequence at render time.
function _sortSections(sections) {
  return sections.slice().sort(function (a, b) {
    return SECTION_ALLOWLIST_ORDER.indexOf(a.heading) -
           SECTION_ALLOWLIST_ORDER.indexOf(b.heading);
  });
}

// CHANGELOG mode — single-line bullet entry:
//   - vX.Y.Z (YYYY-MM-DD) — **Headline.** Summary paragraph.
//     Section heading: item-title — item-body. ...
//     References: [label1](url1) · [label2](url2) ...
// One-line shape preserves an awk-friendly extract contract.
function renderChangelogLine(notes) {
  var out = '- v' + notes.version + ' (' + notes.date + ') — **' + notes.headline + '.**';
  if (notes.summary && notes.summary.length > 0) {
    out += ' ' + notes.summary;
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    out += ' **' + sec.heading + ':** ';
    var parts = sec.items.map(function (it) {
      return '*' + it.title + '* — ' + it.body;
    });
    out += parts.join(' · ');
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    var refList = notes.references.map(function (r) {
      return '[' + r.label + '](' + r.url + ')';
    });
    out += ' **References:** ' + refList.join(' · ');
  }
  return out;
}

// Release-page mode — multi-section markdown for the GitHub release
// page. Uses `##` headings + bullet lists per section so each item
// renders as its own scannable card on the release page instead of a
// single dense paragraph. The workflow's gh-release-create step
// passes this output via --notes-file.
function renderReleasePage(notes) {
  var lines = [];
  lines.push('**' + notes.headline + '.**');
  lines.push('');
  if (notes.summary && notes.summary.length > 0) {
    lines.push(notes.summary);
    lines.push('');
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    lines.push('## ' + sec.heading);
    lines.push('');
    for (var t = 0; t < sec.items.length; t += 1) {
      var it = sec.items[t];
      lines.push('- **' + it.title + '** — ' + it.body);
    }
    lines.push('');
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    lines.push('## References');
    lines.push('');
    for (var r = 0; r < notes.references.length; r += 1) {
      var ref = notes.references[r];
      lines.push('- [' + ref.label + '](' + ref.url + ')');
    }
    lines.push('');
  }
  return lines.join('\n');
}

// Source of truth for the project version is `lib/constants.js`'s
// VERSION constant (the build embeds it in the SEA binary; the tag
// matches it). Parse the literal string without require()-ing the
// module so this script stays side-effect-free during validation.
function _readProjectVersion() {
  var raw;
  try { raw = fs.readFileSync(CONSTANTS_JS, 'utf8'); }
  catch (e) { _exit('cannot read ' + CONSTANTS_JS + ': ' + (e && e.message || e)); }
  // Anchor to the exact `const VERSION = '...'` declaration and capture
  // only a semver triple. An unanchored `VERSION[:=]...` also matches an
  // unrelated `*_VERSION` constant (e.g. `const TLS_MIN_VERSION = 'TLSv1.3'`)
  // and `.match()` returns the FIRST hit — declaration order would then
  // decide which string is extracted. The semver-shaped capture refuses a
  // non-version literal at the boundary rather than relying on a later
  // _requireSemver to catch the mis-extraction.
  var m = raw.match(/\bconst VERSION\s*=\s*'(\d+\.\d+\.\d+)'/);
  if (!m) _exit('could not find `const VERSION = \'<semver>\'` literal in lib/constants.js');
  return m[1];
}

// Strict semver gate at the trust boundary. Every downstream use of
// `version` builds a regex (`^- v<version> (`), a path segment, or a
// CHANGELOG splice — feeding raw operator-controlled input into any
// of those is unsafe. Refuse anything that doesn't match
// `^\d+\.\d+\.\d+$` here.
function _requireSemver(version, label) {
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) {
    _exit(label + ' is not strict semver `\\d+.\\d+.\\d+`: ' + JSON.stringify(version));
  }
  return version;
}

function _tryReadJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) {
    if (e && e.code === 'ENOENT') return null;
    _exit('cannot read ' + label + ' (' + filePath + '): ' + (e && e.message || e));
  }
  try { return JSON.parse(raw); }
  catch (e) { _exit('malformed JSON in ' + label + ' (' + filePath + '): ' + (e && e.message || e)); }
}

// Lookup tries the per-patch file first, then the consolidated
// minor-line rollup. This lets non-current minor lines collapse to
// a single `v<minor>.x.json` (via `scripts/consolidate-release-notes.js`)
// without breaking the generator's `node scripts/generate-changelog-entry.js
// 0.8.23`-style invocations.
function _loadReleaseNotes(version) {
  var perPatchPath = path.join(NOTES_DIR, 'v' + version + '.json');
  var perPatch = _tryReadJson(perPatchPath, 'release-notes/v' + version + '.json');
  if (perPatch !== null) {
    return { notes: perPatch, source: 'v' + version + '.json' };
  }
  var minor = version.replace(/\.\d+$/, '');
  var consolidatedPath = path.join(NOTES_DIR, 'v' + minor + '.x.json');
  var con = _tryReadJson(consolidatedPath, 'release-notes/v' + minor + '.x.json');
  if (con !== null) {
    if (!Array.isArray(con.releases)) {
      _exit('consolidated file release-notes/v' + minor + '.x.json missing `releases` array');
    }
    for (var i = 0; i < con.releases.length; i += 1) {
      if (con.releases[i] && con.releases[i].version === version) {
        return {
          notes:  con.releases[i],
          source: 'v' + minor + '.x.json (releases[' + i + '])',
        };
      }
    }
    _exit('v' + version + ' not found inside consolidated file ' +
      'release-notes/v' + minor + '.x.json — ' +
      'the rollup may be stale or the version may not exist');
  }
  _exit('cannot find release notes for v' + version + ' — ' +
    'looked at release-notes/v' + version + '.json AND ' +
    'release-notes/v' + minor + '.x.json (neither present)');
  return null;
}

// Walk `release-notes/`, load every release (both per-patch and
// consolidated minor-line files), de-duplicate by version, and return a
// flat array sorted newest-first.
//
// A version can legitimately appear in BOTH a per-patch `v<X>.<Y>.<Z>.json`
// AND a consolidated `v<X>.<Y>.x.json` — the consolidate step's no-prune
// preview is a supported mode that writes the rollup while leaving the
// per-patch source on disk. Without de-dup that version's CHANGELOG line
// would render twice. The per-patch file is authoritative (it is the
// live-edited source); the consolidated copy is the shadow. If the two
// copies of the same version DIFFER in content, the rollup is stale —
// surface that loudly rather than silently picking one.
function _loadAllReleases() {
  if (!fs.existsSync(NOTES_DIR)) return [];
  var entries = fs.readdirSync(NOTES_DIR);
  // Collect into a version-keyed map. Per-patch entries are applied AFTER
  // consolidated entries so per-patch wins the key; a content divergence
  // between the two sources for the same version is a hard error.
  var byVersion = Object.create(null);
  var consolidated = [];
  var perPatch = [];
  for (var i = 0; i < entries.length; i += 1) {
    var name = entries[i];
    if (!/\.json$/.test(name)) continue;
    var conMatch = name.match(/^v(\d+\.\d+)\.x\.json$/);
    if (conMatch) {
      var con = _readJson(path.join(NOTES_DIR, name), 'release-notes/' + name);
      if (!Array.isArray(con.releases)) {
        _exit('consolidated file release-notes/' + name + ' missing `releases` array');
      }
      for (var r = 0; r < con.releases.length; r += 1) {
        // The consolidated filename only encodes the minor, so the in-file
        // `version` is the sole semver source for each entry. Assert it is a
        // strict triple at the load/trust boundary so the version-sort
        // comparator below can never see a NaN-producing malformed string.
        var crel = con.releases[r];
        if (!crel || typeof crel.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(crel.version)) {
          _exit('release-notes/' + name + ' releases[' + r + '] has a non-semver `version` ' +
            JSON.stringify(crel && crel.version) + ' — fix it to a strict `\\d+.\\d+.\\d+` triple');
        }
        consolidated.push({ rel: crel, from: name });
      }
      continue;
    }
    var verMatch = name.match(/^v(\d+\.\d+\.\d+)\.json$/);
    if (!verMatch) continue;
    var prel = _readJson(path.join(NOTES_DIR, name), 'release-notes/' + name);
    // The per-patch filename encodes the full triple; cross-check the in-file
    // `version` against it so a correctly-named file carrying a malformed or
    // mismatched in-file version (e.g. "0.9.12" inside v0.9.11.json, "0.8",
    // "0.8.x") fails loud here instead of scrambling the sort/grouping.
    if (!prel || typeof prel.version !== 'string' || prel.version !== verMatch[1]) {
      _exit('release-notes/' + name + ' declares version ' + JSON.stringify(prel && prel.version) +
        ' but the filename encodes ' + JSON.stringify(verMatch[1]) +
        ' — fix the in-file `version` field to the strict semver matching the filename');
    }
    perPatch.push({ rel: prel, from: name });
  }
  for (var c = 0; c < consolidated.length; c += 1) {
    var cv = String(consolidated[c].rel && consolidated[c].rel.version);
    byVersion[cv] = consolidated[c];
  }
  for (var p = 0; p < perPatch.length; p += 1) {
    var pv = String(perPatch[p].rel && perPatch[p].rel.version);
    var prior = byVersion[pv];
    if (prior && prior.from !== perPatch[p].from &&
        JSON.stringify(prior.rel) !== JSON.stringify(perPatch[p].rel)) {
      _exit('v' + pv + ' differs between ' + perPatch[p].from + ' and ' + prior.from +
        ' — the consolidated rollup is stale. Re-run ' +
        '`node scripts/consolidate-release-notes.js --prune` (or reconcile the two by hand) before rebuilding.');
    }
    byVersion[pv] = perPatch[p];
  }
  var all = Object.keys(byVersion).map(function (v) { return byVersion[v].rel; });
  // Newest-first via the framework comparator. Every version reaching this
  // sort has already passed the strict-triple gates above, so ordering is
  // byte-identical to the previous inline comparator for all valid inputs.
  all.sort(function (x, y) { return b.selfUpdate.compareTags(y.version, x.version); });
  return all;
}

// Build the full `CHANGELOG.md` content from `release-notes/`. Every
// entry is validated through the schema + leak-vocabulary sweep
// before render, so a malformed JSON anywhere in the tree fails the
// rebuild loud (rather than producing a silently-broken markdown
// section).
function rebuildChangelog() {
  var releases = _loadAllReleases();
  if (releases.length === 0) _exit('no releases found in release-notes/');
  for (var i = 0; i < releases.length; i += 1) {
    validate(releases[i], releases[i].version);
  }
  var byMinor = {};
  var minorOrder = [];
  for (var j = 0; j < releases.length; j += 1) {
    var v = releases[j].version;
    var minor = v.replace(/\.\d+$/, '');
    if (!byMinor[minor]) {
      byMinor[minor] = [];
      minorOrder.push(minor);
    }
    byMinor[minor].push(releases[j]);
  }
  var parts = [];
  parts.push('# Changelog');
  parts.push('');
  parts.push('One entry per released tag, grouped by minor. Latest first.');
  parts.push('');
  parts.push('The project follows semantic versioning from 1.0 onward: a major');
  parts.push('release may change behaviour operators depend on, while minor and');
  parts.push('patch releases do not. Read each entry before upgrading across more');
  parts.push('than a few releases at a time. Releases older than the first');
  parts.push('structured entry below live in the git log and on the GitHub');
  parts.push('Releases page.');
  parts.push('');
  for (var m = 0; m < minorOrder.length; m += 1) {
    parts.push('## v' + minorOrder[m] + '.x');
    parts.push('');
    var bucket = byMinor[minorOrder[m]];
    for (var k2 = 0; k2 < bucket.length; k2 += 1) {
      parts.push(renderChangelogLine(bucket[k2]));
      parts.push('');
    }
  }
  while (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts.join('\n') + '\n';
}

function main() {
  var argv = process.argv.slice(2);
  var rebuildMode     = argv.indexOf('--rebuild')      !== -1;
  var checkMode       = argv.indexOf('--check')        !== -1;
  var releasePageMode = argv.indexOf('--release-page') !== -1;
  var explicitVersion = null;
  for (var a = 0; a < argv.length; a += 1) {
    if (!argv[a].startsWith('--')) { explicitVersion = argv[a]; break; }
  }
  var modeFlags = [rebuildMode, checkMode, releasePageMode].filter(Boolean).length;
  if (modeFlags > 1) {
    _exit('--rebuild, --check, and --release-page are mutually exclusive');
  }

  if (rebuildMode) {
    var rebuilt = rebuildChangelog();
    fs.writeFileSync(CHANGELOG, rebuilt);
    process.stderr.write('[generate-changelog-entry] OK — rebuilt CHANGELOG.md (' +
      rebuilt.length + ' bytes) from release-notes/\n');
    return;
  }

  if (checkMode) {
    var expected = rebuildChangelog();
    var actual;
    try { actual = fs.readFileSync(CHANGELOG, 'utf8'); }
    catch (e) {
      if (e && e.code === 'ENOENT') _exit('CHANGELOG.md does not exist');
      _exit('cannot read CHANGELOG.md: ' + (e && e.message || e));
    }
    if (expected.replace(/\r\n/g, '\n') === actual.replace(/\r\n/g, '\n')) {
      process.stderr.write('[generate-changelog-entry] OK — CHANGELOG.md matches the rebuild from release-notes/\n');
      return;
    }
    _exit('CHANGELOG.md drifts from release-notes/ — run `node scripts/generate-changelog-entry.js --rebuild` to regenerate (then commit both)');
  }

  var version = _requireSemver(
    explicitVersion || _readProjectVersion(),
    explicitVersion ? 'argv[1] (explicit version)' : 'lib/constants.js#VERSION'
  );
  var loaded = _loadReleaseNotes(version);
  var notes  = loaded.notes;
  validate(notes, version);

  if (releasePageMode) {
    var releaseMd = renderReleasePage(notes);
    process.stdout.write(releaseMd);
    process.stderr.write('[generate-changelog-entry] OK — rendered v' + version +
      ' release-page markdown (' + releaseMd.length + ' chars)\n');
    return;
  }

  var rendered = renderChangelogLine(notes);
  process.stdout.write(rendered + '\n');
  process.stderr.write('[generate-changelog-entry] OK — rendered v' + version +
    ' entry (' + rendered.length + ' chars). Use --rebuild to write CHANGELOG.md, ' +
    '--check to gate drift, --release-page to emit GH-release-page markdown.\n');
}

// Run the CLI only when invoked directly. Guarding this lets other maintainer
// tooling (the docs-leak-vocab gate) `require()` this file to reuse
// `_leakPatterns` as the single source of truth without triggering a version
// read, release-notes validation, stdout emission, or process.exit at import.
if (require.main === module) {
  main();
}

module.exports = { _leakPatterns };
