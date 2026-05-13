'use strict';

/**
 * codebase-patterns — automated grep gates for bug classes that have
 * surfaced in the blamejs framework's release history, applied to
 * hermitstash-sync's own JavaScript surface.
 *
 * Modeled on `examples/wiki/test/codebase-patterns.test.js` in the
 * blamejs repo. The sync client consumes blamejs via the vendored
 * `b = require('../vendor/blamejs')` import, so the canonical helpers
 * here are `b.constants.TIME.*` / `b.constants.BYTES.*` / `b.safeJson`
 * / `b.safeUrl` / `b.safeEnv` / `b.crypto.*` / `b.httpClient.*` /
 * `b.safeAsync.sleep`. Same fundamental-fix expectations as the
 * framework gate.
 *
 * Scope:
 *   bin/**.js
 *   lib/**.js
 *
 * Skipped:
 *   vendor/**             (upstream sources own their own gates)
 *   tests/**              (test code has its own conventions)
 *   build/**              (generated artifacts)
 *   scripts/**            (release-time helpers — host-side, not shipped)
 *
 * Allow markers (file-level + per-line) match the framework test's
 * convention so an author needing a documented exception uses the
 * same shape:
 *
 *   1. File-level header within the first 50 lines:
 *        // codebase-patterns:allow-file <class> — <reason>
 *
 *   2. Per-line marker on the same line or one or two lines above:
 *        ... // allow:<class> — <reason>
 *
 * Runs as part of `node tests/run-all.js`. Does not need the test
 * server — pure static analysis over the working tree.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');

const SCAN_DIRS = [
  path.join(REPO_ROOT, 'bin'),
  path.join(REPO_ROOT, 'lib'),
];

function _isSkippedPath(absPath) {
  var rel = path.relative(REPO_ROOT, absPath).replace(/\\/g, '/');
  if (rel.indexOf('vendor/') === 0) return true;
  if (rel.indexOf('tests/') === 0) return true;
  if (rel.indexOf('build/') === 0) return true;
  if (rel.indexOf('scripts/') === 0) return true;
  if (rel.indexOf('node_modules/') !== -1) return true;
  return false;
}

function _walk(dir, files) {
  files = files || [];
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(dir, e.name);
    if (_isSkippedPath(full)) continue;
    if (e.isDirectory()) _walk(full, files);
    else if (e.isFile() && e.name.endsWith('.js')) files.push(full);
  }
  return files;
}

function _sourceFiles() {
  var out = [];
  for (var i = 0; i < SCAN_DIRS.length; i++) _walk(SCAN_DIRS[i], out);
  return out;
}

function _relPath(absPath) {
  return path.relative(REPO_ROOT, absPath).replace(/\\/g, '/');
}

function _scan(regex, opts) {
  opts = opts || { skipComments: true };
  var matches = [];
  var files = _sourceFiles();
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], 'utf8'); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (opts.skipComments && /^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (regex.test(line)) {
        matches.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: line.trim(),
        });
      }
    }
  }
  return matches;
}

function _filterMarkers(matches, allowClass) {
  var fileCache = {};
  var fileAllowCache = {};
  function _readContext(file) {
    if (!fileCache[file]) {
      try {
        var p = path.resolve(REPO_ROOT, file);
        fileCache[file] = fs.readFileSync(p, 'utf8').split(/\r?\n/);
      } catch (_e) { fileCache[file] = []; }
    }
    return fileCache[file];
  }
  function _hasFileAllow(file) {
    if (Object.prototype.hasOwnProperty.call(fileAllowCache, file)) return fileAllowCache[file];
    var lines = _readContext(file).slice(0, 50);
    var re = new RegExp('codebase-patterns:allow-file\\s+' + allowClass + '\\b'); // allow:dynamic-regex — internal allowClass token
    var found = lines.some(function (l) { return re.test(l); });
    fileAllowCache[file] = found;
    return found;
  }
  function _hasLineAllow(file, lineNum) {
    var lines = _readContext(file);
    if (!lines.length) return false;
    var same  = lines[lineNum - 1] || '';
    var above = lines[lineNum - 2] || '';
    var twoAbove = lines[lineNum - 3] || '';
    var re = new RegExp('allow:' + allowClass + '\\b'); // allow:dynamic-regex — internal allowClass token
    return re.test(same) || re.test(above) || re.test(twoAbove);
  }
  return matches.filter(function (m) {
    if (_hasFileAllow(m.file)) return false;
    if (_hasLineAllow(m.file, m.line)) return false;
    return true;
  });
}

function _formatViolations(label, matches) {
  if (matches.length === 0) return null;
  var preview = matches.map(function (m) {
    return '    ' + m.file + ':' + m.line + ': ' + m.content.slice(0, 120);
  }).join('\n');
  return label + ': ' + matches.length + ' violation(s):\n' + preview;
}

function _assertClean(label, matches) {
  var msg = _formatViolations(label, matches);
  assert.equal(msg, null, msg || '');
}

describe('codebase-patterns', { timeout: 30000 }, () => {

  it('no raw byte-shaped literals (n >= 8 && n % 8 === 0; use b.constants.BYTES.*)', () => {
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        var stripped = line
          .replace(/"(?:[^"\\]|\\.)*"/g, '')
          .replace(/'(?:[^'\\]|\\.)*'/g, '')
          .replace(/`(?:[^`\\]|\\.)*`/g, '')
          .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, '')
          .replace(/0x[0-9a-fA-F]+/g, '');
        if (/\b(?:C|b\.constants)\.(BYTES|TIME)\.\w+\(/.test(stripped)) continue;
        var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
        if (statusCmpRe.test(stripped)) continue;
        var statusAssignRe = /\b(status|statusCode|status_code|http_status)\s*[:=]/i;
        if (statusAssignRe.test(stripped)) continue;
        var statusArgRe = /\b(?:status|setStatus|writeHead|_send|sendStatus)\s*\([^,]+,\s*(?:200|201|204|301|302|303|304|400|401|403|404|409|410|413|415|422|429|500|502|503|504)\b/;
        if (statusArgRe.test(stripped)) continue;
        stripped = stripped.replace(/(?:>>>?|<<)\s*\d+/g, '');
        stripped = stripped.replace(/[&|^]\s*\d+/g, '');
        var hit = false;
        var re = /\b(\d{1,})\b/g;
        var m;
        while ((m = re.exec(stripped)) !== null) {
          var n = Number(m[1]);
          if (!Number.isFinite(n)) continue;
          if (n < 8) continue;
          if (n % 8 !== 0) continue;
          if (n >= 1900 && n <= 2100) continue;
          hit = true;
          break;
        }
        if (hit) {
          bad.push({
            file:    _relPath(files[fi]),
            line:    li + 1,
            content: line.trim(),
          });
        }
      }
    }
    bad = _filterMarkers(bad, 'raw-byte-literal');
    _assertClean('raw-byte-literal', bad);
  });

  it('no raw time-shaped literals (n >= 60 && n % 60 === 0; use b.constants.TIME.*)', () => {
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        var stripped = line
          .replace(/"(?:[^"\\]|\\.)*"/g, '')
          .replace(/'(?:[^'\\]|\\.)*'/g, '')
          .replace(/`(?:[^`\\]|\\.)*`/g, '')
          .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, '')
          .replace(/0x[0-9a-fA-F]+/g, '');
        var hit = false;
        if (/[)\w]\s*\*\s*1000\b(?!\s*\*\s*1000)/.test(stripped)) hit = true;
        if (!hit) {
          if (/\b(?:C|b\.constants)\.TIME\.\w+\(/.test(stripped)) continue;
          var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
          if (statusCmpRe.test(stripped)) continue;
          var re = /\b(\d{2,})\b/g;
          var m;
          while ((m = re.exec(stripped)) !== null) {
            var n = Number(m[1]);
            if (!Number.isFinite(n)) continue;
            if (n < 60) continue;
            if (n % 60 !== 0) continue;
            if (n >= 1900 && n <= 2100) continue;
            hit = true;
            break;
          }
        }
        if (hit) {
          bad.push({
            file:    _relPath(files[fi]),
            line:    li + 1,
            content: line.trim(),
          });
        }
      }
    }
    bad = _filterMarkers(bad, 'raw-time-literal');
    _assertClean('raw-time-literal', bad);
  });

  it('no stray console.* calls (route through logger)', () => {
    var matches = _scan(/\bconsole\.(log|error|warn|info|debug)\(/);
    matches = _filterMarkers(matches, 'console-direct');
    _assertClean('console-direct', matches);
  });

  it('no TODO / FIXME / HACK / XXX markers', () => {
    var matches = _scan(/\b(TODO|FIXME|HACK|XXX)(?::|\s)/);
    matches = _filterMarkers(matches, 'unresolved-marker');
    _assertClean('unresolved-marker', matches);
  });

  it('no Tier-A / Tier-B / Tier-C terminology in code', () => {
    var matches = _scan(/\bTier[- ]?(A|B|C)\b/i, { skipComments: false });
    matches = _filterMarkers(matches, 'tier-terminology');
    _assertClean('tier-terminology', matches);
  });

  it('require() at top of file (or has inline-require allow marker)', () => {
    var matches = _scan(/^\s+\S.*\brequire\(["']\.\.?\//);
    matches = _filterMarkers(matches, 'inline-require');
    _assertClean('inline-require', matches);
  });

  it('Math.random() has explicit non-crypto allow marker', () => {
    var matches = _scan(/\bMath\.random\(/);
    matches = _filterMarkers(matches, 'math-random-noncrypto');
    _assertClean('math-random-noncrypto', matches);
  });

  it('new URL(...) routes through b.safeUrl.parse', () => {
    var matches = _scan(/\bnew URL\(/);
    matches = _filterMarkers(matches, 'raw-new-url');
    _assertClean('raw-new-url', matches);
  });

  it('JSON.parse on operator input routes through b.safeJson.parse', () => {
    var matches = _scan(/\bJSON\.parse\(/);
    matches = _filterMarkers(matches, 'bare-json-parse');
    _assertClean('bare-json-parse', matches);
  });

  it('Object.keys(...).sort() canonicalize walks route through b.canonicalJson', () => {
    var matches = _scan(/Object\.keys\(\w+\)\.sort\(\)/);
    matches = _filterMarkers(matches, 'bare-canonicalize-walk');
    _assertClean('bare-canonicalize-walk', matches);
  });

  it('regex-only validators bound length before .test()', () => {
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        if (!/\b[A-Z_]+_RE\.test\(/.test(line)) continue;
        var window = (lines[li-2] || '') + (lines[li-1] || '') +
                     line + (lines[li+1] || '') + (lines[li+2] || '');
        if (/\.length\s*[><=]/.test(window)) continue;
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
    bad = _filterMarkers(bad, 'regex-no-length-cap');
    _assertClean('regex-no-length-cap', bad);
  });

  it('no process.exit() (entry points need an allow marker)', () => {
    var matches = _scan(/\bprocess\.exit\(/);
    matches = _filterMarkers(matches, 'process-exit');
    _assertClean('process-exit', matches);
  });

  it('empty catch(_e) {} blocks have explicit silent-catch allow marker', () => {
    var matches = _scan(/catch\s*\(\s*_\w*\s*\)\s*\{\s*\}/);
    matches = _filterMarkers(matches, 'silent-catch');
    _assertClean('silent-catch', matches);
  });

  it('new RegExp(...) marked with dynamic-regex allow marker', () => {
    var matches = _scan(/new RegExp\(/);
    matches = _filterMarkers(matches, 'dynamic-regex');
    _assertClean('dynamic-regex', matches);
  });

  it('process.env reads route through b.safeEnv.readVar (or have allow marker)', () => {
    var matches = _scan(/\bprocess\.env\.\w+/);
    matches = _filterMarkers(matches, 'raw-process-env');
    _assertClean('raw-process-env', matches);
  });

  it('crypto.timingSafeEqual routes through b.crypto.timingSafeEqual', () => {
    var matches = _scan(/\b(nodeCrypto|crypto)\.timingSafeEqual\(/);
    matches = _filterMarkers(matches, 'raw-timing-safe-equal');
    _assertClean('raw-timing-safe-equal', matches);
  });

  it('parseInt(...) called with explicit radix', () => {
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        var m = /\bparseInt\s*\(/.exec(line);
        if (!m) continue;
        var start = m.index + m[0].length;
        var depth = 1;
        var hasCommaAtDepth0 = false;
        var i;
        for (i = start; i < line.length && depth > 0; i++) {
          var ch = line.charAt(i);
          if (ch === '(') depth += 1;
          else if (ch === ')') depth -= 1;
          else if (ch === ',' && depth === 1) hasCommaAtDepth0 = true;
        }
        if (depth > 0) continue;
        if (!hasCommaAtDepth0) {
          bad.push({
            file:    _relPath(files[fi]),
            line:    li + 1,
            content: line.trim(),
          });
        }
      }
    }
    bad = _filterMarkers(bad, 'parseint-no-radix');
    _assertClean('parseint-no-radix', bad);
  });

  it('setInterval timers call .unref() (or have allow marker)', () => {
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        if (!/\bsetInterval\(/.test(line)) continue;
        var window = line + (lines[li+1] || '') + (lines[li+2] || '') +
                     (lines[li+3] || '') + (lines[li+4] || '');
        if (/\.unref\(\)/.test(window)) continue;
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
    bad = _filterMarkers(bad, 'timer-no-unref');
    _assertClean('timer-no-unref', bad);
  });

  it('nodeCrypto.randomBytes(n).toString routes through b.crypto.generateToken', () => {
    var matches = _scan(/\b(nodeCrypto|crypto)\.randomBytes\([^)]+\)\s*\.\s*toString\s*\(/);
    matches = _filterMarkers(matches, 'raw-randombytes-token');
    _assertClean('raw-randombytes-token', matches);
  });

  it('Promise+setTimeout routes through b.safeAsync.sleep', () => {
    var matches = _scan(/new Promise\([^)]*\)\s*=>\s*setTimeout|new Promise\(function[^{]*\{\s*setTimeout|new Promise\(\s*(?:resolve|r)\s*=>\s*setTimeout/);
    matches = _filterMarkers(matches, 'handrolled-sleep');
    _assertClean('handrolled-sleep', matches);
  });

  it('http(s).request / fetch route through b.httpClient', () => {
    var matches = _scan(/\b(http|https)\.(request|get)\s*\(|^[^/]*\bfetch\s*\(/);
    matches = _filterMarkers(matches, 'raw-outbound-http');
    _assertClean('raw-outbound-http', matches);
  });

  it('Number(process.env.X) routes through b.config.coerce.number / b.safeEnv typed readers', () => {
    var matches = _scan(/\bNumber\s*\(\s*process\.env\b/);
    matches = _filterMarkers(matches, 'number-env-coerce');
    _assertClean('number-env-coerce', matches);
  });

  // Every `(const|let|var) <name> = require('<target>')` binding for the
  // same require target MUST use the same variable name across every file
  // in the repo. The intent: `b` always means blamejs, `fs` always means
  // node:fs, `https` always means node:https — a reader who greps for
  // `b.foo()` shouldn't have to mentally check which module `b` aliases
  // in this particular file. No allow markers — the fix is to align every
  // file on one binding name. Pick the SAFER (less-conflicting) variant,
  // not the most-popular one: a disambiguated alias like `nodeCrypto`
  // beats the bare `crypto` (which collides with the global Web Crypto
  // and with the npm `bcrypt` family); `nodeBuffer` beats `buffer`; etc.
  // The test surfaces the variance but doesn't prescribe a winner — a
  // human picks the safer name and migrates every file to match.
  it('require() bindings name the same target the same way across all files', () => {
    var files = _sourceFiles();
    var bindingRe = /^\s*(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/;
    var byTarget = Object.create(null);
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        var m = bindingRe.exec(line);
        if (!m) continue;
        var name = m[1];
        var target = m[2];
        if (!byTarget[target]) byTarget[target] = Object.create(null);
        if (!byTarget[target][name]) byTarget[target][name] = [];
        byTarget[target][name].push(_relPath(files[fi]) + ':' + (li + 1));
      }
    }
    var violations = [];
    var targets = Object.keys(byTarget).sort();
    for (var ti = 0; ti < targets.length; ti++) {
      var t = targets[ti];
      var names = Object.keys(byTarget[t]);
      if (names.length < 2) continue;
      names.sort();
      var detail = names.map(function (n) {
        return '      ' + n + ' (' + byTarget[t][n].length + 'x): ' +
               byTarget[t][n].join(', ');
      }).join('\n');
      violations.push('    require(\'' + t + '\') is bound to ' + names.length + ' names:\n' + detail +
                      '\n      -> pick the safer (less-conflicting) name and migrate every file');
    }
    if (violations.length > 0) {
      var msg = 'require-binding-mismatch: ' + violations.length + ' target(s):\n' +
                violations.join('\n');
      assert.equal(null, msg, msg);
    }
  });

});
