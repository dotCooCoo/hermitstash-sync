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

  it('process.on(SIGTERM/SIGINT) + process.exit needs sea-sigterm-bug allow marker', () => {
    // Multiline match: process.on('SIGTERM' | 'SIGINT', ...) within ~800 chars
    // of a process.exit() call. Surfaces the Node SEA bug bisected across
    // sync v0.8.15 → v0.8.20: process.exit(N) called from inside a SIGTERM
    // handler in a SEA-packaged binary exits with signal-default code 143
    // (= 128 + SIGTERM) instead of the requested N. The Dockerfile's
    // `tini -e 143` remaps the bogus 143 to 0 for container deployments
    // (Kubernetes preStop, docker stop, etc.) but operators running the
    // binary directly under systemd or in foreground will see 143 on every
    // clean shutdown. Any NEW SIGTERM handler that ends in process.exit
    // must either (a) compose with the existing lib/daemon.js handleTerm
    // path so the same tini remap covers it, or (b) carry an explicit
    // `// allow:sea-sigterm-bug — <reason>` marker documenting the
    // deployment scope where 143 is acceptable.
    var matches = _scan(/process\.(?:on|once)\(['"]SIG(?:TERM|INT)['"][\s\S]{0,800}?process\.exit\s*\(/);
    matches = _filterMarkers(matches, 'sea-sigterm-bug');
    _assertClean('sea-sigterm-bug', matches);
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

  // Every `require("<X>")` of a Node built-in must use the `node:`
  // prefix. Three reasons (from blamejs v0.9.17 release notes):
  //   1. userland-package shadowing protection (npm packages CAN be
  //      named after built-ins; without `node:`, a typo / accidental
  //      install could shadow the built-in);
  //   2. at-a-glance origin clarity — `node:` is the unambiguous
  //      "this is Node, not a userland module" signal;
  //   3. bundler / SEA static-trace clarity — esbuild / ncc / webpack
  //      / rollup / Bun's bundler / Node's SEA static-analysis pass
  //      all treat `node:` as the canonical Node-builtin marker.
  it('require() of Node built-ins uses the node: prefix', () => {
    var builtins = 'fs|path|crypto|os|net|http|https|http2|stream|tls|url|zlib|dgram|events|child_process|readline|fs\\\/promises|util|assert|buffer|querystring|process';
    var re = new RegExp('\\brequire\\(\\s*[\'"](' + builtins + ')[\'"]\\s*\\)');
    var matches = _scan(re);
    matches = _filterMarkers(matches, 'bare-node-builtin-require');
    _assertClean('bare-node-builtin-require', matches);
  });

  // Internal binding names (the framework's preferred aliases —
  // `nodeFs`, `nodePath`, `nodeCrypto`, `nodeStream`, `nodeTls`,
  // `nodeUrl`, `bCrypto`, etc.) must NOT appear in operator-facing
  // surface: comment / JSDoc prose, error-message strings, audit
  // metadata. Operators see the public-API name (`fs`, `path`,
  // `crypto`, …), never our internal alias. From blamejs's v0.9.17
  // `internal-binding-in-prose` detector.
  it('internal binding names do not leak into comments or string literals', () => {
    var internal = ['nodeFs', 'nodePath', 'nodeCrypto', 'nodeOs', 'nodeNet',
                    'nodeHttp', 'nodeHttps', 'nodeReadline', 'nodeFsPromises',
                    'nodeStream', 'nodeTls', 'nodeUrl', 'nodeEvents', 'bCrypto'];
    var bad = [];
    var files = _sourceFiles();
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        var fragments = [];
        // Comment lines / JSDoc continuation lines — whole line counts as prose.
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) {
          fragments.push(line);
        }
        // String literals — only plain `"..."` / `'...'`. Template
        // literals (`...${expr}...`) are skipped because `${expr}` is
        // executable code, not prose — flagging an `${internalName}`
        // expansion would be a false positive.
        var strRe = /(['"])((?:\\.|(?!\1).)*)\1/g;
        var sm;
        while ((sm = strRe.exec(line)) !== null) fragments.push(sm[0]);
        for (var f2i = 0; f2i < fragments.length; f2i++) {
          for (var ii = 0; ii < internal.length; ii++) {
            var nre = new RegExp('\\b' + internal[ii] + '\\b'); // allow:dynamic-regex — internal-name token from a fixed allowlist
            if (nre.test(fragments[f2i])) {
              bad.push({
                file: _relPath(files[fi]),
                line: li + 1,
                content: 'internal binding `' + internal[ii] + '` appears in prose / string — operator-facing surface should use the public name (drop the `node` / `b` prefix)',
              });
              break;
            }
          }
        }
      }
    }
    _assertClean('internal-binding-in-prose', bad);
  });

  // Literal `===` / `!==` on identifiers whose names suggest cryptographic
  // material (Hash, Token, Sig, Signature, Mac, Digest, Tag) is timing-
  // attack-prone. Should route through `b.crypto.timingSafeEqual`. From
  // blamejs's testNoRawHashCompare detector (v0.9.x patterns suite).
  it('hash/token/sig/mac/digest names compared with timingSafeEqual', () => {
    var matches = _scan(
      /\b\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)\s*(?:===|!==)\s*\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)/);
    matches = _filterMarkers(matches, 'raw-hash-compare');
    _assertClean('raw-hash-compare', matches);
  });

  // `Buffer.from("...")` defaults to UTF-8, but the absence of an
  // explicit encoding masks intent — and for hex/base64 strings the
  // default UTF-8 is wrong silently. From blamejs's
  // testBufferFromStringEncoding (v0.9.x patterns suite).
  it('Buffer.from(string) requires explicit encoding', () => {
    var matches = _scan(/\bBuffer\.from\(\s*(?:"[^"]*"|'[^']*')\s*\)/);
    matches = _filterMarkers(matches, 'buffer-from-no-encoding');
    _assertClean('buffer-from-no-encoding', matches);
  });

  // `require(<non-literal>)` is opaque to bundler static analysis —
  // esbuild / pkg / nexe / Bun-compile cannot include the target in
  // the bundle, breaking packaging-mode invariance at runtime. Caught
  // by us during the v0.9.8 vendor-data dynamic-require bug; upstream
  // adopted the same detector at v0.9.13. From blamejs's
  // testNoDynamicRequires.
  it('require() argument must be a string literal (no dynamic require)', () => {
    var matches = _scan(/\brequire\(\s*[^"'`)]/);
    matches = _filterMarkers(matches, 'dynamic-require');
    _assertClean('dynamic-require', matches);
  });

  // Literal NUL (0x00) bytes in source files. ESLint catches it in CI
  // but Windows local lint may not — and any literal NUL in a string
  // is almost always a copy-paste artifact or a hostile-paste attempt.
  // Use ` ` escape if a NUL is genuinely needed. From blamejs's
  // testNoLiteralNulBytesInSource.
  it('no literal NUL (0x00) bytes in source files', () => {
    var bad = [];
    var files = _sourceFiles();
    for (var fi = 0; fi < files.length; fi++) {
      var buf;
      try { buf = fs.readFileSync(files[fi]); }
      catch (_e) { continue; }
      for (var i = 0; i < buf.length; i++) {
        if (buf[i] === 0) {
          var lineNo = 1;
          for (var k = 0; k < i; k++) if (buf[k] === 0x0a) lineNo += 1;
          bad.push({
            file: _relPath(files[fi]),
            line: lineNo,
            content: 'literal NUL byte at byte offset ' + i + ' (use \\u0000 escape if needed)',
          });
          break;
        }
      }
    }
    _assertClean('literal-nul-byte', bad);
  });

  // Every `(const|let|var) <name> = require('<target>')` binding for a
  // given module MUST use the same variable name across every file in
  // the repo. Inconsistent names (`fs` vs `nodeFs`, `crypto` vs
  // `nodeCrypto`, `path` vs `nodePath`) make grep across the lib
  // unreliable and let shadowing bugs slip past review.
  //
  // CANONICAL_REQUIRE_BINDINGS is the same shape blamejs adopted at
  // v0.9.15 — safety-first defaults: Node built-ins use a `node<X>`
  // prefix so a local var named `fs` / `path` / `crypto` can never
  // shadow them. Modules not listed fall back to majority-wins
  // (most-sites name; alphabetical tiebreak).
  //
  // No allow markers — the fix is rename, not allowlist. If one file
  // has a genuine reason to bind under a different name, every other
  // file gets renamed to match — never the other way around.
  it('require() bindings name the same target the same way across all files', () => {
    var CANONICAL_REQUIRE_BINDINGS = {
      'fs':              'nodeFs',
      'node:fs':         'nodeFs',
      'node:fs/promises':'nodeFsPromises',
      'path':            'nodePath',
      'node:path':       'nodePath',
      'crypto':          'nodeCrypto',
      'node:crypto':     'nodeCrypto',
      'os':              'nodeOs',
      'node:os':         'nodeOs',
      'net':             'nodeNet',
      'node:net':        'nodeNet',
      'http':            'nodeHttp',
      'node:http':       'nodeHttp',
      'https':           'nodeHttps',
      'node:https':      'nodeHttps',
      'readline':        'nodeReadline',
      'node:readline':   'nodeReadline',
      'stream':          'nodeStream',
      'node:stream':     'nodeStream',
      'tls':             'nodeTls',
      'node:tls':        'nodeTls',
      'url':             'nodeUrl',
      'node:url':        'nodeUrl',
    };

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
        // Skip underscore-prefixed bindings — convention is local helpers
        // that intentionally vary from canonical (e.g. _config inside a
        // function that takes `config` as a param).
        if (name.indexOf('_') === 0) continue;
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
      var nameMap = byTarget[t];
      var nameKeys = Object.keys(nameMap);
      var canonical;
      if (Object.prototype.hasOwnProperty.call(CANONICAL_REQUIRE_BINDINGS, t)) {
        canonical = CANONICAL_REQUIRE_BINDINGS[t];
      } else if (nameKeys.length <= 1) {
        continue;
      } else {
        // Majority-wins fallback. Ties resolve alphabetically.
        canonical = nameKeys[0];
        var topCount = nameMap[nameKeys[0]].length;
        for (var nk = 1; nk < nameKeys.length; nk++) {
          var c = nameMap[nameKeys[nk]].length;
          if (c > topCount || (c === topCount && nameKeys[nk] < canonical)) {
            canonical = nameKeys[nk]; topCount = c;
          }
        }
      }
      // Report every site whose binding name is NOT the canonical pick.
      var offending = [];
      for (var nk2 = 0; nk2 < nameKeys.length; nk2++) {
        var n = nameKeys[nk2];
        if (n === canonical) continue;
        offending.push({ name: n, sites: nameMap[n] });
      }
      if (offending.length === 0) continue;
      var detail = offending.map(function (o) {
        return '      `' + o.name + '` -> rename to `' + canonical + '` at: ' +
               o.sites.join(', ');
      }).join('\n');
      violations.push('    require(\'' + t + '\') canonical is `' + canonical + '`:\n' + detail);
    }
    if (violations.length > 0) {
      var msg = 'require-binding-mismatch: ' + violations.length + ' target(s):\n' +
                violations.join('\n');
      assert.equal(null, msg, msg);
    }
  });

  it('no JSON.parse(JSON.stringify(...)) deep-clone (use structuredClone)', () => {
    // class: handrolled-deep-clone
    // The `JSON.parse(JSON.stringify(x))` idiom silently drops Date /
    // Buffer / Map / Set / BigInt / RegExp / function / undefined.
    // structuredClone is the modern answer (Node 17+).
    var matches = _scan(/\bJSON\.parse\s*\(\s*JSON\.stringify\s*\(/);
    matches = _filterMarkers(matches, 'handrolled-deep-clone');
    _assertClean('handrolled-deep-clone', matches);
  });

  it('no for+setTimeout retry loops (route through b.retry.withRetry)', () => {
    // class: handrolled-retry-loop
    // `for (var attempt = 0; attempt < N; attempt++)` with a
    // `setTimeout` inside is the retry-with-backoff idiom. The
    // vendored `b.retry.withRetry` handles isPermanent classification,
    // crypto-strength jitter, max-elapsed-time cap, and observability
    // events. Any inline reinvention is a candidate for replacement.
    var files = _sourceFiles();
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length - 1; li++) {
        var m = /for\s*\(\s*(?:var|let|const)\s+(attempt|tries|retr\w*)\s*=/i.exec(lines[li]);
        if (!m) continue;
        var win = lines.slice(li, Math.min(li + 12, lines.length)).join('\n');
        if (/\bsetTimeout\s*\(/.test(win)) {
          bad.push({
            file:    rel,
            line:    li + 1,
            content: lines[li].trim(),
          });
          break;
        }
      }
    }
    bad = _filterMarkers(bad, 'handrolled-retry-loop');
    _assertClean('handrolled-retry-loop', bad);
  });

  it('no url.format(...) (use new URL() / safeUrl; CVE-2026-21712 IDN crash class)', () => {
    // class: legacy-url-format
    // Node legacy `url.format()` crashes on adversarial IDN input.
    // The WHATWG URL constructor + b.safeUrl are the supported paths.
    var matches = _scan(/\burl\.format\s*\(/);
    matches = _filterMarkers(matches, 'legacy-url-format');
    _assertClean('legacy-url-format', matches);
  });

  it('no dense wildcard runs (4+ consecutive `*` — wildcard-amplification class)', () => {
    // class: dense-wildcard
    // CVE-2026-4923 / CVE-2026-33671 / CVE-2026-26996 — multi-wildcard
    // route / glob patterns compile to catastrophic-backtracking regex
    // on engines that fold `*` into a regex alternation. Four+ runs of
    // `*` outside comments is the smell. The detector regex is a bare
    // run with no surrounding string-literal anchors so the matcher
    // itself can't catastrophic-backtrack on long lines.
    var matches = _scan(/\*{4,}/);
    matches = _filterMarkers(matches, 'dense-wildcard');
    _assertClean('dense-wildcard', matches);
  });

  it('regex literal seen in 3+ files → extract to a shared constant', () => {
    // class: duplicate-regex
    // Same regex literal in 3+ files is an extraction candidate (the
    // canonical example is the email regex). The matcher requires a
    // regex-context preceding token (`=`, `(`, `,`, `?`, `:`, `[`,
    // `;`, `!`, `&&`, `||`, `return`, `throw`, arrow) so a `*/`
    // comment closer or a `path/to/file` string can't trip it.
    var files = _sourceFiles();
    var seen = {};
    var regexCtxRe = /(?:^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\s*\/((?:\\.|[^/\\\n])+)\/([gimsuy]*)(?=[\s,);.\]]|$)/g;
    for (var fi = 0; fi < files.length; fi++) {
      var content;
      try { content = fs.readFileSync(files[fi], 'utf8'); }
      catch (_e) { continue; }
      var lines = content.split(/\r?\n/);
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        var foundMatch;
        regexCtxRe.lastIndex = 0;
        while ((foundMatch = regexCtxRe.exec(line)) !== null) {
          var src = foundMatch[1];
          if (src.length < 6) continue;                                                 // allow:raw-byte-literal — min-source-length floor for triviality skip
          if (!/[\\^$*+?{}()|[\]]/.test(src)) continue;
          if (!seen[src]) seen[src] = [];
          seen[src].push({ file: _relPath(files[fi]), line: li + 1 });
        }
      }
    }
    var bad = [];
    Object.keys(seen).forEach(function (src) {
      var occurrences = seen[src];
      var distinctFiles = {};
      occurrences.forEach(function (o) { distinctFiles[o.file] = true; });
      if (Object.keys(distinctFiles).length >= 3) {
        bad.push({
          file:    occurrences[0].file,
          line:    occurrences[0].line,
          content: 'regex /' + src.slice(0, 60) + (src.length > 60 ? '…' : '') +
                   '/ appears in ' + Object.keys(distinctFiles).length +
                   ' files: ' + Object.keys(distinctFiles).slice(0, 4).join(', ') +
                   (Object.keys(distinctFiles).length > 4 ? ', …' : ''),
        });
      }
    });
    bad = _filterMarkers(bad, 'duplicate-regex');
    _assertClean('duplicate-regex', bad);
  });

});
