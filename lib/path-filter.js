'use strict';

// Path-pattern matcher shared by the watcher (local-side ignore) and
// the sync engine (server-event filter for selective sync). Same
// vocabulary either direction:
//
//   exact:           path === pattern
//   basename:        no '/' in pattern  → matches basename(path)
//   extension:       pattern starts '*.'
//   tilde:           pattern is '*~'
//   recursive dir:   pattern ends '/**' → matches the dir + everything under it
//   path-qualified:  a pattern containing '/' (no trailing '/**') matches the
//                    path itself AND everything beneath it — 'src/node_modules'
//                    excludes 'src/node_modules' and 'src/node_modules/x/y'.
//                    Equivalent to writing 'src/node_modules/**' but tolerant of
//                    the trailing-'/**' being omitted, which operators routinely
//                    forget. A file path 'src/node_modules.txt' is NOT matched —
//                    the prefix only matches at a path-segment boundary.
//
// `classifyPattern` returns which of those grammar branches a pattern lands in,
// or 'unsupported' for a shape the matcher treats literally (and therefore
// silently never matches). config.js uses it to warn at load so a mistyped
// glob is loud rather than silently letting data through. The matcher's
// supported set is frozen here — widening it changes which files sync and is
// gated behind its own release note.
//
// `shouldSync` is the composition for selective sync:
//   true iff path is INCLUDED (include empty OR matches any include)
//        AND NOT IGNORED (no ignore pattern matches)

const nodePath = require('node:path');

function _matchPattern(filepath, pattern) {
  if (filepath === pattern) return true;

  if (!pattern.includes('/')) {
    const basename = nodePath.basename(filepath);
    if (basename === pattern) return true;
    if (pattern.startsWith('*.')) {
      const ext = pattern.slice(1);
      if (basename.endsWith(ext)) return true;
    }
    if (pattern === '*~' && basename.endsWith('~')) return true;
    return false;
  }

  if (pattern.endsWith('/**')) {
    const dir = pattern.slice(0, -3);
    if (filepath.startsWith(dir + '/') || filepath === dir) return true;
    return false;
  }

  // Path-qualified directory pattern WITHOUT a trailing '/**'. Previously this
  // matched only the directory inode (via the `filepath === pattern` line
  // above) and never its contents, so 'src/node_modules' excluded the empty
  // directory but synced everything under it — the opposite of the operator's
  // intent. Match the subtree the same way '/**' does, but only at a path-
  // segment boundary so 'src/foo' never matches a sibling file 'src/foobar'.
  if (filepath.startsWith(pattern + '/')) return true;

  return false;
}

// Grammar branch a pattern lands in, or 'unsupported' for a shape the matcher
// treats as a literal string (and so silently never matches a real path). The
// branch conditions here mirror _matchPattern exactly; keep them in lockstep.
//
// The 'unsupported' set is the silent-no-op trap: shapes that LOOK like globs
// an operator would reasonably write but that the matcher does not honor —
// anchored leading '/', trailing-slash bare dir, '[...]' char ranges, '?'
// single-char wildcards, '!' negation, prefix/infix '*' (anything with '*'
// that is not exactly '*.<ext>' or '*~'), and a mid-path '**' (only a trailing
// '/**' is recursive). config.js warns on each so the operator hears about a
// pattern that will silently match nothing.
function classifyPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) return 'unsupported';

  // Anchored leading slash — not honored; the matcher has no repo-root anchor.
  if (pattern.startsWith('/')) return 'unsupported';
  // Trailing slash bare directory — 'build/' matches nothing; needs 'build/**'.
  if (pattern.endsWith('/')) return 'unsupported';
  // Char ranges, single-char wildcard, negation — all treated literally.
  if (pattern.includes('[') || pattern.includes(']') ||
      pattern.includes('?') || pattern.includes('!')) {
    return 'unsupported';
  }

  if (!pattern.includes('/')) {
    if (pattern === '*~') return 'tilde';
    // '*.<ext>' is the only wildcard basename shape; the '*' must be the very
    // first char and the rest must carry no further wildcard.
    if (pattern.startsWith('*.') && !pattern.slice(1).includes('*')) return 'ext';
    // Any other '*' in a basename pattern (prefix 'temp*', infix 'a*b', bare
    // '*') is silently literal — flag it.
    if (pattern.includes('*')) return 'unsupported';
    return 'basename';
  }

  if (pattern.endsWith('/**')) {
    // Recursive-dir — but only a SINGLE trailing '/**'. A mid-path '**'
    // ('work/**/cache') or a stray '*' elsewhere in the path is literal.
    const head = pattern.slice(0, -3);
    if (head.includes('*')) return 'unsupported';
    return 'recursive-dir';
  }

  // Path-qualified pattern with a '/'. A '*' anywhere in it (mid-path '**'
  // included) is literal and matches nothing — flag it. Otherwise it is the
  // path-qualified directory-subtree shape.
  if (pattern.includes('*')) return 'unsupported';
  return 'path-qualified';
}

function matchAny(filepath, patterns) {
  if (!patterns || patterns.length === 0) return false;
  const normalized = filepath.split(nodePath.sep).join('/');
  for (const pattern of patterns) {
    if (_matchPattern(normalized, pattern)) return true;
  }
  return false;
}

function isIgnored(filepath, ignorePatterns) {
  return matchAny(filepath, ignorePatterns);
}

// Selective sync semantics: an empty include list means "everything";
// a non-empty list means "only paths matching at least one entry."
// The set of synced paths is therefore included MINUS ignored.
function isIncluded(filepath, includePatterns) {
  if (!includePatterns || includePatterns.length === 0) return true;
  return matchAny(filepath, includePatterns);
}

function shouldSync(filepath, opts) {
  opts = opts || {};
  if (!isIncluded(filepath, opts.include)) return false;
  if (isIgnored(filepath, opts.ignore)) return false;
  return true;
}

module.exports = { matchAny, isIgnored, isIncluded, shouldSync, classifyPattern };
