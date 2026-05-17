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

  return false;
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

module.exports = { matchAny, isIgnored, isIncluded, shouldSync };
