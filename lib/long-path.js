'use strict';

// Windows long-path support. NTFS supports paths up to ~32767 chars
// but the Win32 API surfaces a 260-char MAX_PATH limit unless the
// path is prefixed with `\\?\` (or `\\?\UNC\` for UNC paths). Node
// auto-prepends this in some cases but not all — and only when the
// `LongPathsEnabled` registry flag is on, which many user machines
// don't have. This helper returns a `\\?\`-prefixed path for long
// absolute Windows paths so node:fs calls keep working on deep trees
// (node_modules in particular hits this often).
//
// Pass-through on non-Windows + on already-prefixed paths + on short
// paths under a safety threshold. node:path operations elsewhere
// stay path-agnostic — this helper applies ONLY at the syscall
// boundary in lib/http-client.js + lib/sync-engine.js + lib/diagnose.js.

const nodePath = require('node:path');

// Threshold is below MAX_PATH (260) to leave headroom for downstream
// operations that append (e.g. fs.renameSync(dir, dir + '.bak')).
const LONG_PATH_THRESHOLD = 248; // allow:raw-byte-literal — Windows MAX_PATH-adjacent threshold (count, not bytes)

function longPath(p) {
  if (process.platform !== 'win32') return p;
  if (typeof p !== 'string' || p.length === 0) return p;
  if (p.startsWith('\\\\?\\') || p.startsWith('\\\\.\\')) return p;
  if (p.length < LONG_PATH_THRESHOLD) return p;

  // Resolve to absolute + normalize. node:path.resolve on Windows
  // returns a backslash-canonical path, but defensively swap any
  // forward slashes — `\\?\` form rejects them.
  const absolute = nodePath.resolve(p).replace(/\//g, '\\');

  // UNC path (\\server\share\...) routes through \\?\UNC\server\share.
  if (absolute.startsWith('\\\\')) {
    return '\\\\?\\UNC\\' + absolute.slice(2);
  }
  return '\\\\?\\' + absolute;
}

module.exports = { longPath, LONG_PATH_THRESHOLD };
