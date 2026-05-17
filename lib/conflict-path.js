'use strict';

// Builds a filesystem-portable conflict-suffixed path for last-write-
// wins collisions. Pure function; no I/O.
//
// Shape: <dir>/<base>.conflict-<UTC>.<ext>
//   UTC: YYYY-MM-DDTHH-MM-SSZ  (Windows-safe — no colons)
//
// Example: /sync/notes.md  →  /sync/notes.conflict-2026-05-17T19-30-00Z.md
//
// If the candidate already exists (cosmically-unlikely second collision
// within the same second), appends -1, -2, ... until a free name lands.
// Upstream candidate: b.atomicFile.conflictName({ path, timestamp? })

const nodeFs = require('node:fs');
const nodePath = require('node:path');

function _fmtTimestamp(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/:/g, '-');
}

/**
 * Returns the next available conflict path for `originalPath`. Will
 * not create or move the file — caller is responsible for the rename.
 */
function build(originalPath, opts) {
  opts = opts || {};
  const ts = _fmtTimestamp(opts.timestamp instanceof Date ? opts.timestamp : new Date());
  const dir = nodePath.dirname(originalPath);
  const ext = nodePath.extname(originalPath);
  const base = nodePath.basename(originalPath, ext);
  let candidate = nodePath.join(dir, `${base}.conflict-${ts}${ext}`);
  if (!nodeFs.existsSync(candidate)) return candidate;
  for (let i = 1; i < 1000; i++) { // allow:raw-byte-literal — same-second suffix retry cap (count, not bytes)
    candidate = nodePath.join(dir, `${base}.conflict-${ts}-${i}${ext}`);
    if (!nodeFs.existsSync(candidate)) return candidate;
  }
  // Cosmically unlikely; fall back to a random suffix so we never block.
  const b = require('../vendor/blamejs');                                     // allow:inline-require — cold fallback path; avoids loading blamejs for the common case
  const rand = b.crypto.generateToken({ bytes: 4, encoding: 'hex' });
  return nodePath.join(dir, `${base}.conflict-${ts}-${rand}${ext}`);
}

module.exports = { build };
