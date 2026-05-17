'use strict';

// sd_notify wrapper that shells out to systemd-notify(1). Node's
// node:dgram doesn't support unix DGRAM sockets (the IPC type
// $NOTIFY_SOCKET uses), and we don't ship native addons; the
// systemd-notify CLI on every systemd host accepts KEY=VALUE
// assignments verbatim and writes them to $NOTIFY_SOCKET for us.
//
// No-op when $NOTIFY_SOCKET is absent (Docker / Windows / dev / SysV
// init) or when systemd-notify isn't on PATH. Operator-facing log
// records the first hit either way so it's debuggable.
//
// Spec: https://www.freedesktop.org/software/systemd/man/sd_notify.html
// CLI:  https://www.freedesktop.org/software/systemd/man/systemd-notify.html
//
// Upstream candidate: b.systemdNotify.{ready, status, watchdog, stopping,
// reloading, isUnderSystemd}. blamejs has nothing systemd-specific today
// (just policy comments in app-shutdown.js); this is the highest-leverage
// upstream candidate surfaced by the v0.8.2 audit because every blamejs-
// built Linux daemon would benefit. When upstreamed, swap this module
// for b.systemdNotify; the call sites are call-compatible.

const b = require('../vendor/blamejs');
const log = require('./logger');

const C = b.constants;

// codebase-patterns:allow raw-process-env — sd_notify reads $NOTIFY_SOCKET
// by spec; the value is the documented operator contract from systemd.
function isUnderSystemd() {
  return Boolean(process.env.NOTIFY_SOCKET);                                    // allow:raw-process-env
}

// Sanitize an assignment value: strip CR/LF, refuse NUL. The systemd-
// notify CLI accepts arbitrary bytes but we only emit ASCII status
// strings we control; this is defense-in-depth, not a security gate.
function _safeValue(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/[\r\n\0]/g, ' ').slice(0, 256); // allow:raw-byte-literal — status-string length cap; systemd-notify accepts much longer but we keep it tight
}

let _warnedMissing = false;
async function _sendAssignments(pairs) {
  if (!isUnderSystemd()) return false;
  if (!Array.isArray(pairs) || pairs.length === 0) return false;
  // --pid=<our_pid> tells systemd to attribute the notification to the
  // daemon's PID rather than systemd-notify's transient child PID, which
  // lets the unit file run with NotifyAccess=main instead of =all.
  const argv = ['--pid=' + process.pid].concat(pairs);
  try {
    const result = await b.processSpawn.spawn('systemd-notify', argv, {
      timeoutMs:    C.TIME.seconds(2),
      captureStdio: true,
    });
    if (result && result.code === 0) return true;
    if (!_warnedMissing) {
      _warnedMissing = true;
      log.warn('systemd-notify exited non-zero', { code: result && result.code, stderr: (result && result.stderr || '').slice(0, 200) }); // allow:raw-byte-literal — stderr excerpt cap for log brevity
    }
    return false;
  } catch (err) {
    if (!_warnedMissing) {
      _warnedMissing = true;
      log.warn('systemd-notify unavailable; running under Type=simple semantics', { error: err.message });
    }
    return false;
  }
}

function ready(statusText) {
  const pairs = ['READY=1'];
  if (statusText) pairs.push('STATUS=' + _safeValue(statusText));
  return _sendAssignments(pairs);
}

function status(statusText) {
  if (!statusText) return Promise.resolve(false);
  return _sendAssignments(['STATUS=' + _safeValue(statusText)]);
}

function watchdog() {
  return _sendAssignments(['WATCHDOG=1']);
}

function stopping(statusText) {
  const pairs = ['STOPPING=1'];
  if (statusText) pairs.push('STATUS=' + _safeValue(statusText));
  return _sendAssignments(pairs);
}

function reloading() {
  return _sendAssignments(['RELOADING=1']);
}

module.exports = { ready, status, watchdog, stopping, reloading, isUnderSystemd };
