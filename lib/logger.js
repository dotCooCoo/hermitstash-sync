'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LOG_FILE, CONFIG_DIR } = require('./constants');

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const MAX_LOG_SIZE = 10 * 1024 * 1024; // L4: 10 MB rotation threshold
const ROTATION_CHECK_INTERVAL = 100; // Check rotation every N writes

let _level = LEVELS.info;
let _logStream = null;
let _stdout = true;
let _logPath = null;
let _writeCount = 0;

function init(opts = {}) {
  if (opts.level && LEVELS[opts.level] !== undefined) {
    _level = LEVELS[opts.level];
  }
  if (opts.stdout === false) _stdout = false;

  // Ensure parent directory of log file exists
  _logPath = opts.file || LOG_FILE;
  fs.mkdirSync(path.dirname(_logPath), { recursive: true });

  // H5: Check if log path is a symlink — remove it to prevent symlink attacks
  try {
    const stat = fs.lstatSync(_logPath);
    if (stat.isSymbolicLink()) {
      fs.unlinkSync(_logPath);
    }
  } catch {}

  // Open log file in append mode
  _logStream = fs.createWriteStream(_logPath, { flags: 'a' });
  // M10: Swallow stream errors — logging should never crash the daemon
  _logStream.on('error', () => {});
}

function _write(level, msg, data) {
  if (LEVELS[level] < _level) return;

  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
  };
  if (data !== undefined) {
    if (data instanceof Error) {
      entry.error = { message: data.message, stack: data.stack };
    } else {
      entry.data = data;
    }
  }

  const line = JSON.stringify(entry) + '\n';

  if (_logStream) {
    _logStream.write(line);
    // L4: Check for log rotation periodically
    _writeCount++;
    if (_writeCount >= ROTATION_CHECK_INTERVAL) {
      _writeCount = 0;
      _checkRotation();
    }
  }

  if (_stdout) {
    const prefix = level === 'error' ? '\x1b[31m' :
                   level === 'warn'  ? '\x1b[33m' :
                   level === 'debug' ? '\x1b[90m' : '';
    const reset = prefix ? '\x1b[0m' : '';
    const display = data instanceof Error
      ? `${msg}: ${data.message}`
      : data !== undefined
        ? `${msg} ${typeof data === 'object' ? JSON.stringify(data) : data}`
        : msg;
    process.stdout.write(`${prefix}[${entry.ts.slice(11, 19)}] ${level.toUpperCase().padEnd(5)} ${display}${reset}\n`);
  }
}

/**
 * L4: Rotate log file if it exceeds MAX_LOG_SIZE.
 */
function _checkRotation() {
  if (!_logPath) return;
  try {
    const stat = fs.statSync(_logPath);
    if (stat.size > MAX_LOG_SIZE) {
      _logStream.end();
      try { fs.renameSync(_logPath, _logPath + '.1'); } catch {}
      _logStream = fs.createWriteStream(_logPath, { flags: 'a' });
      _logStream.on('error', () => {});
    }
  } catch {}
}

function close() {
  if (_logStream) {
    _logStream.end();
    _logStream = null;
  }
}

module.exports = {
  init,
  close,
  debug: (msg, data) => _write('debug', msg, data),
  info:  (msg, data) => _write('info', msg, data),
  warn:  (msg, data) => _write('warn', msg, data),
  error: (msg, data) => _write('error', msg, data),
};
