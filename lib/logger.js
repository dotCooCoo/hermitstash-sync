'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LOG_FILE, CONFIG_DIR } = require('./constants');

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

let _level = LEVELS.info;
let _logStream = null;
let _stdout = true;

function init(opts = {}) {
  if (opts.level && LEVELS[opts.level] !== undefined) {
    _level = LEVELS[opts.level];
  }
  if (opts.stdout === false) _stdout = false;

  // Ensure parent directory of log file exists
  const logPath = opts.file || LOG_FILE;
  fs.mkdirSync(path.dirname(logPath), { recursive: true });

  // Open log file in append mode
  _logStream = fs.createWriteStream(logPath, { flags: 'a' });
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
