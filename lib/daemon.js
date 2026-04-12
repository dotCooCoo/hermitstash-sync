'use strict';

const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { PID_FILE, LOG_FILE, CONFIG_DIR } = require('./constants');
const log = require('./logger');

/**
 * Fork the current process as a background daemon
 */
function daemonize() {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });

  const logFd = fs.openSync(LOG_FILE, 'a');

  const child = spawn(process.execPath, process.argv.slice(1).filter(a => a !== '--daemon'), {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: { ...process.env, HERMITSTASH_SYNC_DAEMON: '1' },
  });

  child.unref();

  // H6: Write PID file with exclusive create to avoid TOCTOU race
  try {
    const fd = fs.openSync(PID_FILE, 'wx');
    fs.writeSync(fd, String(child.pid));
    fs.closeSync(fd);
  } catch (err) {
    if (err.code === 'EEXIST') {
      // PID file already exists — check if the process is alive
      const existingPid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
      try {
        process.kill(existingPid, 0);
        console.error(`Daemon already running (PID ${existingPid})`);
        process.exit(1);
      } catch {
        // Stale PID file — overwrite
        fs.writeFileSync(PID_FILE, String(child.pid), { mode: 0o644 });
      }
    } else {
      throw err;
    }
  }

  console.log(`Daemon started (PID ${child.pid})`);
  console.log(`Log: ${LOG_FILE}`);
  console.log(`PID: ${PID_FILE}`);

  process.exit(0);
}

/**
 * Check if a daemon is running
 */
function isRunning() {
  if (!fs.existsSync(PID_FILE)) return false;

  const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
  if (isNaN(pid)) return false;

  try {
    process.kill(pid, 0); // signal 0 = check if process exists
    return pid;
  } catch {
    // Process doesn't exist — stale PID file
    fs.unlinkSync(PID_FILE);
    return false;
  }
}

/**
 * Stop a running daemon
 */
function stop() {
  const pid = isRunning();
  if (!pid) {
    console.log('No daemon running');
    return false;
  }

  try {
    process.kill(pid, 'SIGTERM');
    console.log(`Sent SIGTERM to PID ${pid}`);

    // Wait up to 5 seconds for clean shutdown
    const start = Date.now();
    while (Date.now() - start < 5000) {
      try {
        process.kill(pid, 0);
        // M9: Cross-platform 200ms wait (no shell dependency)
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      } catch {
        // Process exited
        break;
      }
    }

    // Clean up PID file
    if (fs.existsSync(PID_FILE)) {
      fs.unlinkSync(PID_FILE);
    }

    console.log('Daemon stopped');
    return true;
  } catch (err) {
    console.error(`Failed to stop daemon: ${err.message}`);
    return false;
  }
}

/**
 * Write PID file for foreground mode.
 * H6: Uses exclusive create to avoid TOCTOU race.
 */
function writePid() {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  try {
    const fd = fs.openSync(PID_FILE, 'wx');
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
  } catch (err) {
    if (err.code === 'EEXIST') {
      // Check if the existing PID is alive
      const existingPid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
      try {
        process.kill(existingPid, 0);
        // Process is alive — bail out
        throw new Error(`Another instance is running (PID ${existingPid})`);
      } catch (e) {
        if (e.message.includes('Another instance')) throw e;
        // Stale PID file — overwrite
        fs.writeFileSync(PID_FILE, String(process.pid), { mode: 0o644 });
      }
    } else {
      throw err;
    }
  }
}

/**
 * Remove PID file
 */
function removePid() {
  try {
    if (fs.existsSync(PID_FILE)) {
      fs.unlinkSync(PID_FILE);
    }
  } catch {}
}

/**
 * Install signal handlers for clean shutdown
 */
function installSignalHandlers(shutdownFn, resyncFn) {
  const handler = async (signal) => {
    log.info(`Received ${signal}, shutting down`);
    await shutdownFn();
    removePid();
    process.exit(0);
  };

  process.on('SIGTERM', () => handler('SIGTERM'));
  process.on('SIGINT', () => handler('SIGINT'));

  // L9: SIGHUP is not available on Windows
  if (resyncFn && process.platform !== 'win32') {
    process.on('SIGHUP', () => {
      log.info('Received SIGHUP, triggering resync');
      resyncFn();
    });
  }

  process.on('uncaughtException', err => {
    log.error('Uncaught exception', err);
    removePid();
    process.exit(1);
  });

  process.on('unhandledRejection', err => {
    log.error('Unhandled rejection', err);
  });
}

module.exports = { daemonize, isRunning, stop, writePid, removePid, installSignalHandlers };
