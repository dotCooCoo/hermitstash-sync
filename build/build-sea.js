#!/usr/bin/env node
'use strict';

/**
 * Build a Node.js Single Executable Application (SEA)
 * 
 * Prerequisites:
 *   - Node.js 22+ (with SEA support)
 *   - npx postject (installed globally or via npx)
 * 
 * Usage:
 *   node build/build-sea.js
 * 
 * Output:
 *   build/hermitstash-sync       (Linux/macOS)
 *   build/hermitstash-sync.exe   (Windows)
 */

const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = __dirname;
const SEA_CONFIG = path.join(BUILD_DIR, 'sea-config.json');
const BLOB_PATH = path.join(BUILD_DIR, 'hermitstash-sync.blob');

const isWindows = os.platform() === 'win32';
const EXE_NAME = isWindows ? 'hermitstash-sync.exe' : 'hermitstash-sync';
const EXE_PATH = path.join(BUILD_DIR, EXE_NAME);
const NODE_PATH = process.execPath;

function run(cmd, opts = {}) {
  console.log(`  > ${cmd}`);
  execSync(cmd, { stdio: 'inherit', cwd: ROOT, ...opts });
}

console.log('=== HermitStash Sync — SEA Build ===\n');
console.log(`Platform: ${os.platform()} ${os.arch()}`);
console.log(`Node.js:  ${process.version}`);
console.log(`OpenSSL:  ${process.versions.openssl}\n`);

// Step 1: Generate the blob
console.log('Step 1: Generating SEA blob...');
run(`node --experimental-sea-config ${SEA_CONFIG}`);

if (!fs.existsSync(BLOB_PATH)) {
  console.error('ERROR: Blob was not generated.');
  process.exit(1);
}
console.log(`  Blob: ${BLOB_PATH} (${(fs.statSync(BLOB_PATH).size / 1024 / 1024).toFixed(1)} MB)\n`);

// Step 2: Copy Node.js binary
console.log('Step 2: Copying Node.js binary...');
fs.copyFileSync(NODE_PATH, EXE_PATH);

// Remove code signature on macOS (required before injecting)
if (os.platform() === 'darwin') {
  console.log('  Removing macOS code signature...');
  try {
    run(`codesign --remove-signature ${EXE_PATH}`);
  } catch {
    console.log('  codesign not available, skipping...');
  }
}

console.log(`  Binary: ${EXE_PATH}\n`);

// Step 3: Inject the blob
console.log('Step 3: Injecting SEA blob into binary...');
const sentinel = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

try {
  run(`npx --yes postject ${EXE_PATH} NODE_SEA_BLOB ${BLOB_PATH} --sentinel-fuse ${sentinel}` +
    (os.platform() === 'darwin' ? ' --macho-segment-name NODE_SEA' : ''));
} catch (err) {
  console.error('\nERROR: postject failed. Install it with: npm install -g postject');
  process.exit(1);
}

// Step 4: Re-sign on macOS
if (os.platform() === 'darwin') {
  console.log('\nStep 4: Re-signing macOS binary...');
  try {
    run(`codesign --sign - ${EXE_PATH}`);
  } catch {
    console.log('  codesign not available, skipping...');
  }
}

// Make executable on Unix
if (!isWindows) {
  fs.chmodSync(EXE_PATH, 0o755);
}

// Clean up blob
fs.unlinkSync(BLOB_PATH);

const size = (fs.statSync(EXE_PATH).size / 1024 / 1024).toFixed(1);
console.log(`\n=== Build complete ===`);
console.log(`Output: ${EXE_PATH} (${size} MB)`);
console.log(`\nTest: ${EXE_PATH} version`);
