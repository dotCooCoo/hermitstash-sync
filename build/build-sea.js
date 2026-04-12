#!/usr/bin/env node
'use strict';

/**
 * Build a Node.js Single Executable Application (SEA)
 *
 * Prerequisites:
 *   - Node.js 22+ (with SEA support)
 *   - npx postject (installed globally or via npx)
 *   - npx esbuild (for bundling into single file)
 *
 * Usage:
 *   node build/build-sea.js
 *
 * Output:
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}.sha256
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}.sha3-512
 */

const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = __dirname;
const BUNDLE_PATH = path.join(BUILD_DIR, 'bundle.js');
const SEA_CONFIG = path.join(BUILD_DIR, 'sea-config.json');
const BLOB_PATH = path.join(BUILD_DIR, 'hermitstash-sync.blob');

const VERSION = require(path.join(ROOT, 'lib', 'constants.js')).VERSION;
const PLATFORM = os.platform();
const ARCH = os.arch();
const isWindows = PLATFORM === 'win32';
const platformTag = (PLATFORM === 'win32' ? 'win' : PLATFORM === 'darwin' ? 'macos' : 'linux') + '-' + ARCH;
const EXE_EXT = isWindows ? '.exe' : '';
const EXE_NAME = 'hermitstash-sync-v' + VERSION + '-' + platformTag + EXE_EXT;
const EXE_PATH = path.join(BUILD_DIR, EXE_NAME);
const NODE_PATH = process.execPath;

// Build commands use execSync (shell) because paths contain spaces (Dropbox).
// All arguments are hardcoded — no user input, no injection risk.
function run(cmd) {
  console.log('  > ' + cmd);
  execSync(cmd, { stdio: 'inherit', cwd: ROOT });
}

function q(p) { return '"' + p + '"'; }

console.log('=== HermitStash Sync — SEA Build ===\n');
console.log('Version:  v' + VERSION);
console.log('Platform: ' + PLATFORM + ' ' + ARCH);
console.log('Node.js:  ' + process.version);
console.log('OpenSSL:  ' + process.versions.openssl + '\n');

// Step 1: Bundle
console.log('Step 1: Bundling source files...');
run('npx --yes esbuild ' + q(path.join(ROOT, 'bin', 'hermitstash-sync.js')) + ' --bundle --platform=node --format=cjs --outfile=' + q(BUNDLE_PATH) + ' --external:node:* --banner:js="\'use strict\';"');
if (!fs.existsSync(BUNDLE_PATH)) { console.error('ERROR: Bundle not generated.'); process.exit(1); }
console.log('  Bundle: ' + (fs.statSync(BUNDLE_PATH).size / 1024).toFixed(1) + ' KB\n');

// Step 2: SEA blob
console.log('Step 2: Generating SEA blob...');
run(q(process.execPath) + ' --experimental-sea-config ' + q(SEA_CONFIG));
if (!fs.existsSync(BLOB_PATH)) { console.error('ERROR: Blob not generated.'); process.exit(1); }
console.log('  Blob: ' + (fs.statSync(BLOB_PATH).size / 1024 / 1024).toFixed(1) + ' MB\n');

// Step 3: Copy Node binary
console.log('Step 3: Copying Node.js binary...');
fs.copyFileSync(NODE_PATH, EXE_PATH);
if (PLATFORM === 'darwin') {
  console.log('  Removing macOS code signature...');
  try { run('codesign --remove-signature ' + q(EXE_PATH)); } catch { /* ok */ }
}
console.log('  Binary: ' + EXE_NAME + '\n');

// Step 4: Inject blob
console.log('Step 4: Injecting SEA blob...');
var sentinel = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
var postjectCmd = 'npx --yes postject ' + q(EXE_PATH) + ' NODE_SEA_BLOB ' + q(BLOB_PATH) + ' --sentinel-fuse ' + sentinel;
if (PLATFORM === 'darwin') postjectCmd += ' --macho-segment-name NODE_SEA';
try { run(postjectCmd); } catch { console.error('ERROR: postject failed.'); process.exit(1); }

// Step 5: Re-sign macOS
if (PLATFORM === 'darwin') {
  console.log('\nStep 5: Re-signing macOS binary...');
  try { run('codesign --sign - ' + q(EXE_PATH)); } catch { /* ok */ }
}

// Permissions
if (!isWindows) fs.chmodSync(EXE_PATH, 0o755);

// Cleanup intermediate files
fs.unlinkSync(BLOB_PATH);
fs.unlinkSync(BUNDLE_PATH);

// Step 6: Generate checksums
console.log('\nStep 6: Generating checksums...');
var exeData = fs.readFileSync(EXE_PATH);

var sha256 = crypto.createHash('sha256').update(exeData).digest('hex');
fs.writeFileSync(path.join(BUILD_DIR, EXE_NAME + '.sha256'), sha256 + '  ' + EXE_NAME + '\n');

var sha3 = crypto.createHash('sha3-512').update(exeData).digest('hex');
fs.writeFileSync(path.join(BUILD_DIR, EXE_NAME + '.sha3-512'), sha3 + '  ' + EXE_NAME + '\n');

var size = (exeData.length / 1024 / 1024).toFixed(1);

console.log('\n=== Build complete ===');
console.log('Binary:     ' + EXE_NAME + ' (' + size + ' MB)');
console.log('SHA-256:    ' + sha256);
console.log('SHA3-512:   ' + sha3.substring(0, 32) + '...');
console.log('\nArtifacts:');
console.log('  ' + EXE_NAME);
console.log('  ' + EXE_NAME + '.sha256');
console.log('  ' + EXE_NAME + '.sha3-512');
console.log('\nVerify: "' + EXE_PATH + '" version');
