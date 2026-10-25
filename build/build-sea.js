#!/usr/bin/env node
'use strict';

/**
 * Build a Node.js Single Executable Application (SEA)
 *
 * Prerequisites:
 *   - Node.js 24.21.0+ (matches package.json engines.node; the build embeds this runtime)
 *   - `npm ci --ignore-scripts`, which installs the esbuild and postject
 *     versions package-lock.json pins
 *
 * Usage:
 *   node build/build-sea.js
 *
 * Output:
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}.sha256
 *   build/hermitstash-sync-v{VERSION}-{platform}-{arch}{.exe}.sha3-512
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

// esbuild and postject come from node_modules at the versions package-lock.json
// pins. Without them the build stops and names the install command.
function requireBuildTool(name) {
  try {
    return require(name);
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND') {
      console.error('ERROR: ' + name + ' is not installed. Run `npm ci --ignore-scripts` in the repository root, ' +
        'which installs the version package-lock.json pins, then run this build again.');
      process.exit(1);
    }
    throw e;
  }
}
const esbuild = requireBuildTool('esbuild');
const postject = requireBuildTool('postject');

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
// Use --node-binary flag or NODE_BIN env var to override the Node binary
// (Homebrew-built Node strips the SEA fuse; official binaries from nodejs.org are required)
const NODE_PATH = (() => {
  const flagIdx = process.argv.indexOf('--node-binary');
  if (flagIdx !== -1 && process.argv[flagIdx + 1]) return path.resolve(process.argv[flagIdx + 1]);
  if (process.env.NODE_BIN) return path.resolve(process.env.NODE_BIN);
  return process.execPath;
})();
const SENTINEL_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

// Runs a program with an argument array and no shell, so a path with spaces in
// it reaches the program as one argument.
function run(file, args) {
  console.log('  > ' + [file].concat(args).map(function (a) { return /\s/.test(a) ? '"' + a + '"' : a; }).join(' '));
  execFileSync(file, args, { stdio: 'inherit', cwd: ROOT });
}

async function main() {
  console.log('=== HermitStash Sync — SEA Build ===\n');
  console.log('Version:  v' + VERSION);
  console.log('Platform: ' + PLATFORM + ' ' + ARCH);
  console.log('Node.js:  ' + process.version);
  console.log('OpenSSL:  ' + process.versions.openssl);
  console.log('esbuild:  ' + esbuild.version + '\n');

  // Step 1: Bundle
  console.log('Step 1: Bundling source files...');
  const bundled = esbuild.buildSync({
    absWorkingDir: ROOT,
    entryPoints: [path.join(ROOT, 'bin', 'hermitstash-sync.js')],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    outfile: BUNDLE_PATH,
    external: ['node:*'],
    banner: { js: "'use strict';" },
    logLevel: 'info',
    metafile: true,
  });
  if (!fs.existsSync(BUNDLE_PATH)) { console.error('ERROR: Bundle not generated.'); process.exit(1); }
  // The client may require only node: built-ins and files in this repository,
  // vendored blamejs included. node_modules holds the dev tools `npm ci`
  // installed for this build, and none of them belongs in the binary.
  const fromPackages = Object.keys(bundled.metafile.inputs).filter((p) => /(^|[\\/])node_modules[\\/]/.test(p));
  if (fromPackages.length > 0) {
    console.error('ERROR: the bundle includes ' + fromPackages.length + ' file(s) from node_modules, starting with ' +
      fromPackages[0] + '. Replace the require() that reaches it with a node: built-in or vendored code.');
    process.exit(1);
  }
  console.log('  Bundle: ' + (fs.statSync(BUNDLE_PATH).size / 1024).toFixed(1) + ' KB\n');

  // Step 2: SEA blob
  console.log('Step 2: Generating SEA blob...');
  run(process.execPath, ['--experimental-sea-config', SEA_CONFIG]);
  if (!fs.existsSync(BLOB_PATH)) { console.error('ERROR: Blob not generated.'); process.exit(1); }
  console.log('  Blob: ' + (fs.statSync(BLOB_PATH).size / 1024 / 1024).toFixed(1) + ' MB\n');

  // Step 3: Copy Node binary
  console.log('Step 3: Copying Node.js binary...');
  fs.copyFileSync(NODE_PATH, EXE_PATH);
  if (PLATFORM === 'darwin') {
    console.log('  Removing macOS code signature...');
    try { run('codesign', ['--remove-signature', EXE_PATH]); } catch { /* ok */ }
  }
  console.log('  Binary: ' + EXE_NAME + '\n');

  // Step 4: Inject blob
  console.log('Step 4: Injecting SEA blob...');
  try {
    await postject.inject(EXE_PATH, 'NODE_SEA_BLOB', fs.readFileSync(BLOB_PATH), {
      sentinelFuse: SENTINEL_FUSE,
      machoSegmentName: PLATFORM === 'darwin' ? 'NODE_SEA' : undefined,
    });
  } catch (e) {
    console.error('ERROR: postject failed: ' + (e && e.message ? e.message : String(e)));
    process.exit(1);
  }

  // Step 5: Re-sign macOS
  if (PLATFORM === 'darwin') {
    console.log('\nStep 5: Re-signing macOS binary...');
    try { run('codesign', ['--sign', '-', EXE_PATH]); } catch { /* ok */ }
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
}

main().catch(function (e) {
  console.error('ERROR: ' + (e && e.stack ? e.stack : String(e)));
  process.exit(1);
});
