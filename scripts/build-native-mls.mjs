// Build source-only native MLS artifacts into ignored local storage. No credentials.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const crate = resolve(root, 'crypto/mls-spike');
const mode = process.argv[2];
const allowed = ['apple-simulator', 'apple-device', 'android'];
if (!allowed.includes(mode)) throw new Error(`Choose one of: ${allowed.join(', ')}`);
function run(command, args, env = process.env) {
  execFileSync(command, args, { cwd: crate, stdio: 'inherit', env });
}
function build(target, extra = {}) {
  run('rustup', ['target', 'add', target]);
  run('cargo', ['build', '--locked', '--release', '--lib', '--target', target], { ...process.env, CARGO_TARGET_DIR: resolve(crate, 'target'), ...extra });
}
if (mode.startsWith('apple-')) {
  if (platform() !== 'darwin') throw new Error('Apple builds require macOS and Xcode.');
  const simulator = mode === 'apple-simulator';
  const targets = simulator ? ['aarch64-apple-ios-sim', 'x86_64-apple-ios'] : ['aarch64-apple-ios'];
  for (const target of targets) build(target, { IPHONEOS_DEPLOYMENT_TARGET: '17.0' });
  const destination = resolve(root, '.local/native/apple', simulator ? 'iphonesimulator' : 'iphoneos');
  mkdirSync(destination, { recursive: true });
  const archives = targets.map(target => resolve(crate, 'target', target, 'release/libsquadtime_mls_spike.a'));
  const output = resolve(destination, 'libsquadtime_mls_spike.a');
  if (archives.length === 1) copyFileSync(archives[0], output);
  else run('xcrun', ['lipo', '-create', ...archives, '-output', output]);
} else {
  const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT;
  const ndk = process.env.ANDROID_NDK_HOME ?? (sdk && resolve(sdk, 'ndk/29.0.14206865'));
  if (!ndk) throw new Error('Set ANDROID_HOME or ANDROID_NDK_HOME to the installed Android toolchain.');
  const host = platform() === 'darwin' ? 'darwin-x86_64' : platform() === 'linux' ? 'linux-x86_64' : null;
  if (!host) throw new Error('Android build helper supports macOS and Linux hosts.');
  const bin = resolve(ndk, 'toolchains/llvm/prebuilt', host, 'bin');
  const clang = resolve(bin, 'aarch64-linux-android31-clang');
  if (!existsSync(clang)) throw new Error('The required NDK compiler is missing.');
  build('aarch64-linux-android', {
    ANDROID_NDK_HOME: ndk, ANDROID_NDK_ROOT: ndk,
    CC_aarch64_linux_android: clang,
    AR_aarch64_linux_android: resolve(bin, 'llvm-ar'),
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER: clang,
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS: '-C link-arg=-Wl,-z,max-page-size=16384',
  });
  const destination = resolve(root, '.local/native/android/arm64-v8a');
  mkdirSync(destination, { recursive: true });
  copyFileSync(resolve(crate, 'target/aarch64-linux-android/release/libsquadtime_mls_spike.so'),
    resolve(destination, 'libsquadtime_mls_spike.so'));
}
console.log(`Built native MLS artifacts: ${mode}.`);
