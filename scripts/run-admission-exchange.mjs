// Explicit local simulator/emulator proof. Copies ONLY public protocol envelopes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { base64, publicKey } from './verify-enrollment-fixture.mjs';
import { verifyAdmissionFixture } from './verify-admission-fixture.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const options = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  if (!['--simulator', '--android', '--derived', '--direction'].includes(process.argv[i]) || !process.argv[i + 1]) {
    throw new Error('Use --simulator UUID --android emulator-PORT [--derived PATH] [--direction both|apple|android].');
  }
  options.set(process.argv[i], process.argv[i + 1]);
}
const simulator = options.get('--simulator');
const serial = options.get('--android');
assert.match(simulator ?? '', /^[A-Fa-f0-9-]{36}$/);
assert.match(serial ?? '', /^emulator-[0-9]+$/);
const direction = options.get('--direction') ?? 'both';
assert.ok(['both', 'apple', 'android'].includes(direction));
const derived = resolve(root, options.get('--derived') ?? '.local/admission-derived');
const adb = resolve(process.env.ANDROID_HOME ?? resolve(homedir(), 'Library/Android/sdk'), 'platform-tools/adb');
const runRoot = resolve(root, '.local/admission-exchange', new Date().toISOString().replace(/[:.]/g, '-'));
mkdirSync(runRoot, { recursive: true });
const project = resolve(root, 'native/apple/SquadtimeAppleProof.xcodeproj');
const component = 'dev.squadtime.proof.test/dev.squadtime.proof.VaultRestartInstrumentation';
const phases = { ownerStart: 'testOwnerStart', joinerStart: 'testJoinerStart', ownerAdmit: 'testOwnerAdmit',
  joinerFinish: 'testJoinerFinish', resume: 'testResume', verifyInbox: 'testVerifyInbox', cleanup: 'testCleanup' };
const records = [];
let step = 0;
function command(program, args, { input, log, allowFailure = false } = {}) {
  const result = spawnSync(program, args, { cwd: root, input, encoding: 'utf8', timeout: 180_000, maxBuffer: 32 * 1024 * 1024 });
  if (log) writeFileSync(log, `${result.stdout ?? ''}\n${result.stderr ?? ''}`);
  if (!allowFailure && (result.error || result.status !== 0)) throw new Error(`Proof command failed; inspect ${log ?? 'the scoped native command'}.`);
  return result.stdout ?? '';
}
function android(args, options) { return command(adb, ['-s', serial, ...args], options); }
function apple(args, options) { return command('xcrun', ['simctl', ...args], options); }
function publicOutput(text) {
  assert.ok(Buffer.byteLength(text) <= 192 * 1024);
  const output = JSON.parse(text);
  assert.deepEqual(Object.keys(output).sort(), ['kind', 'nativePublicKey', 'outbox']);
  assert.ok(['invitation', 'request', 'welcome', 'joined'].includes(output.kind));
  publicKey(output.nativePublicKey);
  if (output.kind === 'joined') assert.equal(output.outbox, '');
  else base64(output.outbox, 128 * 1024);
  return output;
}
function execute(platform, phase, input = {}) {
  assert.ok(Object.hasOwn(phases, phase));
  const label = `${String(++step).padStart(2, '0')}-${platform}-${phase}`;
  const log = resolve(runRoot, `${label}.log`);
  let result;
  let processId;
  if (platform === 'apple') {
    apple(['terminate', simulator, 'dev.squadtime.proof.host'], { allowFailure: true });
    const container = apple(['get_app_container', simulator, 'dev.squadtime.proof.host', 'data']).trim();
    assert.ok(container.startsWith('/') && existsSync(container));
    const exchange = resolve(container, 'Documents/admission-exchange');
    mkdirSync(exchange, { recursive: true });
    writeFileSync(resolve(exchange, 'input.json'), JSON.stringify(input));
    rmSync(resolve(exchange, 'output.json'), { force: true });
    const output = command('xcodebuild', ['test-without-building', '-project', project,
      '-scheme', 'AdmissionExchangeProof', '-destination', `platform=iOS Simulator,id=${simulator}`,
      '-derivedDataPath', derived, '-parallel-testing-enabled', 'NO',
      '-only-testing:AdmissionExchangeProofTests/AdmissionExchangeProofTests/' + phases[phase],
      '-resultBundlePath', resolve(runRoot, `${label}.xcresult`)], { log });
    const pid = output.match(/ADMISSION_PHASE\s+\S+\s+PID\s+(\d+)/);
    assert.ok(pid, 'Missing successful Apple phase/process evidence');
    processId = Number(pid[1]);
    if (phase !== 'cleanup') {
      // Query again: installation/testing can change the container UUID.
      const fresh = apple(['get_app_container', simulator, 'dev.squadtime.proof.host', 'data']).trim();
      result = publicOutput(readFileSync(resolve(fresh, 'Documents/admission-exchange/output.json'), 'utf8'));
    }
    apple(['terminate', simulator, 'dev.squadtime.proof.host'], { allowFailure: true });
  } else {
    android(['shell', 'am', 'force-stop', 'dev.squadtime.proof']);
    android(['shell', 'run-as', 'dev.squadtime.proof', 'mkdir', '-p', 'files/admission-exchange']);
    android(['shell', 'run-as', 'dev.squadtime.proof', 'rm', '-f', 'files/admission-exchange/output.json']);
    // adb exec-out does not reliably propagate stdin EOF to a remote cat.
    // Copy a public-only file, then move it into the scoped proof container.
    const publicInput = resolve(runRoot, `${label}.input.public.json`);
    const remoteInput = `/data/local/tmp/squadtime-admission-${process.pid}.json`;
    writeFileSync(publicInput, JSON.stringify(input));
    try {
      android(['push', publicInput, remoteInput]);
      android(['shell', 'run-as', 'dev.squadtime.proof', 'cp', remoteInput, 'files/admission-exchange/input.json']);
    } finally {
      android(['shell', 'rm', '-f', remoteInput], { allowFailure: true });
    }
    const output = android(['shell', 'am', 'instrument', '-w', '-r', '-e', 'admissionProof', 'true',
      '-e', 'phase', phase, component], { log });
    assert.match(output, /admissionProof=passed/);
    assert.match(output, /INSTRUMENTATION_CODE:\s*-1/);
    const pid = output.match(/processId=(\d+)/);
    assert.ok(pid, 'Missing successful Android phase/process evidence');
    processId = Number(pid[1]);
    if (phase !== 'cleanup') result = publicOutput(android(['exec-out', 'run-as', 'dev.squadtime.proof', 'cat', 'files/admission-exchange/output.json']));
    android(['shell', 'am', 'force-stop', 'dev.squadtime.proof']);
  }
  const previous = records.filter(r => r.platform === platform).at(-1);
  if (previous) assert.notEqual(previous.processId, processId, 'Expected a fresh app process');
  records.push({ platform, phase, processId });
  if (result) writeFileSync(resolve(runRoot, `${label}.public.json`), JSON.stringify(result, null, 2) + '\n');
  console.log(`PASS: ${platform} ${phase} in a fresh process.`);
  return result;
}
function resume(platform, expected) {
  const resumed = execute(platform, 'resume');
  assert.deepEqual(resumed, expected, 'Resume must preserve exact committed public outbox');
}
function exchange(owner) {
  const joiner = owner === 'apple' ? 'android' : 'apple';
  const now = 1_700_000_000;
  const invitation = execute(owner, 'ownerStart', { now });
  assert.equal(invitation.kind, 'invitation');
  resume(owner, invitation);
  // Explicit test trust provisioning reads the other local app's public export,
  // not an alleged key inside a relay-supplied invitation/request.
  const request = execute(joiner, 'joinerStart', { now: now + 1, outbox: invitation.outbox,
    trustedAdminPublicKey: invitation.nativePublicKey });
  assert.equal(request.kind, 'request');
  resume(joiner, request);
  const welcome = execute(owner, 'ownerAdmit', { now: now + 2, outbox: request.outbox,
    trustedDevicePublicKey: request.nativePublicKey, userConfirmed: true });
  assert.equal(welcome.kind, 'welcome');
  resume(owner, welcome);
  const fixture = { invitation: invitation.outbox, request: request.outbox, welcome: welcome.outbox,
    trustedAdminPublicKey: invitation.nativePublicKey, trustedDevicePublicKey: request.nativePublicKey,
    admissionNow: now + 2 };
  verifyAdmissionFixture(fixture);
  writeFileSync(resolve(runRoot, `${owner}-owner.public-fixture.json`), JSON.stringify(fixture, null, 2) + '\n');
  // Deliberately late delivery: no new admission after expiry, but already
  // committed and authorized Welcome may arrive after the request deadline.
  const joined = execute(joiner, 'joinerFinish', { now: now + 600, outbox: welcome.outbox });
  assert.equal(joined.kind, 'joined');
  resume(joiner, joined);
  execute(joiner, 'verifyInbox');
  execute(owner, 'cleanup');
  execute(joiner, 'cleanup');
}
try {
  // Callers prepare/install native artifacts and boot only their owned test devices.
  if (direction === 'both' || direction === 'apple') exchange('apple');
  if (direction === 'both' || direction === 'android') exchange('android');
  writeFileSync(resolve(runRoot, 'process-evidence.json'), JSON.stringify(records, null, 2) + '\n');
  console.log(`PASS: independent native admission, exact outbox resume, late Welcome and durable inbox. Evidence: ${runRoot}`);
} catch {
  // Keep scoped state for investigation; do not silently delete a failed phase.
  writeFileSync(resolve(runRoot, 'process-evidence.json'), JSON.stringify(records, null, 2) + '\n');
  console.error(`FAIL: admission exchange stopped; scoped diagnostics: ${runRoot}`);
  process.exitCode = 1;
}
