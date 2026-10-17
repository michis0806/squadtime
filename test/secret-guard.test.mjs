import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function withTemporaryRepository(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'squadtime-secret-guard-'));
  try {
    mkdirSync(path.join(root, 'scripts'));
    for (const file of ['check-secrets.mjs', 'install-git-hooks.mjs', 'pre-commit']) {
      writeFileSync(
        path.join(root, 'scripts', file),
        readFileSync(path.join(projectRoot, 'scripts', file)),
      );
    }
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'secret-guard-test@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'Secret Guard Test'], { cwd: root });
    const install = spawnSync(process.execPath, ['scripts/install-git-hooks.mjs'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(install.status, 0, install.stderr);
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function git(root, ...args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
}

function runHook(root) {
  return spawnSync(path.join(root, '.git', 'hooks', 'pre-commit'), [], {
    cwd: root,
    encoding: 'utf8',
  });
}

function syntheticCredentialLine() {
  const key = ['pass', 'word'].join('');
  const value = `synthetic-${'x'.repeat(32)}`;
  return `${key} = "${value}"\n`;
}

test('pre-commit scans the staged blob, not unstaged worktree content', () => {
  withTemporaryRepository((root) => {
    writeFileSync(path.join(root, 'note.txt'), 'safe\n');
    git(root, 'add', 'note.txt');
    git(root, 'commit', '-qm', 'initial');

    writeFileSync(path.join(root, 'note.txt'), syntheticCredentialLine());
    assert.equal(runHook(root).status, 0);

    git(root, 'add', 'note.txt');
    writeFileSync(path.join(root, 'note.txt'), 'safe worktree copy\n');
    const stagedCredential = runHook(root);
    assert.notEqual(stagedCredential.status, 0);
    assert.doesNotMatch(stagedCredential.stderr, /synthetic-x/);
    assert.match(stagedCredential.stderr, /possible credential assignment/);
  });
});

test('credential assignments distinguish TypeScript types from JSON and environment values', () => {
  withTemporaryRepository((root) => {
    writeFileSync(path.join(root, 'note.txt'), 'safe\n');
    git(root, 'add', 'note.txt');
    git(root, 'commit', '-qm', 'initial');

    const key = ['pass', 'word'].join('');
    const value = `synthetic-${'y'.repeat(32)}`;
    writeFileSync(path.join(root, 'worker.d.ts'), `${key}: URLPatternComponentResult;\n`);
    git(root, 'add', 'worker.d.ts');
    assert.equal(runHook(root).status, 0);

    git(root, 'reset', '-q');
    writeFileSync(path.join(root, 'settings.json'), `{"${key}":"${value}"}\n`);
    git(root, 'add', 'settings.json');
    const jsonFinding = runHook(root);
    assert.notEqual(jsonFinding.status, 0);
    assert.match(jsonFinding.stderr, /possible credential assignment/);
    assert.doesNotMatch(jsonFinding.stderr, /synthetic-y/);

    git(root, 'reset', '-q');
    writeFileSync(path.join(root, '.env'), `${key.toUpperCase()}=${value}\n`);
    git(root, 'add', '-f', '.env');
    const environmentFinding = runHook(root);
    assert.notEqual(environmentFinding.status, 0);
    assert.match(environmentFinding.stderr, /possible credential assignment/);
    assert.doesNotMatch(environmentFinding.stderr, /synthetic-y/);
  });
});

test('pre-commit checks force-added dependency and local deployment paths', () => {
  withTemporaryRepository((root) => {
    writeFileSync(path.join(root, 'note.txt'), 'safe\n');
    git(root, 'add', 'note.txt');
    git(root, 'commit', '-qm', 'initial');

    const dependencyFile = path.join(root, 'node_modules', 'cache', 'config.json');
    mkdirSync(path.dirname(dependencyFile), { recursive: true });
    writeFileSync(dependencyFile, syntheticCredentialLine());
    git(root, 'add', '-f', 'node_modules/cache/config.json');
    const dependencyFinding = runHook(root);
    assert.notEqual(dependencyFinding.status, 0);
    assert.match(dependencyFinding.stderr, /possible credential assignment/);

    git(root, 'reset', '-q');
    const localConfig = path.join(root, '.local', 'wrangler.remote.jsonc');
    mkdirSync(path.dirname(localConfig), { recursive: true });
    writeFileSync(localConfig, '{ "account_id": "synthetic" }\n');
    git(root, 'add', '-f', '.local/wrangler.remote.jsonc');
    const localFinding = runHook(root);
    assert.notEqual(localFinding.status, 0);
    assert.match(localFinding.stderr, /risky credential filename/);

    git(root, 'reset', '-q');
    writeFileSync(path.join(root, 'wrangler.remote.jsonc'), '{ "account_id": "synthetic" }\n');
    git(root, 'add', '-f', 'wrangler.remote.jsonc');
    const remoteFinding = runHook(root);
    assert.notEqual(remoteFinding.status, 0);
    assert.match(remoteFinding.stderr, /risky credential filename/);

    git(root, 'reset', '-q');
    const credentialsFile = path.join(root, 'node_modules', 'credentials', 'settings.json');
    mkdirSync(path.dirname(credentialsFile), { recursive: true });
    writeFileSync(credentialsFile, '{ "safe": true }\n');
    git(root, 'add', '-f', 'node_modules/credentials/settings.json');
    const directoryFinding = runHook(root);
    assert.notEqual(directoryFinding.status, 0);
    assert.match(directoryFinding.stderr, /risky credential filename/);
  });
});

test('hook installer refuses to replace a custom pre-commit hook', () => {
  withTemporaryRepository((root) => {
    const hook = path.join(root, '.git', 'hooks', 'pre-commit');
    const customHook = '#!/bin/sh\nexit 0\n';
    writeFileSync(hook, customHook);

    const install = spawnSync(process.execPath, ['scripts/install-git-hooks.mjs'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.notEqual(install.status, 0);
    assert.match(install.stderr, /Refusing to overwrite existing pre-commit hook/);
    assert.equal(readFileSync(hook, 'utf8'), customHook);
  });
});
