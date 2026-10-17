#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
let hooksPath = '.git/hooks';
try {
  hooksPath = execFileSync('git', ['config', '--path', '--get', 'core.hooksPath'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim() || hooksPath;
} catch (error) {
  if (error.status !== 1) throw error;
}
const hooksDir = resolve(root, hooksPath);
mkdirSync(hooksDir, { recursive: true });
const hook = join(hooksDir, 'pre-commit');
const contents = '#!/bin/sh\nrepo_root=$(git rev-parse --show-toplevel)\nexec node "$repo_root/scripts/check-secrets.mjs" --staged\n';
let existing;
try {
  const info = lstatSync(hook);
  if (!info.isFile()) throw new Error(`Refusing to replace non-file pre-commit hook at ${hook}`);
  existing = readFileSync(hook, 'utf8');
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (existing !== undefined && existing !== contents) {
  throw new Error(`Refusing to overwrite existing pre-commit hook at ${hook}`);
}
if (existing === undefined) writeFileSync(hook, contents, { mode: 0o755, flag: 'wx' });
else chmodSync(hook, 0o755);
console.log(`Installed pre-commit hook at ${hook}`);
