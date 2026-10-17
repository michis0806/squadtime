#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const staged = process.argv.includes('--staged');

function git(args, options = {}) {
  return execFileSync('git', args, { cwd: root, encoding: 'buffer', ...options });
}

function listFiles() {
  const raw = staged
    ? git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'])
    : git(['ls-files', '-z']);
  return raw.toString('utf8').split('\0').filter(Boolean);
}

const riskyDirectory = /(?:^|\/)(?:credentials?|secrets?)(?:\/|$)/i;
const riskyName = /(?:\.env(?:\..*)?|\.dev\.vars(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]*\.(?:pem|p8|p12|pfx|key|jks|keystore))$/i;
const safeExample = /(?:^|\/)(?:\.env(?:\.[^/]*)?\.(?:example|sample|template)|\.dev\.vars\.(?:example|sample|template)|[^/]*(?:example|sample|template)[^/]*\.(?:pem|key))$/i;
const privateDeploymentPath = /(?:^|\/)\.local(?:\/|$)|(?:^|\/)wrangler\.remote\.jsonc$/i;
const detectors = [
  ['private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/],
  ['AWS access key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
  [
    'credential assignment',
    /(?:["']?\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret[_-]?key)\b["']?\s*=\s*["']?(?!your[_ -]|change[_ -]?me|replace[_ -]?me|example\b|placeholder\b|<)[A-Za-z0-9_./+=-]{16,}|["']\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret[_-]?key)\b["']\s*:\s*["'](?!your[_ -]|change[_ -]?me|replace[_ -]?me|example\b|placeholder\b|<)[A-Za-z0-9_./+=-]{16,}["'])/i,
  ],
];
const findings = [];

for (const path of listFiles()) {
  const normalized = path.replaceAll('\\', '/');
  if (
    privateDeploymentPath.test(normalized) ||
    riskyDirectory.test(normalized) ||
    (riskyName.test(normalized) && !safeExample.test(normalized))
  ) {
    findings.push(`${path}: risky credential filename`);
  }

  let content;
  try {
    content = staged
      ? git(['show', `:${path}`]).toString('utf8')
      : readFileSync(join(root, path), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') continue;
    throw error;
  }
  if (content.includes('\0')) continue;
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    for (const [label, pattern] of detectors) {
      if (pattern.test(lines[index])) {
        findings.push(`${path}:${index + 1}: possible ${label}`);
        break;
      }
    }
  }
}

if (findings.length) {
  console.error(`Secret guard found ${findings.length} issue(s):`);
  for (const finding of findings) console.error(`  ${finding}`);
  console.error('Remove credentials from the file/history and use local environment files or a secret manager.');
  process.exit(1);
}

console.log(`Secret guard passed (${staged ? 'staged' : 'tracked'} files; ${listFiles().length} paths checked).`);
