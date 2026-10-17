import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
const path = 'backend/worker-configuration.d.ts';
execFileSync(process.execPath, ['node_modules/wrangler/bin/wrangler.js', 'types', path], {
  stdio: 'inherit', env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
});
// Normalize generator whitespace without hand-maintaining runtime declarations.
writeFileSync(path, readFileSync(path, 'utf8').replace(/[\t ]+$/gm, ''));
