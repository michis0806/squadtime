import { mkdirSync, writeFileSync } from 'node:fs';
const account = process.env.CLOUDFLARE_ACCOUNT_ID;
const database = process.env.SQUADTIME_D1_ID;
if (!/^[a-f0-9]{32}$/.test(account ?? '') || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(database ?? '') || database === '00000000-0000-0000-0000-000000000000') {
  throw new Error('Set explicit CLOUDFLARE_ACCOUNT_ID and SQUADTIME_D1_ID for the verified DEV account.');
}
mkdirSync('.local', { recursive: true, mode: 0o700 });
writeFileSync('.local/wrangler.json', JSON.stringify({
  $schema: '../node_modules/wrangler/config-schema.json', name: 'squadtime-api-dev',
  account_id: account, main: '../backend/src/index.ts', compatibility_date: '2026-10-17',
  workers_dev: true, preview_urls: false, observability: { enabled: false },
  d1_databases: [{ binding: 'DB', database_name: 'squadtime-dev', database_id: database,
    migrations_dir: '../backend/migrations' }], triggers: { crons: ['17 * * * *'] },
}, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
console.log('Wrote ignored .local/wrangler.json; no credentials stored.');
