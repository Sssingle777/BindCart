import { readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Expand paths in JavaScript: cmd.exe does not expand test/*.test.mjs.
const root = fileURLToPath(new URL('../', import.meta.url));
const group = process.argv[2] ?? 'all';
if (!['all', 'dual', 'dbac'].includes(group)) throw new Error('Expected all, dual or dbac');
const files = (await readdir(new URL('../test/', import.meta.url))).filter(name =>
  name.endsWith('.test.mjs') && (group === 'all' || (group === 'dbac'
    ? /^(dbac|framework|w3c|credential-status)/.test(name)
    : /^(storefront|live-|merchant|delivery-flow)/.test(name)))).sort();
const child = spawn(process.execPath, ['--test', '--test-concurrency=2', '--test-reporter=tap', ...files.map(name => `test/${name}`)], {
  cwd: root, stdio: 'inherit', env: { ...process.env, UWS_USE_FALLBACK: '1' },
});
child.once('error', error => { console.error(error.message); process.exitCode = 1; });
child.once('exit', code => { process.exitCode = code ?? 1; });
