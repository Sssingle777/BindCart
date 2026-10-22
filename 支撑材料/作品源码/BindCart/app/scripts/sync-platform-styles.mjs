// public/ owns shared styles. Owner serves exact local copies on its own origin.
// No server routing, CSP or authorization changes are needed for this contract.
import { readFile, writeFile } from 'node:fs/promises';

const check = process.argv.includes('--check');
let mismatch = false;
for (const name of ['tokens.css', 'platform.css']) {
  const source = await readFile(new URL(`../public/${name}`, import.meta.url));
  const target = new URL(`../owner-public/${name}`, import.meta.url);
  if (check) {
    const actual = await readFile(target);
    if (!source.equals(actual)) {
      console.error(`Shared style differs: owner-public/${name}; run npm run styles:sync`);
      mismatch = true;
    }
  } else {
    await writeFile(target, source);
  }
}
if (mismatch) process.exitCode = 1;
else console.log(check ? 'Shared platform styles are identical.' : 'Owner shared styles synchronized from public/.');
