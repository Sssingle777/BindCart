import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('independent Owner origin serves the same platform tokens and components', async () => {
  for (const name of ['tokens.css', 'platform.css']) {
    const [source, owner] = await Promise.all([
      readFile(new URL(`../public/${name}`, import.meta.url), 'utf8'),
      readFile(new URL(`../owner-public/${name}`, import.meta.url), 'utf8'),
    ]);
    assert.equal(owner, source, `${name}: run npm run styles:sync after editing public/`);
  }
});
