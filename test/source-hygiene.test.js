import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
test('source hygiene', async () => {
  async function files(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    return (await Promise.all(entries.map((e) => e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)])))
      .flat();
  }
  for (const file of await files(fileURLToPath(new URL('../src/', import.meta.url)))) {
    const source = await readFile(file, 'utf8');
    for (
      const forbidden of [
        /\beval\s*\(/,
        /\bprocess\s*\.\s*env\b/,
        /\b(?:new\s+)?RegExp\s*\(/,
        /\b(?:node:)?(?:child_process|https?|net|tls|dgram|dns)\b/,
      ]
    ) assert.doesNotMatch(source, forbidden, file);
  }
});
