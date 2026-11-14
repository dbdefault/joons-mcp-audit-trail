import { fileURLToPath as __f } from 'node:url';
process.chdir(__f(new URL('..', import.meta.url)));
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
test('readmes document commands and flags', async () => {
  for (const f of ['README.md', 'README.ko.md']) {
    const s = await readFile(f, 'utf8');
    for (
      const term of [
        'append',
        'verify',
        'anchor',
        'show',
        'summary',
        'export',
        '--type',
        '--actor',
        '--tool',
        '--outcome',
        '--data',
        '--time',
        '--key-file',
        '--anchor',
        '--format',
        '--out',
        '--force',
        '--from',
        '--to',
        '--details',
        '--help',
        '--version',
      ]
    ) assert.ok(s.includes(term), `${f}: ${term}`);
  }
});
test('package allowlist', async () => {
  const p = JSON.parse(await readFile('package.json', 'utf8'));
  assert.deepEqual(p.files, [
    'bin',
    'src',
    'docs',
    'examples',
    'README.md',
    'README.ko.md',
    'ARCHITECTURE.md',
    'SECURITY.md',
    'LIMITATIONS.md',
    'CHANGELOG.md',
    'LICENSE',
  ]);
});
