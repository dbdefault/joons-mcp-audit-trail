import { fileURLToPath as __f } from 'node:url';
process.chdir(__f(new URL('..', import.meta.url)));
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
const digest = (x) => createHash('sha256').update(x.toLowerCase()).digest('hex');
const banned = new Set([
  '5b4b48680ddbf06da83e238d1f1d91d9d12adaf2468968735762174c16da8cc4',
  '60c5590f72eef292f9545afc28bf63ca91d2016a0a288f90f9a32f89d3fffcaf',
  '06f8faea3b5f697691b6d063a07ba4ffaf1ece9a1d473c588565231cdc8e59cc',
  '55eae50b75e2b2990f2c18be84ca079727a85f61b839c3359249801fe1ab9e9c',
  '879cc67a846b570c4241f1880f79e6ed1646abd9eca44882782cb6c8c568ab53',
  'bb349f269976d971294e3cdd5847b128917eb85d2834cc5320a5142f8cc579b8',
  '49b871379e80ec1010bf0ec5542b1a9a3feff3241ec193c0c18e10faf52fbc7b',
  '5f56ae8c1b334076da229cc9a77550bfd24388e9f7d273f0fbe1752929d7cbe2',
]);
const hasBanned = (s) => s.match(/[A-Za-z0-9_:\\-]+/g)?.some((x) => banned.has(digest(x))) ?? false;
test('hashed sentinel detection', () => {
  const marker = String.fromCharCode(112, 108, 97, 110, 116, 101, 100, 115, 101, 110, 116, 105, 110, 101, 108);
  assert.equal(hasBanned(marker), true);
  assert.equal(hasBanned('ordinary'), false);
});
test('documentation links and minimum size', async () => {
  for (const f of ['README.md', 'README.ko.md', 'docs/API.md', 'ARCHITECTURE.md']) {
    const s = await readFile(f, 'utf8');
    if (f.startsWith('README')) assert.ok(Buffer.byteLength(s) >= 6000, `${f} is too short`);
    for (const m of s.matchAll(/\]\(([^)#]+)(?:#[^)]*)?\)/g)) {
      if (!/^[a-z]+:/i.test(m[1])) assert.ok((await stat(resolve(dirname(f), m[1]))).isFile(), m[1]);
    }
  }
});
test('shipped files contain no hashed forbidden tokens', async () => {
  const paths = [
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
  ];
  async function scan(p) {
    const st = await stat(p);
    if (st.isDirectory()) { for (const name of await readdir(p)) await scan(join(p, name)); }
    else assert.equal(hasBanned(await readFile(p, 'utf8')), false, p);
  }
  for (const p of paths) await scan(p);
});
test('source has no network, dynamic evaluation or subprocess', async () => {
  async function scan(p) {
    const st = await stat(p);
    if (st.isDirectory()) { for (const name of await readdir(p)) await scan(join(p, name)); }
    else {
      const s = await readFile(p, 'utf8');
      assert.doesNotMatch(s, /\b(?:eval|fetch)\s*\(|node:(?:child_process|http|https|net|tls)|process\.env/);
    }
  }
  await scan('src');
});
