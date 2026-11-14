import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash, createHmac } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLog } from '../src/index.js';
import { ERROR_KINDS } from '../src/errors.js';
import { help } from '../src/cli/core.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const read = (name) => readFile(join(root, name), 'utf8');

// Independent canonicalizer, written for this test only.
const canon = (v) =>
  v === null || typeof v !== 'object'
    ? JSON.stringify(v)
    : Array.isArray(v)
    ? '[' + v.map(canon).join(',') + ']'
    : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
const hashOf = (record, key) => {
  const { hash, ...body } = record;
  void hash;
  return (key ? createHmac('sha256', key) : createHash('sha256')).update(canon(body), 'utf8').digest('hex');
};

test('FORMAT.md test vectors are recomputed with node:crypto', async (t) => {
  const text = await read('docs/FORMAT.md');
  const stored = [...text.matchAll(/^(\{.*"hash":"[0-9a-f]{64}".*\})$/gm)].map((m) => m[1]);
  const lines = stored.map((l) => JSON.parse(l));
  // The documented lines are the exact stored form: they equal the canonical form of their own content.
  for (const [i, l] of stored.entries()) assert.equal(canon(lines[i]), l);
  assert.equal(lines.length, 4);
  const [header, event, anchor, keyedHeader] = [lines[0], lines[1], lines[2], lines[3]];
  const key = Buffer.from('0123456789abcdef');
  assert.equal(hashOf(header, null), header.hash);
  assert.equal(hashOf(event, null), event.hash);
  assert.equal(event.prev, header.hash);
  assert.equal(hashOf(anchor, null), anchor.hash);
  assert.equal(anchor.headHash, event.hash);
  assert.equal(hashOf(keyedHeader, key), keyedHeader.hash);
  assert.equal(
    keyedHeader.keyId,
    createHash('sha256').update(createHash('sha256').update(key).digest()).digest('hex').slice(0, 16),
  );
  const { hash: ignored, ...headerBody } = header;
  void ignored;
  const canonicalHeader = canon(headerBody);
  assert.ok(text.includes(canonicalHeader));
  assert.ok(text.includes(createHash('sha256').update(canonicalHeader).digest('hex')));
  // The two complete lines form a log that the real verifier accepts.
  const dir = await mkdtemp(join(tmpdir(), 'audit-docs-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const log = join(dir, 'log');
  await writeFile(log, stored[0] + '\n' + stored[1] + '\n');
  const report = await verifyLog(log, {});
  assert.equal(report.ok, true, JSON.stringify(report));
});

test('README.md and README.ko.md document the same commands, flags, errors and sections', async () => {
  const en = await read('README.md');
  const ko = await read('README.ko.md');
  const terms = [
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
    '--require-keyed',
    '--anchor',
    '--format',
    '--out',
    '--force',
    '--from',
    '--to',
    '--details',
    '--help',
    '--version',
    'terminal',
    'json',
    'markdown',
    'csv',
    ...ERROR_KINDS,
    'truncated_tail',
    'header_not_keyed',
    'line_not_canonical',
    'key_mismatch',
    'anchor_mismatch',
    'hash_mismatch',
  ];
  for (const term of terms) {
    assert.ok(en.includes(term), `README.md: ${term}`);
    assert.ok(ko.includes(term), `README.ko.md: ${term}`);
  }
  const headings = (s) => s.split('\n').filter((l) => l.startsWith('## ')).length;
  assert.equal(headings(en), headings(ko));
  const fences = (s) => (s.match(/^```/gm) || []).length;
  assert.equal(fences(en), fences(ko));
  assert.ok((ko.match(/[가-힣]/g) || []).length > 1500);
  // Every usage line in --help appears in both READMEs.
  for (const line of help.split('\n').filter((l) => /^ {2}(append|verify|anchor|show|summary|export) /.test(l))) {
    assert.ok(en.includes('joons-mcp-audit-trail' + line.trim().replace(/^/, ' ')), line);
    assert.ok(ko.includes('joons-mcp-audit-trail' + line.trim().replace(/^/, ' ')), line);
  }
});

test('honest-scope paragraph is present in README, SECURITY and LIMITATIONS', async () => {
  const sentences = [
    'detects modification; it does not prevent it',
    'can recompute hashes in unkeyed mode, can forge a log',
    'Tail truncation is detected only against an anchor or a known count',
    'Timestamps are caller-supplied claims, not trusted time',
    'does not authenticate who wrote a record',
    'not a replacement for write-once storage',
  ];
  for (const file of ['README.md', 'SECURITY.md', 'LIMITATIONS.md']) {
    const s = await read(file);
    for (const x of sentences) assert.ok(s.includes(x), `${file}: ${x}`);
  }
  const downgrade = 'cannot be told from a genuine plain log';
  for (const file of ['README.md', 'SECURITY.md', 'LIMITATIONS.md']) {
    assert.ok((await read(file)).includes(downgrade), file);
  }
  const ko = await read('README.ko.md');
  assert.ok(ko.includes('변경을 감지할 뿐 막지는 못합니다'));
  assert.ok(ko.includes('구별할 수 없습니다'));
});

test('documents contain no replacement-character damage', async () => {
  for (
    const file of [
      'README.md',
      'README.ko.md',
      'SECURITY.md',
      'LIMITATIONS.md',
      'ARCHITECTURE.md',
      'CHANGELOG.md',
      'docs/API.md',
      'docs/FORMAT.md',
    ]
  ) {
    const s = await read(file);
    assert.ok(!s.includes('�'), file);
    assert.ok(!/\w\?\w/.test(s.replace(/`[^`]*`/g, '')), `${file}: stray question mark inside a word`);
    assert.ok(!s.startsWith('﻿'), `${file}: byte-order mark`);
  }
});

test('API.md names every library export', async () => {
  const api = await read('docs/API.md');
  const exported = await import('../src/index.js');
  for (const name of Object.keys(exported)) assert.ok(api.includes(name), name);
});

test('README quick start has separate shell forms and a tamper demo that works on macOS', async () => {
  for (const file of ['README.md', 'README.ko.md']) {
    const s = await read(file);
    assert.ok(s.includes('```bat'), file + ': cmd form');
    assert.ok(s.includes('```powershell'), file + ': PowerShell form');
    assert.ok(s.includes('UTF-16'), file + ': PowerShell 5.1 note');
    assert.ok(!/echo '/.test(s), file + ': echo with single quotes');
    assert.ok(!/sed -i/.test(s), file + ': GNU-only sed -i');
    assert.ok(s.includes('node -e'), file + ': node one-liner');
  }
});

test('CI job has a timeout and the changelog is dated', async () => {
  const workflow = await read('.github/workflows/test.yml');
  assert.match(workflow, /timeout-minutes: 30/);
  assert.match(await read('CHANGELOG.md'), /^## 0\.1\.0 Preview \(\d{4}-\d{2}-\d{2}\)$/m);
});

test('SECURITY and LIMITATIONS state the documented limits', async () => {
  for (const file of ['SECURITY.md', 'LIMITATIONS.md']) {
    const s = await read(file);
    for (const phrase of ['Parent directory components', 'entropy', 'hard links', '.name.<hex>.tmp']) {
      assert.ok(s.includes(phrase), file + ': ' + phrase);
    }
  }
  assert.ok((await read('SECURITY.md')).includes('--require-keyed'));
  assert.ok((await read('SECURITY.md')).includes('key identifier'));
});
