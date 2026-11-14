import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { buildRecords, cli, errLine, expectFail, expectOk, KEY, tempDir, writeLog } from '../reference/helpers.js';
import { appendRecord, createAnchor, readRecords, summarize, verifyLog } from '../src/index.js';
import {
  checkPath,
  createAtomicWriter,
  internal,
  loadKey,
  readSmallFile,
  sameFile,
  statLogSafe,
  writeFileAtomic,
} from '../src/log/index.js';
import { lockPathFor } from '../src/log/paths.js';

const BS = String.fromCharCode(92);
const bs = (s) => s.replaceAll('|', BS);
const kindOf = (fn) => {
  try {
    fn();
  } catch (e) {
    return e.kind;
  }
  return null;
};

// Spellings of UNC and device-namespace paths. "|" stands for a backslash.
const NAMESPACE_PATHS = [
  '//host/share/file',
  '||host|share|file',
  '/|host|share|file',
  '|/host/share/file',
  '/|?|C:|file',
  '|/.|file',
  '//?/C:/file',
  '|?|C:|file',
  '||?|C:|file',
  '||.|pipe|name',
  '//./pipe/name',
  '/|.|pipe|name',
].map(bs);

const BAD_NAMES = [
  'CON',
  'con',
  'Prn',
  'AUX',
  'nul',
  'NUL.jsonl',
  'COM1',
  'com9.txt',
  'LPT1',
  'lpt9.a.b',
  'Con.Tar.Gz',
  'CONIN$',
  'log.',
  'log ',
  'a:b',
  'log.jsonl:stream',
  'log.jsonl::$DATA',
];

test('path checker refuses UNC, device and mixed-separator spellings for every kind', () => {
  for (const p of NAMESPACE_PATHS) {
    for (const kind of ['output_error', 'input_unreadable', 'key_invalid']) {
      assert.equal(kindOf(() => checkPath(p, kind)), kind, p);
    }
  }
});

test('path checker refuses NUL bytes, empty and non-string paths', () => {
  for (const p of ['a' + String.fromCharCode(0) + 'b', '', null, undefined, 5, {}]) {
    assert.equal(kindOf(() => checkPath(p, 'input_unreadable')), 'input_unreadable');
  }
});

test('path checker refuses alternate data streams and reserved device names on every platform', async (t) => {
  const dir = tempDir(t);
  for (const name of BAD_NAMES) {
    assert.equal(kindOf(() => checkPath(join(dir, name), 'output_error')), 'output_error', name);
    assert.equal(kindOf(() => checkPath(name, 'output_error')), 'output_error', name);
  }
  assert.equal(kindOf(() => checkPath(join(dir, 'ok.jsonl'), 'output_error')), null);
  assert.equal(kindOf(() => checkPath(join(dir, 'console.log'), 'output_error')), null);
  assert.equal(kindOf(() => checkPath('C:' + BS + 'dir' + BS + 'log.jsonl', 'output_error')), null);
  // Nothing is created by a refused call.
  for (const name of ['CON', 'NUL', 'nul.jsonl', 'COM1', 'PRN', 'log.jsonl:stream']) {
    await assert.rejects(appendRecord(join(dir, name), { type: 'x' }), { kind: 'output_error' });
    await assert.rejects(writeFileAtomic(join(dir, name), 'x'), { kind: 'output_error' });
    await assert.rejects(statLogSafe(join(dir, name)), { kind: 'input_unreadable' });
  }
  assert.deepEqual(await fs.readdir(dir), []);
});

test('real-process CLI: every path argument is checked with the right error kind', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const key = join(dir, 'key');
  const data = join(dir, 'data.json');
  const anchor = join(dir, 'anchor.json');
  expectOk(cli(['append', log, '--type', 'first']));
  expectOk(cli(['anchor', log, '--out', anchor]));
  void key;
  void data;
  const sample = [2, 5, 8, 9].map((i) => NAMESPACE_PATHS[i]);
  for (const p of [...sample, join(dir, 'CON'), join(dir, 'log.jsonl:stream')]) {
    expectFail(cli(['verify', p]), 2, 'input_unreadable');
    expectFail(cli(['verify', log, '--anchor', p]), 2, 'input_unreadable');
    expectFail(cli(['verify', log, '--key-file', p]), 2, 'key_invalid');
    expectFail(cli(['append', p, '--type', 'x']), 4, 'output_error');
    expectFail(cli(['append', log, '--type', 'x', '--data', p]), 2, 'input_unreadable');
    expectFail(cli(['append', log, '--type', 'x', '--key-file', p]), 2, 'key_invalid');
    expectFail(cli(['anchor', log, '--out', p]), 4, 'output_error');
    expectFail(cli(['export', log, '--out', p, '--format', 'json']), 4, 'output_error');
    expectFail(cli(['show', p]), 2, 'input_unreadable');
    expectFail(cli(['summary', p]), 2, 'input_unreadable');
  }
});

test('input files must be regular files: directory, hard link', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  writeLog(log, buildRecords(2));
  const sub = join(dir, 'folder');
  await fs.mkdir(sub);
  const file = join(dir, 'file.txt');
  await fs.writeFile(file, '{"x":1}');
  await fs.link(file, join(dir, 'file-link.txt'));
  for (const bad of [sub, file]) {
    await assert.rejects(readSmallFile(bad, 10, 'input_unreadable'), { kind: 'input_unreadable' });
    await assert.rejects(loadKey(bad), { kind: 'key_invalid' });
    await assert.rejects(verifyLog(log, { anchorFile: bad }), { kind: 'input_unreadable' });
    expectFail(cli(['append', log, '--type', 'x', '--data', bad]), 2, 'input_unreadable');
    expectFail(cli(['verify', log, '--anchor', bad]), 2, 'input_unreadable');
    expectFail(cli(['verify', log, '--key-file', bad]), 2, 'key_invalid');
  }
  await assert.rejects(statLogSafe(sub), { kind: 'input_unreadable' });
  await assert.rejects(appendRecord(sub, { type: 'x' }), { kind: 'output_error' });
});

async function trySymlink(t, target, link) {
  try {
    await fs.symlink(target, link);
    return true;
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOSYS', 'UNKNOWN'].includes(e.code)) {
      t.skip('SKIPPED: this system does not allow creating symbolic links (' + e.code + ')');
      return false;
    }
    throw e;
  }
}

test('symbolic links are refused everywhere (skipped visibly if they cannot be created)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  writeLog(log, buildRecords(2, KEY));
  const keyFile = join(dir, 'key');
  await fs.writeFile(keyFile, KEY);
  const dataFile = join(dir, 'data.json');
  await fs.writeFile(dataFile, '{"a":1}');
  const anchorFile = join(dir, 'anchor.json');
  expectOk(cli(['anchor', log, '--out', anchorFile, '--key-file', keyFile]));
  const links = {
    log: join(dir, 'l-log'),
    key: join(dir, 'l-key'),
    data: join(dir, 'l-data'),
    anchor: join(dir, 'l-anchor'),
  };
  if (!(await trySymlink(t, log, links.log))) return;
  await fs.symlink(keyFile, links.key);
  await fs.symlink(dataFile, links.data);
  await fs.symlink(anchorFile, links.anchor);
  expectFail(cli(['verify', links.log, '--key-file', keyFile]), 2, 'input_unreadable');
  expectFail(cli(['append', links.log, '--type', 'x', '--key-file', keyFile]), 4, 'output_error');
  expectFail(cli(['verify', log, '--key-file', links.key]), 2, 'key_invalid');
  expectFail(cli(['verify', log, '--key-file', keyFile, '--anchor', links.anchor]), 2, 'input_unreadable');
  expectFail(cli(['append', log, '--type', 'x', '--data', links.data, '--key-file', keyFile]), 2, 'input_unreadable');
  expectFail(cli(['anchor', log, '--out', links.log, '--force', '--key-file', keyFile]), 4, 'output_error');
  expectFail(cli(['export', log, '--out', links.data, '--force', '--format', 'json']), 4, 'output_error');
});

test('parent directories are not checked: a junction or symlinked parent is accepted', async (t) => {
  const dir = tempDir(t);
  const real = join(dir, 'real');
  await fs.mkdir(real);
  const via = join(dir, 'via');
  try {
    await fs.symlink(real, via, 'junction');
  } catch (e) {
    t.skip('SKIPPED: cannot create a junction or directory link here (' + e.code + ')');
    return;
  }
  expectOk(cli(['append', join(via, 'log.jsonl'), '--type', 'first']));
  expectOk(cli(['append', join(real, 'log.jsonl'), '--type', 'second']));
  expectOk(cli(['verify', join(via, 'log.jsonl')]));
  assert.equal(await lockPathFor(join(via, 'log.jsonl')), await lockPathFor(join(real, 'log.jsonl')));
});

test('the lock path comes from the real parent directory and folds case where file names fold case', async (t) => {
  const dir = tempDir(t);
  const lower = await lockPathFor(join(dir, 'log.jsonl'));
  const upper = await lockPathFor(join(dir, 'LOG.JSONL'));
  assert.ok(lower.endsWith('.lock'));
  if (process.platform === 'win32' || process.platform === 'darwin') assert.equal(lower, upper);
  else assert.notEqual(lower, upper);
  await assert.rejects(lockPathFor(join(dir, 'missing', 'log')), { kind: 'output_error' });
});

test('Windows 8.3 aliases ("~" and a digit) are refused for the log path on Windows', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('SKIPPED: 8.3 short names exist only on Windows');
    return;
  }
  const dir = tempDir(t);
  for (const name of ['LONGLO~1.JSO', 'a~1', 'x~9.log']) {
    await assert.rejects(appendRecord(join(dir, name), { type: 'x' }), { kind: 'output_error' }, name);
    await assert.rejects(statLogSafe(join(dir, name)), { kind: 'input_unreadable' }, name);
  }
  await appendRecord(join(dir, 'a~b.log'), { type: 'x' });
});

test('named pipes and sockets are never opened (no connection is made, no hang)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  writeLog(log, buildRecords(2));
  let connections = 0;
  let pipePath;
  if (process.platform === 'win32') {
    pipePath = BS + BS + '.' + BS + 'pipe' + BS + 'audit-test-' + process.pid + '-' + Date.now();
  } else pipePath = join(dir, 'pipe');
  let created = false;
  if (process.platform === 'win32') {
    const server = createServer(() => {
      connections++;
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(pipePath, resolve);
    });
    t.after(() => new Promise((resolve) => server.close(resolve)));
    created = true;
  } else {
    const made = spawnSync('mkfifo', [pipePath]);
    created = made.status === 0;
    if (!created) {
      t.skip('SKIPPED: mkfifo is not available');
      return;
    }
  }
  assert.ok(created);
  const started = Date.now();
  for (
    const args of [
      ['append', log, '--type', 'x', '--data', pipePath],
      ['verify', log, '--anchor', pipePath],
      ['verify', log, '--key-file', pipePath],
      ['verify', pipePath],
      ['append', pipePath, '--type', 'x'],
    ]
  ) {
    const r = cli(args, { timeout: 20000 });
    assert.notEqual(r.status, null, 'process hung: ' + args[0]);
    assert.ok([2, 4].includes(r.status), r.stderr);
    assert.match(r.stderr, /^joons-mcp-audit-trail: (input_unreadable|key_invalid|output_error)\n$/);
  }
  assert.ok(Date.now() - started < 60000);
  assert.equal(connections, 0);
});

test('a unix socket file is refused (POSIX only)', async (t) => {
  if (process.platform === 'win32') {
    t.skip('SKIPPED: unix socket files are not used on Windows');
    return;
  }
  const dir = tempDir(t);
  const sock = join(dir, 's.sock');
  const server = createServer(() => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(sock, resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(readSmallFile(sock, 10, 'input_unreadable'), { kind: 'input_unreadable' });
  await assert.rejects(statLogSafe(sock), { kind: 'input_unreadable' });
});

test('library errors carry only the kind: no path, no message detail', async (t) => {
  const dir = tempDir(t);
  const secretName = join(dir, 'private-name-12345', 'log.jsonl');
  for (
    const attempt of [
      () => appendRecord(secretName, { type: 'x' }),
      () => verifyLog(secretName),
      () => createAnchor(secretName),
      () => summarize(secretName),
      async () => {
        for await (const item of readRecords(secretName)) void item;
      },
      () => writeFileAtomic(secretName, 'x'),
      () => loadKey(secretName),
    ]
  ) {
    try {
      await attempt();
      assert.fail('expected an error');
    } catch (e) {
      assert.match(e.message, /^[a-z_]+$/);
      assert.ok(!String(e.stack).includes('private-name-12345') || !e.message.includes('private'));
      assert.ok(!JSON.stringify(e).includes('private-name'));
    }
  }
  const r = cli(['verify', secretName]);
  assert.equal(r.stderr, errLine('input_unreadable'));
});

test('--out equal to any input is refused even with --force, and the input is untouched', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const key = join(dir, 'key');
  writeLog(log, buildRecords(2, KEY));
  await fs.writeFile(key, KEY);
  const anchorFile = join(dir, 'anchor.json');
  expectOk(cli(['anchor', log, '--out', anchorFile, '--key-file', key]));
  const logBefore = await fs.readFile(log);
  const keyBefore = await fs.readFile(key);
  const spellings = (p) => [p, join(dir, '.', p.slice(dir.length + 1)), join(dir, 'x', '..', p.slice(dir.length + 1))];
  for (const out of spellings(log)) {
    expectFail(cli(['anchor', log, '--out', out, '--force', '--key-file', key]), 4, 'output_error');
    expectFail(cli(['export', log, '--out', out, '--force', '--format', 'json']), 4, 'output_error');
    expectFail(cli(['export', log, '--out', out, '--force', '--format', 'csv']), 4, 'output_error');
  }
  for (const out of spellings(key)) {
    expectFail(cli(['anchor', log, '--out', out, '--force', '--key-file', key]), 4, 'output_error');
  }
  assert.deepEqual(await fs.readFile(log), logBefore);
  assert.deepEqual(await fs.readFile(key), keyBefore);
  // The library writer protects every listed input (log, key file, anchor file, data file).
  const data = join(dir, 'data.json');
  await fs.writeFile(data, '{}');
  for (const protectedPath of [log, key, anchorFile, data]) {
    await assert.rejects(createAtomicWriter(protectedPath, { force: true, protect: [log, key, anchorFile, data] }), {
      kind: 'output_error',
    });
  }
  assert.deepEqual(await fs.readdir(dir).then((names) => names.filter((n) => n.endsWith('.tmp'))), []);
  assert.equal(await sameFile(log, join(dir, '.', 'log.jsonl')), true);
  assert.equal(await sameFile(log, key), false);
  if (process.platform === 'win32' || process.platform === 'darwin') {
    assert.equal(await sameFile(log, join(dir, 'LOG.JSONL')), true);
    expectFail(cli(['anchor', log, '--out', join(dir, 'LOG.JSONL'), '--force', '--key-file', key]), 4, 'output_error');
  }
});

test('lock file holds a random token; it is removed only while it still holds our token', async (t) => {
  const dir = tempDir(t);
  const lock = join(dir, 'x.lock');
  const token = await internal.acquireLock(lock);
  assert.match(token, /^[0-9a-f]{32}$/);
  assert.equal(await fs.readFile(lock, 'utf8'), token);
  // A foreign lock (someone else's token) is left alone.
  await fs.writeFile(lock, 'foreign-token');
  await internal.releaseLock(lock, token);
  assert.equal(await fs.readFile(lock, 'utf8'), 'foreign-token');
  // Our token: removed. Already gone: tolerated silently.
  await fs.writeFile(lock, token);
  await internal.releaseLock(lock, token);
  await assert.rejects(fs.stat(lock), { code: 'ENOENT' });
  await internal.releaseLock(lock, token);
  // Two tokens differ.
  const a = await internal.acquireLock(join(dir, 'a.lock'));
  const b = await internal.acquireLock(join(dir, 'b.lock'));
  assert.notEqual(a, b);
});

test('a lock that disappears during the append does not fail the append (ENOENT on cleanup)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await appendRecord(log, { type: 'a' });
  assert.deepEqual((await fs.readdir(dir)).sort(), ['log.jsonl']);
});
