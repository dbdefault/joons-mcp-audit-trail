import { fileURLToPath as __f } from 'node:url';
process.chdir(__f(new URL('..', import.meta.url)));
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { appendRecord, internal, loadKey, readRecords, statLogSafe, writeFileAtomic } from '../src/log/index.js';
import { createHash, createHmac } from 'node:crypto';
const GENESIS_HASH = '0'.repeat(64);
function independentCanon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(independentCanon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + independentCanon(v[k])).join(',') + '}';
}
function independentHash(record, key) {
  const { hash, ...body } = record;
  void hash;
  return (key ? createHmac('sha256', key) : createHash('sha256')).update(independentCanon(body)).digest('hex');
}
const setup = async (t) => {
  const dir = await fs.mkdtemp(join(tmpdir(), 'audit-log-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
};
const event = { type: 'event' };
const fixed = '2026-01-01T00:00:00.000Z';
const collect = async (p) => {
  const a = [];
  for await (const x of readRecords(p)) a.push(x);
  return a;
};
const kind = (promise, k) => assert.rejects(promise, (e) => e.kind === k);
async function chain(p, key = null) {
  const a = await collect(p);
  let prev = GENESIS_HASH;
  for (let i = 0; i < a.length; i++) {
    const r = a[i].record;
    assert.equal(r.seq, i);
    assert.equal(r.prev, prev);
    assert.equal(r.hash, independentHash(r, key));
    prev = r.hash;
  }
  return a;
}
test('plain header and sequential chain', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  for (let i = 0; i < 300; i++) await appendRecord(p, event, { now: fixed });
  const a = await chain(p);
  assert.equal(a.length, 301);
  assert.equal(a[0].record.mode, 'sha256');
});
test('keyed mode and key consistency', async (t) => {
  const d = await setup(t), p = join(d, 'log'), k = join(d, 'key'), bad = join(d, 'bad');
  await fs.writeFile(k, '1234567890123456\n');
  await fs.writeFile(bad, 'abcdefghijklmnop');
  await appendRecord(p, event, { keyFile: k, now: fixed });
  await appendRecord(p, event, { keyFile: k, now: fixed });
  assert.equal((await chain(p, await loadKey(k))).length, 3);
  await kind(appendRecord(p, event, {}), 'key_required');
  await kind(appendRecord(p, event, { keyFile: bad }), 'key_invalid');
});
test('four real processes preserve the chain', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  const moduleUrl = new URL('../src/log/index.js', import.meta.url).href;
  const script = `import {appendRecord} from ${
    JSON.stringify(moduleUrl)
  }; for(let i=0;i<10;i++) await appendRecord(process.argv[1],{type:'event'},{now:${JSON.stringify(fixed)}});`;
  await Promise.all(Array.from({ length: 4 }, () =>
    new Promise((res, rej) => {
      const c = spawn(process.execPath, ['--input-type=module', '-e', script, p], { windowsHide: true, stdio: 'pipe' });
      let err = '';
      c.stderr.on('data', (x) => err += x);
      c.on('error', rej);
      c.on('exit', (n) => n === 0 ? res() : rej(new Error(err)));
    })));
  assert.equal((await chain(p)).length, 41);
});
test('lock timeout leaves existing lock intact', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p + '.lock', '');
  const started = Date.now();
  await kind(appendRecord(p, event, {}), 'lock_timeout');
  assert.ok(Date.now() - started >= 4900 && Date.now() - started < 15000);
  assert.ok(await fs.stat(p + '.lock'));
});
test('partial and tampered tails refused', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await appendRecord(p, event, { now: fixed });
  const original = await fs.readFile(p);
  await fs.writeFile(p, original.subarray(0, original.length - 1));
  await kind(appendRecord(p, event, {}), 'log_corrupt');
  const text = original.toString().replace('"type":"event"', '"type":"other"');
  await fs.writeFile(p, text);
  await kind(appendRecord(p, event, {}), 'log_corrupt');
});
test('path safety and keys', async (t) => {
  const d = await setup(t), p = join(d, 'log'), link = join(d, 'link');
  await fs.writeFile(p, 'x');
  await kind(statLogSafe(d), 'input_unreadable');
  await kind(appendRecord(d, event, {}), 'output_error');
  await kind(statLogSafe('//server/share'), 'input_unreadable');
  await kind(appendRecord('\\\\server\\share', event, {}), 'output_error');
  await fs.link(p, link);
  await kind(statLogSafe(p), 'input_unreadable');
  await fs.unlink(link);
  try {
    await fs.symlink(p, link);
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') {
      t.diagnostic('symlink unavailable');
      return;
    }
    throw e;
  }
  await kind(statLogSafe(link), 'input_unreadable');
  await kind(loadKey(link), 'key_invalid');
});
test('reader continues after bad JSON and enforces line limits', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, '{}\ninvalid\n{}\n');
  const a = await collect(p);
  assert.equal(a.length, 3);
  assert.deepEqual(a[1], { error: 'bad_json', lineNo: 2 });
  await fs.writeFile(p, 'x'.repeat(65537) + '\n');
  assert.equal((await collect(p))[0].error, 'long_line');
});
test('reader handles large streamed input', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, '{}\n'.repeat(100000));
  let n = 0;
  for await (const x of readRecords(p)) {
    assert.ok(x.record);
    n++;
  }
  assert.equal(n, 100000);
});
test('atomic writes and refusal', async (t) => {
  const d = await setup(t), p = join(d, 'output');
  await writeFileAtomic(p, 'one');
  await kind(writeFileAtomic(p, 'two'), 'output_error');
  assert.equal(await fs.readFile(p, 'utf8'), 'one');
  await writeFileAtomic(p, 'two', { force: true });
  assert.equal(await fs.readFile(p, 'utf8'), 'two');
  assert.deepEqual(await fs.readdir(d), ['output']);
});
test('file and record count limits', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  const h = await fs.open(p, 'w');
  await h.truncate(256 * 1024 * 1024 + 1);
  await h.close();
  await kind(collect(p), 'limit_exceeded');
  await kind(appendRecord(p, event, {}), 'limit_exceeded');
  await fs.writeFile(p, '{}\n'.repeat(1000001));
  await kind(collect(p), 'limit_exceeded');
});
test('invalid key sizes and plain mode rejects key', async (t) => {
  const d = await setup(t), p = join(d, 'log'), k = join(d, 'key');
  await fs.writeFile(k, 'short');
  await kind(loadKey(k), 'key_invalid');
  await fs.writeFile(k, Buffer.alloc(4097));
  await kind(loadKey(k), 'key_invalid');
  await fs.writeFile(k, '1234567890123456');
  await appendRecord(p, event, { now: fixed });
  await kind(appendRecord(p, event, { keyFile: k }), 'key_invalid');
});
test('eight processes preserve contiguous chain', async (t) => {
  const d = await setup(t), p = join(d, 'log'), url = new URL('../src/log/index.js', import.meta.url).href;
  const script = `import {appendRecord} from ${
    JSON.stringify(url)
  };for(let i=0;i<5;i++)await appendRecord(process.argv[1],{type:'event'},{now:${JSON.stringify(fixed)}});`;
  await Promise.all(Array.from({ length: 8 }, () =>
    new Promise((ok, fail) => {
      const c = spawn(process.execPath, ['--input-type=module', '-e', script, p], { windowsHide: true, stdio: 'pipe' });
      let err = '';
      c.stderr.on('data', (x) => err += x);
      c.on('error', fail);
      c.on('exit', (n) => n ? fail(new Error(err)) : ok());
    })));
  assert.equal((await chain(p)).length, 41);
});
for (
  const [name, bytes, error] of [
    ['BOM', Buffer.from([0xef, 0xbb, 0xbf, 123, 125, 10]), 'bad_encoding'],
    ['invalid UTF-8', Buffer.from([0xff, 10]), 'bad_encoding'],
    ['NUL', Buffer.from([123, 0, 125, 10]), 'bad_json'],
    ['CRLF', Buffer.from('{}\r\n'), 'bad_json'],
    ['partial last line', Buffer.from('{}'), 'partial_last_line'],
    ['long line', Buffer.from('x'.repeat(65537) + '\n'), 'long_line'],
  ]
) {
  test('reader classifies ' + name, async (t) => {
    const d = await setup(t), p = join(d, 'log');
    await fs.writeFile(p, bytes);
    assert.deepEqual(await collect(p), [{ error, lineNo: 1 }]);
  });
}
test('reader continues after a long line', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, 'x'.repeat(70000) + '\n{}\n');
  const a = await collect(p);
  assert.equal(a[0].error, 'long_line');
  assert.deepEqual(a[1].record, {});
});
for (const offset of [1, 2, 5, 20, 60]) {
  test('truncated tail ' + offset, async (t) => {
    const d = await setup(t), p = join(d, 'log');
    await appendRecord(p, event, { now: fixed });
    const b = await fs.readFile(p);
    const truncated = b.subarray(0, b.length - offset);
    await fs.writeFile(p, truncated);
    await kind(appendRecord(p, event, {}), 'log_corrupt');
    assert.deepEqual(await fs.readFile(p), truncated);
  });
}
test('garbage after log is not repaired', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await appendRecord(p, event, {});
  await fs.appendFile(p, 'garbage\n');
  const before = await fs.readFile(p);
  await kind(appendRecord(p, event, {}), 'log_corrupt');
  assert.deepEqual(await fs.readFile(p), before);
});
for (const keyed of [false, true]) {
  test('tail hash tamper refused ' + keyed, async (t) => {
    const d = await setup(t), p = join(d, 'log'), k = join(d, 'key');
    await fs.writeFile(k, '1234567890123456');
    const opts = keyed ? { keyFile: k } : {};
    await appendRecord(p, event, opts);
    const text = (await fs.readFile(p, 'utf8')).replace('"type":"event"', '"type":"other"');
    await fs.writeFile(p, text);
    await kind(appendRecord(p, event, opts), 'log_corrupt');
    assert.equal(await fs.readFile(p, 'utf8'), text);
  });
}
test('empty file creates header', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, '');
  await appendRecord(p, { type: 'event', time: fixed }, {});
  const a = await collect(p);
  assert.equal(a.length, 2);
  assert.equal(a[0].record.time, fixed);
  assert.equal(a[1].record.time, fixed);
});
test('invalid event leaves no lock', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await kind(appendRecord(p, {}, {}), 'invalid_record');
  await assert.rejects(fs.stat(p + '.lock'), { code: 'ENOENT' });
});
test('wrong key removes lock', async (t) => {
  const d = await setup(t), p = join(d, 'log'), k = join(d, 'key'), bad = join(d, 'bad');
  await fs.writeFile(k, '1234567890123456');
  await fs.writeFile(bad, 'abcdefghijklmnop');
  await appendRecord(p, event, { keyFile: k });
  await kind(appendRecord(p, event, { keyFile: bad }), 'key_invalid');
  await assert.rejects(fs.stat(p + '.lock'), { code: 'ENOENT' });
});
for (
  const [name, content, expected] of [
    ['15 bytes', 'x'.repeat(15), null],
    ['16 bytes', 'x'.repeat(16), 'x'.repeat(16)],
    ['one newline', 'x'.repeat(16) + '\n', 'x'.repeat(16)],
    ['two newlines', 'x'.repeat(16) + '\n\n', 'x'.repeat(16) + '\n'],
    ['CRLF', 'x'.repeat(16) + '\r\n', 'x'.repeat(16)],
    ['CRLF then LF', 'x'.repeat(16) + '\r\n\n', 'x'.repeat(16) + '\r\n'],
    ['LF then CRLF', 'x'.repeat(16) + '\n\r\n', 'x'.repeat(16) + '\n'],
    ['lone CR is part of the key', 'x'.repeat(16) + '\r', 'x'.repeat(16) + '\r'],
    ['CRLF with a short key', 'x'.repeat(15) + '\r\n', null],
    ['only line terminators', '\n'.repeat(20), null],
    ['only CRLF terminators', '\r\n'.repeat(20), null],
    ['only carriage returns', '\r'.repeat(20), null],
    ['4096 bytes', 'x'.repeat(4096), 'x'.repeat(4096)],
    ['4097 bytes', 'x'.repeat(4097), null],
  ]
) {
  test('key ' + name, async (t) => {
    const d = await setup(t), p = join(d, 'key');
    await fs.writeFile(p, content);
    if (expected === null) {
      await assert.rejects(loadKey(p), (e) => e.kind === 'key_invalid' && !e.message.includes(content));
    } else assert.equal((await loadKey(p)).toString(), expected);
  });
}
for (const name of ['missing', 'directory']) {
  test('key ' + name + ' rejected', async (t) => {
    const d = await setup(t);
    await kind(loadKey(name === 'directory' ? d : join(d, 'missing')), 'key_invalid');
  });
}
for (
  const [name, path] of [
    ['UNC slash', '//host/share'],
    ['UNC backslash', '\\\\host\\share'],
    ['device question', '\\\\?\\C:\\file'],
    ['device dot', '\\\\.\\device'],
    ['NUL', 'a\0b'],
  ]
) {
  test('unsafe path ' + name, async () => {
    await kind(statLogSafe(path), 'input_unreadable');
    await kind(appendRecord(path, event, {}), 'output_error');
    await kind(writeFileAtomic(path, 'x'), 'output_error');
  });
}
test('stat regular and missing', async (t) => {
  const d = await setup(t), p = join(d, 'file');
  assert.equal(await statLogSafe(p), null);
  await fs.writeFile(p, 'x');
  assert.ok((await statLogSafe(p)).isFile());
});
test('stat hard link rejected', async (t) => {
  const d = await setup(t), p = join(d, 'a');
  await fs.writeFile(p, 'x');
  await fs.link(p, join(d, 'b'));
  await kind(statLogSafe(p), 'input_unreadable');
  await kind(writeFileAtomic(p, 'x', { force: true }), 'output_error');
});
test('atomic directory rejected and contents preserved', async (t) => {
  const d = await setup(t), p = join(d, 'folder');
  await fs.mkdir(p);
  await kind(writeFileAtomic(p, 'x', { force: true }), 'output_error');
  assert.ok((await fs.stat(p)).isDirectory());
  assert.deepEqual(await fs.readdir(d), ['folder']);
});
test('atomic missing parent fails', async (t) => {
  const d = await setup(t);
  await kind(writeFileAtomic(join(d, 'missing', 'out'), 'x'), 'output_error');
  assert.deepEqual(await fs.readdir(d), []);
});
test('injected global size limit', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, '{}\n{}\n');
  const read = async () => {
    for await (const x of internal.readRecords(p, { ...internal.DEFAULT_LIMITS, size: 5 })) void x;
  };
  await kind(read(), 'limit_exceeded');
});
test('injected global count limit', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await fs.writeFile(p, '{}\n{}\n');
  const read = async () => {
    for await (const x of internal.readRecords(p, { ...internal.DEFAULT_LIMITS, count: 1 })) void x;
  };
  await kind(read(), 'limit_exceeded');
});
test('injected append count limit', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await appendRecord(p, event, {});
  await kind(internal.appendRecord(p, event, {}, { ...internal.DEFAULT_LIMITS, count: 2 }), 'limit_exceeded');
});
test('source excludes forbidden execution and network APIs', async () => {
  for (const p of ['src/log/index.js', 'src/canon/index.js', 'src/errors.js']) {
    const s = await fs.readFile(p, 'utf8');
    for (
      const pattern of [
        /\beval\s*\(/,
        /\bprocess\s*\.\s*env\b/,
        /node:child_process/,
        /node:(?:http|https|net|tls|dgram)\b/,
        /\bfetch\s*\(/,
        /new\s+RegExp\s*\(/,
      ]
    ) assert.doesNotMatch(s, pattern);
  }
});
test('event schema rejects extra fields before locking', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await kind(appendRecord(p, { type: 'event', extra: 1 }, {}), 'invalid_record');
  await assert.rejects(fs.stat(p + '.lock'), { code: 'ENOENT' });
});
test('credential event refused before locking', async (t) => {
  const d = await setup(t), p = join(d, 'log');
  await kind(
    appendRecord(p, { type: 'event', data: { value: 'AK' + 'IAABCDEFGHIJKLMNOP' } }, {}),
    'credential_detected',
  );
  await assert.rejects(fs.stat(p + '.lock'), { code: 'ENOENT' });
});
