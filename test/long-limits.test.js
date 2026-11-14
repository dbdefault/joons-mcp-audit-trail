import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, existsSync, openSync, rmSync, statSync, writeSync } from 'node:fs';
import { statfs } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cli, expectFail, expectOk, tempDir } from '../reference/helpers.js';
import { canonicalize, event, hashRecord, header } from '../reference/model.js';
import { appendRecord } from '../src/index.js';

// LONG TEST GROUP (slow, about 250 MB on disk). It runs only when the file test/long-tests.enabled exists
// (`npm run test:long` creates it for the duration of the run). The default `node --test` skips it.
// It builds a real log with the hard maximum of 1,000,000 records by streaming it straight to disk (not through
// appendRecord), then checks the real limits with the real command line under a 256 MB heap cap.

const enabled = existsSync(new URL('./long-tests.enabled', import.meta.url));
const GiB = 1024 ** 3;
const HEAP = ['--max-old-space-size=256'];
const RECORDS = 1000000;

function streamLog(path, total) {
  const fd = openSync(path, 'w');
  try {
    let record = header('2026-01-01T00:00:00.000Z');
    let chunk = [canonicalize(record)];
    for (let seq = 1; seq < total; seq++) {
      record = event(seq, '2026-01-01T00:00:00.000Z', 'bulk', record.hash);
      chunk.push(canonicalize(record));
      if (chunk.length === 5000) {
        writeSync(fd, chunk.join('\n') + '\n');
        chunk = [];
      }
    }
    if (chunk.length) writeSync(fd, chunk.join('\n') + '\n');
  } finally {
    closeSync(fd);
  }
}

test('LONG: a real 1,000,000-record log (limits, verify, export under a 256 MB heap)', {
  skip: enabled ? false : 'long tests are off (create test/long-tests.enabled or run npm run test:long)',
  timeout: 20 * 60 * 1000,
}, async (t) => {
  const dir = tempDir(t, 'audit-long-');
  const free = await statfs(tmpdir());
  if (Number(free.bavail) * Number(free.bsize) < GiB) return t.skip('less than 1 GB of free disk space');
  const log = join(dir, 'big.jsonl');
  const started = Date.now();
  streamLog(log, RECORDS);
  const size = statSync(log).size;
  t.diagnostic(
    `generated ${RECORDS} records, ${(size / 1e6).toFixed(1)} MB in ${((Date.now() - started) / 1000).toFixed(1)} s`,
  );
  assert.ok(size <= 256 * 1024 * 1024, 'the generated log is inside the 256 MiB limit');

  await t.test('append is refused with limit_exceeded (library and command line) and changes nothing', async () => {
    await assert.rejects(appendRecord(log, { type: 'one.too.many' }), { kind: 'limit_exceeded' });
    expectFail(cli(['append', log, '--type', 'one.too.many'], { timeout: 120000 }), 2, 'limit_exceeded');
    assert.equal(statSync(log).size, size);
  });

  await t.test('verify reports OK for all 1,000,000 records within a generous time', () => {
    const begin = Date.now();
    const r = cli(['verify', log], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
    expectOk(r);
    assert.match(r.stdout, /^verify: OK\nrecords: 1000000\n/);
    assert.ok(Date.now() - begin < 10 * 60 * 1000);
  });

  await t.test('summary and a small show range work under the heap cap', () => {
    const summary = cli(['summary', log, '--format', 'json'], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
    expectOk(summary);
    assert.equal(JSON.parse(summary.stdout).records, RECORDS - 1);
    const shown = cli(['show', log, '--from', '500000', '--to', '500009', '--format', 'json'], { nodeArgs: HEAP });
    expectOk(shown);
    assert.equal(JSON.parse(shown.stdout).length, 10);
  });

  for (const format of ['json', 'csv']) {
    await t.test(`export ${format} streams all records under the heap cap`, () => {
      const out = join(dir, 'out.' + format);
      const r = cli(['export', log, '--out', out, '--format', format], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
      expectOk(r);
      assert.ok(statSync(out).size > size / 2);
      rmSync(out, { force: true });
    });
  }
});

test('LONG: a 262 MB log of 8,100 records of about 32 KB (show is bounded by bytes under a 256 MB heap)', {
  skip: enabled ? false : 'long tests are off (create test/long-tests.enabled or run npm run test:long)',
  timeout: 20 * 60 * 1000,
}, async (t) => {
  const dir = tempDir(t, 'audit-long-');
  const free = await statfs(tmpdir());
  if (Number(free.bavail) * Number(free.bsize) < GiB) return t.skip('less than 1 GB of free disk space');
  const log = join(dir, 'fat.jsonl');
  const { writeFatLog } = await import('../reference/helpers.js');
  writeFatLog(log, 8100);
  assert.ok(statSync(log).size > 240e6);
  const big = cli(['show', log, '--from', '1', '--to', '8100'], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
  expectFail(big, 2, 'limit_exceeded');
  const small = cli(['show', log, '--to', '400'], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
  expectOk(small);
  assert.equal(JSON.parse(small.stdout).length, 400);
});

test('LONG: a forged 257 MB log of 4,000 records with distinct 64,000-character actors (summary is bounded)', {
  skip: enabled ? false : 'long tests are off (create test/long-tests.enabled or run npm run test:long)',
  timeout: 20 * 60 * 1000,
}, async (t) => {
  const dir = tempDir(t, 'audit-long-');
  const free = await statfs(tmpdir());
  if (Number(free.bavail) * Number(free.bsize) < GiB) return t.skip('less than 1 GB of free disk space');
  const log = join(dir, 'forged.jsonl');
  const fd = openSync(log, 'w');
  try {
    let record = header('2026-01-01T00:00:00.000Z');
    writeSync(fd, canonicalize(record) + '\n');
    for (let seq = 1; seq <= 4000; seq++) {
      const body = {
        seq,
        time: '2026-01-01T00:00:00.000Z',
        type: 'bulk',
        actor: String(seq).padStart(6, '0') + 'a'.repeat(63994),
        tool: null,
        outcome: null,
        data: null,
        prev: record.hash,
      };
      record = { ...body, hash: hashRecord(body) };
      writeSync(fd, canonicalize(record) + '\n');
    }
  } finally {
    closeSync(fd);
  }
  assert.ok(statSync(log).size > 250e6);
  for (const args of [['summary'], ['summary', '--details'], ['summary', '--details', '--format', 'json']]) {
    const r = cli([...args, log], { nodeArgs: HEAP, timeout: 10 * 60 * 1000 });
    expectOk(r);
    assert.ok(r.stdout.length < 2000);
  }
});
