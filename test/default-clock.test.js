import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cli, cliPath, expectFail, expectOk, KEY, tempDir } from '../reference/helpers.js';
import { appendRecord, readRecords, verifyLog } from '../src/index.js';

// Appends without an explicit time (no --time, no event.time) take the time while the lock is held and never
// run earlier than the tail, so concurrent default-clock appends cannot be refused for time order.
// Timing margin: the lock wait is 5 s. On the reference machine the slowest single append in these bursts waits about
// 1.2 s (about 25 percent), so the bursts are kept small enough to stay far below 40 percent of the wait even when
// other test files run in parallel.

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => out += d);
    child.stderr.on('data', (d) => err += d);
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

async function checkChain(log, expectedEvents, key) {
  const report = await verifyLog(log, key ? { keyFile: key } : {});
  assert.deepEqual(report.findings, []);
  assert.equal(report.ok, true);
  let count = 0;
  let previousTime = -Infinity;
  for await (const item of readRecords(log)) {
    assert.equal(item.record.seq, count);
    const time = Date.parse(item.record.time);
    assert.ok(time >= previousTime, 'time never goes backwards');
    previousTime = time;
    count++;
  }
  assert.equal(count, expectedEvents + 1, 'one header plus every event');
}

for (
  const [name, workers, perWorker, keyed] of [
    ['6 processes x 6 appends, plain', 6, 6, false],
    ['6 processes x 6 appends, keyed', 6, 6, true],
    ['8 processes x 4 appends, plain', 8, 4, false],
  ]
) {
  test(`default clock, real processes: ${name}: zero failures`, { timeout: 240000 }, async (t) => {
    const dir = tempDir(t);
    const log = join(dir, 'log.jsonl');
    const keyFile = join(dir, 'key');
    writeFileSync(keyFile, KEY);
    const keyArgs = keyed ? ['--key-file', keyFile] : [];
    const failures = [];
    await Promise.all(
      Array.from({ length: workers }, async (_, w) => {
        for (let i = 0; i < perWorker; i++) {
          const r = await runCli(['append', log, '--type', 'tool.call', '--actor', 'w' + w, ...keyArgs]);
          if (r.code !== 0) failures.push(r.err.trim() || 'exit ' + r.code);
        }
      }),
    );
    assert.deepEqual(failures, []);
    await checkChain(log, workers * perWorker, keyed ? keyFile : null);
    expectOk(cli(['verify', log, ...keyArgs]));
  });
}

test('default clock, one process: 3 Promise.all loops x 6 appends, zero failures', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await Promise.all(
    Array.from({ length: 3 }, async (_, w) => {
      for (let i = 0; i < 6; i++) await appendRecord(log, { type: 'tool.call', actor: 'w' + w });
    }),
  );
  await checkChain(log, 18, null);
});

test('default clock, first append race: 8 simultaneous processes on a new log write exactly one header', {
  timeout: 120000,
}, async (t) => {
  for (let trial = 0; trial < 3; trial++) {
    const dir = tempDir(t);
    const log = join(dir, 'log.jsonl');
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => runCli(['append', log, '--type', 'first', '--actor', 'p' + i])),
    );
    assert.deepEqual(results.filter((r) => r.code !== 0), []);
    await checkChain(log, 8, null);
    let headers = 0;
    for await (const item of readRecords(log)) if (item.record.format) headers++;
    assert.equal(headers, 1);
  }
});

test('a backwards system clock step drops no event: the time is clamped to the tail time', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const readings = ['2026-05-01T10:00:00.000Z', '2026-05-01T09:00:00.000Z', '2026-05-01T09:59:59.999Z'];
  for (const reading of readings) await appendRecord(log, { type: 'tick' }, { now: () => reading });
  const times = [];
  for await (const item of readRecords(log)) times.push(item.record.time);
  assert.deepEqual(times, Array(4).fill('2026-05-01T10:00:00.000Z'));
  await checkChain(log, 3, null);
});

test('an explicit time earlier than the tail is still refused (CLI and library)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectOk(cli(['append', log, '--type', 'a', '--time', '2026-05-01T10:00:00Z']));
  expectFail(cli(['append', log, '--type', 'b', '--time', '2026-05-01T09:59:59Z']), 2, 'invalid_record');
  await assert.rejects(appendRecord(log, { type: 'b', time: '2026-05-01T09:59:59Z' }), { kind: 'invalid_record' });
  await checkChain(log, 1, null);
});

test('an invalid clock value is refused before anything is created', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await assert.rejects(appendRecord(log, { type: 'x' }, { now: () => 'garbage' }), { kind: 'invalid_record' });
  await assert.rejects(
    appendRecord(log, { type: 'x' }, {
      now: () => {
        throw new Error('boom');
      },
    }),
    { kind: 'invalid_record' },
  );
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(dir), []);
});
