import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildRecords, cli, expectFail, expectOk, T0, tempDir, toText, writeLog } from '../reference/helpers.js';
import { canonicalize, readRecords, summarize, verifyLog } from '../src/index.js';
import * as publicApi from '../src/index.js';
import { appendRecord } from '../src/log/index.js';
import { internalVerify } from '../src/verify/index.js';
import { parseArgs } from '../src/cli/args.js';
import { internal } from '../src/log/index.js';

const NL = String.fromCharCode(10);

test('append refuses a time earlier than the tail record and never changes the log', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectOk(cli(['append', log, '--type', 'a', '--time', '2026-01-01T00:00:10Z']));
  const before = readFileSync(log);
  expectFail(cli(['append', log, '--type', 'b', '--time', '2026-01-01T00:00:09.999Z']), 2, 'invalid_record');
  expectFail(cli(['append', log, '--type', 'b', '--time', '2025-12-31T23:59:59Z']), 2, 'invalid_record');
  assert.deepEqual(readFileSync(log), before);
  assert.deepEqual(await fs.readdir(dir), ['log.jsonl']);
  // Equal instants are allowed, whatever the spelling.
  expectOk(cli(['append', log, '--type', 'c', '--time', '2026-01-01T00:00:10Z']));
  expectOk(cli(['append', log, '--type', 'd', '--time', '2026-01-01T00:00:10.000Z']));
  expectOk(cli(['append', log, '--type', 'e', '--time', '2026-01-01T00:00:10.001Z']));
  // Instants are compared, not strings: ".5Z" is later than "Z" although "." sorts before "Z".
  expectFail(cli(['append', log, '--type', 'f', '--time', '2026-01-01T00:00:10Z']), 2, 'invalid_record');
  expectOk(cli(['verify', log]));
});

test('append with the clock (no --time) is clamped to the tail; an earlier explicit time is refused', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const far = '9999-12-31T23:59:59.999Z';
  expectOk(cli(['append', log, '--type', 'future', '--time', far]));
  expectOk(cli(['append', log, '--type', 'now']));
  await appendRecord(log, { type: 'x' }, { now: '2000-01-01T00:00:00Z' });
  await appendRecord(log, { type: 'y' }, { now: () => new Date(0) });
  expectFail(cli(['append', log, '--type', 'explicit', '--time', '2000-01-01T00:00:00Z']), 2, 'invalid_record');
  await assert.rejects(appendRecord(log, { type: 'z', time: '2000-01-01T00:00:00Z' }), { kind: 'invalid_record' });
  const times = [];
  for await (const item of readRecords(log)) times.push(item.record.time);
  assert.deepEqual(times.slice(1), [far, far, far, far]);
  expectOk(cli(['verify', log]));
});

test('an event time before the header time is refused on the second append', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await appendRecord(log, { type: 'a' }, { now: '2026-06-01T00:00:00Z' });
  await assert.rejects(appendRecord(log, { type: 'b', time: '2026-05-01T00:00:00Z' }), { kind: 'invalid_record' });
});

test('library appendRecord validates the time before it opens or creates anything', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'new.jsonl');
  const bad = [
    'garbage',
    '2026-02-30T00:00:00Z',
    '2026-01-01',
    5,
    {},
    new Date(Number.NaN),
    () => {
      throw new Error('boom');
    },
    () => 'garbage',
  ];
  for (const now of bad) await assert.rejects(appendRecord(log, { type: 'x' }, { now }), { kind: 'invalid_record' });
  await assert.rejects(appendRecord(log, { type: 'x', time: 'garbage' }), { kind: 'invalid_record' });
  assert.deepEqual(await fs.readdir(dir), []);
});

test('the hidden _limits option is gone from the public surface', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  for (let i = 0; i < 3; i++) await appendRecord(log, { type: 'x' }, { _limits: { count: 1, size: 1 } });
  assert.equal((await verifyLog(log, { _limits: { count: 1 } })).records, 4);
  assert.deepEqual(Object.keys(publicApi).sort(), [
    'FORMAT',
    'GENESIS_HASH',
    'appendRecord',
    'canonicalize',
    'createAnchor',
    'hashRecord',
    'readRecords',
    'summarize',
    'verifyLog',
  ]);
  assert.ok(Object.isFrozen(internal));
});

test('command names are looked up with hasOwn: inherited names are usage errors', () => {
  for (const name of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']) {
    assert.throws(() => parseArgs([name, 'x']), name);
    expectFail(cli([name, 'x']), 3, 'usage_error');
  }
});

test('--opt=value accepts line and paragraph separators and every other character', () => {
  for (const code of [0x2028, 0x2029, 0x0a, 0x0d, 0x85]) {
    const value = 'a' + String.fromCodePoint(code) + 'b';
    assert.equal(parseArgs(['append', 'x', '--actor=' + value, '--type=t']).options.actor, value);
    assert.equal(parseArgs(['append', 'x', '--type=' + value]).options.type, value);
  }
});

test('a separator in --actor reaches the record check (invalid_record), not the usage error', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  for (const code of [0x2028, 0x2029]) {
    expectFail(
      cli(['append', log, '--type', 't', '--actor=a' + String.fromCodePoint(code) + 'b']),
      2,
      'invalid_record',
    );
  }
});

test('summary from and to use parsed instants, not string order', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  writeLog(log, [
    ...buildRecords(0),
  ]);
  expectOk(cli(['append', log, '--type', 'a', '--time', '2026-01-01T00:00:01Z']));
  expectOk(cli(['append', log, '--type', 'b', '--time', '2026-01-01T00:00:01.500Z']));
  const r = cli(['summary', log, '--format', 'json']);
  expectOk(r);
  const s = JSON.parse(r.stdout);
  assert.equal(s.from, '2026-01-01T00:00:01Z');
  assert.equal(s.to, '2026-01-01T00:00:01.500Z');
  assert.equal(s.records, 2);
});

function manyTypes(count) {
  const records = buildRecords(0);
  for (let i = 1; i <= count; i++) {
    const prev = records.at(-1);
    records.push(buildEvent(i, 't' + i, prev.hash));
  }
  return records;
}
import { event as modelEvent } from '../reference/model.js';
function buildEvent(seq, type, prev) {
  return modelEvent(seq, '2026-01-01T00:00:00Z', type, prev, null, 'same', null, null);
}

test('summary caps distinct names at exactly 10,000 and the other bucket is not counted', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  writeLog(log, manyTypes(10005));
  const plain = await summarize(log);
  assert.equal(plain.type.distinct, 10000);
  assert.equal(plain.actor.distinct, 1);
  assert.equal(plain.records, 10005);
  const details = await summarize(log, { details: true });
  const names = Object.keys(details.type);
  assert.equal(names.length, 10001);
  assert.equal(details.type['(other)'], 5);
  assert.equal(details.actor.same, 10005);
  const exactly = join(dir, 'exact.jsonl');
  writeLog(exactly, manyTypes(10000));
  assert.equal((await summarize(exactly)).type.distinct, 10000);
  assert.equal(Object.keys((await summarize(exactly, { details: true })).type).length, 10000);
});

function deepObject(depth) {
  return '{"a":'.repeat(depth) + '1' + '}'.repeat(depth);
}

const JUNK = {
  'bare null': 'null',
  'a number': '5',
  'a string': '"text"',
  'an array': '[]',
  'an empty object': '{}',
  'an object with extra keys': '{"x":1}',
  'deeply nested objects': deepObject(9000),
  'deeply nested arrays': '['.repeat(20000) + ']'.repeat(20000),
};

for (const [name, junk] of Object.entries(JUNK)) {
  test(`a line holding ${name}: show, summary and export fail with log_corrupt, verify reports it`, (t) => {
    const dir = tempDir(t);
    const log = join(dir, 'log.jsonl');
    const good = toText(buildRecords(2)).split(NL);
    writeFileSync(log, good[0] + NL + junk + NL + good[1] + NL);
    expectFail(cli(['show', log]), 2, 'log_corrupt');
    expectFail(cli(['summary', log]), 2, 'log_corrupt');
    expectFail(cli(['export', log, '--out', join(dir, 'out.json'), '--format', 'json']), 2, 'log_corrupt');
    expectFail(cli(['export', log, '--out', join(dir, 'out.csv'), '--format', 'csv']), 2, 'log_corrupt');
    const r = cli(['verify', log, '--format', 'json']);
    assert.equal(r.status, 1, r.stderr);
    assert.equal(r.stderr, '');
    assert.ok(JSON.parse(r.stdout).findings.length > 0);
    assert.deepEqual(readdirSyncNoTemp(dir), ['log.jsonl']);
  });
}

import { readdirSync } from 'node:fs';
function readdirSyncNoTemp(dir) {
  return readdirSync(dir).sort();
}

test('show, summary and export also refuse a log with a non-canonical line', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const lines = toText(buildRecords(2)).split(NL);
  lines[1] = lines[1].replace('"seq":1,', '"seq": 1,');
  writeFileSync(log, lines.join(NL));
  expectFail(cli(['show', log]), 2, 'log_corrupt');
  expectFail(cli(['summary', log]), 2, 'log_corrupt');
});

test('verify reports junk lines beyond the record cap as a finding (exit 1), not as exit 2', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const good = toText(buildRecords(2)).split(NL);
  writeFileSync(log, good.slice(0, 3).join(NL) + NL + '{}' + NL + '{}' + NL + '{}' + NL + '{}' + NL);
  const limits = { ...internal.DEFAULT_LIMITS, count: 5 };
  const report = await internalVerify.verifyLog(log, {}, limits);
  assert.equal(report.ok, false);
  assert.ok(report.findings.some((f) => f.kind === 'trailing_garbage'), JSON.stringify(report.findings));
  // Readers keep returning limit_exceeded when a log is over the cap.
  await assert.rejects(async () => {
    for await (const item of internal.readRecords(log, limits)) void item;
  }, { kind: 'limit_exceeded' });
});

test('real command line: 1,000,001 lines of trailing junk give a verify report, not an error', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const good = toText(buildRecords(2));
  writeFileSync(log, good + '{}\n'.repeat(1000001 - 3));
  const r = cli(['verify', log, '--format', 'json'], { timeout: 120000 });
  assert.equal(r.status, 1, r.stderr);
  assert.equal(r.stderr, '');
  const report = JSON.parse(r.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.findings.length, 101);
  assert.equal(report.findings.at(-1).kind, 'truncated_report');
  expectFail(cli(['summary', log]), 2, 'log_corrupt');
});

test('findings are never duplicated for one problem', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const lines = toText(buildRecords(3)).split(NL);
  lines[2] = lines[2].replace('"type":"event2"', '"type":"bad type"');
  writeFileSync(log, lines.join(NL));
  const report = await verifyLog(log);
  const ids = report.findings.map((f) => [f.kind, f.seq, f.detail].join('|'));
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.length > 0);
  assert.equal(canonicalize(report.findings).length > 0, true);
  void T0;
});
