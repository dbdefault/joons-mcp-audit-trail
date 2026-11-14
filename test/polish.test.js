import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { cli, expectFail, expectOk, KEY, root, tempDir } from '../reference/helpers.js';
import { canonicalize, hashRecord, header } from '../reference/model.js';
import { appendRecord, readRecords, summarize, verifyLog } from '../src/index.js';
import {
  exportParts,
  MAX_SUMMARY_BYTES,
  renderShow,
  renderSummary,
  sanitizeText,
  showParts,
} from '../src/report/index.js';
import { validateEvent } from '../src/canon/index.js';
import { hasDuplicateKeys } from '../src/cli/strict-json.js';

const BS = String.fromCharCode(92);
// A nested `node --test` must not inherit the outer runner's context, or it prints nothing.
const plainEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NODE_TEST_CONTEXT'));
const T = '2026-01-01T00:00:00.000Z';
const CAP = 16 * 1024 * 1024;

/** Streams a forged plain log to disk: a header, then `count` event records made by `make(i)` (not by append). */
function forgeLog(path, count, make) {
  const fd = openSync(path, 'w');
  try {
    let prev = header(T);
    writeSync(fd, canonicalize(prev) + '\n');
    for (let i = 1; i <= count; i++) {
      const fields = { type: 'e', actor: null, tool: null, outcome: null, data: null, ...make(i) };
      const body = { seq: i, time: T, ...fields, prev: prev.hash };
      prev = { ...body, hash: hashRecord(body) };
      writeSync(fd, canonicalize(prev) + '\n');
    }
  } finally {
    closeSync(fd);
  }
}

// ---- summary resource bound ---------------------------------------------------------------------------------------

test('summary counts names longer than 128 code points under (other) and never stores them', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const points128 = '\u{1f600}'.repeat(128);
  const names = [points128, points128 + 'x', 'x'.repeat(128), 'x'.repeat(129), 'x'.repeat(5000), 'short'];
  forgeLog(log, names.length, (i) => ({ actor: names[i - 1], tool: names[i - 1] }));
  const detailed = await summarize(log, { details: true });
  assert.deepEqual(detailed.actor, { [points128]: 1, ['x'.repeat(128)]: 1, '(other)': 3, short: 1 });
  assert.deepEqual(detailed.tool, detailed.actor);
  const plain = await summarize(log, {});
  assert.deepEqual(plain.actor, { distinct: 3 }, '(other) is not a distinct name');
  // A name that is already stored keeps counting; a long name is never added.
  forgeLog(log, 4, (i) => ({ actor: i === 4 ? 'x'.repeat(200) : 'same' }));
  assert.deepEqual((await summarize(log, { details: true })).actor, { '(other)': 1, same: 3 });
});

test('summary --details with 800 forged records of 64,000-character actors: no V8 abort under a 96 MB heap', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'big.jsonl');
  forgeLog(log, 800, (i) => ({ actor: String(i).padStart(6, '0') + 'a'.repeat(63994) }));
  assert.ok(statSync(log).size > 50000000);
  for (const format of ['terminal', 'json', 'markdown']) {
    const r = cli(['summary', log, '--details', '--format', format], { nodeArgs: ['--max-old-space-size=96'] });
    assert.equal(r.status, 0, r.stderr.slice(0, 300));
    assert.equal(r.stderr, '');
    assert.ok(r.stdout.includes('(other)') && r.stdout.includes('800'), format);
    assert.ok(r.stdout.length < 2000, 'no long name is stored or printed');
  }
  const plain = cli(['summary', log], { nodeArgs: ['--max-old-space-size=96'] });
  expectOk(plain);
});

test('summary --details output is capped at 16 MiB: limit_exceeded, exit 2, one fixed stderr line', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'wide.jsonl');
  // 10,000 distinct 120-character names with 100 NULs (6 bytes each as JSON escapes) in three dimensions.
  const name = (i, k) => '\u0000'.repeat(100) + k + String(i).padStart(8, '0') + 'z'.repeat(8);
  forgeLog(log, 10000, (i) => ({ type: name(i, 't'), actor: name(i, 'a'), tool: name(i, 'o') }));
  for (const format of ['json', 'markdown']) {
    const r = cli(['summary', log, '--details', '--format', format], { nodeArgs: ['--max-old-space-size=256'] });
    expectFail(r, 2, 'limit_exceeded');
  }
  // The terminal form replaces every control with one "?", so the same log renders far below the cap.
  const terminal = cli(['summary', log, '--details'], { nodeArgs: ['--max-old-space-size=256'] });
  expectOk(terminal);
  assert.ok(terminal.stdout.length < CAP);
  // Without --details the output is tiny.
  expectOk(cli(['summary', log, '--format', 'json']));
});

test('renderSummary counts the whole rendered output: cap - 1 and cap pass, cap + 1 fails (json)', () => {
  const make = (pad) => ({ records: 1, from: null, to: null, type: { a: 1, [pad]: 1 } });
  const base = Buffer.byteLength(renderSummary(make(''), 'json'));
  assert.equal(MAX_SUMMARY_BYTES, CAP);
  for (const [extra, ok] of [[-1, true], [0, true], [1, false]]) {
    const pad = 'p'.repeat(CAP - base + extra);
    const build = () => renderSummary(make(pad), 'json');
    if (ok) assert.equal(Buffer.byteLength(build()), CAP + extra);
    else assert.throws(build, { kind: 'limit_exceeded' });
  }
});

// ---- names: stable reading, strict writing -------------------------------------------------------------------------

/** One forged record chain with the given (already valid or invalid) actor values; returns the log path. */
function forgedWith(t, actors, key = null) {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  forgeLog(log, actors.length, (i) => ({ actor: actors[i - 1], tool: actors[i - 1] }));
  void key;
  return log;
}

test('a log whose names hold code points that only a newer Unicode version assigns verifies when read', async (t) => {
  const odd = [
    'new \u{323b0} char', // assigned only from Unicode 17: a newer writer accepts it, an older reader must too
    'unassigned \u{378} here', // unassigned in every version: the writer refuses it, the reader does not look at it
    'unassigned \u{50000}', // plane 5 is unassigned in every Unicode version
    '(other)',
    ' padded ',
    ' ',
  ];
  const log = forgedWith(t, odd);
  const report = await verifyLog(log);
  assert.deepEqual(report.findings, []);
  assert.equal(report.ok, true);
  expectOk(cli(['verify', log]));
  expectOk(cli(['show', log]));
  expectOk(cli(['summary', log, '--details']));
  expectOk(cli(['export', log, '--out', join(join(log, '..'), 'o.json'), '--format', 'json']));
  expectOk(cli(['export', log, '--out', join(join(log, '..'), 'o.csv'), '--format', 'csv']));
  // append reads the tail with the lenient rule and appends a normal record.
  await appendRecord(log, { type: 'next', actor: 'fine' }, {});
  assert.equal((await verifyLog(log)).ok, true);
  let count = 0;
  for await (const item of readRecords(log)) assert.equal(item.record.seq, count++);
  assert.equal(count, odd.length + 2);
});

test('the version-independent reader table still reports the stable classes as bad_record', async (t) => {
  const classes = [
    0x1,
    0x1f,
    0x7f,
    0x85,
    0xa0,
    0xad,
    0x34f,
    0x600,
    0x61c,
    0x1680,
    0x180e,
    0x2000,
    0x200b,
    0x200e,
    0x2028,
    0x2029,
    0x202e,
    0x202f,
    0x2060,
    0x2066,
    0x2800,
    0x3000,
    0x3164,
    0xfdd0,
    0xfe0f,
    0xfeff,
    0xffa0,
    0xfff9,
    0xfffc,
    0xfffe,
    0xd800,
    0xe000,
    0x110bd,
    0x13430,
    0x1bca0,
    0x1d173,
    0x1fffe,
    0xe0001,
    0xe0100,
    0xf0000,
    0x10ffff,
  ].map((c) => String.fromCodePoint(c));
  for (const ch of classes) {
    const log = forgedWith(t, ['a' + ch + 'b']);
    const report = await verifyLog(log);
    assert.equal(report.ok, false, JSON.stringify(ch));
    assert.ok(report.findings.some((f) => f.kind === 'bad_record' && f.seq === 1), JSON.stringify(ch));
  }
});

test('writing is strict: unassigned code points, "(other)" and spaces at either end are refused', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const bad = ['a\u{378}b', '(other)', ' ', '  ', ' x', 'x ', ' (other)', '\u{e000f}'];
  for (const value of bad) {
    for (const field of ['actor', 'tool']) {
      assert.throws(
        () => validateEvent({ type: 't', [field]: value }),
        { kind: 'invalid_record' },
        `${field} ${value}`,
      );
      await assert.rejects(appendRecord(log, { type: 't', [field]: value }, {}), { kind: 'invalid_record' });
    }
  }
  assert.equal(existsSync(log), false, 'a refused name creates nothing');
  expectFail(cli(['append', log, '--type', 't', '--actor', '(other)']), 2, 'invalid_record');
  expectFail(cli(['append', log, '--type', 't', '--tool', ' ']), 2, 'invalid_record');
  expectFail(cli(['append', log, '--type', 't', '--actor=x ']), 2, 'invalid_record');
  for (const value of ['(other', 'other', '(other) x', 'a b', '(other)(other)', 'x y ']) {
    if (value.endsWith(' ')) continue;
    validateEvent({ type: 't', actor: value, tool: value });
  }
  expectFail(cli(['append', log, '--type', '(other)']), 2, 'invalid_record');
  assert.equal(existsSync(log), false);
});

test('library appendRecord with null options behaves like undefined', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  assert.deepEqual((await appendRecord(log, { type: 'a' }, null)).seq, 1);
  assert.deepEqual((await appendRecord(log, { type: 'b' }, undefined)).seq, 2);
  assert.deepEqual((await appendRecord(log, { type: 'c' })).seq, 3);
  assert.equal((await verifyLog(log)).ok, true);
});

// ---- CSV: the sanitizer predicate escapes every cell ---------------------------------------------------------------

function csvRow(fields) {
  const parts = exportParts('csv');
  const base = {
    seq: 1,
    time: 't',
    type: 'x',
    actor: null,
    tool: null,
    outcome: null,
    data: null,
    prev: 'p',
    hash: 'h',
  };
  return parts.item({ ...base, ...fields }, 0);
}

test('CSV escapes C0 controls, U+2028, U+2029, U+2800 and U+FFFC in every field, including non-data fields', () => {
  for (const code of [0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f, 0x2028, 0x2029, 0x2800, 0xfffc]) {
    const ch = String.fromCodePoint(code);
    const escape = BS + 'u' + code.toString(16).padStart(4, '0');
    for (const field of ['type', 'actor', 'tool', 'outcome', 'time', 'prev', 'hash']) {
      const row = csvRow({ [field]: 'a' + ch + 'b' });
      assert.ok(!row.slice(0, -2).includes(ch), `${field} ${code.toString(16)} stays raw`);
      assert.ok(row.includes('a' + escape + 'b'), `${field} ${code.toString(16)}`);
    }
    // The data cell is canonical JSON: it escapes most controls itself, and the cell rule escapes the rest.
    assert.ok(!csvRow({ data: { k: 'a' + ch } }).slice(0, -2).includes(ch), 'data ' + code.toString(16));
  }
  // Exactly one record terminator per row, whatever a forged field holds.
  assert.equal(
    csvRow({ actor: 'a' + String.fromCodePoint(0x2028, 0x0d, 0x0a) + 'b' }).split(String.fromCharCode(13, 10)).length,
    2,
  );
});

test('CSV escapes exactly the code points that the terminal sanitizer replaces (same predicate)', () => {
  const check = (code) => {
    const ch = String.fromCodePoint(code);
    const replaced = sanitizeText(ch) !== ch;
    const row = csvRow({ actor: ch }).slice(0, -2); // without the record terminator
    assert.equal(!row.includes(ch), replaced, code.toString(16));
  };
  for (let code = 0; code < 0x30000; code++) check(code);
  for (let code = 0x30000; code <= 0x10ffff; code += 61) check(code);
  for (const code of [0xe0000, 0xe0001, 0xe0020, 0xe007f, 0xe0100, 0xe01ef, 0xe0fff, 0xf0000, 0xffffd, 0x10ffff]) {
    check(code);
  }
});

// ---- show: the 16 MiB cap counts the closing tail; exact cap-1 / cap / cap+1 ----------------------------------

function showTotal(records, format) {
  const parts = showParts(format);
  let total = Buffer.byteLength(parts.head());
  records.forEach((r, i) => total += Buffer.byteLength(parts.item(r, i)));
  return total + Buffer.byteLength(parts.tail(records.length));
}

test('renderShow counts the closing tail: total = cap - 1 and cap pass, cap + 1 fails (json and terminal)', () => {
  for (const format of ['json', 'terminal']) {
    const make = (pad) => [{ seq: 1, note: pad }];
    const base = showTotal(make(''), format);
    for (const [extra, ok] of [[-1, true], [0, true], [1, false]]) {
      const records = make('p'.repeat(CAP - base + extra));
      assert.equal(showTotal(records, format), CAP + extra);
      if (ok) assert.equal(Buffer.byteLength(renderShow(records, format)), CAP + extra);
      else assert.throws(() => renderShow(records, format), { kind: 'limit_exceeded' });
    }
  }
  // Without the tail the last case would have passed: the items alone are cap + 1 - 3 bytes.
  const records = [{ seq: 1, note: 'p'.repeat(CAP - showTotal([{ seq: 1, note: '' }], 'json') + 1) }];
  const parts = showParts('json');
  assert.equal(Buffer.byteLength(parts.head() + parts.item(records[0], 0)), CAP + 1 - Buffer.byteLength('\n]\n'));
  assert.throws(() => renderShow(records, 'json'), { kind: 'limit_exceeded' });
});

test('the real show command applies the same exact rule: total bytes cap - 1, cap pass, cap + 1 fail', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const fat = (width) => ({
    data: Object.fromEntries(Array.from({ length: 8 }, (_, k) => ['k' + k, 'x'.repeat(width)])),
  });
  const build = (target) => {
    // Records that are 8 x 4000 characters each, then one tuning record; its 8 strings carry the remainder.
    const stub = (extra) => {
      const per = [];
      for (let k = 0; k < 8; k++) per.push(Math.min(4096, Math.max(0, extra - k * 4096)));
      return { data: Object.fromEntries(per.map((n, k) => ['t' + k, 'x'.repeat(n)])) };
    };
    const rec = (i, fields) => {
      const body = {
        seq: i,
        time: T,
        type: 'e',
        actor: null,
        tool: null,
        outcome: null,
        ...fields,
        prev: '0'.repeat(64),
      };
      return { ...body, hash: hashRecord(body) };
    };
    const one = showTotal([rec(1, fat(4000))], 'json') - showTotal([], 'json');
    const empty = showTotal([rec(1, stub(0))], 'json');
    const count = Math.floor((target - empty - 1000) / (one + 1));
    const records = Array.from({ length: count }, (_, i) => rec(i + 1, fat(4000)));
    const fixed = showTotal([...records, rec(count + 1, stub(0))], 'json');
    const extra = target - fixed;
    assert.ok(extra >= 0 && extra <= 32768, 'tuning range ' + extra);
    records.push(rec(count + 1, stub(extra)));
    assert.equal(showTotal(records, 'json'), target);
    return records;
  };
  const results = [];
  for (const [delta, status] of [[-1, 0], [0, 0], [1, 2]]) {
    const records = build(CAP + delta);
    const fd = openSync(log, 'w');
    try {
      writeSync(fd, canonicalize(header(T)) + '\n');
      for (const r of records) writeSync(fd, canonicalize(r) + '\n');
    } finally {
      closeSync(fd);
    }
    const r = cli(['show', log, '--format', 'json', '--from', '1', '--to', String(records.length)]);
    results.push([delta, r.status]);
    if (status === 0) {
      assert.equal(r.stderr, '');
      assert.equal(Buffer.byteLength(r.stdout), CAP + delta);
    } else expectFail(r, 2, 'limit_exceeded');
  }
  assert.deepEqual(results, [[-1, 0], [0, 0], [1, 2]]);
});

// ---- --out may never be a lock file --------------------------------------------------------------------------------

test('anchor and export refuse --out equal to a lock path, even with --force; held locks stay', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectOk(cli(['append', log, '--type', 'a']));
  const st = await fs.stat(log, { bigint: true });
  const nameLock = log + '.lock';
  const idName = st.ino === 0n
    ? null
    : `.audit-id-${createHash('sha256').update(`${st.dev}:${st.ino}`).digest('hex').slice(0, 32)}.lock`;
  const targets = [nameLock, dir + '/./log.jsonl.lock', dir + '/x/../log.jsonl.lock'];
  if (idName) targets.push(join(dir, idName));
  targets.push(join(dir, '.audit-id-' + 'a'.repeat(32) + '.lock'));
  for (const target of targets) {
    for (const held of [true, false]) {
      if (held) writeFileSync(target, 'held by another writer');
      for (
        const args of [['anchor', log, '--out', target, '--force'], ['anchor', log, '--out', target], [
          'export',
          log,
          '--out',
          target,
          '--format',
          'json',
          '--force',
        ], ['export', log, '--out', target, '--format', 'csv']]
      ) {
        const r = cli(args);
        expectFail(r, 4, 'output_error');
        if (held) assert.equal(readFileSync(target, 'utf8'), 'held by another writer', args.join(' '));
        else assert.equal(existsSync(target), false, 'nothing is created at a lock path');
      }
      if (held) await fs.rm(target);
    }
  }
  // Any existing file named *.lock is never replaced with --force.
  const other = join(dir, 'something.lock');
  writeFileSync(other, 'keep me');
  expectFail(cli(['anchor', log, '--out', other, '--force']), 4, 'output_error');
  expectFail(cli(['export', log, '--out', other, '--format', 'json', '--force']), 4, 'output_error');
  assert.equal(readFileSync(other, 'utf8'), 'keep me');
  // A key file's own lock name is refused too, and ordinary outputs still work (also over an existing file).
  const keyed = join(dir, 'keyed.jsonl');
  const keyFile = join(dir, 'key');
  writeFileSync(keyFile, KEY);
  expectOk(cli(['append', keyed, '--type', 'a', '--key-file', keyFile]));
  expectFail(cli(['anchor', keyed, '--key-file', keyFile, '--out', keyFile + '.lock']), 4, 'output_error');
  const fine = join(dir, 'anchor.json');
  expectOk(cli(['anchor', log, '--out', fine]));
  expectOk(cli(['anchor', log, '--out', fine, '--force']));
  expectOk(cli(['export', log, '--out', join(dir, 'fine.json'), '--format', 'json']));
  assert.deepEqual(readdirSync(dir).filter((n) => n.endsWith('.tmp')), []);
});

// ---- suite gaps found by mutation testing --------------------------------------------------------------------------

test('real show: 10,000 records pass and 10,001 fail with limit_exceeded', (t) => {
  const dir = tempDir(t);
  const small = join(dir, 'small.jsonl');
  const large = join(dir, 'large.jsonl');
  forgeLog(small, 10000, (i) => ({ data: { n: i } }));
  forgeLog(large, 10001, (i) => ({ data: { n: i } }));
  const ok = cli(['show', small, '--format', 'json']);
  expectOk(ok);
  assert.equal(JSON.parse(ok.stdout).length, 10000);
  expectFail(cli(['show', large, '--format', 'json']), 2, 'limit_exceeded');
  expectFail(cli(['show', large]), 2, 'limit_exceeded');
  // A bounded range of the same log still works.
  const part = cli(['show', large, '--from', '5', '--to', '9', '--format', 'json']);
  expectOk(part);
  assert.deepEqual(JSON.parse(part.stdout).map((r) => r.seq), [5, 6, 7, 8, 9]);
});

test('duplicate keys are found after an array value and in nested containers', (t) => {
  for (
    const text of [
      '{"a":[1],"b":1,"b":2}',
      '{"a":[1,2],"b":{"c":1},"b":2}',
      '{"a":[{"x":1}],"a":2}',
      '{"a":[[1],[2]],"z":0,"a":1}',
      '{"n":{"a":[1],"a":2}}',
      '{"a":[1],"a\\u0062":1,"ab":2}',
    ]
  ) assert.equal(hasDuplicateKeys(text), true, text);
  for (const text of ['{"a":[1],"b":1,"c":2}', '{"a":[{"x":1},{"x":2}],"b":[1]}', '{"a":{"b":1},"b":{"a":1}}']) {
    assert.equal(hasDuplicateKeys(text), false, text);
  }
  const dir = tempDir(t);
  const data = join(dir, 'd.json');
  writeFileSync(data, '{"a":[1],"b":1,"b":2}');
  expectFail(cli(['append', join(dir, 'log.jsonl'), '--type', 't', '--data', data]), 2, 'invalid_record');
  assert.equal(existsSync(join(dir, 'log.jsonl')), false);
});

test('show lists integer-like keys in code unit order in terminal and JSON output', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await appendRecord(log, { type: 't', data: { b: 1, 10: 2, a: 3, 9: 4, 1: 5, 100: 6 } }, {});
  const order = (text) => [...text.matchAll(/"(\d+|[ab])":/g)].map((m) => m[1]).filter((k) => /^(\d+|[ab])$/.test(k));
  const want = ['1', '10', '100', '9', 'a', 'b'];
  for (const format of ['terminal', 'json']) {
    const r = cli(['show', log, '--from', '1', '--to', '1', '--format', format]);
    expectOk(r);
    const block = r.stdout.slice(r.stdout.indexOf('"data"'));
    assert.deepEqual(order(block), want, format);
  }
  // The stored line uses the same order.
  const stored = readFileSync(log, 'utf8').split('\n')[1];
  assert.deepEqual(order(stored.slice(stored.indexOf('"data"'))), want);
});

// ---- scripts and temp files ----------------------------------------------------------------------------------------

test('node --test does not discover the long-test runner script', async (t) => {
  const dir = tempDir(t);
  await fs.mkdir(join(dir, 'scripts'));
  const body = "import { writeFileSync } from 'node:fs';\n" +
    "const name = import.meta.url.split('/').at(-1);\n" +
    "writeFileSync(new URL('./ran-' + name + '.txt', import.meta.url), 'x');\n";
  writeFileSync(join(dir, 'scripts', 'run-long-tests.mjs'), body);
  writeFileSync(join(dir, 'scripts', 'test-long.mjs'), body); // the old name: Node's discovery picks this one up
  const r = spawnSync(process.execPath, ['--test'], {
    cwd: dir,
    encoding: 'utf8',
    timeout: 60000,
    windowsHide: true,
    env: plainEnv(),
  });
  assert.equal(existsSync(join(dir, 'scripts', 'ran-test-long.mjs.txt')), true, 'discovery sanity check: ' + r.stdout);
  assert.equal(existsSync(join(dir, 'scripts', 'ran-run-long-tests.mjs.txt')), false);
  assert.equal(existsSync(join(root, 'scripts', 'test-long.mjs')), false);
  assert.equal(existsSync(join(root, 'scripts', 'run-long-tests.mjs')), true);
});

test('the long test group skips cleanly without its marker file (no long run)', (t) => {
  if (existsSync(join(root, 'test', 'long-tests.enabled'))) return t.skip('the marker exists: this is a long run');
  const started = Date.now();
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=spec', join(root, 'test', 'long-limits.test.js')], {
    encoding: 'utf8',
    timeout: 60000,
    windowsHide: true,
    env: plainEnv(),
  });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /skipped 3\b/);
  assert.match(r.stdout, /pass 0\b/);
  assert.ok(Date.now() - started < 30000);
});
