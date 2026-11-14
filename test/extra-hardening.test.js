import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { cli, expectFail, expectOk, KEY, tempDir, writeFatLog } from '../reference/helpers.js';
import { appendRecord, canonicalize as productCanonicalize, readRecords, verifyLog } from '../src/index.js';
import { checkPath, lockPathFor } from '../src/log/paths.js';
import { renderExport, renderShow, sanitizeText, showParts } from '../src/report/index.js';
import { validateEvent } from '../src/canon/index.js';
import { hasDuplicateKeys } from '../src/cli/strict-json.js';

const BS = String.fromCharCode(92);
const cp = (...codes) => codes.map((c) => String.fromCodePoint(c)).join('');
const MiB = 1024 * 1024;

// ---- show is bounded by rendered bytes (16 MiB) as well as by record count ---------------------------------------

test('show stops with limit_exceeded when the rendered range would pass 16 MiB; smaller ranges work', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'fat.jsonl');
  writeFatLog(log, 700);
  assert.ok(readFileSync(log).length > 21 * MiB);
  for (const format of ['terminal', 'json']) {
    const big = cli(['show', log, '--from', '1', '--to', '700', '--format', format]);
    expectFail(big, 2, 'limit_exceeded');
    assert.equal(big.stderr.split('\n').length, 2, 'one fixed stderr line');
    const small = cli(['show', log, '--to', '100', '--format', format]);
    expectOk(small);
    assert.equal(JSON.parse(small.stdout).length, 100);
    assert.ok(Buffer.byteLength(small.stdout) < 16 * MiB);
  }
  expectFail(cli(['show', log, '--to', '700']), 2, 'limit_exceeded');
});

test('the library renderer applies the same byte bound before building the output', () => {
  const fat = { seq: 1, data: { text: 'y'.repeat(60000) } };
  assert.throws(() => renderShow(Array(400).fill(fat)), { kind: 'limit_exceeded' });
  assert.doesNotThrow(() => renderShow(Array(100).fill(fat)));
  assert.equal(renderShow([]), '[]\n');
});

test('showParts gives the same bytes as the whole-list renderer in every format', () => {
  const records = [
    { seq: 1, data: { b: 1, 10: 'x', 9: { z: [1, { y: 2, x: 3 }] }, a: null }, note: 'a|b' },
    { seq: 2, data: {}, list: [] },
  ];
  for (const format of ['terminal', 'json', 'markdown']) {
    const parts = showParts(format);
    let out = parts.head();
    records.forEach((r, i) => out += parts.item(r, i));
    out += parts.tail(records.length);
    assert.equal(out, renderShow(records, format), format);
  }
});

// ---- JSON output and the CSV data cell use the same canonical key order ------------------------------------------

test('JSON export and CSV data cell list object keys in canonical (code unit) order', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const data = join(dir, 'data.json');
  writeFileSync(data, '{"b":1,"9":2,"10":3,"a":{"2":1,"10":2}}');
  expectOk(cli(['append', log, '--type', 'order', '--data', data, '--time', '2026-01-01T00:00:00Z']));
  const jsonOut = join(dir, 'o.json');
  const csvOut = join(dir, 'o.csv');
  expectOk(cli(['export', log, '--out', jsonOut, '--format', 'json']));
  expectOk(cli(['export', log, '--out', csvOut, '--format', 'csv']));
  const canonical = '{"10":3,"9":2,"a":{"10":2,"2":1},"b":1}';
  assert.ok(readFileSync(jsonOut, 'utf8').includes('"10": 3,\n      "9": 2,'));
  assert.ok(readFileSync(csvOut, 'utf8').includes('"' + canonical.replaceAll('"', '""') + '"'));
  const shown = cli(['show', log, '--format', 'json']);
  expectOk(shown);
  assert.ok(shown.stdout.indexOf('"10"') < shown.stdout.indexOf('"9"'));
  assert.equal(productCanonicalize(JSON.parse(canonical)), canonical);
});

// ---- CSV cells are sanitized -------------------------------------------------------------------------------------

test('CSV cells escape C1 controls, DEL and invisible or bidirectional characters (formula guard kept)', () => {
  const row = (fields) =>
    renderExport(
      [{
        seq: 1,
        time: 't',
        type: 'x',
        actor: null,
        tool: null,
        outcome: null,
        data: null,
        prev: 'p',
        hash: 'h',
        ...fields,
      }],
      'csv',
    ).split('\r\n')[1];
  assert.ok(row({ actor: 'a' + cp(0x85) + 'b' }).includes('"a' + BS + 'u0085b"'));
  assert.ok(row({ actor: 'a' + cp(0x7f) + 'b' }).includes('"a' + BS + 'u007fb"'));
  assert.ok(row({ actor: 'a' + cp(0x202e) + 'b' }).includes('"a' + BS + 'u202eb"'));
  assert.ok(row({ actor: 'a' + cp(0x200b, 0xfeff) + 'b' }).includes('"a' + BS + 'u200b' + BS + 'ufeffb"'));
  assert.ok(row({ actor: 'a' + cp(0x110bd) + 'b' }).includes('"a' + BS + 'u{110bd}b"'));
  assert.ok(row({ actor: 'a' + cp(0xe0001) + 'b' }).includes('"a' + BS + 'u{e0001}b"'));
  assert.ok(row({ actor: 'a' + cp(0x378) + 'b' }).includes('"a' + BS + 'u0378b"'));
  assert.ok(row({ actor: 'a' + String.fromCharCode(0xd800) + 'b' }).includes('"a' + BS + 'ud800b"'));
  assert.ok(row({ data: { s: 'x' + cp(0x85) } }).includes(BS + 'u0085'));
  assert.ok(row({ actor: '=1+1' + cp(0x85) }).includes('"\'=1+1' + BS + 'u0085"'));
  // Plain text, accents, Korean and emoji are kept as they are; tab, CR and LF are controls and are escaped too.
  assert.ok(row({ actor: 'é 한글 😀' }).includes('"é 한글 😀"'));
  assert.ok(row({ actor: 'a\tb' }).includes('"a' + BS + 'u0009b"'));
  for (const c of [0x85, 0x7f, 0x202e, 0x200b, 0xfeff, 0x110bd, 0xe0001, 0x378, 0xd800]) {
    assert.ok(
      !/[\u{7f}-\u{9f}\u{200b}\u{202e}\u{feff}\u{110bd}\u{e0001}\u{378}\u{d800}]/u.test(row({ actor: 'a' + cp(c) })),
    );
  }
});

// ---- terminal sanitizer ------------------------------------------------------------------------------------------

test('the sanitizer replaces the 22 listed format characters, unassigned and default-ignorable code points', () => {
  const listed = [
    0x110bd,
    0x110cd,
    ...Array.from({ length: 16 }, (_, i) => 0x13430 + i),
    0x1bca0,
    0x1bca1,
    0x1bca2,
    0x1bca3,
  ];
  assert.equal(listed.length, 22);
  const others = [0x378, 0xfdd0, 0xfffe, 0xffff, 0x50000, 0xe0080, 0xe00ff, 0xfff0, 0x2065, 0x1d173, 0x115f, 0x3164];
  for (const c of [...listed, ...others]) assert.equal(sanitizeText('a' + cp(c) + 'b'), 'a?b', 'U+' + c.toString(16));
  const kept = 'a b é 한글 😀 – “q” ~ ';
  assert.equal(sanitizeText(kept), kept);
  assert.equal(sanitizeText(cp(0xa0, 0x3000)), '??');
});

// ---- actor, tool and type name rules -----------------------------------------------------------------------------

test('actor and tool refuse non-ASCII spaces, default-ignorable and unassigned code points', () => {
  const refused = [
    0xa0,
    0x1680,
    0x2000,
    0x2003,
    0x200a,
    0x202f,
    0x205f,
    0x3000,
    0x2028,
    0x2029,
    0x378,
    0xe0080,
    0xfff0,
    0x2065,
  ];
  for (const c of refused) {
    for (const field of ['actor', 'tool']) {
      assert.throws(
        () => validateEvent({ type: 'x', [field]: 'agent' + cp(c) }),
        { kind: 'invalid_record' },
        'U+' + c.toString(16),
      );
      assert.throws(() => validateEvent({ type: 'x', [field]: 'a' + cp(c) + 'b' }), { kind: 'invalid_record' });
    }
    assert.throws(() => validateEvent({ type: 'x' + cp(c) }), { kind: 'invalid_record' });
  }
  assert.equal(validateEvent({ type: 'x', actor: 'my agent', tool: 'a b' }).actor, 'my agent');
  assert.equal(validateEvent({ type: 'x', actor: '한글 é 😀' }).actor, '한글 é 😀');
});

test('real command line: an actor with a no-break space is refused', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectOk(cli(['append', log, '--type', 'x', '--actor', 'agent']));
  expectFail(cli(['append', log, '--type', 'x', '--actor', 'agent' + cp(0xa0)]), 2, 'invalid_record');
  expectFail(cli(['append', log, '--type', 'x', '--tool', cp(0x3000) + 'tool']), 2, 'invalid_record');
});

// ---- reserved device names ---------------------------------------------------------------------------------------

test('reserved device names with superscript digits and CLOCK$ are refused, also with a trailing dot or space', () => {
  const names = [
    'COM' + cp(0xb9),
    'COM' + cp(0xb2),
    'COM' + cp(0xb3),
    'LPT' + cp(0xb9),
    'LPT' + cp(0xb2),
    'LPT' + cp(0xb3),
    'CLOCK$',
  ];
  for (const base of names) {
    for (
      const variant of [base, base.toLowerCase(), base + '.', base + ' ', base + '.txt', base + ' .log', 'dir/' + base]
    ) {
      assert.throws(() => checkPath(variant, 'output_error'), { kind: 'output_error' }, JSON.stringify(variant));
    }
  }
  for (const ok of ['COM', 'COM0', 'COMX', 'LPT10', 'CLOCK', 'CLOCKS', 'clock-1']) {
    assert.doesNotThrow(() => checkPath('dir/' + ok, 'output_error'), ok);
  }
});

test('real command line: a log named COM-superscript or CLOCK$ is refused without touching the file system', (t) => {
  const dir = tempDir(t);
  for (const name of ['COM' + cp(0xb9), 'LPT' + cp(0xb3) + '.log', 'CLOCK$']) {
    expectFail(cli(['append', join(dir, name), '--type', 'x']), 4, 'output_error');
  }
  assert.deepEqual(readdirSync(dir), []);
});

// ---- key file: exactly one trailing LF or CRLF --------------------------------------------------------------------

test('real command line: a key file saved with CRLF equals the same key saved with LF', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const lf = join(dir, 'key.lf');
  const crlf = join(dir, 'key.crlf');
  const none = join(dir, 'key.none');
  writeFileSync(lf, KEY + '\n');
  writeFileSync(crlf, KEY + '\r\n');
  writeFileSync(none, KEY);
  expectOk(cli(['append', log, '--type', 'a', '--key-file', lf]));
  expectOk(cli(['append', log, '--type', 'b', '--key-file', crlf]));
  expectOk(cli(['append', log, '--type', 'c', '--key-file', none]));
  expectOk(cli(['verify', log, '--key-file', crlf]));
  expectOk(cli(['verify', log, '--key-file', lf]));
});

test('real command line: a key file that is only line terminators is key_invalid', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  for (const [name, content] of [['lf', '\n'.repeat(20)], ['crlf', '\r\n'.repeat(20)], ['cr', '\r'.repeat(20)]]) {
    const key = join(dir, 'key.' + name);
    writeFileSync(key, content);
    expectFail(cli(['append', log, '--type', 'a', '--key-file', key]), 2, 'key_invalid');
  }
  assert.equal(existsSync(log), false);
});

// ---- zero-byte log -----------------------------------------------------------------------------------------------

test('a zero-byte log: summary, show, export fail with log_corrupt; verify says bad_header', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'empty.jsonl');
  writeFileSync(log, '');
  expectFail(cli(['summary', log]), 2, 'log_corrupt');
  expectFail(cli(['summary', log, '--details', '--format', 'json']), 2, 'log_corrupt');
  expectFail(cli(['show', log]), 2, 'log_corrupt');
  const out = join(dir, 'out.json');
  expectFail(cli(['export', log, '--out', out, '--format', 'json']), 2, 'log_corrupt');
  expectFail(cli(['export', log, '--out', out, '--format', 'csv']), 2, 'log_corrupt');
  assert.equal(existsSync(out), false);
  assert.deepEqual(readdirSync(dir), ['empty.jsonl']);
  const verify = cli(['verify', log, '--format', 'json']);
  assert.equal(verify.status, 1);
  assert.equal(JSON.parse(verify.stdout).findings[0].kind, 'bad_header');
  expectOk(cli(['append', log, '--type', 'first']));
  expectOk(cli(['verify', log]));
  expectOk(cli(['show', log]));
});

// ---- --data duplicate keys ---------------------------------------------------------------------------------------

test('hasDuplicateKeys finds a repeated key at any depth and nothing else', () => {
  const dup = [
    '{"a":1,"a":2}',
    '{"x":{"b":1,"b":2}}',
    '{"x":[{"c":1,"c":1}]}',
    '{"a":1,"' + BS + 'u0061":2}',
    '{"a":{"a":1},"b":[1,{"q":1,"q":2}]}',
    '{ "a" : 1 , "a" : 2 }',
    '{"k' + BS + '"":1,"k' + BS + '"":2}',
  ];
  for (const text of dup) assert.equal(hasDuplicateKeys(text), true, text);
  const fine = [
    '{}',
    '{"a":1}',
    '{"a":{"a":1},"b":[{"a":1},{"a":2}]}',
    '{"a":"{' + BS + '"x' + BS + '":1,' + BS + '"x' + BS + '":2}"}',
    '{"a,' + BS + '"b":1,"c":"a","d":"a"}',
    '{"a":[[{"a":1}],[{"a":1}]],"b":{"a":{"a":{"a":1}}}}',
    '{"a":"' + BS + BS + '","b":"x"}',
  ];
  for (const text of fine) {
    JSON.parse(text);
    assert.equal(hasDuplicateKeys(text), false, text);
  }
});

test('real command line: --data with a duplicate key at any depth is invalid_record and writes nothing', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const data = join(dir, 'data.json');
  for (
    const text of [
      '{"a":1,"a":2}',
      '{"x":{"b":1,"b":2}}',
      '{"x":[{"c":1},{"d":1,"d":1}]}',
      '{"a":1,"' + BS + 'u0061":2}',
    ]
  ) {
    writeFileSync(data, text);
    expectFail(cli(['append', log, '--type', 'x', '--data', data]), 2, 'invalid_record');
  }
  assert.equal(existsSync(log), false);
  writeFileSync(data, '{"a":{"a":1},"b":[{"a":1},{"a":2}],"c":"{' + BS + '"z' + BS + '":1}"}');
  expectOk(cli(['append', log, '--type', 'x', '--data', data]));
});

// ---- markdown ----------------------------------------------------------------------------------------------------

test('markdown puts every cell into one inline code span, so bare URLs and addresses are not links', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectOk(cli(['append', log, '--type', 'x', '--actor', 'https://example.org/a?b=c', '--tool', 'me@example.org']));
  expectOk(cli(['append', log, '--type', 'y', '--actor', 'back`tick``pair', '--tool', 'www.example.org|pipe']));
  const md = cli(['summary', log, '--details', '--format', 'markdown']);
  expectOk(md);
  const rows = md.stdout.split('\n').filter(Boolean).slice(2);
  assert.ok(rows.length >= 5);
  for (const row of rows) assert.match(row, /^\| ` [^|]* ` \| (`+) .* \1 \|$/, row);
  // Fence longer than any backtick run inside: three backticks around text that holds a run of two.
  const actorRow = rows.find((r) => r.includes('tick'));
  assert.match(actorRow, /\| ``` .*back`tick``pair.* ``` \|/);
  assert.ok(rows.some((r) => r.includes('www.example.org' + BS + 'u007cpipe')));
  // A pipe inside a cell never splits the table: every row has exactly two cells.
  for (const row of rows) assert.equal(row.split('|').length, 4, row);
  void md;
});

// ---- lock names ---------------------------------------------------------------------------------------------------

const FOLDS = process.platform === 'win32' || process.platform === 'darwin';

test('the lock name folds case, final sigma and normalization on case-folding file systems', async (t) => {
  const dir = tempDir(t);
  const names = [
    ['\u{3a3}log', '\u{3c3}log', '\u{3c2}log'],
    ['audit\u{3a3}', 'audit\u{3c3}', 'audit\u{3c2}'],
    ['LOG', 'log', 'Log'],
    ['caf\u{e9}', 'cafe\u{301}', 'CAF\u{c9}'],
  ];
  for (const group of names) {
    const locks = await Promise.all(group.map((n) => lockPathFor(join(dir, n))));
    if (FOLDS) assert.equal(new Set(locks).size, 1, JSON.stringify(group));
    else assert.equal(new Set(locks).size, group.length);
  }
});

// 8 simultaneous appends (4 per spelling) wait far below the fixed 5 s lock wait even when the machine is busy;
// 24 of them were too close to it under three parallel test runs. One spelling pair still shares one lock.
test('8 concurrent appends through sigma and capital sigma spellings of one name keep one clean chain', {
  timeout: 120000,
}, async (t) => {
  if (!FOLDS) return t.skip('this file system does not fold case');
  const dir = tempDir(t);
  const spellings = ['\u{3a3}', '\u{3c3}'].map((s) => join(dir, 'audit' + s));
  await Promise.all(
    Array.from({ length: 8 }, (_, i) => appendRecord(spellings[i % 2], { type: 'x', actor: 'a' + i })),
  );
  const report = await verifyLog(spellings[0]);
  assert.deepEqual(report.findings, []);
  let count = 0;
  for await (const item of readRecords(spellings[1])) assert.equal(item.record.seq, count++);
  assert.equal(count, 9);
  assert.equal(readdirSync(dir).length, 1, 'no lock file is left behind');
});

test('a second lock named from the file identity (device and inode) also guards an existing log', {
  timeout: 60000,
}, async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await appendRecord(log, { type: 'first' });
  const st = await fs.stat(log, { bigint: true });
  if (st.ino === 0n) return t.skip('this file system reports no inode numbers');
  const id = createHash('sha256').update(`${st.dev}:${st.ino}`).digest('hex').slice(0, 32);
  const idLock = join(dir, `.audit-id-${id}.lock`);
  writeFileSync(idLock, 'held by someone else');
  const started = Date.now();
  await assert.rejects(appendRecord(log, { type: 'second' }), { kind: 'lock_timeout' });
  assert.ok(Date.now() - started >= 4000);
  await fs.unlink(idLock);
  await appendRecord(log, { type: 'fourth' });
  assert.deepEqual(readdirSync(dir), ['log.jsonl'], 'locks are removed after each append');
  assert.equal((await verifyLog(log)).ok, true);
});
