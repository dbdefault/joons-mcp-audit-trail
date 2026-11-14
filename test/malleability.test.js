import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildRecords, cli, expectFail, expectOk, KEY, tempDir, toText, writeLog } from '../reference/helpers.js';
import { appendRecord, canonicalize, readRecords, verifyLog } from '../src/index.js';

const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const BS = String.fromCharCode(92);

function setup(t, keyed = false) {
  const dir = tempDir(t);
  const f = { dir, log: join(dir, 'log.jsonl'), key: join(dir, 'key') };
  writeFileSync(f.key, KEY);
  const records = buildRecords(3, keyed ? KEY : null);
  writeLog(f.log, records);
  return { ...f, records, lines: toText(records).split('\n').slice(0, -1) };
}

const join2 = (lines) => lines.join('\n') + '\n';

// Each mutation rewrites one stored line (index 1..3 are events, 0 is the header) to a different spelling of the
// same JSON value (or, for the BOM class, adds a byte order mark). Every spelling must be reported.
function spellings(line) {
  const obj = JSON.parse(line);
  const keys = Object.keys(obj);
  const reordered = '{' +
    keys.slice().reverse().map((k) => JSON.stringify(k) + ':' + JSON.stringify(obj[k])).join(',') + '}';
  const duplicateKey = line.replace('{', '{"seq":' + obj.seq + ',');
  return {
    spaceAfterColon: line.replace('"seq":', '"seq": '),
    spaceAfterComma: line.replace('",', '", '),
    spaceBeforeBrace: line + ' ',
    leadingSpace: ' ' + line,
    tab: line.replace('{', '{\t'),
    keyReorder: reordered,
    duplicateKey,
    escapeLetter: line.replace('"hash":"' + obj.hash[0], '"hash":"' + BS + 'u00' + obj.hash.charCodeAt(0).toString(16)),
    escapeT: line.replace('T', BS + 'u0054'),
    numberSpelling: line.replace('"seq":' + obj.seq + ',', '"seq":' + obj.seq + '.0,'),
    numberExponent: line.replace('"seq":' + obj.seq + ',', '"seq":' + obj.seq + 'e0,'),
    padded: line + ' '.repeat(65536 - Buffer.byteLength(line)),
  };
}

// Test titles need the spelling names before any directory exists, so the line is built without touching the disk.
const lineAt = (keyed, index) => toText(buildRecords(3, keyed ? KEY : null)).split(String.fromCharCode(10))[index];

for (const keyed of [false, true]) {
  for (const index of [0, 1, 3]) {
    const names = Object.keys(spellings(lineAt(keyed, index)));
    for (const name of names) {
      test(`non-canonical ${name} on line ${index} (${keyed ? 'keyed' : 'plain'}) is reported`, async (t) => {
        const f = setup(t, keyed);
        const lines = f.lines.slice();
        const mutated = spellings(lines[index])[name];
        assert.notEqual(mutated, lines[index]);
        lines[index] = mutated;
        writeFileSync(f.log, join2(lines));
        const report = await verifyLog(f.log, keyed ? { keyFile: f.key } : {});
        assert.equal(report.ok, false);
        const expectedKind = index === 0 ? 'bad_header' : 'bad_record';
        const hit = report.findings.find((x) => x.seq === index && x.kind === expectedKind);
        assert.ok(hit, JSON.stringify(report.findings));
        assert.ok(['line_not_canonical', 'record_invalid'].includes(hit.detail), hit.detail);
        // The hash chain checks keep running: the hashes and links of every line are still correct.
        assert.ok(!report.findings.some((x) => ['hash_mismatch', 'chain_break', 'seq_gap'].includes(x.kind)));
        // Same through the real command line.
        const r = cli(['verify', f.log, ...(keyed ? ['--key-file', f.key] : []), '--format', 'json']);
        assert.equal(r.status, 1);
        assert.equal(r.stderr, '');
      });
    }
  }
}

for (const index of [0, 1, 2, 3]) {
  test(`byte order mark at the start of line ${index} is reported and the chain checks continue`, async (t) => {
    const f = setup(t);
    const parts = f.lines.map((l) => Buffer.from(l + '\n'));
    parts[index] = Buffer.concat([BOM, parts[index]]);
    writeFileSync(f.log, Buffer.concat(parts));
    const report = await verifyLog(f.log);
    assert.equal(report.ok, false);
    assert.ok(report.findings.some((x) => x.seq === index && ['bad_record', 'bad_header'].includes(x.kind)));
    assert.equal(report.records, 4);
    const r = cli(['verify', f.log]);
    assert.equal(r.status, 1);
  });
}

test('duplicate keys with different values: the last one wins in parsing but the line is not canonical', async (t) => {
  const f = setup(t);
  const lines = f.lines.slice();
  lines[1] = lines[1].replace('"type":"event1"', '"type":"other","type":"event1"');
  writeFileSync(f.log, join2(lines));
  const report = await verifyLog(f.log);
  assert.equal(report.ok, false);
  assert.deepEqual(report.findings.map((x) => [x.kind, x.seq, x.detail]), [['bad_record', 1, 'line_not_canonical']]);
});

test('CRLF line ends are reported', async (t) => {
  const f = setup(t);
  writeFileSync(f.log, f.lines.join('\r\n') + '\r\n');
  const report = await verifyLog(f.log);
  assert.equal(report.ok, false);
  assert.ok(report.findings.length >= 4);
});

test('a line of exactly 65,536 bytes is read, one byte more is a long line', async (t) => {
  const f = setup(t);
  const lines = f.lines.slice();
  lines[2] = lines[2] + ' '.repeat(65536 - Buffer.byteLength(lines[2]) + 1);
  writeFileSync(f.log, join2(lines));
  const report = await verifyLog(f.log);
  assert.equal(report.findings.find((x) => x.seq === 2).detail, 'record_invalid');
});

test('readRecords exposes the raw line and a canonical flag', async (t) => {
  const f = setup(t);
  const lines = f.lines.slice();
  lines[2] = lines[2].replace('"seq":2,', '"seq": 2,');
  writeFileSync(f.log, join2(lines));
  const items = [];
  for await (const item of readRecords(f.log)) items.push(item);
  assert.deepEqual(items.map((x) => x.canonical), [true, true, false, true]);
  assert.equal(items[2].line, lines[2]);
  assert.equal(items[1].line, lines[1]);
  assert.equal(canonicalize(items[1].record), items[1].line);
});

test('append refuses a tail or header line that is not canonical and changes nothing', async (t) => {
  for (const index of [0, 3]) {
    const f = setup(t);
    const lines = f.lines.slice();
    lines[index] = lines[index].replace('"seq":' + index + ',', '"seq": ' + index + ',');
    const text = join2(lines);
    writeFileSync(f.log, text);
    await assert.rejects(appendRecord(f.log, { type: 'x' }, { now: '2027-01-01T00:00:00Z' }), { kind: 'log_corrupt' });
    assert.equal(readFileSync(f.log, 'utf8'), text);
    expectFail(cli(['append', f.log, '--type', 'x']), 2, 'log_corrupt');
  }
});

test('every stored line equals canonicalize of its parsed record', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log');
  for (let i = 0; i < 10; i++) {
    expectOk(cli(['append', log, '--type', 'event' + i, '--actor', 'a' + i, '--time', '2026-01-01T00:00:0' + i + 'Z']));
  }
  const lines = readFileSync(log, 'utf8').split(String.fromCharCode(10)).slice(0, -1);
  assert.equal(lines.length, 11);
  for (const line of lines) assert.equal(canonicalize(JSON.parse(line)), line);
});
