import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cli, expectOk, tempDir } from '../reference/helpers.js';
import {
  exportParts,
  renderExport,
  renderShow,
  renderSummary,
  renderVerify,
  sanitizeText,
} from '../src/report/index.js';
import { validateEvent } from '../src/canon/index.js';

const BS = String.fromCharCode(92);
const cp = (...codes) => codes.map((c) => String.fromCodePoint(c)).join('');
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);

const HIDDEN = [
  ...[0xad, 0x34f, 0x6dd, 0x70f, 0x8e2, 0x2800, 0x3164, 0xffa0, 0xfffc],
  ...range(0x600, 0x605),
  ...range(0x890, 0x891),
  ...range(0x115f, 0x1160),
  ...range(0x17b4, 0x17b5),
  ...range(0x180b, 0x180f),
  ...range(0x2061, 0x2064),
  ...range(0x206a, 0x206f),
  ...range(0xfe00, 0xfe0f),
  ...range(0xfff9, 0xfffb),
  ...range(0x1d173, 0x1d17a),
  ...range(0xe0100, 0xe01ef),
  // already covered before: controls, bidi, zero width, tags, separators, byte order mark
  ...range(0, 0x1f),
  ...range(0x7f, 0x9f),
  0x61c,
  ...range(0x200b, 0x200f),
  ...range(0x2028, 0x202e),
  0x2060,
  ...range(0x2066, 0x2069),
  0xfeff,
  ...range(0xe0000, 0xe007f),
  // private use, including the two supplementary planes
  0xe000,
  0xf8ff,
  0xf0000,
  0xffffd,
  0x100000,
  0x10fffd,
];

test('terminal sanitizer replaces every invisible, reordering and private-use character with a question mark', () => {
  for (const code of HIDDEN) {
    assert.equal(sanitizeText('a' + cp(code) + 'b'), 'a?b', 'U+' + code.toString(16));
  }
  assert.equal(sanitizeText('a' + String.fromCharCode(0xd800) + 'b'), 'a?b');
  assert.equal(sanitizeText('abc 한글 é 😀 ~'), 'abc 한글 é 😀 ~');
});

const TEXT_REFUSED = [
  ...range(0x200b, 0x200f),
  ...range(0x202a, 0x202e),
  ...range(0x2066, 0x2069),
  0x2060,
  0xfeff,
  0xad,
  0x34f,
  0x61c,
  0x115f,
  0x1160,
  0x17b4,
  0x180e,
  ...range(0xfe00, 0xfe0f),
  ...range(0xe0100, 0xe01ef),
  0xe0001,
  0xe0041,
  0x2800,
  0x3164,
  0xffa0,
  0xfffc,
  0x2028,
  0x2029,
  0xe000,
  ...range(0x206a, 0x206f),
];

test('actor and tool refuse format, bidi, zero-width, variation-selector and tag characters', () => {
  for (const code of TEXT_REFUSED) {
    for (const field of ['actor', 'tool']) {
      assert.throws(
        () => validateEvent({ type: 'x', [field]: 'a' + cp(code) + 'b' }),
        { kind: 'invalid_record' },
        field + ' U+' + code.toString(16),
      );
    }
    assert.throws(() => validateEvent({ type: 'a' + cp(code) }), { kind: 'invalid_record' });
  }
  for (const ok of ['agent', '한국어 도구', 'café', 'tool-1', '😀 smile', 'a b']) {
    assert.equal(validateEvent({ type: 'x', actor: ok, tool: ok }).actor, ok);
  }
});

test('JSON output escapes DEL and the C1 controls and stays valid JSON with the same values', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const data = join(dir, 'data.json');
  const text = 'x' + cp(0x7f, 0x80, 0x85, 0x9f) + 'y';
  writeFileSync(data, JSON.stringify({ text }));
  expectOk(cli(['append', log, '--type', 'c1', '--data', data]));
  const shown = cli(['show', log, '--format', 'json']);
  expectOk(shown);
  for (const raw of [0x7f, 0x80, 0x85, 0x9f]) assert.ok(!shown.stdout.includes(cp(raw)), String(raw));
  for (const esc of ['007f', '0080', '0085', '009f']) assert.ok(shown.stdout.includes(BS + 'u' + esc), esc);
  assert.equal(JSON.parse(shown.stdout)[0].data.text, text);
  const out = join(dir, 'out.json');
  expectOk(cli(['export', log, '--out', out, '--format', 'json']));
  const exported = readFileSync(out, 'utf8');
  assert.ok(!exported.includes(cp(0x85)));
  assert.equal(JSON.parse(exported)[1].data.text, text);
  const terminal = cli(['show', log]);
  expectOk(terminal);
  assert.ok(!terminal.stdout.includes(cp(0x85)));
  assert.ok(terminal.stdout.includes('x????y'));
});

test('markdown output escapes markup characters and newlines', () => {
  const nasty = [
    '<script>',
    '[a](b)',
    '![i](j)',
    '*x*',
    '_y_',
    'a|b',
    '`c`',
    'back' + BS + 'slash',
    'two' + String.fromCharCode(10) + 'lines',
  ];
  const summary = { records: 1, from: null, to: null, type: Object.fromEntries(nasty.map((n) => [n, 1])) };
  const out = renderSummary(summary, 'markdown');
  const rows = out.split(String.fromCharCode(10)).filter(Boolean);
  const typeRow = rows.find((r) => r.startsWith('| ` type ` '));
  assert.ok(typeRow);
  assert.equal(rows.length, 2 + 4);
  // Every cell is one inline code span: exactly two cell separators remain and the pipe is written as |.
  assert.equal(typeRow.split('|').length, 4, typeRow);
  assert.ok(typeRow.includes('a' + BS + 'u007cb'));
  assert.match(typeRow, /^\| ` type ` \| `` .* `` \|$/);
  const shown = renderShow([{ seq: 1, data: { text: 'a' + String.fromCharCode(10) + '<b>' } }], 'markdown');
  assert.equal(shown.split(String.fromCharCode(10)).filter(Boolean).length, 3);
  assert.match(shown.split(String.fromCharCode(10))[2], /^\| ` .*<b>.* ` \|$/);
  const verifyOut = renderVerify({ ok: false, findings: [{ kind: '<k>', seq: 1, detail: '[d](x)' }] }, 'markdown');
  assert.match(verifyOut.split(String.fromCharCode(10))[2], /^\| ` .*\[d\]\(x\).*<k>.* ` \|$/);
});

test('CSV guard also protects a formula after leading spaces or tabs', () => {
  const rows = (type) =>
    renderExport([{
      seq: 1,
      time: 't',
      type,
      actor: null,
      tool: null,
      outcome: null,
      data: null,
      prev: 'p',
      hash: 'h',
    }], 'csv')
      .split('\r\n')[1];
  for (
    const v of [
      '=1+1',
      '+1',
      '-1',
      '@x',
      ' =1',
      '  +1',
      ' -1',
      ' @x',
    ]
  ) {
    assert.ok(rows(v).startsWith('"1","t","' + "'"), JSON.stringify(v));
  }
  for (const v of ['a=1', 'x +1', '1', 'plain text']) assert.ok(rows(v).startsWith('"1","t","' + v), v);
  // A tab is a control: it is written as escape text, so a raw tab never leads a cell.
  assert.ok(rows(String.fromCharCode(9) + '=1').startsWith('"1","t","' + String.fromCharCode(92) + 'u0009=1"'));
});

test('streamed export parts give the same bytes as the whole-list renderer, JSON and CSV', () => {
  const records = Array.from({ length: 5 }, (_, i) => ({
    seq: i,
    time: '2026-01-01T00:00:00Z',
    type: i ? 'e' + i : null,
    actor: i % 2 ? 'a' : null,
    tool: null,
    outcome: 'ok',
    data: i ? { z: [1, { b: 2, a: 'x' }], a: null } : null,
    prev: 'p' + i,
    hash: 'h' + i,
  }));
  for (const format of ['json', 'csv']) {
    const parts = exportParts(format);
    let streamed = parts.head();
    records.forEach((r, i) => (streamed += parts.item(r, i)));
    streamed += parts.tail(records.length);
    assert.equal(streamed, renderExport(records, format));
  }
  const json = renderExport(records, 'json');
  assert.deepEqual(JSON.parse(json).map((r) => r.seq), [0, 1, 2, 3, 4]);
  assert.equal(renderExport([], 'json'), '[]' + String.fromCharCode(10));
  assert.throws(() => renderExport(new Array(1000001), 'csv'), { kind: 'limit_exceeded' });
});
