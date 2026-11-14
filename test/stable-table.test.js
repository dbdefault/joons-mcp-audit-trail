import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { cli, expectOk, KEY, root, tempDir } from '../reference/helpers.js';
import { canonicalize, hashRecord, header, validateEvent as refValidate } from '../reference/model.js';
import { validateEvent, validateStoredEvent } from '../src/canon/index.js';
import { renderShow, renderSummary, sanitizeText, summarize } from '../src/report/index.js';

const T = '2026-01-01T00:00:00.000Z';
const accepts = (fn, e) => {
  try {
    fn(e);
    return true;
  } catch {
    return false;
  }
};
// Code points that the writer refuses by an explicit rule (not by a general category).
const EXPLICIT = new RegExp(
  '[\\u{34f}\\u{115f}\\u{1160}\\u{17b4}\\u{17b5}\\u{180b}-\\u{180f}\\u{2800}\\u{3164}' +
    '\\u{fe00}-\\u{fe0f}\\u{ffa0}\\u{fffc}\\u{e0100}-\\u{e01ef}]',
  'u',
);
const CLASSES = /[\p{Cc}\p{Cf}\p{Zs}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}\p{Default_Ignorable_Code_Point}]/u;

test('all code points: writer accepts implies reader accepts; table entries are rejected classes', () => {
  const failures = [];
  const hidden = new Set();
  // Chunks of 100 code points are checked as one name first; a chunk the reader accepts holds no table entry, so the
  // implication needs no per-code-point call there. Only chunks with a table entry are examined one by one.
  const named = (chars) => ({ type: 't', actor: 'x' + chars + 'y' });
  for (let start = 0; start <= 0x10ffff; start += 100) {
    const end = Math.min(start + 100, 0x110000);
    let chars = '';
    for (let cp = start; cp < end; cp++) chars += String.fromCodePoint(cp);
    if (accepts(validateStoredEvent, named(chars))) continue;
    for (let cp = start; cp < end; cp++) {
      const ch = String.fromCodePoint(cp);
      if (accepts(validateStoredEvent, named(ch))) continue;
      hidden.add(cp);
      // every table entry is one of the stable classes (or explicitly listed) and is refused by the writer too
      if (accepts(validateEvent, named(ch)) || !(CLASSES.test(ch) || EXPLICIT.test(ch))) {
        failures.push('table ' + cp.toString(16));
      }
    }
  }
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (!(cp % 97 === 0 || (cp >= 0x2000 && cp < 0x2100) || cp < 0x300)) continue;
    const ch = String.fromCodePoint(cp);
    // data keys and values are not names: the writer and the reader treat them the same way
    if (cp % 97 === 0 || (cp >= 0x2000 && cp < 0x2100) || cp < 0x300) {
      const d = { type: 't', data: { ['k' + ch]: 'v' + ch } };
      assert.equal(accepts(validateEvent, d), accepts(validateStoredEvent, d), 'data U+' + cp.toString(16));
    }
    // the independent reference model agrees with the shipped reader and writer
    if (cp % 101 === 0 || (cp >= 0x2000 && cp < 0x2100) || cp < 0x300) {
      const e = { type: 't', actor: 'x' + ch + 'y' };
      assert.equal(accepts((x) => refValidate(x, true), e), accepts(validateStoredEvent, e), 'ref reader ' + cp);
      assert.equal(accepts(refValidate, e), accepts(validateEvent, e), 'ref writer ' + cp);
    }
  }
  assert.deepEqual(failures, []);
  // visible punctuation in the old wide range is accepted by both sides
  for (const c of [0x2010, 0x2013, 0x2014, 0x2018, 0x2019, 0x201c, 0x2022, 0x2026, 0x2030, 0x2032, 0x205e]) {
    assert.equal(hidden.has(c), false, 'U+' + c.toString(16));
  }
  for (const c of [0x2000, 0x200b, 0x200f, 0x2028, 0x202a, 0x202f, 0x205f, 0x2060, 0x2066, 0x206f]) {
    assert.equal(hidden.has(c), true, 'U+' + c.toString(16));
  }
});

const NAMES = [
  ['actor', 'it\u{2019}s-me'],
  ['actor', 'a\u{2014}b'],
  ['tool', 'x\u{2026}'],
  ['actor', 'Prices \u{2013} 5\u{2030}'],
];

for (const keyed of [false, true]) {
  test(`typographic names append, verify and take later appends with the CLI (${keyed ? 'keyed' : 'plain'})`, (t) => {
    for (const [field, name] of NAMES) {
      const dir = tempDir(t);
      const log = join(dir, 'a.log');
      const extra = [];
      if (keyed) {
        const keyFile = join(dir, 'k.key');
        writeFileSync(keyFile, KEY);
        extra.push('--key-file', keyFile);
      }
      expectOk(cli(['append', log, '--type', 'ev', '--' + field, name, ...extra]));
      const v = cli(['verify', log, ...extra]);
      expectOk(v);
      assert.ok(v.stdout.includes('OK'), v.stdout);
      expectOk(cli(['append', log, '--type', 'ev', '--actor', 'bob', ...extra]));
      expectOk(cli(['verify', log, ...extra]));
      expectOk(cli(['show', log]));
      expectOk(cli(['summary', log, '--details']));
    }
  });
}

/** Streams a forged plain log: a header, then one event per `make(i)` (not written by append). */
function forge(path, count, make) {
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

test('summary --details in markdown, terminal and json works for 3,000 actors made of backtick runs', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  forge(log, 3000, (i) => {
    let actor = String(i);
    for (let k = 0; k < 60; k++) actor += '`' + 'abcdefghijklmnopqrstuvwxyz'[(i + k) % 26];
    return { actor };
  });
  assert.equal(validateEvent({ type: 'e', actor: '1`a`b' }).actor, '1`a`b');
  for (const format of ['markdown', 'terminal', 'json']) {
    const r = cli(['summary', log, '--details', '--format', format]);
    expectOk(r);
    assert.ok(r.stdout.length > 100000, format);
  }
});

test('a markdown cell with hundreds of thousands of backtick runs does not overflow the argument limit', () => {
  const many = { records: 1, from: null, to: null, type: { distinct: 1 }, actor: {}, tool: {}, outcome: {} };
  for (let i = 0; i < 150000; i++) many.actor['a`' + i] = 1;
  const out = renderSummary(many, 'markdown');
  assert.ok(out.startsWith('| Field | Value |'));
});

test('non-ASCII space separators are replaced in terminal, markdown and CSV output', (t) => {
  const spaces = [0xa0, 0x1680, ...Array.from({ length: 11 }, (_, i) => 0x2000 + i), 0x202f, 0x205f, 0x3000];
  for (const c of spaces) assert.equal(sanitizeText('a' + String.fromCodePoint(c) + 'b'), 'a?b', 'U+' + c.toString(16));
  assert.equal(sanitizeText('a b'), 'a b');
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  forge(log, 1, () => ({ data: { v: 'p\u{a0}q\u{3000}r', ['k\u{2003}']: 1 } }));
  const shown = cli(['show', log]);
  expectOk(shown);
  assert.ok(shown.stdout.includes('p?q?r'));
  assert.ok(!/[\u{a0}\u{3000}\u{2003}]/u.test(shown.stdout));
  const md = renderShow([{ seq: 1, data: { v: 'p\u{a0}q\u{3000}r', ['k\u{2003}']: 1 } }], 'markdown');
  assert.ok(md.includes('p?q?r') && !/[\u{a0}\u{3000}\u{2003}]/u.test(md));
  const out = join(dir, 'o.csv');
  expectOk(cli(['export', log, '--out', out, '--format', 'csv']));
  const csv = readFileSync(out, 'utf8');
  assert.ok(csv.includes('\\u00a0') && csv.includes('\\u3000'), csv);
  assert.ok(!/[\u{a0}\u{3000}\u{2003}]/u.test(csv));
  // the stored value itself is kept (json export)
  const jo = join(dir, 'o.json');
  expectOk(cli(['export', log, '--out', jo, '--format', 'json']));
  assert.ok(readFileSync(jo, 'utf8').includes('p\u{a0}q\u{3000}r'));
});

test('summary counts non-string values and the literal (other) under (other)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  const actors = [[1], '1', '(other)', 1, { a: 1 }, true, '1'];
  forge(log, actors.length, (i) => ({ actor: actors[i - 1] }));
  const s = await summarize(log, { details: true });
  assert.deepEqual(s.actor, { '(other)': 5, '1': 2 });
  assert.deepEqual((await summarize(log)).actor, { distinct: 1 });
});

const CANONICAL_SHA = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';
test('LICENSE is the canonical Apache-2.0 text', () => {
  const text = readFileSync(join(root, 'LICENSE'), 'utf8').replace(/\r\n/g, '\n');
  assert.ok(text.includes('\n   Copyright [yyyy] [name of copyright owner]\n'));
  assert.ok(!text.includes('JOONS'));
  assert.equal(createHash('sha256').update(text).digest('hex'), CANONICAL_SHA);
  assert.ok(readFileSync(join(root, 'README.md'), 'utf8').includes('Copyright 2026 JOONS contributors'));
});
