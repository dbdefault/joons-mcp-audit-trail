import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from '../src/cli/args.js';
import { validateStoredEvent } from '../src/canon/index.js';
import { cli, errLine, root } from '../reference/helpers.js';

// The reader table of stable hidden classes, written out here independently of the shipped source.
const RANGES = [
  [0x0, 0x1f], [0x7f, 0xa0], [0xad], [0x34f], [0x600, 0x605], [0x61c], [0x6dd], [0x70f], [0x890, 0x891], [0x8e2],
  [0x115f, 0x1160], [0x1680], [0x17b4, 0x17b5], [0x180b, 0x180f], [0x2000, 0x200f], [0x2028, 0x202f],
  [0x205f, 0x206f], [0x2800], [0x3000], [0x3164], [0xd800, 0xf8ff], [0xfdd0, 0xfdef], [0xfe00, 0xfe0f], [0xfeff],
  [0xffa0], [0xfff0, 0xfffc], [0xfffe, 0xffff], [0x110bd], [0x110cd], [0x13430, 0x1343f], [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a], [0xe0000, 0xe0fff], [0xf0000, 0x10ffff],
];
for (let plane = 1; plane <= 14; plane++) RANGES.push([plane * 0x10000 + 0xfffe, plane * 0x10000 + 0xffff]);
const inTable = (cp) => RANGES.some(([a, b = a]) => cp >= a && cp <= b);
const reads = (cp, field) => {
  try {
    validateStoredEvent({ type: 't', [field]: 'x' + String.fromCodePoint(cp) + 'y' });
    return true;
  } catch {
    return false;
  }
};

test('reader table: both ends of every range are refused, the neighbours outside are accepted', () => {
  for (const field of ['actor', 'tool']) {
    for (const [a, b = a] of RANGES) {
      for (const cp of [a, b]) assert.equal(reads(cp, field), false, `${field} U+${cp.toString(16)} refused`);
      for (const cp of [a - 1, b + 1]) {
        if (cp < 0 || cp > 0x10ffff || inTable(cp)) continue;
        assert.equal(reads(cp, field), true, `${field} U+${cp.toString(16)} accepted`);
      }
    }
  }
  // the last private-use code point of the basic plane is part of the table
  assert.equal(reads(0xf8ff, 'actor'), false);
  assert.equal(reads(0xf900, 'actor'), true);
  assert.equal(reads(0xd7ff, 'actor'), true);
});

test('reader table: every table member is refused and a sample outside is accepted', () => {
  for (const [a, b = a] of RANGES) {
    const step = Math.max(1, Math.floor((b - a) / 50));
    for (let cp = a; cp <= b; cp += step) assert.equal(reads(cp, 'actor'), false, 'U+' + cp.toString(16));
  }
  for (const cp of [0x20, 0x41, 0xa1, 0xe9, 0x4e2d, 0xac00, 0x1f1e6, 0x1f600]) assert.equal(reads(cp, 'actor'), true);
});

test('explicit show range: exactly 10,000 records is accepted, 10,001 is a usage error', () => {
  assert.equal(parseArgs(['show', 'x', '--from', '1', '--to', '10000']).options.to, '10000');
  assert.equal(parseArgs(['show', 'x', '--from', '5', '--to', '10004']).options.to, '10004');
  for (const argv of [['show', 'x', '--from', '1', '--to', '10001'], ['show', 'x', '--from', '5', '--to', '10005']]) {
    assert.throws(() => parseArgs(argv));
  }
  // a lone --to is not a usage error
  assert.equal(parseArgs(['show', 'x', '--to', '20000']).options.to, '20000');
  // through the real program: the accepted range reaches the (missing) log, the refused one stops at the arguments
  const ok = cli(['show', join(root, 'no-such-log-file.log'), '--from', '1', '--to', '10000']);
  assert.equal(ok.status, 2);
  assert.equal(ok.stderr, errLine('input_unreadable'));
  const bad = cli(['show', join(root, 'no-such-log-file.log'), '--from', '1', '--to', '10001']);
  assert.equal(bad.status, 3);
  assert.equal(bad.stderr, errLine('usage_error'));
});

test('the launcher is executable in git (mode 100755) when the checkout has a git directory', (t) => {
  if (!existsSync(join(root, '.git'))) return t.skip('no .git directory');
  let line;
  try {
    line = execFileSync('git', ['ls-files', '-s', '--', 'bin/joons-mcp-audit-trail.js'], {
      cwd: root,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
  } catch {
    return t.skip('git is not available');
  }
  assert.match(line, /^100755 [0-9a-f]{40,64} 0\tbin\/joons-mcp-audit-trail\.js$/);
});
