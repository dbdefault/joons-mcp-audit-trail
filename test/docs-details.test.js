import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cli, expectOk, root, tempDir } from '../reference/helpers.js';

const read = (name) => readFileSync(join(root, name), 'utf8');

test('package.json has a description, repository and keywords and the long-test script', () => {
  const p = JSON.parse(read('package.json'));
  assert.ok(typeof p.description === 'string' && p.description.length > 40);
  assert.equal(p.repository.type, 'git');
  assert.equal(p.repository.url, 'git+https://github.com/dbdefault/joons-mcp-audit-trail.git');
  assert.ok(Array.isArray(p.keywords) && p.keywords.includes('audit') && p.keywords.includes('mcp'));
  assert.equal(p.scripts.test, 'node --test');
  assert.equal(p.scripts['test:long'], 'node scripts/run-long-tests.mjs');
  assert.ok(existsSync(join(root, 'scripts', 'run-long-tests.mjs')));
});

test('the long test group is gated by test/long-tests.enabled and the default run does not need it', () => {
  assert.equal(existsSync(join(root, 'test', 'long-tests.enabled')), false);
  const source = read('test/long-limits.test.js');
  assert.ok(source.includes('long-tests.enabled'));
  assert.ok(read('scripts/run-long-tests.mjs').includes('long-tests.enabled'));
  assert.ok(read('.gitignore').includes('test/long-tests.enabled'));
});

test('both READMEs reference the shipped examples, the three-digit fraction and the long tests', () => {
  for (const file of ['README.md', 'README.ko.md']) {
    const s = read(file);
    for (const needle of ['examples/event.json', 'examples/session.txt', 'npm run test:long', '16 MiB', '.audit-id-']) {
      assert.ok(s.includes(needle), `${file}: ${needle}`);
    }
    assert.ok(s.includes('CLOCK$'), file);
    assert.ok(s.includes('test/long-tests.enabled'), file);
  }
  assert.ok(read('README.md').includes('exactly three digits'));
  assert.ok(read('README.ko.md').includes('정확히 세 자리'));
  assert.ok(read('README.md').includes('CRLF'));
  assert.ok(read('README.ko.md').includes('CRLF'));
});

test('docs state the 16 MiB show cap, the clamped default clock and the key terminator rule', () => {
  for (const file of ['docs/API.md', 'LIMITATIONS.md', 'CHANGELOG.md']) {
    assert.ok(read(file).includes('16 MiB'), file);
  }
  for (const file of ['docs/API.md', 'docs/FORMAT.md', 'CHANGELOG.md', 'LIMITATIONS.md']) {
    assert.ok(/clamped/.test(read(file)), file + ': clamped default clock');
  }
  for (const file of ['docs/API.md', 'docs/FORMAT.md', 'SECURITY.md']) {
    assert.ok(read(file).includes('\\r\\n'), file + ': CRLF key terminator');
  }
  for (const file of ['SECURITY.md', 'LIMITATIONS.md', 'CHANGELOG.md']) {
    assert.ok(/zero-byte|Zero-byte|zero byte/.test(read(file)) || file === 'SECURITY.md', file);
  }
});

test('examples/session.txt is runnable and gives a log that verifies', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'audit.jsonl');
  const lines = read('examples/session.txt').split('\n').filter(Boolean);
  assert.ok(lines.length >= 2);
  assert.ok(lines[0].includes('--time '), 'the session uses a fixed time');
  for (const line of lines) {
    const args = line.replace(/^joons-mcp-audit-trail /, '').split(' ').map((a) =>
      a === 'audit.jsonl' ? log : a === 'examples/event.json' ? join(root, 'examples', 'event.json') : a
    );
    expectOk(cli(args));
  }
});
