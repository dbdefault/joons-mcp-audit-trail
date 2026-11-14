import test from 'node:test';
import assert from 'node:assert/strict';
import fs, { writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { main } from '../src/cli/index.js';
import { KEY, tempDir } from '../reference/helpers.js';

// Proves that a refused path argument is judged as text before any file system call sees it: every path-taking
// function of node:fs and node:fs/promises is wrapped and the paths it is given are recorded.
const NAMES = [
  'stat', 'lstat', 'realpath', 'open', 'readFile', 'access', 'writeFile', 'appendFile', 'rename', 'link', 'unlink',
  'copyFile', 'readdir', 'mkdir', 'rm', 'rmdir', 'truncate', 'utimes', 'chmod', 'symlink', 'readlink', 'opendir',
];
const SYNC_ONLY = ['existsSync', 'createReadStream', 'createWriteStream'];
const MARK = 'zq9bad';

function spy() {
  const seen = [];
  const restore = [];
  const note = (v) => {
    if (typeof v === 'string') seen.push(v);
    else if (v instanceof URL) seen.push(v.href);
    else if (Buffer.isBuffer(v)) seen.push(v.toString('latin1'));
  };
  const wrap = (target, name) => {
    const orig = target[name];
    if (typeof orig !== 'function') return;
    target[name] = function (...args) {
      note(args[0]);
      if (['rename', 'link', 'copyFile', 'symlink'].includes(name)) note(args[1]);
      return orig.apply(this, args);
    };
    restore.push(() => {
      target[name] = orig;
    });
  };
  for (const n of NAMES) {
    wrap(fs.promises, n);
    wrap(fs, n);
    wrap(fs, n + 'Sync');
  }
  for (const n of SYNC_ONLY) wrap(fs, n);
  syncBuiltinESMExports();
  return {
    seen,
    stop() {
      for (const r of restore.reverse()) r();
      syncBuiltinESMExports();
    },
  };
}

async function runSpied(argv) {
  let out = '';
  let err = '';
  const io = { stdout: { write: (s) => void (out += s) }, stderr: { write: (s) => void (err += s) } };
  const s = spy();
  let code;
  try {
    code = await main(argv, io);
  } finally {
    s.stop();
  }
  return { code, out, err, seen: s.seen };
}

const kindOf = (r) => /^joons-mcp-audit-trail: (\w+)\n$/.exec(r.err)?.[1];
const touched = (r) => r.seen.filter((p) => p.toLowerCase().includes(MARK) || p.toLowerCase().includes('attacker'));

// Bad spellings; every one carries the marker so that a call on it (or on its resolved form) is recognisable.
const BAD = (dir) => {
  const list = [
    `\\\\attacker.invalid\\share\\${MARK}.log`,
    `//attacker.invalid/share/${MARK}.log`,
    `\\\\.\\pipe\\${MARK}`,
    `//./pipe/${MARK}`,
    `\\\\?\\C:\\${MARK}\\x.log`,
    `\\\\?\\UNC\\attacker.invalid\\share\\${MARK}.log`,
    `\\/attacker.invalid/share/${MARK}.log`,
    join(dir, `${MARK}.log:stream`),
    join(dir, `${MARK}.log::$DATA`),
    join(dir, `CON.${MARK}`),
    join(dir, `nul.${MARK}.txt`),
    join(dir, `COM1.${MARK}`),
    join(dir, `LPT\u00b9.${MARK}`),
    join(dir, `${MARK}.log.`),
    join(dir, `${MARK}.log `),
    join(dir, `${MARK}.`) + '/..',
  ];
  return list;
};
// 8.3 short names are refused for logs on Windows only.
const SHORT = (dir) => (process.platform === 'win32' ? [join(dir, `${MARK.toUpperCase()}~1.LOG`)] : []);

function fixtures(t) {
  const dir = tempDir(t);
  const log = join(dir, 'a.log');
  const keyFile = join(dir, 'k.key');
  const data = join(dir, 'd.json');
  const anchor = join(dir, 'a.anchor');
  writeFileSync(keyFile, KEY);
  writeFileSync(data, '{"n":1}');
  return { dir, log, keyFile, data, anchor };
}

test('the spy sees real calls (so an empty result is meaningful)', async (t) => {
  const f = fixtures(t);
  assert.equal((await runSpied(['append', f.log, '--type', 'e'])).code, 0);
  const r = await runSpied(['verify', f.log]);
  assert.equal(r.code, 0);
  assert.ok(r.seen.some((p) => p.includes('a.log')), JSON.stringify(r.seen));
});

test('refused log paths are never given to the file system, on every command', async (t) => {
  const f = fixtures(t);
  assert.equal((await runSpied(['append', f.log, '--type', 'e'])).code, 0);
  assert.equal((await runSpied(['anchor', f.log, '--out', f.anchor])).code, 0);
  const out = join(f.dir, 'o.out');
  for (const bad of [...BAD(f.dir), ...SHORT(f.dir)]) {
    const commands = [
      [['append', bad, '--type', 'e', '--data', f.data, '--key-file', f.keyFile], 'output_error', 4],
      [['append', bad, '--type', 'e'], 'output_error', 4],
      [['verify', bad], 'input_unreadable', 2],
      [['verify', bad, '--anchor', f.anchor], 'input_unreadable', 2],
      [['show', bad], 'input_unreadable', 2],
      [['show', bad, '--from', '1', '--to', '2'], 'input_unreadable', 2],
      [['summary', bad], 'input_unreadable', 2],
      [['export', bad, '--out', out, '--format', 'json'], 'input_unreadable', 2],
      [['export', bad, '--out', out, '--format', 'csv', '--force'], 'input_unreadable', 2],
      [['anchor', bad, '--out', join(f.dir, 'n.anchor')], 'input_unreadable', 2],
      [['anchor', bad, '--out', join(f.dir, 'n.anchor'), '--force'], 'input_unreadable', 2],
    ];
    for (const [argv, kind, code] of commands) {
      const r = await runSpied(argv);
      const label = `${argv[0]} ${JSON.stringify(bad)}`;
      assert.equal(r.code, code, label + ' ' + r.err);
      assert.equal(kindOf(r), kind, label);
      assert.equal(r.out, '', label);
      assert.deepEqual(touched(r), [], label);
    }
  }
  // nothing was created by any refused run
  assert.equal(fs.existsSync(out), false);
  assert.equal(fs.existsSync(join(f.dir, 'n.anchor')), false);
});

test('refused --out, --key-file, --anchor and --data paths are never given to the file system', async (t) => {
  const f = fixtures(t);
  assert.equal((await runSpied(['append', f.log, '--type', 'e'])).code, 0);
  assert.equal((await runSpied(['anchor', f.log, '--out', f.anchor])).code, 0);
  for (const bad of BAD(f.dir)) {
    const cases = [
      [['anchor', f.log, '--out', bad], 'output_error', 4],
      [['anchor', f.log, '--out', bad, '--force'], 'output_error', 4],
      [['export', f.log, '--out', bad, '--format', 'json'], 'output_error', 4],
      [['export', f.log, '--out', bad, '--format', 'csv', '--force'], 'output_error', 4],
      [['append', f.log, '--type', 'e', '--key-file', bad], 'key_invalid', 2],
      [['verify', f.log, '--key-file', bad], 'key_invalid', 2],
      [['anchor', f.log, '--out', join(f.dir, 'q.anchor'), '--key-file', bad], 'key_invalid', 2],
      [['verify', f.log, '--anchor', bad], 'input_unreadable', 2],
      [['append', f.log, '--type', 'e', '--data', bad], 'input_unreadable', 2],
    ];
    for (const [argv, kind, code] of cases) {
      const r = await runSpied(argv);
      const label = `${argv.join(' ')}`.replace(f.dir, '<d>');
      assert.equal(r.code, code, label + ' ' + r.err);
      assert.equal(kindOf(r), kind, label);
      assert.deepEqual(touched(r), [], label);
    }
  }
  assert.equal(fs.existsSync(join(f.dir, 'q.anchor')), false);
});

test('a refused path in the protect list of the writers is never given to the file system', async (t) => {
  const { createAtomicWriter } = await import('../src/log/atomic.js');
  const f = fixtures(t);
  for (const bad of BAD(f.dir)) {
    const s = spy();
    let kind;
    try {
      await createAtomicWriter(join(f.dir, 'w.out'), { protect: [bad] });
    } catch (e) {
      kind = e.kind;
    } finally {
      s.stop();
    }
    assert.equal(kind, 'input_unreadable', bad);
    assert.deepEqual(s.seen.filter((p) => p.toLowerCase().includes(MARK) || p.toLowerCase().includes('attacker')), []);
    assert.equal(fs.existsSync(join(f.dir, 'w.out')), false);
  }
});
