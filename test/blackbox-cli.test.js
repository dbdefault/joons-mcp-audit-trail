import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { anchor, canonicalize, event, header, verify } from '../reference/model.js';
const rootFile = new URL('./root.txt', import.meta.url);
if (!existsSync(rootFile)) throw new Error('test/root.txt is missing');
const root = resolve(fileURLToPath(new URL('.', import.meta.url)), readFileSync(rootFile, 'utf8').trim());
const cli = join(root, 'bin', 'joons-mcp-audit-trail.js');
const skip = false;
const T = '2026-01-02T03:04:05.000Z';
const err = (k) => `joons-mcp-audit-trail: ${k}\n`;
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-bb-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { dir, log: join(dir, 'log'), key: join(dir, 'key'), out: join(dir, 'out') };
}
function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    timeout: 30000,
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  });
}
function ok(r) {
  assert.equal(r.status, 0, `${r.stderr}\n${r.stdout}`);
  assert.equal(r.stderr, '');
}
function fail(r, code, kind) {
  assert.equal(r.status, code, `${r.stderr}\n${r.stdout}`);
  assert.equal(r.stdout, '');
  assert.equal(r.stderr, err(kind));
}
function append(log, type = 'sample', ...opts) {
  return run('append', log, '--type', type, '--time', T, ...opts);
}
function setup(t, keyed = false) {
  const f = fixture(t);
  let opts = [];
  if (keyed) {
    writeFileSync(f.key, '0123456789abcdef');
    opts = ['--key-file', f.key];
  }
  for (let i = 0; i < 3; i++) ok(append(f.log, 'event' + i, ...opts));
  return { ...f, opts };
}
function lines(p) {
  return readFileSync(p, 'utf8').trimEnd().split('\n').map(JSON.parse);
}
function put(p, rs) {
  writeFileSync(p, rs.map((r) => canonicalize(r)).join('\n') + '\n');
}
for (const keyed of [false, true]) {
  test(`differential and determinism ${keyed ? 'keyed' : 'plain'}`, { skip }, (t) => {
    const f = setup(t, keyed), key = keyed ? Buffer.from('0123456789abcdef') : null;
    const actual = lines(f.log);
    assert.equal(verify(readFileSync(f.log, 'utf8'), key).ok, true);
    let rs = [header(T, key)];
    for (let i = 0; i < 3; i++) rs.push(event(i + 1, T, 'event' + i, rs.at(-1).hash, null, null, null, null, key));
    assert.deepEqual(actual.map((x) => x.hash), rs.map((x) => x.hash));
    put(f.out, rs);
    ok(run('verify', f.out, ...f.opts));
    const second = join(f.dir, 'second');
    for (let i = 0; i < 3; i++) ok(append(second, 'event' + i, ...f.opts));
    assert.equal(readFileSync(f.log, 'utf8'), readFileSync(second, 'utf8'));
  });
}
test('tamper matrix against real logs', { skip }, (t) => {
  const f = setup(t);
  const original = lines(f.log);
  const cases = {
    edit: (r) => r[1].type = 'edited',
    middle: (r) => r.splice(2, 1),
    head: (r) => r.shift(),
    insert: (r) => r.splice(2, 0, structuredClone(r[1])),
    reorder: (r) => [r[1], r[2]] = [r[2], r[1]],
    duplicate: (r) => r.push(structuredClone(r[2])),
    seq: (r) => r[2].seq = 99,
    prev: (r) => r[2].prev = 'f'.repeat(64),
    hash: (r) => r[2].hash = 'f'.repeat(64),
    time: (r) => r[2].time = '2020-01-01T00:00:00.000Z',
    actor: (r) => r[1].actor = 'other',
    tool: (r) => r[1].tool = 'other',
    outcome: (r) => r[1].outcome = 'ok',
    data: (r) => r[1].data = { x: 1 },
    header: (r) => r[0].version = 2,
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const rs = structuredClone(original);
    mutate(rs);
    put(f.log, rs);
    const x = run('verify', f.log);
    assert.equal(x.status, 1, `${name}: ${x.stderr}`);
    assert.equal(x.stderr, '');
  }
  put(f.log, original);
  ok(run('anchor', f.log, '--out', f.out));
  put(f.log, original.slice(0, -1));
  ok(run('verify', f.log));
  assert.equal(run('verify', f.log, '--anchor', f.out).status, 1);
  const rs = structuredClone(original);
  rs[3] = event(3, T, 'rewritten', rs[2].hash);
  put(f.log, rs);
  ok(run('verify', f.log));
  assert.equal(run('verify', f.log, '--anchor', f.out).status, 1);
});
test('key handling, partial line, and path safety', { skip }, (t) => {
  const f = setup(t, true);
  fail(run('verify', f.log), 2, 'key_required');
  writeFileSync(f.out, 'fedcba9876543210');
  const wrong = run('verify', f.log, '--key-file', f.out);
  assert.ok([1, 2].includes(wrong.status));
  writeFileSync(f.out, 'short');
  fail(run('verify', f.log, '--key-file', f.out), 2, 'key_invalid');
  writeFileSync(f.out, 'x'.repeat(5000));
  fail(run('verify', f.log, '--key-file', f.out), 2, 'key_invalid');
  fail(run('verify', f.log, '--key-file', f.dir), 2, 'key_invalid');
  writeFileSync(f.log, readFileSync(f.log, 'utf8') + '{"seq":');
  fail(append(f.log, 'x', ...f.opts), 2, 'log_corrupt');
  fail(append(f.dir), 4, 'output_error');
  const hard = join(f.dir, 'hard');
  linkSync(f.log, hard);
  fail(append(hard, 'x', ...f.opts), 4, 'output_error');
  try {
    const sym = join(f.dir, 'sym');
    symlinkSync(f.log, sym);
    fail(append(sym, 'x', ...f.opts), 4, 'output_error');
  } catch (e) {
    if (!['EPERM', 'EACCES', 'ENOSYS'].includes(e.code)) throw e;
  }
});
test('credential and data validation attacks', { skip }, (t) => {
  const f = fixture(t);
  const samples = [
    '-----BEGIN ' + '' + 'PRIVATE KEY-----',
    'Be' + 'arer abcdefghijklmnopqrstuvwxyz',
    'ey' + 'JhbGciOiJIUzI1NiJ9' + '.ey' + 'JzdWIiOiIxMjM0NTY3ODkwIn0' + '.signature' + '123456',
    'AK' + 'IA1234567890ABCDEF',
    'AS' + 'IA1234567890ABCDEF',
    'AG' + 'PA1234567890ABCDEF',
    'AI' + 'DA1234567890ABCDEF',
    'AR' + 'OA1234567890ABCDEF',
    'AI' + 'PA1234567890ABCDEF',
    'AN' + 'PA1234567890ABCDEF',
    'AN' + 'VA1234567890ABCDEF',
    'gh' + 'p_12345678901234567890',
    'gh' + 'o_12345678901234567890',
    'gh' + 'u_12345678901234567890',
    'gh' + 's_12345678901234567890',
    'gh' + 'r_12345678901234567890',
    'gl' + 'pat-12345678901234567890',
    'xo' + 'xb-12345678901234567890',
    'sk' + '_live_12345678901234567890',
    'pk' + '_live_12345678901234567890',
    'rk' + '_live_12345678901234567890',
    'AI' + 'za12345678901234567890123456789012345',
    'SG' + '.1234567890123456.1234567890123456',
    'np' + 'm_' + '1234567890123456789012345678901234',
  ];
  for (const s of samples) fail(append(f.log, 'event', '--actor', s), 2, 'credential_detected');
  ok(append(f.log, 'event', '--actor', 'ordinary user'));
  for (
    const data of [
      '{"__proto__":1}',
      '{"constructor":1}',
      '{"prototype":1}',
      '{"n":1.5}',
      JSON.stringify({ a: { b: { c: { d: { e: { f: { g: 1 } } } } } } }),
    ]
  ) {
    writeFileSync(f.out, data);
    fail(append(f.log, 'event', '--data', f.out), 2, 'invalid_record');
  }
  writeFileSync(f.out, JSON.stringify({ x: 'a'.repeat(33000) }));
  fail(append(f.log, 'event', '--data', f.out), 2, 'limit_exceeded');
});
test('lock, output overwrite, fixed error lines and no key disclosure', { skip, timeout: 20000 }, (t) => {
  const f = setup(t, true);
  const secret = readFileSync(f.key, 'utf8');
  writeFileSync(f.log + '.lock', '');
  const start = Date.now();
  const locked = append(f.log, 'test', ...f.opts);
  fail(locked, 4, 'lock_timeout');
  assert.ok(Date.now() - start < 15000);
  writeFileSync(f.out, 'exists');
  fail(run('export', f.log, '--out', f.out, '--format', 'json'), 4, 'output_error');
  fail(run('nonsense'), 3, 'usage_error');
  fail(run('verify', join(f.dir, 'missing')), 2, 'input_unreadable');
  for (const x of [locked, run('show', f.log), run('summary', f.log), run('verify', f.log, ...f.opts)]) {
    assert.ok(!(x.stdout + x.stderr).includes(secret));
  }
  assert.ok(!readFileSync(f.log, 'utf8').includes(secret));
});
test('four concurrent writers', { skip, timeout: 120000 }, async (t) => {
  const f = fixture(t);
  ok(append(f.log));
  const children = Array.from(
    { length: 4 },
    () =>
      spawn(process.execPath, [cli, 'append', f.log, '--type', 'parallel', '--time', T], {
        windowsHide: true,
        stdio: 'pipe',
      }),
  );
  await Promise.all(children.map((c) =>
    new Promise((res, rej) => {
      let e = '';
      c.stderr.on('data', (x) => e += x);
      c.on('error', rej);
      c.on('close', (code) => code === 0 ? res() : rej(Error(e)));
    })
  ));
  for (let batch = 1; batch < 10; batch++) {
    const cs = Array.from(
      { length: 4 },
      () =>
        spawn(process.execPath, [cli, 'append', f.log, '--type', 'parallel', '--time', T], {
          windowsHide: true,
          stdio: 'pipe',
        }),
    );
    await Promise.all(cs.map((c) =>
      new Promise((res, rej) => {
        let e = '';
        c.stderr.on('data', (x) => e += x);
        c.on('error', rej);
        c.on('close', (code) => code === 0 ? res() : rej(Error(e)));
      })
    ));
  }
  ok(run('verify', f.log));
  assert.equal(lines(f.log).length, 42);
});
test('seeded byte mutation never crashes', { skip, timeout: 120000 }, (t) => {
  const f = setup(t);
  const bytes = readFileSync(f.log);
  let seed = 0x12345678;
  for (let i = 0; i < 40; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const b = Buffer.from(bytes), at = seed % b.length;
    b[at] ^= 1;
    writeFileSync(f.out, b);
    const r = run('verify', f.out);
    assert.ok([0, 1, 2].includes(r.status));
    assert.notEqual(r.status, 0, `mutation ${at}`);
    assert.doesNotMatch(r.stderr, /fatal|stack|v8/i);
    if (r.status === 2) {
      assert.match(
        r.stderr,
        /^joons-mcp-audit-trail: (?:input_unreadable|invalid_record|log_corrupt|limit_exceeded)\n$/,
      );
    }
  }
});

const usageCases = [
  ['append'],
  ['verify'],
  ['show'],
  ['summary'],
  ['anchor'],
  ['export'],
  ['--help', 'x'],
  ['--version', 'x'],
  ['--help', '--version'],
  ['verify', 'x', '--'],
  ['verify', 'x', 'extra'],
  ['verify', 'x', '--unknown'],
  ['verify', 'x', '--format'],
  ['verify', 'x', '--format', 'json', '--format', 'json'],
  ['show', 'x', '--from', '-1'],
  ['show', 'x', '--to', 'no'],
  ['show', 'x', '--from', '5', '--to', '2'],
  ['show', 'x', '--from', '0', '--to', '10000'],
  ['append', 'x', '--type'],
  ['append', 'x', '--type', 'a', '--type', 'b'],
  ['append', 'x', '--format', 'json'],
  ['verify', 'x', '--force'],
  ['summary', 'x', '--key-file', 'x'],
  ['export', 'x', '--out', 'x'],
  ['export', 'x', '--format', 'csv'],
  ['anchor', 'x', '--out'],
  ['show', 'x', '--format', 'csv'],
  ['verify', 'x', '--format', 'csv'],
  ['summary', 'x', '--format', 'csv'],
  ['append', 'x', '--type', 'x', 'extra'],
];
for (const [i, args] of usageCases.entries()) {
  test(`usage matrix ${i}`, { skip }, () => fail(run(...args), 3, 'usage_error'));
}
for (
  const [i, s] of [
    'AK' + 'IA1234567890ABCDEF',
    'AS' + 'IA1234567890ABCDEF',
    'AG' + 'PA1234567890ABCDEF',
    'AI' + 'DA1234567890ABCDEF',
    'AR' + 'OA1234567890ABCDEF',
    'AI' + 'PA1234567890ABCDEF',
    'AN' + 'PA1234567890ABCDEF',
    'AN' + 'VA1234567890ABCDEF',
    'gh' + 'p_12345678901234567890',
    'gh' + 'o_12345678901234567890',
    'gh' + 'u_12345678901234567890',
    'gh' + 's_12345678901234567890',
    'gh' + 'r_12345678901234567890',
    'gl' + 'pat-abc123',
    'xo' + 'xa-abc',
    'xo' + 'xb-abc',
    'xo' + 'xp-abc',
    'xo' + 'xr-abc',
    'xo' + 'xs-abc',
    'sk' + '_live_abcdefghij',
    'pk' + '_live_abcdefghij',
    'rk' + '_live_abcdefghij',
    'AI' + 'za12345678901234567890123456789012345',
    'SG' + '.abcdefghijklmnop.abcdefghijklmnop',
    'np' + 'm_abcdefghijklmnopqrstuvwxyz0123',
    'Be' + 'arer abcdefghijklmnop',
    'ey' + 'Jaaaaaaa.bbbbbbbbbb.cccccccccc',
    '-----BEGIN ' + 'PRIVATE KEY-----',
  ].entries()
) {
  test(`credential family ${i}`, { skip }, (t) => {
    const f = fixture(t);
    fail(append(f.log, 'test', '--actor', s), 2, 'credential_detected');
  });
}
for (
  const [i, s] of [
    'AK' + 'IA1234567890ABCDE',
    'gh' + 'p_1234567890123456789',
    'AI' + 'za1234567890123456789012345678901234',
    'ordinary user',
    'token without secret',
    'AK' + 'IB1234567890ABCDEF',
    'gh' + 'x_12345678901234567890',
    'xo' + 'xz-abc',
    'sk' + '_test_abc',
    'npm without underscore',
    'Bearer of good news',
    'bearer token required',
    'ESG.report',
    'MSG.id',
    'ASG.web',
    'npm_config_cache',
    'npm_install',
    'pnpm_store',
    'sk_live_mode',
    'pk_live_demo',
    'organization.application.controller',
    'kubernetes-dashboard.kubernetes-system.configuration',
    'order-' + 'AK' + 'IA1234567890ABCDEF-not-key',
  ].entries()
) {
  test(`credential negative ${i}`, { skip }, (t) => {
    const f = fixture(t);
    ok(append(f.log, 'test', '--actor', s));
  });
}
for (
  const [i, content] of ['', '\ufeff{}\n', '{}\r\n', '\0\n', '\n', 'x'.repeat(70 * 1024) + '\n', '{}', '{}\n\n']
    .entries()
) {
  test(`malformed log ${i}`, { skip }, (t) => {
    const f = fixture(t);
    writeFileSync(f.log, content);
    const r = run('verify', f.log);
    assert.equal(r.status, 1, `${r.stderr}`);
    assert.equal(r.stderr, '');
  });
}
for (
  const [i, time] of ['no', '2026-02-30T00:00:00Z', '2026-01-01', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00.1Z']
    .entries()
) {
  test(`invalid time ${i}`, { skip }, (t) => {
    const f = fixture(t);
    fail(run('append', f.log, '--type', 'a', '--time', time), 2, 'invalid_record');
  });
}
test('help lists commands and version exact', { skip }, () => {
  const h = run('--help');
  ok(h);
  assert.match(h.stdout, /^Usage:/);
  for (const s of ['append', 'verify', 'anchor', 'show', 'summary', 'export']) assert.ok(h.stdout.includes(s));
  const v = run('--version');
  ok(v);
  assert.equal(v.stdout, 'joons-mcp-audit-trail 0.1.0\n');
});
test('wrong key is report and wrong append key is error', { skip }, (t) => {
  const f = setup(t, true);
  writeFileSync(f.out, 'fedcba9876543210');
  const r = run('verify', f.log, '--key-file', f.out);
  assert.equal(r.status, 1);
  assert.equal(r.stderr, '');
  fail(append(f.log, 'x', '--key-file', f.out), 2, 'key_invalid');
  fail(append(f.log, 'x'), 2, 'key_required');
});
test('output force and CSV formula protection', { skip }, (t) => {
  const f = fixture(t);
  ok(append(f.log, 'x', '--actor', '=1+1'));
  writeFileSync(f.out, 'existing');
  fail(run('export', f.log, '--out', f.out, '--format', 'csv'), 4, 'output_error');
  ok(run('export', f.log, '--out', f.out, '--format', 'csv', '--force'));
  assert.match(readFileSync(f.out, 'utf8'), /'=1\+1/);
});
test('terminal output neutralizes embedded escapes', { skip }, (t) => {
  const f = fixture(t);
  writeFileSync(f.out, JSON.stringify({ message: 'test\u001b[31m\u200b' }));
  ok(append(f.log, 'event', '--data', f.out));
  for (const command of ['show', 'summary', 'verify']) {
    const r = run(command, f.log);
    ok(r);
    assert.doesNotMatch(r.stdout, /\u001b|\u200b/);
  }
});
