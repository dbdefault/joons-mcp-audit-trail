import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac } from 'node:crypto';
import { createAnchor, verifyLog } from '../src/verify/index.js';
import { renderExport, renderShow, renderSummary, renderVerify, sanitizeText, summarize } from '../src/report/index.js';
const canon = (v) =>
  v === null || typeof v !== 'object'
    ? JSON.stringify(v)
    : Array.isArray(v)
    ? '[' + v.map(canon).join(',') + ']'
    : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
const digest = (r, k) => {
  const { hash, ...v } = r;
  return (k ? createHmac('sha256', k) : createHash('sha256')).update(canon(v)).digest('hex');
};
const key = Buffer.from('0123456789abcdef');
function records(k = null) {
  const kid = k
    ? createHash('sha256').update(createHash('sha256').update(k).digest()).digest('hex').slice(0, 16)
    : null;
  let h = {
    format: 'joons-mcp-audit-trail/log',
    version: 1,
    seq: 0,
    time: '2026-01-01T00:00:00Z',
    mode: k ? 'hmac-sha256' : 'sha256',
    keyId: kid,
    prev: '0'.repeat(64),
  };
  h.hash = digest(h, k);
  const a = [h];
  for (let i = 1; i <= 3; i++) {
    const r = {
      seq: i,
      time: `2026-01-01T00:00:0${i}Z`,
      type: 'call',
      actor: 'A',
      tool: 'T',
      outcome: 'ok',
      data: null,
      prev: a.at(-1).hash,
    };
    r.hash = digest(r, k);
    a.push(r);
  }
  return a;
}
async function setup(t, rs = records()) {
  const dir = await mkdtemp(join(tmpdir(), 'audit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'log'), keyFile = join(dir, 'key');
  await writeFile(keyFile, key);
  const save = async (rows) => writeFile(path, rows.map((r) => canon(r)).join('\n') + '\n');
  await save(rs);
  return { path, keyFile, save, dir };
}
for (const keyed of [false, true]) {
  test(`valid ${keyed ? 'keyed' : 'plain'} and anchor`, async (t) => {
    const rs = records(keyed ? key : null),
      { path, keyFile, dir } = await setup(t, rs),
      opts = keyed ? { keyFile } : {};
    assert.equal((await verifyLog(path, opts)).ok, true);
    const a = await createAnchor(path, opts), file = join(dir, 'anchor');
    await writeFile(file, JSON.stringify(a));
    assert.equal((await verifyLog(path, { ...opts, anchorFile: file })).anchor.ok, true);
  });
}
for (
  const [name, mutate, kind] of [
    ['edit', (r) => r[1].type = 'changed', 'hash_mismatch'],
    ['delete', (r) => r.splice(1, 1), 'seq_gap'],
    ['insert', (r) => r.splice(2, 0, r[1]), 'seq_gap'],
    ['reorder', (r) => [r[1], r[2]] = [r[2], r[1]], 'chain_break'],
    ['seq', (r) => r[1].seq = 8, 'seq_gap'],
    ['header', (r) => r.shift(), 'bad_header'],
    ['shape', (r) => delete r[1].type, 'bad_record'],
    ['time', (r) => {
      r[2].time = '2026-01-01T00:00:00Z';
      r[2].hash = digest(r[2]);
    }, 'time_regress'],
  ]
) {
  test(name, async (t) => {
    const r = records();
    mutate(r);
    const { path } = await setup(t, r);
    assert.ok((await verifyLog(path)).findings.some((f) => f.kind === kind));
  });
}
test('anchor catches truncation and rewritten tail', async (t) => {
  const r = records(), { path, dir, save } = await setup(t, r), a = await createAnchor(path), f = join(dir, 'anchor');
  await writeFile(f, JSON.stringify(a));
  await save(r.slice(0, -1));
  assert.ok((await verifyLog(path, { anchorFile: f })).findings.some((x) => x.kind === 'truncated_tail'));
  r[3].type = 'edited';
  r[3].hash = digest(r[3]);
  await save(r);
  assert.equal((await verifyLog(path)).ok, true);
  assert.ok((await verifyLog(path, { anchorFile: f })).findings.some((x) => x.kind === 'anchor_mismatch'));
});
test('invalid line and finding cap', async (t) => {
  const { path } = await setup(t);
  await writeFile(path, canon(records()[0]) + '\n' + ('bad\n'.repeat(105)));
  const r = await verifyLog(path);
  assert.equal(r.findings.length, 101);
  assert.equal(r.findings.at(-1).kind, 'truncated_report');
  assert.equal(r.findings[0].kind, 'bad_record');
});
test('wrong key and missing key', async (t) => {
  const { path, dir } = await setup(t, records(key));
  const f = join(dir, 'wrong');
  await writeFile(f, 'abcdefghijklmnop');
  assert.ok((await verifyLog(path, { keyFile: f })).findings.some((x) => x.kind === 'key_mismatch'));
  await assert.rejects(verifyLog(path), { kind: 'key_required' });
});
test('summary and rendering', async (t) => {
  const { path } = await setup(t);
  const s = await summarize(path, { details: true });
  assert.equal(s.records, 3);
  assert.equal(s.type.call, 3);
  assert.equal(sanitizeText('a\u202eb\u{e0001}'), 'a?b?');
  assert.match(renderSummary({ x: 'a|`b' }, 'markdown'), /\| `` a\\u007c`b `` \|/);
  assert.match(renderExport([{ type: '=x', actor: 'a"b' }], 'csv'), /"'=x".*"a""b"/);
  assert.deepEqual(JSON.parse(renderShow([{ a: 1 }], 'json')), [{ a: 1 }]);
  assert.equal(JSON.parse(renderVerify({ ok: true }, 'json')).ok, true);
});
test('line encoding violations and size limit', async (t) => {
  const { path } = await setup(t);
  for (
    const data of [
      '\ufeff' + canon(records()[0]) + '\n',
      canon(records()[0]) + '\r\n',
      canon(records()[0]) + '\n\0\n',
    ]
  ) {
    await writeFile(path, data);
    assert.equal((await verifyLog(path)).ok, false);
  }
  await writeFile(path, 'x'.repeat(70 * 1024) + '\n');
  assert.equal((await verifyLog(path)).findings[0].kind, 'bad_record');
});
test('keyed anchor tamper and rewrite without key', async (t) => {
  const r = records(key),
    { path, keyFile, dir, save } = await setup(t, r),
    a = await createAnchor(path, { keyFile }),
    f = join(dir, 'anchor');
  a.hash = '0'.repeat(64);
  await writeFile(f, JSON.stringify(a));
  assert.equal((await verifyLog(path, { keyFile, anchorFile: f })).anchor.ok, false);
  for (const row of r) row.hash = digest(row);
  await save(r);
  assert.equal((await verifyLog(path, { keyFile })).ok, false);
});
test('terminal sanitizes values and preserves line breaks', () => {
  const text = renderShow([{ type: 'x\u202ey' }]);
  assert.ok(text.includes('\n'));
  assert.ok(text.includes('x?y'));
});
test('summary caps distinct names', async (t) => {
  const rs = records().slice(0, 1);
  for (let i = 1; i <= 10002; i++) {
    rs.push({
      seq: i,
      time: '2026-01-01T00:00:00Z',
      type: 'n' + i,
      actor: null,
      tool: null,
      outcome: null,
      data: null,
      prev: '0'.repeat(64),
      hash: '0'.repeat(64),
    });
  }
  const { path } = await setup(t, rs);
  const s = await summarize(path, { details: true });
  assert.equal(s.type['(other)'], 2);
  assert.equal(Object.keys(s.type).length, 10001);
});
const expectedDetails = {
  bad_header: 'header_invalid',
  bad_record: 'record_invalid',
  hash_mismatch: 'hash_differs',
  chain_break: 'prev_differs',
  seq_gap: 'seq_not_contiguous',
  time_regress: 'time_earlier_than_previous',
  mode_change: 'anchor_mode_differs',
  key_mismatch: 'key_id_differs',
  truncated_tail: 'log_shorter_than_anchor',
  anchor_mismatch: 'anchor_head_differs',
  trailing_garbage: 'unterminated_or_extra_line',
  truncated_report: 'more_than_100_findings',
};
for (
  const [field, value] of Object.entries({
    seq: 25,
    time: '2026-01-01T00:00:08Z',
    type: 'other',
    actor: 'B',
    tool: 'U',
    outcome: 'deny',
    data: { x: 1 },
    prev: '1'.repeat(64),
    hash: '2'.repeat(64),
  })
) {
  test('tamper event ' + field, async (t) => {
    const r = records();
    r[1][field] = value;
    const { path } = await setup(t, r);
    assert.equal((await verifyLog(path)).ok, false);
  });
}
for (
  const [field, value] of Object.entries({
    format: 'bad',
    version: 2,
    seq: 2,
    time: '2026-01-01T00:00:09Z',
    mode: 'sha256x',
    keyId: 'bad',
    prev: '1'.repeat(64),
    hash: '2'.repeat(64),
  })
) {
  test('tamper header ' + field, async (t) => {
    const r = records();
    r[0][field] = value;
    const { path } = await setup(t, r);
    assert.equal((await verifyLog(path)).ok, false);
  });
}
for (
  const [label, mutate, kind] of [
    ['duplicate', (r) => r.splice(2, 0, r[1]), 'seq_gap'],
    ['remove middle', (r) => r.splice(2, 1), 'seq_gap'],
    ['remove first', (r) => r.shift(), 'bad_header'],
    ['change previous', (r) => r[1].prev = '1'.repeat(64), 'chain_break'],
    ['invalid schema', (r) => delete r[1].actor, 'bad_record'],
    ['edit hash', (r) => r[1].hash = 'f'.repeat(64), 'hash_mismatch'],
    ['regression', (r) => r[2].time = '2026-01-01T00:00:00Z', 'time_regress'],
  ]
) {
  test('finding detail ' + label, async (t) => {
    const r = records();
    mutate(r);
    const { path } = await setup(t, r);
    const report = await verifyLog(path);
    assert.ok(report.findings.some((f) => f.kind === kind && f.detail === expectedDetails[kind]));
  });
}
for (
  const [label, data, kind] of [
    ['empty', '', 'bad_header'],
    ['blank', '\n', 'bad_record'],
    ['garbage', 'garbage\n', 'bad_record'],
    ['partial', 'garbage', 'trailing_garbage'],
    ['bom', '\ufeff{}\n', 'bad_record'],
    ['crlf', '{}\r\n', 'bad_record'],
    ['nul', '\0\n', 'bad_record'],
    ['long', 'x'.repeat(70 * 1024) + '\n', 'bad_record'],
  ]
) {
  test('reader ' + label, async (t) => {
    const { path } = await setup(t);
    await writeFile(path, data);
    const report = await verifyLog(path);
    assert.ok(report.findings.some((f) => f.kind === kind && f.detail === expectedDetails[kind]));
  });
}
test('150 findings capped', async (t) => {
  const { path } = await setup(t);
  await writeFile(path, canon(records()[0]) + '\n' + 'bad\n'.repeat(150));
  const r = await verifyLog(path);
  assert.equal(r.findings.length, 101);
  assert.deepEqual(r.findings.at(-1), {
    kind: 'truncated_report',
    seq: null,
    detail: expectedDetails.truncated_report,
  });
});
test('tail removal requires anchor', async (t) => {
  const r = records(), { path, dir, save } = await setup(t, r);
  const a = await createAnchor(path), f = join(dir, 'anchor');
  await writeFile(f, JSON.stringify(a));
  await save(r.slice(0, -1));
  assert.equal((await verifyLog(path)).ok, true);
  assert.ok(
    (await verifyLog(path, { anchorFile: f })).findings.some((x) =>
      x.kind === 'truncated_tail' && x.detail === expectedDetails.truncated_tail
    ),
  );
});
test('invalid anchor detail', async (t) => {
  const { path, dir } = await setup(t);
  const f = join(dir, 'anchor');
  await writeFile(f, 'bad');
  assert.ok(
    (await verifyLog(path, { anchorFile: f })).findings.some((x) =>
      x.kind === 'anchor_mismatch' && x.detail === 'anchor_invalid'
    ),
  );
});
test('anchor hash detail', async (t) => {
  const { path, dir } = await setup(t);
  const a = await createAnchor(path), f = join(dir, 'anchor');
  a.hash = 'f'.repeat(64);
  await writeFile(f, JSON.stringify(a));
  assert.ok((await verifyLog(path, { anchorFile: f })).findings.some((x) => x.detail === 'anchor_hash_invalid'));
});
test('plain anchor on keyed log', async (t) => {
  const { path, keyFile, dir, save } = await setup(t);
  const a = await createAnchor(path), f = join(dir, 'anchor');
  await writeFile(f, JSON.stringify(a));
  await save(records(key));
  assert.ok(
    (await verifyLog(path, { anchorFile: f, keyFile })).findings.some((x) =>
      x.kind === 'mode_change' && x.detail === expectedDetails.mode_change
    ),
  );
});
test('wrong key detail', async (t) => {
  const { path, dir } = await setup(t, records(key));
  const f = join(dir, 'wrong');
  await writeFile(f, 'abcdefghijklmnop');
  assert.ok(
    (await verifyLog(path, { keyFile: f })).findings.some((x) =>
      x.kind === 'key_mismatch' && x.detail === expectedDetails.key_mismatch
    ),
  );
});
for (
  const cp of [
    0,
    9,
    10,
    13,
    31,
    127,
    128,
    159,
    0x61c,
    0x200b,
    0x200c,
    0x200d,
    0x200e,
    0x200f,
    0x2028,
    0x2029,
    0x202a,
    0x202b,
    0x202c,
    0x202d,
    0x202e,
    0x2060,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0xfeff,
    0xe0000,
    0xe007f,
  ]
) test('sanitize ' + cp.toString(16), () => assert.equal(sanitizeText('a' + String.fromCodePoint(cp) + 'b'), 'a?b'));
for (const prefix of ['=', '+', '-', '@']) {
  test(
    'csv guard ' + JSON.stringify(prefix),
    () => assert.ok(renderExport([{ type: prefix + 'value' }], 'csv').includes('"\'' + prefix + 'value"')),
  );
}
for (const fn of [renderSummary, renderShow, renderVerify]) {
  test(
    'markdown escaping ' + fn.name,
    () => assert.match(fn(fn === renderShow ? [{ a: '|`' }] : { a: '|`' }, 'markdown'), /`` .*\\u007c`.* ``/),
  );
}
test('json stable key order', () =>
  assert.equal(renderShow([{ z: 1, a: { y: 2, b: 3 } }], 'json'), renderShow([{ a: { b: 3, y: 2 }, z: 1 }], 'json')));
test('show bound', () => assert.throws(() => renderShow(Array(10001).fill({})), { kind: 'limit_exceeded' }));
test('csv quote and line breaks (breaks are controls and are escaped)', () =>
  assert.ok(
    renderExport([{ type: 'hello,"world"\r\nnext' }], 'csv').includes('"hello,""world""\\u000d\\u000anext"'),
  ));
test('source has no restricted facilities', async () => {
  const { readFile, readdir } = await import('node:fs/promises');
  async function walk(dir) {
    let out = [];
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      out = out.concat(e.isDirectory() ? await walk(p) : [p]);
    }
    return out;
  }
  for (const p of await walk(fileURLToPath(new URL('../src/', import.meta.url)))) {
    const s = await readFile(p, 'utf8');
    assert.doesNotMatch(s, /\b(?:eval\s*\(|process\.env|child_process|node:https?|node:net|node:dgram)\b/);
  }
});
