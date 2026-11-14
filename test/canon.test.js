import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { AuditError, ERROR_KINDS } from '../src/errors.js';
import {
  canonicalize,
  FORMAT,
  GENESIS_HASH,
  hashRecord,
  isIsoUtc,
  keyIdOf,
  scanForCredential,
  validateEvent,
  validateRecordShape,
} from '../src/canon/index.js';
const bad = (fn) => assert.throws(fn, (e) => e instanceof AuditError && e.kind === 'invalid_record');
const time = '2024-02-29T12:30:59.123Z';
const header = () => ({
  format: FORMAT,
  version: 1,
  seq: 0,
  time,
  mode: 'sha256',
  keyId: null,
  prev: GENESIS_HASH,
  hash: 'a'.repeat(64),
});
const record = () => ({
  seq: 1,
  time,
  type: 'task-runner',
  actor: null,
  tool: null,
  outcome: null,
  data: null,
  prev: 'a'.repeat(64),
  hash: 'b'.repeat(64),
});
test('independent golden digests', () => {
  const vectors = [[{}, '{}', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'], [
    { b: 'x', a: 1 },
    '{"a":1,"b":"x"}',
    'ecf9e98ec0641e23113ff3ce8bdc78d0ddd249886517fd4a7f68cc83d4e65667',
  ], [
    { type: 'test', seq: 1, hash: 'ignored' },
    '{"seq":1,"type":"test"}',
    '1e47cd3d1f2cd54712412b6b710be7240ae7453c860b69e99ff73687633c3680',
  ]];
  for (const [obj, text, expected] of vectors) {
    assert.equal(createHash('sha256').update(text, 'utf8').digest('hex'), expected);
    assert.equal(hashRecord(obj, null), expected);
  }
  const key = Buffer.from('0123456789abcdef');
  assert.equal(
    createHmac('sha256', key).update('{}').digest('hex'),
    'f91e3e9f05cc2df64ac1c26f8adccdffda8d1e4a7a8c50a1a08eeadac6ddfec5',
  );
  assert.equal(hashRecord({}, key), 'f91e3e9f05cc2df64ac1c26f8adccdffda8d1e4a7a8c50a1a08eeadac6ddfec5');
  assert.equal(
    keyIdOf(key),
    createHash('sha256').update(createHash('sha256').update(key).digest()).digest('hex').slice(0, 16),
  );
});
test('canonical strings and order', () => {
  assert.equal(
    canonicalize({ '\uE000': 1, '😀': 2, a: ['한글', '\n"\\', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER] }),
    '{"a":["한글","\\n\\"\\\\",9007199254740991,-9007199254740991],"😀":2,"":1}',
  );
  assert.equal(canonicalize(Object.assign(Object.create(null), { z: true, a: null })), '{"a":null,"z":true}');
});
test('canonical invalid values and depth', () => {
  for (
    const x of [
      undefined,
      () => {},
      Symbol(),
      1n,
      NaN,
      Infinity,
      0.1,
      Number.MAX_SAFE_INTEGER + 1,
      new Date(),
      [undefined],
      Array(1),
      { x: undefined },
    ]
  ) bad(() => canonicalize(x));
  const x = {};
  x.self = x;
  bad(() => canonicalize(x));
  let a = 0;
  for (let i = 0; i < 32; i++) a = [a];
  canonicalize(a);
  bad(() => canonicalize([a]));
});
test('calendar', () => {
  for (const s of [time, '2000-02-29T00:00:00Z', '0000-01-01T00:00:00Z']) assert.equal(isIsoUtc(s), true);
  for (
    const s of [
      '1900-02-29T00:00:00Z',
      '2023-02-29T00:00:00Z',
      '2024-04-31T00:00:00Z',
      '2024-13-01T00:00:00Z',
      '2024-01-01T24:00:00Z',
      '2024-01-01T00:60:00Z',
      '2024-01-01T00:00:60Z',
      '2024-01-01T00:00:00.1Z',
      '2024-01-01T00:00:00+00:00',
      null,
    ]
  ) assert.equal(isIsoUtc(s), false);
});
test('event matrix', () => {
  assert.deepEqual(validateEvent({ type: 'run' }), {
    type: 'run',
    actor: null,
    tool: null,
    outcome: null,
    data: null,
    time: null,
  });
  const values = [
    {},
    { type: '' },
    { type: 'a b' },
    { type: 'x'.repeat(65) },
    { type: 'ok', actor: '' },
    { type: 'ok', tool: 'a\n' },
    { type: 'ok', actor: 'a'.repeat(129) },
    { type: 'ok', outcome: 'yes' },
    { type: 'ok', time: 'bad' },
    { type: 'ok', data: [] },
    { type: 'ok', data: { x: 'a'.repeat(4097) } },
    { type: 'ok', data: { x: Array(65).fill(1) } },
    { type: 'ok', data: Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['k' + i, 1])) },
    { type: 'ok', data: JSON.parse('{"a":{"__proto__":1}}') },
    { type: 'ok', data: { constructor: 1 } },
    { type: 'ok', data: { prototype: 1 } },
    { type: 'ok', data: { x: 1.1 } },
    { type: 'ok', data: Object.fromEntries(Array.from({ length: 9 }, (_, i) => ['k' + i, 'a'.repeat(4096)])) },
  ];
  for (const v of values) bad(() => validateEvent(v));
  let d = {};
  for (let i = 0; i < 7; i++) d = { x: d };
  bad(() => validateEvent({ type: 'ok', data: d }));
  assert.doesNotThrow(() => validateEvent({ type: 'ok', data: Object.assign(Object.create(null), { x: 1 }) }));
  assert.throws(
    () => validateEvent({ type: 'ok', data: { x: 'Be' + 'arer abcdefghijklmnop' } }),
    (e) => e.kind === 'credential_detected',
  );
});
test('record shape matrix', () => {
  assert.equal(validateRecordShape(header(), 0).seq, 0);
  assert.equal(validateRecordShape(record(), 1).seq, 1);
  for (
    const v of [
      { ...header(), extra: 1 },
      { ...header(), version: 2 },
      { ...header(), mode: 'sha256', keyId: 'a'.repeat(16) },
      { ...header(), mode: 'hmac-sha256', keyId: null },
      { ...header(), prev: 'a'.repeat(64) },
      { ...record(), seq: 2 },
      { ...record(), hash: 'A'.repeat(64) },
      { ...record(), time: 'bad' },
      { ...record(), outcome: 'bad' },
    ]
  ) bad(() => validateRecordShape(v, v.seq === 0 ? 0 : 1));
  const r = record();
  delete r.actor;
  bad(() => validateRecordShape(r, 1));
});
test('credential families and negative controls', () => {
  const positives = [
    '-----BEGIN ' + '' + 'PRIVATE KEY-----',
    '-----BEGIN ' + '' + 'RSA PRIVATE KEY-----',
    'Be' + 'arer abcdefghijklmnop',
    'ey' + 'Jaaaaaaa' + '.bbbbbbbbbb.cccccccccc',
    'AK' + 'IA' + 'A'.repeat(16),
    'AS' + 'IA' + 'A'.repeat(16),
    'AG' + 'PA' + 'A'.repeat(16),
    'AI' + 'DA' + 'A'.repeat(16),
    'AR' + 'OA' + 'A'.repeat(16),
    'AI' + 'PA' + 'A'.repeat(16),
    'AN' + 'PA' + 'A'.repeat(16),
    'AN' + 'VA' + 'A'.repeat(16),
    'gh' + 'p_' + 'a'.repeat(20),
    'gl' + 'pat-' + 'a'.repeat(10),
    'xo' + 'xb-' + 'a'.repeat(10),
    'sk' + '_live_' + 'a'.repeat(10),
    'pk' + '_live_' + 'a'.repeat(10),
    'rk' + '_live_' + 'a'.repeat(10),
    'AI' + 'za' + 'a'.repeat(35),
    'SG' + '.' + 'a'.repeat(16) + '.' + 'a'.repeat(16),
    'np' + 'm_' + 'a'.repeat(30),
  ];
  for (const s of positives) {
    assert.equal(scanForCredential(s), true, s);
    assert.equal(scanForCredential({ [s]: 'x' }), true, s);
  }
  assert.equal(scanForCredential('Be' + 'arer%20abcdefghijklmnop'), true);
  for (const s of ['task-runner', 'normal text', 'one.two', 'token']) assert.equal(scanForCredential(s), false, s);
});
test('error kinds', () => {
  assert.equal(ERROR_KINDS.length, 11);
  assert.equal(new AuditError('unknown').kind, 'internal_error');
});
