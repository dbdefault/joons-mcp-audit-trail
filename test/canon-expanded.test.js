import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
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
const invalid = (fn) => assert.throws(fn, (e) => e.kind === 'invalid_record');
const event = (extra) => ({ type: 'run', ...extra });
const tm = '2024-02-29T00:00:00Z';
const head = () => ({
  format: FORMAT,
  version: 1,
  seq: 0,
  time: tm,
  mode: 'sha256',
  keyId: null,
  prev: GENESIS_HASH,
  hash: 'a'.repeat(64),
});
const rec = () => ({
  seq: 1,
  time: tm,
  type: 'run',
  actor: null,
  tool: null,
  outcome: null,
  data: null,
  prev: 'a'.repeat(64),
  hash: 'b'.repeat(64),
});
const checks = [
  ['{"x":0}', { x: 0 }, '5bff452c5ed93f2e87a23984db5a15050c6477335fdec955b70063bb2d692bf1'],
  ['{"a":"한글"}', { a: '한글' }, '1019597a266a464fce603dcba7a3878fd6d47d5427faa0c27940e2e0b62ebb92'],
  ['{"a":[1,true,null]}', { a: [1, true, null] }, '6d1592667f338d1cf0afe1c2e2371acf5781539b63e7762fa0f64c1fe355713b'],
];
for (const [s, v, h] of checks) {
  test('digest ' + s, () => {
    assert.equal(createHash('sha256').update(s).digest('hex'), h);
    assert.equal(hashRecord(v, null), h);
  });
}
test('second HMAC vector', () => {
  const h = 'dd86446badf92a0201ed8769ab18e5ffdcd67d46964bd809c3bab802cb42ea40';
  assert.equal(createHmac('sha256', 'key').update('{"x":0}').digest('hex'), h);
  assert.equal(hashRecord({ x: 0 }, Buffer.from('key')), h);
});
test('seeded independent canonical and hash comparisons', () => {
  let seed = 1234567;
  const rand = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  const independent = (v) =>
    v === null
      ? 'null'
      : Array.isArray(v)
      ? '[' + v.map(independent).join(',') + ']'
      : typeof v === 'object'
      ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + independent(v[k])).join(',') + '}'
      : JSON.stringify(v);
  for (let i = 0; i < 200; i++) {
    const r = { z: rand(), a: ['한', rand() % 300, -(rand() % 50)], ['k' + rand() % 10]: { x: rand() % 2 === 0 } };
    const bytes = independent(r);
    assert.equal(canonicalize(r), bytes);
    assert.equal(hashRecord(r, null), createHash('sha256').update(bytes).digest('hex'));
    assert.equal(hashRecord(r, Buffer.from('key')), createHmac('sha256', 'key').update(bytes).digest('hex'));
  }
});
test('key identifier known vector', () => assert.equal(keyIdOf(Buffer.from('abc')), '4f8b42c22dd3729b'));
for (
  const [v, want] of [[-0, '0'], ['\ud800', '"\\ud800"'], ['e\u0301', '"é"'], ['😀', '"😀"'], [
    Number.MIN_SAFE_INTEGER,
    '-9007199254740991',
  ]]
) test('canonical ' + JSON.stringify(v), () => assert.equal(canonicalize(v), want));
for (
  const [s, valid] of [
    ['2000-02-29T00:00:00Z', 1],
    ['1900-02-29T00:00:00Z', 0],
    ['2400-02-29T00:00:00Z', 1],
    ['2100-02-29T00:00:00Z', 0],
    ['2024-02-29T23:59:59.999Z', 1],
    ['2023-02-29T00:00:00Z', 0],
    ['2024-01-31T00:00:00Z', 1],
    ['2024-02-30T00:00:00Z', 0],
    ['2024-03-31T00:00:00Z', 1],
    ['2024-04-31T00:00:00Z', 0],
    ['2024-05-31T00:00:00Z', 1],
    ['2024-06-31T00:00:00Z', 0],
    ['2024-07-31T00:00:00Z', 1],
    ['2024-08-31T00:00:00Z', 1],
    ['2024-09-31T00:00:00Z', 0],
    ['2024-10-31T00:00:00Z', 1],
    ['2024-11-31T00:00:00Z', 0],
    ['2024-12-31T00:00:00Z', 1],
    ['2024-00-01T00:00:00Z', 0],
    ['2024-13-01T00:00:00Z', 0],
    ['2024-01-00T00:00:00Z', 0],
    ['2024-01-01T24:00:00Z', 0],
    ['2024-01-01T00:60:00Z', 0],
    ['2024-01-01T00:00:60Z', 0],
    ['2024-01-01T00:00:00.00Z', 0],
    ['2024-01-01T00:00:00.0000Z', 0],
    ['2024-01-01T00:00:00.000Z', 1],
    ['2024-01-01T00:00:00z', 0],
    ['2024-01-01 00:00:00Z', 0],
    ['2024-1-01T00:00:00Z', 0],
    ['0000-02-29T00:00:00Z', 1],
    ['9999-12-31T23:59:59Z', 1],
    ['2024-01-01T00:00:00+00:00', 0],
  ]
) test('time ' + s, () => assert.equal(isIsoUtc(s), !!valid));
for (
  const [field, val] of [
    ['format', 'wrong'],
    ['version', '1'],
    ['seq', '0'],
    ['time', null],
    ['mode', 'x'],
    ['keyId', 'a'.repeat(16)],
    ['prev', 'A'.repeat(64)],
    ['hash', 'B'.repeat(64)],
  ]
) test('header invalid ' + field, () => invalid(() => validateRecordShape({ ...head(), [field]: val }, 0)));
for (
  const [field, val] of [
    ['seq', 2],
    ['time', '2023-02-29T00:00:00Z'],
    ['type', 7],
    ['actor', false],
    ['tool', {}],
    ['outcome', 'invalid'],
    ['data', []],
    ['prev', 'A'.repeat(64)],
    ['hash', null],
  ]
) test('record invalid ' + field, () => invalid(() => validateRecordShape({ ...rec(), [field]: val }, 1)));
for (const k of Object.keys(head())) {
  test('header missing ' + k, () => {
    const o = head();
    delete o[k];
    invalid(() => validateRecordShape(o, 0));
  });
}
for (const k of Object.keys(rec())) {
  test('event missing ' + k, () => {
    const o = rec();
    delete o[k];
    invalid(() => validateRecordShape(o, 1));
  });
}
test('extra event input and record keys rejected', () => {
  invalid(() => validateEvent(event({ extra: 1 })));
  invalid(() => validateRecordShape({ ...rec(), extra: 1 }, 1));
});
test('unicode lengths actor and data', () => {
  validateEvent(event({ actor: '😀'.repeat(128), data: { x: '😀'.repeat(4096) } }));
  invalid(() => validateEvent(event({ actor: '😀'.repeat(129) })));
  invalid(() => validateEvent(event({ data: { x: '😀'.repeat(4097) } })));
});
test('exact data size boundaries', () => {
  const d = Object.fromEntries(Array.from({ length: 8 }, (_, i) => ['k' + i, 'x'.repeat(i === 7 ? 4031 : 4096)]));
  const n = Buffer.byteLength(canonicalize(d));
  d.k7 += 'x'.repeat(32768 - n);
  assert.equal(Buffer.byteLength(canonicalize(d)), 32768);
  validateEvent(event({ data: d }));
  d.k7 += 'x';
  invalid(() => validateEvent(event({ data: d })));
});
test('key and array boundaries', () => {
  validateEvent(
    event({
      data: { x: Array(64).fill(1), ...Object.fromEntries(Array.from({ length: 63 }, (_, i) => ['k' + i, 1])) },
    }),
  );
  invalid(() => validateEvent(event({ data: { x: Array(65).fill(1) } })));
});
for (const key of ['__proto__', 'constructor', 'prototype']) {
  for (let depth = 1; depth <= 6; depth++) {
    test('forbidden ' + key + ' depth ' + depth, () => {
      let d = JSON.parse('{"' + key + '":1}');
      for (let i = 1; i < depth; i++) d = { x: d };
      invalid(() => validateEvent(event({ data: d })));
    });
  }
}
test('container depth six accepted seven rejected', () => {
  let d = { x: 1 };
  for (let i = 1; i < 6; i++) d = { x: d };
  validateEvent(event({ data: d }));
  invalid(() => validateEvent(event({ data: { x: d } })));
});
for (
  const prefix of [
    'gl' + 'pat-',
    'xo' + 'xa-',
    'xo' + 'xb-',
    'xo' + 'xp-',
    'xo' + 'xr-',
    'xo' + 'xs-',
  ]
) {
  test('credential prefix ' + prefix, () => {
    assert.equal(scanForCredential({ nested: [{ [prefix]: 'safe' }] }), true);
    assert.throws(() => validateEvent(event({ data: { nested: [prefix] } })), (e) => e.kind === 'credential_detected');
  });
}
for (const p of ['p', 'o', 'u', 's', 'r']) {
  test('github family ' + p, () => {
    assert.equal(scanForCredential('gh' + p + '_' + 'a'.repeat(20)), true);
    assert.equal(scanForCredential('gh' + p + '_' + 'a'.repeat(19)), false);
  });
}
test('two decoding rounds and JWT boundary', () => {
  assert.equal(scanForCredential('Be' + 'arer%2520abcdefghijklmnop'), true);
  const jwt = (a, b, c) => 'ey' + 'J' + 'a'.repeat(a - 3) + '.' + 'b'.repeat(b) + '.' + 'c'.repeat(c);
  assert.equal(scanForCredential(jwt(10, 10, 10)), true);
  assert.equal(scanForCredential(jwt(9, 10, 10)), false);
  assert.equal(scanForCredential(jwt(10, 9, 10)), false);
  assert.equal(scanForCredential(jwt(10, 10, 9)), false);
  assert.equal(scanForCredential('a'.repeat(10) + '.' + 'b'.repeat(10) + '.' + 'c'.repeat(10)), false);
});
test('private header shift and negative controls', () => {
  for (const s of ['-----BEGIN ' + '' + 'PRIVATE KEY-----', 'x-----BEGIN ' + 'PRIVATE KEY-----']) {
    assert.equal(scanForCredential(s), true);
  }
  for (const s of ['-----BEGIN ' + '' + 'CERTIFICATE-----', 'task-runner', 'ask-me-anything', 'skeleton-key']) {
    assert.equal(scanForCredential(s), false);
  }
});
