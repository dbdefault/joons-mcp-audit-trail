import test from 'node:test';
import assert from 'node:assert/strict';
import { scanForCredential, validateEvent } from '../src/canon/index.js';
import { cli, expectFail, expectOk, tempDir } from '../reference/helpers.js';
import { join } from 'node:path';

// Credential-shaped literals are built from fragments so that a repository secret scan stays clean.
const a = (n, c = 'a') => c.repeat(n);
const AWS = ['AK' + 'IA', 'AS' + 'IA', 'AG' + 'PA', 'AI' + 'DA', 'AR' + 'OA', 'AI' + 'PA', 'AN' + 'PA', 'AN' + 'VA'];
const FAMILIES = {
  aws: AWS.map((p) => p + a(16, 'A')),
  github: ['p', 'o', 'u', 's', 'r'].map((x) => 'gh' + x + '_' + a(20)),
  gitlab: ['gl' + 'pat-' + 'abc'],
  slack: ['a', 'b', 'p', 'r', 's'].map((x) => 'xo' + 'x' + x + '-1'),
  stripe: ['sk', 'pk', 'rk'].map((x) => x + '_live_' + a(10)),
  google: ['AI' + 'za' + a(35)],
  sendgrid: ['SG' + '.' + a(16) + '.' + a(16)],
  npm: ['np' + 'm_' + a(30)],
  bearer: ['Be' + 'arer ' + a(16)],
  jwt: ['ey' + 'J' + a(7) + '.' + a(10) + '.' + a(10)],
  privateKey: ['-----BEGIN ' + 'PRIVATE KEY-----', '-----BEGIN ' + 'RSA PRIVATE KEY-----'],
};

test('every family is refused at its start boundary: start, space, equals, colon, quote, bracket, comma, slash', () => {
  for (const [name, samples] of Object.entries(FAMILIES)) {
    for (const sample of samples) {
      for (const before of ['', ' ', '=', ':', '"', '(', ',', '/', '#', '.']) {
        assert.equal(
          scanForCredential('x' === before ? sample : before + sample),
          true,
          name + ' after ' + JSON.stringify(before),
        );
      }
      assert.throws(() => validateEvent({ type: 'ok', actor: 'user ' + sample }), { kind: 'credential_detected' });
    }
  }
});

test('prefix families inside a longer alphanumeric, underscore or hyphen run are not keys', () => {
  const prefixed = [
    ...FAMILIES.aws,
    ...FAMILIES.github,
    ...FAMILIES.gitlab,
    ...FAMILIES.slack,
    ...FAMILIES.stripe,
    ...FAMILIES.google,
  ];
  for (const sample of prefixed) {
    for (const before of ['x', 'Z', '7', '_', '-']) {
      assert.equal(scanForCredential(before + sample), false, before + sample);
    }
  }
  assert.equal(scanForCredential('order-' + 'AK' + 'IA1234567890ABCDEF-not-key'), false);
  assert.equal(scanForCredential('ORDER' + 'AK' + 'IA' + a(16, 'A')), false);
});

test('minimum lengths: one character short is accepted, the minimum is refused', () => {
  const pairs = [
    ['bearer', 'Be' + 'arer ' + a(15), 'Be' + 'arer ' + a(16)],
    ['bearer charset', 'Be' + 'arer ' + a(15) + '!', 'Be' + 'arer ' + a(8) + '._~+/=-' + 'b'],
    ['npm', 'np' + 'm_' + a(29), 'np' + 'm_' + a(30)],
    ['sendgrid first', 'SG' + '.' + a(15) + '.' + a(16), 'SG' + '.' + a(16) + '.' + a(16)],
    ['sendgrid second', 'SG' + '.' + a(16) + '.' + a(15), 'SG' + '.' + a(16) + '.' + a(16)],
    ['stripe sk', 'sk' + '_live_' + a(9), 'sk' + '_live_' + a(10)],
    ['stripe pk', 'pk' + '_live_' + a(9), 'pk' + '_live_' + a(10)],
    ['stripe rk', 'rk' + '_live_' + a(9), 'rk' + '_live_' + a(10)],
    ['aws', 'AK' + 'IA' + a(15, 'A'), 'AK' + 'IA' + a(16, 'A')],
    ['github', 'gh' + 'p_' + a(19), 'gh' + 'p_' + a(20)],
    ['google', 'AI' + 'za' + a(34), 'AI' + 'za' + a(35)],
    ['jwt first', 'ey' + 'J' + a(6) + '.' + a(10) + '.' + a(10), 'ey' + 'J' + a(7) + '.' + a(10) + '.' + a(10)],
    ['jwt second', 'ey' + 'J' + a(7) + '.' + a(9) + '.' + a(10), 'ey' + 'J' + a(7) + '.' + a(10) + '.' + a(10)],
    ['jwt third', 'ey' + 'J' + a(7) + '.' + a(10) + '.' + a(9), 'ey' + 'J' + a(7) + '.' + a(10) + '.' + a(10)],
  ];
  for (const [name, short, enough] of pairs) {
    assert.equal(scanForCredential(short), false, name + ' short');
    assert.equal(scanForCredential(enough), true, name + ' enough');
  }
});

test('JWT needs a first segment that starts with eyJ', () => {
  assert.equal(scanForCredential(a(10) + '.' + a(10) + '.' + a(10)), false);
  assert.equal(scanForCredential('organization.application.controller'), false);
  assert.equal(scanForCredential('kubernetes-dashboard.kubernetes-system.configuration'), false);
  assert.equal(scanForCredential('production-api.engineering.corporate.example'), false);
  assert.equal(scanForCredential('ey' + 'Jhbgcioij.' + a(10) + '.' + a(10)), true);
});

test('required negative controls are accepted', () => {
  for (
    const s of [
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
      'MSG.TXT',
    ]
  ) {
    assert.equal(scanForCredential(s), false, s);
    assert.equal(validateEvent({ type: 'ok', actor: s, tool: s, data: { [s]: s } }).actor, s);
  }
});

test('key names and nested values are scanned, percent-encoding is decoded for two rounds', () => {
  const key = 'np' + 'm_' + a(30);
  assert.throws(() => validateEvent({ type: 'ok', data: { [key]: 1 } }), { kind: 'credential_detected' });
  assert.throws(() => validateEvent({ type: 'ok', data: { a: [{ b: key }] } }), { kind: 'credential_detected' });
  assert.equal(scanForCredential('Be' + 'arer%20' + a(16)), true);
  assert.equal(scanForCredential('Be' + 'arer%2520' + a(16)), true);
});

test('real command line: a refused credential never reaches the log', (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  expectFail(cli(['append', log, '--type', 'x', '--actor', 'np' + 'm_' + a(30)]), 2, 'credential_detected');
  expectOk(cli(['append', log, '--type', 'x', '--actor', 'npm_install']));
});

test('shared references cannot blow up the scan: a hard node cap gives invalid_record quickly', () => {
  let node = { leaf: 1 };
  for (let i = 0; i < 4; i++) node = { children: Array.from({ length: 64 }, () => node) };
  const started = Date.now();
  assert.throws(() => validateEvent({ type: 'ok', data: node }), { kind: 'invalid_record' });
  assert.ok(Date.now() - started < 5000);
  const wide = {
    a: Array.from({ length: 64 }, () => Array.from({ length: 64 }, () => Array.from({ length: 64 }, () => 1))),
  };
  assert.throws(() => validateEvent({ type: 'ok', data: wide }), { kind: 'invalid_record' });
});

test('getters are refused and never called; the normalized snapshot is detached from the input', () => {
  let calls = 0;
  const withGetter = {};
  Object.defineProperty(withGetter, 'x', {
    enumerable: true,
    get() {
      calls++;
      return 'value';
    },
  });
  assert.throws(() => validateEvent({ type: 'ok', data: withGetter }), { kind: 'invalid_record' });
  const event = {};
  Object.defineProperty(event, 'type', {
    enumerable: true,
    get() {
      calls++;
      return 'ok';
    },
  });
  assert.throws(() => validateEvent(event), { kind: 'invalid_record' });
  assert.equal(calls, 0);
  const input = { type: 'ok', data: { list: [1, { deep: 'x' }], n: -0 } };
  const out = validateEvent(input);
  assert.notEqual(out.data, input.data);
  assert.notEqual(out.data.list, input.data.list);
  assert.deepEqual(out.data, { list: [1, { deep: 'x' }], n: 0 });
  assert.ok(Object.is(out.data.n, 0));
  input.data.list[1].deep = 'changed';
  assert.equal(out.data.list[1].deep, 'x');
});

test('hostile structures are refused: holes, extra array properties, symbols, class instances, cycles', () => {
  const holes = [1, , 3]; // eslint-disable-line no-sparse-arrays
  const extra = [1];
  extra.prop = 1;
  const symbolic = { [Symbol('s')]: 1 };
  const cycle = {};
  cycle.self = cycle;
  for (
    const data of [
      { holes },
      { extra },
      symbolic,
      { date: new Date(0) },
      { map: new Map() },
      cycle,
      { fn: () => 1 },
      { u: undefined },
      { big: 1n },
    ]
  ) {
    assert.throws(() => validateEvent({ type: 'ok', data }), { kind: 'invalid_record' });
  }
});
