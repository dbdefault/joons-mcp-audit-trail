import test from 'node:test';
import assert from 'node:assert/strict';
import {
  anchor,
  canonicalize,
  credential,
  event,
  exportCsv,
  exportJson,
  header,
  sanitize,
  show,
  summarize,
  validateEvent,
  verify,
} from '../reference/model.js';
for (
  const [i, value] of [
    null,
    true,
    false,
    0,
    1,
    -1,
    42,
    'x',
    '한',
    '\n',
    [],
    [1, 2],
    {},
    { b: 1, a: 2 },
    { x: [null, 1] },
    9007199254740991,
    -9007199254740991,
  ].entries()
) {
  test(`canonical vector ${i}`, () =>
    assert.equal(
      canonicalize(value),
      JSON.stringify(
        value && !Array.isArray(value) && typeof value === 'object'
          ? Object.fromEntries(Object.entries(value).sort())
          : value,
      ),
    ));
}
for (const [i, v] of [NaN, Infinity, 1.5, 9007199254740992, undefined, () => 0].entries()) {
  test(`reject invalid canonical ${i}`, () => assert.throws(() => canonicalize(v)));
}
for (
  const [i, v] of [
    {},
    { type: '' },
    { type: 'a b' },
    { type: 'a', extra: 1 },
    { type: 'a', outcome: 'other' },
    { type: 'a', actor: '' },
    { type: 'a', tool: 'x'.repeat(129) },
    { type: 'a', data: [] },
    { type: 'a', data: { x: 1.5 } },
    { type: 'a', data: JSON.parse('{"__proto__":0}') },
    { type: 'a', data: { x: 'a'.repeat(4097) } },
  ].entries()
) test(`invalid event ${i}`, () => assert.throws(() => validateEvent(v)));
for (
  const [i, s] of [
    'AK' + 'IA1234567890ABCDEF',
    'gh' + 'p_12345678901234567890',
    'gl' + 'pat-abc',
    'xo' + 'xb-123',
    'sk' + '_live_abcdefghij',
    'AI' + 'za12345678901234567890123456789012345',
    'SG' + '.abcdefghijklmnop.abcdefghijklmnop',
    'np' + 'm_abcdefghijklmnopqrstuvwxyz0123',
    'Be' + 'arer abcdefghijklmnop',
    'ey' + 'Jaaaaaaa.bbbbbbbbbb.cccccccccc',
  ].entries()
) test(`credential ${i}`, () => assert.equal(credential(s), true));
test('normalization', () =>
  assert.deepEqual(validateEvent({ type: 'x' }), {
    type: 'x',
    actor: null,
    tool: null,
    outcome: null,
    data: null,
    time: null,
  }));
test('report helpers', () => {
  const h = header('2026-01-02T03:04:05.000Z'), e = event(1, h.time, 'x', h.hash, null, '=1');
  assert.equal(summarize([h, e]).events, 1);
  assert.equal(show([h, e], 1, 1).length, 1);
  assert.match(exportCsv([e]), /'=1/);
  assert.deepEqual(JSON.parse(exportJson([e])), [e]);
  assert.equal(sanitize('a\u001b\u200bb'), 'a??b');
});
