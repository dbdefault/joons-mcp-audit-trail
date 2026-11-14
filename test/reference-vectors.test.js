import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { anchor, canonicalize, event, header, keyId, verify } from '../reference/model.js';
const t = '2026-01-02T03:04:05.000Z', key = Buffer.from('0123456789abcdef');
test('canonical ordering, unicode, escapes and integer bounds', () => {
  assert.equal(canonicalize({ z: '\n', a: '한', n: 9007199254740991 }), '{"a":"한","n":9007199254740991,"z":"\\n"}');
  for (const x of [1.2, Infinity, 9007199254740992, undefined]) assert.throws(() => canonicalize(x));
});
test('independent SHA and HMAC vectors', () => {
  for (const k of [null, key]) {
    const h = header(t, k), { hash, ...v } = h;
    const expected = (k ? createHmac('sha256', k) : createHash('sha256')).update(canonicalize(v)).digest('hex');
    assert.equal(hash, expected);
  }
  assert.equal(
    keyId(key),
    createHash('sha256').update(createHash('sha256').update(key).digest()).digest('hex').slice(0, 16),
  );
});
test('reference roundtrip, tamper, anchor and keyed rewrite', () => {
  for (const k of [null, key]) {
    const h = header(t, k),
      e = event(1, t, 'test', h.hash, { a: 1 }, null, null, null, k),
      rs = [h, e],
      text = rs.map((r) => canonicalize(r)).join('\n') + '\n',
      a = anchor(rs, t, k);
    assert.equal(verify(text, k, a).ok, true);
    assert.equal(verify(canonicalize(h) + '\n', k, a).ok, false);
    assert.equal(verify(text.replace('test', 'tast'), k).ok, false);
  }
});
