import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { anchor } from '../reference/model.js';
import {
  buildRecords,
  cli,
  expectFail,
  expectOk,
  KEY,
  OTHER_KEY,
  T0,
  tempDir,
  toText,
  writeLog,
} from '../reference/helpers.js';
import { createAnchor, verifyLog } from '../src/index.js';
import { canonicalize } from '../src/index.js';

function setup(t) {
  const dir = tempDir(t);
  const f = {
    dir,
    keyed: join(dir, 'keyed.jsonl'),
    plain: join(dir, 'plain.jsonl'),
    key: join(dir, 'key'),
    other: join(dir, 'other-key'),
    anchor: join(dir, 'anchor.json'),
    out: join(dir, 'out.json'),
  };
  writeFileSync(f.key, KEY);
  writeFileSync(f.other, OTHER_KEY);
  writeLog(f.keyed, buildRecords(3, KEY));
  // The downgrade: the attacker rewrites the whole log as a plain log with the same events and a recomputed chain.
  writeLog(f.plain, buildRecords(3, null));
  return f;
}

const findings = (r) => JSON.parse(r.stdout).findings;

test('downgrade: a keyed log rewritten as plain fails when a key is supplied', (t) => {
  const f = setup(t);
  expectOk(cli(['verify', f.keyed, '--key-file', f.key]));
  const r = cli(['verify', f.plain, '--key-file', f.key, '--format', 'json']);
  assert.equal(r.status, 1, r.stderr);
  assert.equal(r.stderr, '');
  assert.deepEqual(findings(r), [{ kind: 'key_mismatch', seq: 0, detail: 'header_not_keyed' }]);
});

test('downgrade: without a key or an anchor the plain rewrite is accepted (documented limit)', (t) => {
  const f = setup(t);
  expectOk(cli(['verify', f.plain]));
});

test('downgrade: --require-keyed fails the same way and is a usage error without a key file', (t) => {
  const f = setup(t);
  const r = cli(['verify', f.plain, '--key-file', f.key, '--require-keyed', '--format', 'json']);
  assert.equal(r.status, 1);
  assert.deepEqual(findings(r), [{ kind: 'key_mismatch', seq: 0, detail: 'header_not_keyed' }]);
  expectOk(cli(['verify', f.keyed, '--key-file', f.key, '--require-keyed']));
  expectFail(cli(['verify', f.plain, '--require-keyed']), 3, 'usage_error');
  expectFail(cli(['verify', f.keyed, '--require-keyed']), 3, 'usage_error');
  expectFail(cli(['verify', f.plain, '--require-keyed=yes', '--key-file', f.key]), 3, 'usage_error');
});

test('downgrade: library option requireKeyed', async (t) => {
  const f = setup(t);
  const report = await verifyLog(f.plain, { keyFile: f.key, requireKeyed: true });
  assert.equal(report.ok, false);
  assert.equal(report.findings[0].detail, 'header_not_keyed');
  assert.equal((await verifyLog(f.keyed, { keyFile: f.key, requireKeyed: true })).ok, true);
  await assert.rejects(verifyLog(f.keyed, { requireKeyed: true }), { kind: 'usage_error' });
});

test('downgrade: append with the key refuses the plain rewrite and never changes it', (t) => {
  const f = setup(t);
  const before = toText(buildRecords(3, null));
  expectFail(cli(['append', f.plain, '--type', 'x', '--key-file', f.key]), 2, 'key_invalid');
  assert.equal(cli(['verify', f.plain]).status, 0);
  assert.equal(before, toText(buildRecords(3, null)));
});

test('downgrade: a keyed anchor catches the rewrite and needs the key', (t) => {
  const f = setup(t);
  expectOk(cli(['anchor', f.keyed, '--out', f.anchor, '--key-file', f.key]));
  const r = cli(['verify', f.plain, '--anchor', f.anchor, '--key-file', f.key, '--format', 'json']);
  assert.equal(r.status, 1);
  const kinds = findings(r).map((x) => x.kind + ':' + x.detail);
  assert.ok(kinds.includes('key_mismatch:header_not_keyed'), kinds.join());
  assert.ok(kinds.includes('mode_change:anchor_mode_differs'), kinds.join());
  expectFail(cli(['verify', f.plain, '--anchor', f.anchor]), 2, 'key_required');
});

test('downgrade: a plain anchor of the original does not hide a keyed log verified with the key', (t) => {
  const f = setup(t);
  const records = buildRecords(3, null);
  writeFileSync(f.anchor, canonicalize(anchor(records, T0, null)) + '\n');
  const r = cli(['verify', f.keyed, '--anchor', f.anchor, '--key-file', f.key, '--format', 'json']);
  assert.equal(r.status, 1);
  assert.ok(findings(r).some((x) => x.kind === 'mode_change'));
});

test('anchor command: key problems are key_invalid, a missing key is key_required', (t) => {
  const f = setup(t);
  expectFail(cli(['anchor', f.keyed, '--out', f.out, '--key-file', f.other]), 2, 'key_invalid');
  expectFail(cli(['anchor', f.plain, '--out', f.out, '--key-file', f.key]), 2, 'key_invalid');
  expectFail(cli(['anchor', f.keyed, '--out', f.out]), 2, 'key_required');
  expectOk(cli(['anchor', f.keyed, '--out', f.out, '--key-file', f.key]));
  expectOk(cli(['verify', f.keyed, '--anchor', f.out, '--key-file', f.key]));
});

test('anchor library: wrong key and plain log with key', async (t) => {
  const f = setup(t);
  await assert.rejects(createAnchor(f.keyed, { keyFile: f.other }), { kind: 'key_invalid' });
  await assert.rejects(createAnchor(f.plain, { keyFile: f.key }), { kind: 'key_invalid' });
  await assert.rejects(createAnchor(f.keyed, {}), { kind: 'key_required' });
  const a = await createAnchor(f.keyed, { keyFile: f.key });
  assert.equal(a.mode, 'hmac-sha256');
});
