import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cli, KEY, tempDir } from '../reference/helpers.js';
import { appendRecord, verifyLog } from '../src/index.js';

const KINDS = new Set([
  'bad_header',
  'bad_record',
  'hash_mismatch',
  'chain_break',
  'seq_gap',
  'time_regress',
  'mode_change',
  'key_mismatch',
  'truncated_tail',
  'anchor_mismatch',
  'trailing_garbage',
  'truncated_report',
]);
const DETAILS = new Set([
  'header_invalid',
  'record_invalid',
  'hash_differs',
  'prev_differs',
  'seq_not_contiguous',
  'time_earlier_than_previous',
  'anchor_mode_differs',
  'key_id_differs',
  'log_shorter_than_anchor',
  'anchor_head_differs',
  'unterminated_or_extra_line',
  'more_than_100_findings',
  'line_not_canonical',
  'header_not_keyed',
  'anchor_hash_invalid',
  'anchor_invalid',
]);
const ERROR_KINDS = [
  'input_unreadable',
  'invalid_record',
  'log_corrupt',
  'limit_exceeded',
  'credential_detected',
  'key_required',
  'key_invalid',
  'internal_error',
];
const isErrorLine = (text) =>
  ERROR_KINDS.some((k) =>
    text === `joons-mcp-audit-trail: ${k}
`
  );

function rng(seed) {
  let s = seed >>> 0;
  return (n) => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s % n;
  };
}

// Cutting the log at a record boundary is the one change that only an anchor can reveal (documented limit).
const isBoundaryCut = (original, bytes) =>
  bytes.length > 0 && bytes[bytes.length - 1] === 10 && original.subarray(0, bytes.length).equals(bytes);

/** One seeded mutation of the original bytes. The caller skips results equal to the original. */
function mutate(original, next) {
  const bytes = Buffer.from(original);
  const kind = next(10);
  const at = next(bytes.length);
  const lines = original.toString('utf8').split('\n').slice(0, -1);
  switch (kind) {
    case 0: {
      bytes[at] ^= 1 << next(8);
      return bytes;
    }
    case 1: {
      bytes[at] = (bytes[at] + 1 + next(255)) & 255;
      return bytes;
    }
    case 2:
      return Buffer.concat([bytes.subarray(0, at), bytes.subarray(at + 1)]);
    case 3:
      return Buffer.concat([bytes.subarray(0, at), Buffer.from([next(256)]), bytes.subarray(at)]);
    case 4:
      return Buffer.concat([bytes.subarray(0, at), Buffer.from(' '), bytes.subarray(at)]);
    case 5: {
      const i = next(lines.length);
      return Buffer.from([...lines.slice(0, i + 1), lines[i], ...lines.slice(i + 1)].join('\n') + '\n');
    }
    case 6: {
      const i = next(lines.length - 1);
      const swapped = lines.slice();
      [swapped[i], swapped[i + 1]] = [swapped[i + 1], swapped[i]];
      return Buffer.from(swapped.join('\n') + '\n');
    }
    case 7:
      return bytes.subarray(0, at);
    case 8: {
      // flip one hex digit inside a hash field
      const text = original.toString('utf8');
      const positions = [...text.matchAll(/"hash":"([a-f0-9]{64})"/g)].map((m) => m.index + 8);
      const p = positions[next(positions.length)] + next(64);
      bytes[p] = bytes[p] === 48 ? 49 : 48;
      return bytes;
    }
    default: {
      const i = next(lines.length);
      return Buffer.from(lines.filter((_, k) => k !== i).join('\n') + '\n');
    }
  }
}

async function build(dir, keyed, count) {
  const log = join(dir, keyed ? 'keyed.jsonl' : 'plain.jsonl');
  const keyFile = join(dir, 'key');
  writeFileSync(keyFile, KEY);
  for (let i = 0; i < count; i++) {
    const event = {
      type: 'evt' + i,
      actor: 'actor' + (i % 3),
      tool: 'tool',
      outcome: 'ok',
      data: { i, nested: { list: [1, 2, 3], text: 'value ' + i } },
    };
    await appendRecord(log, event, { now: '2026-01-02T03:04:05.000Z', ...(keyed ? { keyFile } : {}) });
  }
  return { log, keyFile, original: readFileSync(log) };
}

function checkReport(report, label) {
  assert.equal(report.ok, false, label + ': a mutated log must never verify as OK');
  const ids = new Set();
  for (const f of report.findings) {
    assert.ok(KINDS.has(f.kind), label + ' kind ' + f.kind);
    assert.ok(DETAILS.has(f.detail), label + ' detail ' + f.detail);
    const id = [f.kind, f.seq, f.detail].join('|');
    assert.ok(!ids.has(id), label + ' duplicate finding ' + id);
    ids.add(id);
  }
  assert.ok(report.findings.length <= 101);
}

for (const keyed of [false, true]) {
  test(`in-process fuzz (${keyed ? 'keyed' : 'plain'}): 1,200 seeded mutations are all detected`, async (t) => {
    const dir = tempDir(t);
    const { log, keyFile, original } = await build(dir, keyed, 16);
    const next = rng(keyed ? 0x1badcafe : 0x93bcb842);
    const options = keyed ? { keyFile } : {};
    const target = join(dir, 'mutated.jsonl');
    const started = Date.now();
    let compared = 0;
    let cuts = 0;
    for (let n = 0; n < 1200; n++) {
      const bytes = mutate(original, next);
      if (bytes.equals(original)) continue;
      writeFileSync(target, bytes);
      compared++;
      let report;
      try {
        report = await verifyLog(target, options);
        if (isBoundaryCut(original, bytes)) {
          assert.equal(report.ok, true, 'a cut at a record boundary is only detectable with an anchor');
          cuts++;
          continue;
        }
      } catch (e) {
        // The only allowed failures are the fixed error kinds (a mutation can empty the file).
        assert.ok(['input_unreadable', 'log_corrupt', 'key_required', 'limit_exceeded'].includes(e.kind), e.kind);
        continue;
      }
      checkReport(report, 'case ' + n);
    }
    assert.ok(compared > 1100);
    assert.ok(cuts < 300);
    assert.ok(Date.now() - started < 120000);
    assert.deepEqual(readFileSync(log), original);
  });
}

test('about 100 real-process mutations: exit 1 with a report, or exit 2 with one fixed error line', async (t) => {
  const dir = tempDir(t);
  const { original } = await build(dir, false, 8);
  const next = rng(0x5eed1234);
  const target = join(dir, 'mutated.jsonl');
  let reports = 0;
  for (let n = 0; n < 100; n++) {
    const bytes = mutate(original, next);
    if (bytes.equals(original)) continue;
    writeFileSync(target, bytes);
    const r = cli(['verify', target]);
    if (isBoundaryCut(original, bytes)) {
      assert.equal(r.status, 0);
      continue;
    }
    assert.ok([1, 2].includes(r.status), `case ${n}, status ${r.status}, stderr ${r.stderr}`);
    assert.doesNotMatch(r.stderr, /fatal|stack|v8|at .*\(/i);
    if (r.status === 1) {
      assert.equal(r.stderr, '');
      assert.match(r.stdout, /^verify: FAILED\n/);
      reports++;
    } else {
      assert.equal(r.stdout, '');
      assert.ok(isErrorLine(r.stderr), r.stderr);
    }
  }
  assert.ok(reports > 80);
});
