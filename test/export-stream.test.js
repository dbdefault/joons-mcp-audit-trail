import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createWriteStream, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { cli, cliPath, expectFail, expectOk, tempDir } from '../reference/helpers.js';
import { canonicalize } from '../reference/model.js';
import { renderExport } from '../src/report/index.js';
import { pathToFileURL } from 'node:url';

/** Tiny in-test generator: a valid plain log of `count` events, written in batches (memory stays small). */
async function generateLog(path, count, { start = Date.parse('2026-01-01T00:00:00Z'), tail = '' } = {}) {
  const out = createWriteStream(path);
  const sha = (r) => createHash('sha256').update(canonicalize(r)).digest('hex');
  const stamp = (i) => new Date(start + i * 1000).toISOString();
  const finish = (r) => canonicalize({ ...r, hash: sha(r) });
  let prev = '0'.repeat(64);
  const header = {
    format: 'joons-mcp-audit-trail/log',
    version: 1,
    seq: 0,
    time: stamp(0),
    mode: 'sha256',
    keyId: null,
    prev,
  };
  prev = sha(header);
  let buffer = finish(header) + '\n';
  for (let i = 1; i <= count; i++) {
    const record = {
      seq: i,
      time: stamp(i),
      type: 'tool.call',
      actor: 'agent-' + (i % 7),
      tool: i % 3 ? 'search' : null,
      outcome: 'ok',
      data: { index: i, note: 'record number ' + i },
      prev,
    };
    prev = sha(record);
    buffer += finish(record) + '\n';
    if (buffer.length > 1 << 20) {
      if (!out.write(buffer)) await once(out, 'drain');
      buffer = '';
    }
  }
  out.end(buffer + tail);
  await once(out, 'finish');
}

test('streamed export is byte-identical to the whole-list renderer (JSON and CSV)', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await generateLog(log, 3000);
  const records = readFileSync(log, 'utf8').split('\n').slice(0, -1).map((l) => JSON.parse(l));
  const json = join(dir, 'out.json');
  const csv = join(dir, 'out.csv');
  expectOk(cli(['export', log, '--out', json, '--format', 'json']));
  expectOk(cli(['export', log, '--out', csv, '--format', 'csv']));
  assert.equal(readFileSync(json, 'utf8'), renderExport(records, 'json'));
  assert.equal(readFileSync(csv, 'utf8'), renderExport(records, 'csv'));
  // The JSON bytes also equal an independent rendering (records are stored with sorted keys).
  assert.equal(readFileSync(json, 'utf8'), JSON.stringify(records, null, 2) + '\n');
  const rows = readFileSync(csv, 'utf8').split('\r\n');
  assert.equal(rows.length, 3002 + 1);
  assert.equal(rows[0], '"seq","time","type","actor","tool","outcome","data","prev","hash"');
  assert.deepEqual(readdirSync(dir).sort(), ['log.jsonl', 'out.csv', 'out.json']);
});

test('an export that fails half-way leaves neither the target nor a temp file', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await generateLog(log, 3000, { tail: 'null\n' });
  for (const format of ['json', 'csv']) {
    expectFail(cli(['export', log, '--out', join(dir, 'out.' + format), '--format', format]), 2, 'log_corrupt');
  }
  assert.deepEqual(readdirSync(dir), ['log.jsonl']);
});

test('export of an empty-looking small log and of the header alone', async (t) => {
  const dir = tempDir(t);
  const log = join(dir, 'log.jsonl');
  await generateLog(log, 0);
  expectOk(cli(['export', log, '--out', join(dir, 'h.json'), '--format', 'json']));
  assert.equal(JSON.parse(readFileSync(join(dir, 'h.json'), 'utf8')).length, 1);
});

const measureScript = `
import { main } from ${JSON.stringify(pathToFileURL(join(cliPath, '..', '..', 'src', 'cli', 'index.js')).href)};
const code = await main(process.argv.slice(1), { stdout: process.stdout, stderr: process.stderr });
const usage = process.resourceUsage();
const heapMb = Math.round(process.memoryUsage().heapUsed / 1048576);
console.log(JSON.stringify({ code, maxRssKb: usage.maxRSS, heapMb }));
`;

function measuredExport(args, heapMb) {
  const r = spawnSync(process.execPath, [
    '--max-old-space-size=' + heapMb,
    '--input-type=module',
    '-e',
    measureScript,
    ...args,
  ], {
    encoding: 'utf8',
    timeout: 300000,
    windowsHide: true,
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout.trim().split('\n').at(-1));
}

for (const format of ['json', 'csv']) {
  test(`scaled memory check: 200,000 records export as ${format} with a small heap and a low peak RSS`, async (t) => {
    const dir = tempDir(t);
    const log = join(dir, 'log.jsonl');
    await generateLog(log, 200000);
    const logSize = statSync(log).size;
    assert.ok(logSize > 40 * 1024 * 1024, 'log is ' + logSize);
    const out = join(dir, 'out.' + format);
    const result = measuredExport(['export', log, '--out', out, '--format', format], 96);
    assert.equal(result.code, 0);
    // Reading the whole log into memory would need several times the log size; streaming stays near node's base.
    assert.ok(result.maxRssKb < 220 * 1024, 'peak RSS ' + Math.round(result.maxRssKb / 1024) + ' MB');
    assert.ok(statSync(out).size > logSize / 2);
    // Spot check: first and last lines of the output.
    const text = readFileSync(out, 'utf8');
    if (format === 'json') {
      assert.ok(text.startsWith('[\n  {\n    "format": "joons-mcp-audit-trail/log"'));
      assert.ok(text.endsWith('\n  }\n]\n'));
    } else {
      assert.equal(text.split('\r\n').length, 200002 + 1);
    }
    writeFileSync(join(dir, 'done'), '');
  });
}
