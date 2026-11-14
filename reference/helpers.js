// Shared helpers for the test suite. Lives outside test/ so that `node --test` does not run it as a test file.
import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { canonicalize, event, header } from './model.js';

export const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
export const cliPath = join(root, 'bin', 'joons-mcp-audit-trail.js');
export const KEY = Buffer.from('0123456789abcdef');
export const OTHER_KEY = Buffer.from('fedcba9876543210');
export const T0 = '2026-01-02T03:04:05.000Z';

export function tempDir(t, prefix = 'audit-t-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Runs the real command line program. */
export function cli(args, options = {}) {
  return spawnSync(process.execPath, [...(options.nodeArgs ?? []), cliPath, ...args], {
    encoding: 'utf8',
    timeout: options.timeout ?? 60000,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  });
}

export const errLine = (kind) => `joons-mcp-audit-trail: ${kind}\n`;

export function expectOk(r) {
  assert.equal(r.status, 0, `${r.stderr}\n${r.stdout}`);
  assert.equal(r.stderr, '');
}

export function expectFail(r, code, kind) {
  assert.equal(r.status, code, `${r.stderr}\n${r.stdout}`);
  assert.equal(r.stdout, '');
  assert.equal(r.stderr, errLine(kind));
}

/** Records of a valid log built with the independent reference model: header plus `n` events one second apart. */
export function buildRecords(n = 3, key = null, start = Date.parse('2026-01-01T00:00:00Z')) {
  const iso = (i) => new Date(start + i * 1000).toISOString();
  const records = [header(iso(0), key)];
  for (let i = 1; i <= n; i++) {
    records.push(event(i, iso(i), 'event' + i, records.at(-1).hash, { n: i }, 'agent', 'tool', 'ok', key));
  }
  return records;
}

export const toText = (records) => records.map((r) => canonicalize(r)).join('\n') + '\n';

export function writeLog(path, records) {
  writeFileSync(path, toText(records));
}

export const readLines = (path) => readFileSync(path, 'utf8').split('\n').slice(0, -1);

/** Writes a valid plain log directly (not through appendRecord): `count` events with a fat data object each. */
export function writeFatLog(path, count, { keys = 8, width = 4000 } = {}) {
  const fd = openSync(path, 'w');
  try {
    let record = header('2026-01-01T00:00:00.000Z');
    writeSync(fd, canonicalize(record) + '\n');
    const data = {};
    for (let k = 0; k < keys; k++) data['k' + k] = 'x'.repeat(width);
    for (let i = 1; i <= count; i++) {
      record = event(i, '2026-01-01T00:00:00.000Z', 'fat', record.hash, data, 'agent', 'tool', 'ok');
      writeSync(fd, canonicalize(record) + '\n');
    }
  } finally {
    closeSync(fd);
  }
}
