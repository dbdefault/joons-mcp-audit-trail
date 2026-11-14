import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const bin = fileURLToPath(new URL('../bin/joons-mcp-audit-trail.js', import.meta.url));

test('launcher real process: help, version and usage error', () => {
  for (
    const [args, code, out, err] of [
      [['--version'], 0, 'joons-mcp-audit-trail 0.1.0\n', ''],
      [['--help'], 0, 'Usage:', ''],
      [['invalid'], 3, '', 'joons-mcp-audit-trail: usage_error\n'],
    ]
  ) {
    const r = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', windowsHide: true });
    assert.equal(r.status, code);
    assert.ok(r.stdout.startsWith(out));
    assert.equal(r.stderr, err);
  }
});
