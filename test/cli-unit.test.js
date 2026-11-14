import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../src/cli/args.js';
import { run } from '../src/cli/core.js';
class AuditError extends Error {
  constructor(kind) {
    super();
    this.kind = kind;
  }
}
const capture = () => {
  let text = '';
  return {
    write(s) {
      text += s;
    },
    get text() {
      return text;
    },
  };
};
const io = () => ({ stdout: capture(), stderr: capture() });
test('argument usage errors', () => {
  for (
    const argv of [
      [],
      ['wat'],
      ['append', 'x'],
      ['verify', 'x', '--'],
      ['verify', 'x', 'extra'],
      ['verify', 'x', '--bad'],
      ['verify', 'x', '--format'],
      ['verify', 'x', '--format='],
      ['verify', 'x', '--format=json', '--format=json'],
      ['anchor', 'x', '--out', 'y', '--force=yes'],
      ['export', 'x', '--out', 'y', '--format', 'terminal'],
      ['show', 'x', '--from', '0'],
      ['show', 'x', '--from', '2', '--to', '1'],
      ['summary', 'x', '--key-file', 'x'],
    ]
  ) assert.throws(() => parseArgs(argv));
});
test('options accept both forms', () => {
  assert.equal(parseArgs(['append', 'a', '--type=x']).options.type, 'x');
  assert.equal(parseArgs(['verify', 'a', '--format', 'json']).options.format, 'json');
});
test('fixed errors and exit codes', async () => {
  for (
    const [kind, code] of [
      ['input_unreadable', 2],
      ['invalid_record', 2],
      ['log_corrupt', 2],
      ['limit_exceeded', 2],
      ['credential_detected', 2],
      ['key_required', 2],
      ['key_invalid', 2],
      ['usage_error', 3],
      ['output_error', 4],
      ['lock_timeout', 4],
      ['internal_error', 2],
    ]
  ) {
    const streams = io();
    const deps = {
      AuditError,
      verifyLog: async () => {
        throw new AuditError(kind);
      },
    };
    assert.equal(await run(['verify', 'a'], streams, deps), code);
    assert.equal(streams.stderr.text, `joons-mcp-audit-trail: ${kind}\n`);
  }
});
test('unknown error and failed output', async () => {
  let streams = io();
  assert.equal(
    await run(['verify', 'a'], streams, {
      AuditError,
      verifyLog: () => {
        throw Error('sensitive');
      },
    }),
    2,
  );
  assert.equal(streams.stderr.text, 'joons-mcp-audit-trail: internal_error\n');
  streams = io();
  streams.stdout = null;
  assert.equal(await run(['--version'], streams, { AuditError }), 4);
  assert.equal(streams.stderr.text, 'joons-mcp-audit-trail: output_error\n');
});
test('verification findings return one', async () => {
  const streams = io();
  assert.equal(
    await run(['verify', 'a'], streams, {
      AuditError,
      verifyLog: async () => ({ ok: false }),
      renderVerify: () => 'bad\n',
    }),
    1,
  );
  assert.equal(streams.stderr.text, '');
});
