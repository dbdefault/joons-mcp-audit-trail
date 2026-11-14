import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { run } from '../src/cli/core.js';
import { parseArgs } from '../src/cli/args.js';
import { checkedRecord } from '../src/report/index.js';
import { AuditError as RealAuditError } from '../src/errors.js';
class AuditError extends Error {
  constructor(kind) {
    super(kind);
    this.kind = kind;
  }
}
const stream = () => ({
  value: '',
  write(s) {
    this.value += s;
  },
});
const make = () => ({ stdout: stream(), stderr: stream() });
const errors = [
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
];
for (const [kind, code] of errors) {
  test(`error ${kind}`, async () => {
    const io = make();
    const d = {
      AuditError,
      verifyLog: async () => {
        throw new AuditError(kind);
      },
    };
    assert.equal(await run(['verify', 'log'], io, d), code);
    assert.equal(io.stderr.value, `joons-mcp-audit-trail: ${kind}\n`);
  });
}
for (
  const argv of [
    [],
    ['--help', 'x'],
    ['--version', '--help'],
    ['append', 'x'],
    ['append', 'x', '--type='],
    ['verify', 'x', '--format', 'csv'],
    ['verify', 'x', '--format', 'json', '--format', 'json'],
    ['verify', 'x', '--force'],
    ['verify', 'x', '--'],
    ['verify', 'x', 'y'],
    ['anchor', 'x'],
    ['anchor', 'x', '--out', 'y', '--force=no'],
    ['show', 'x', '--from', '0'],
    ['show', 'x', '--from', '1', '--to', '10001'],
    ['show', 'x', '--to', '9007199254740992'],
    ['summary', 'x', '--format', 'csv'],
    ['export', 'x', '--format', 'csv'],
    ['export', 'x', '--out', 'y', '--format', 'terminal'],
  ]
) test(`reject ${argv.join(' ')}`, () => assert.throws(() => parseArgs(argv)));
for (const [argv, expected] of [[['--version'], 'joons-mcp-audit-trail 0.1.0\n'], [['--help'], 'Usage:']]) {
  test(`output ${argv}`, async () => {
    const io = make();
    assert.equal(await run(argv, io, { AuditError }), 0);
    assert.ok(io.stdout.value.startsWith(expected));
  });
}
for (const kind of ['throw', 'callback', 'event']) {
  test(`output failure ${kind}`, async () => {
    const io = make();
    if (kind === 'throw') {
      io.stdout = {
        write() {
          throw Error();
        },
      };
    } else {
      io.stdout = new EventEmitter();
      io.stdout.write = (_s, cb) => {
        if (kind === 'callback') cb(Error());
        else io.stdout.emit('error', Error());
      };
    }
    assert.equal(await run(['--version'], io, { AuditError }), 4);
    assert.equal(io.stderr.value, 'joons-mcp-audit-trail: output_error\n');
  });
}
test('append wires fields and key', async () => {
  const io = make();
  let actual;
  const d = {
    AuditError,
    readData: async () => Buffer.from('{"a":1}'),
    appendRecord: async (...a) => (actual = a, { seq: 1, hash: 'a' }),
  };
  assert.equal(
    await run(
      ['append', 'log', '--type', 'x', '--data', 'data', '--key-file', 'key', '--time', '2026-01-01T00:00:00Z'],
      io,
      d,
    ),
    0,
  );
  assert.equal(actual[0], 'log');
  assert.deepEqual(actual[1].data, { a: 1 });
  assert.equal(actual[2].keyFile, 'key');
});
for (
  const [label, buf, kind] of [
    ['bom', Buffer.from([0xef, 0xbb, 0xbf, 123, 125]), 'invalid_record'],
    ['bad utf8', Buffer.from([0xff]), 'invalid_record'],
    ['array', Buffer.from('[]'), 'invalid_record'],
    ['oversize', Buffer.alloc(32769), 'limit_exceeded'],
    ['bad json', Buffer.from('{'), 'invalid_record'],
  ]
) {
  test(`data ${label}`, async () => {
    const io = make();
    assert.equal(
      await run(['append', 'log', '--type', 'x', '--data', 'x'], io, { AuditError, readData: async () => buf }),
      2,
    );
    assert.equal(io.stderr.value, `joons-mcp-audit-trail: ${kind}\n`);
  });
}
test('verify wires anchor and format and preserves findings', async () => {
  const io = make();
  let got;
  const d = { AuditError, verifyLog: async (...a) => (got = a, { ok: false }), renderVerify: (_r, f) => f };
  assert.equal(await run(['verify', 'l', '--anchor', 'a', '--key-file', 'k', '--format', 'json'], io, d), 1);
  assert.deepEqual(got, ['l', { keyFile: 'k', anchorFile: 'a', requireKeyed: false }]);
  assert.equal(io.stdout.value, 'json');
});
test('anchor writes force', async () => {
  const io = make();
  let got;
  const d = {
    AuditError,
    createAnchor: async () => ({ count: 1 }),
    canonicalize: (x) => JSON.stringify(x),
    writeFileAtomic: async (...a) => got = a,
  };
  assert.equal(await run(['anchor', 'l', '--out', 'a', '--force'], io, d), 0);
  assert.deepEqual(got, ['a', '{"count":1}\n', { force: true, protect: ['l', undefined] }]);
});
test('summary selects details and markdown', async () => {
  const io = make();
  const d = { AuditError, summarize: async (_l, o) => o, renderSummary: (o, f) => `${o.details}:${f}` };
  assert.equal(await run(['summary', 'l', '--details', '--format', 'markdown'], io, d), 0);
  assert.equal(io.stdout.value, 'true:markdown');
});
for (const command of ['show', 'export']) {
  test(`${command} selects format`, async () => {
    const io = make();
    let got, written = '';
    const d = {
      AuditError,
      readRecords: async function* () {
        yield { record: { seq: 1 } };
        yield { record: { seq: 2 } };
      },
      checkedRecord: (item) => item.record,
      showParts: (f) => ({
        head: () => f + ':',
        item: (r, i) => `${r.seq}.${i};`,
        tail: (n) => `end${n}`,
      }),
      exportParts: (f) => ({
        head: () => f + ':',
        item: (r, i) => `${r.seq}.${i};`,
        tail: (n) => `end${n}`,
      }),
      createAtomicWriter: async (...a) => ({
        write: async (x) => written += x,
        commit: async () => got = a,
        abort: async () => {},
      }),
    };
    const argv = command === 'show'
      ? ['show', 'l', '--from', '2', '--format', 'json']
      : ['export', 'l', '--out', 'o', '--format', 'csv'];
    assert.equal(await run(argv, io, d), 0);
    if (command === 'show') assert.equal(io.stdout.value, 'json:2.0;end1');
    else {
      assert.deepEqual(got, ['o', { force: false, protect: ['l'] }]);
      assert.equal(written, 'csv:1.0;2.1;end2');
    }
  });
}
test('line error fails closed', async () => {
  const io = make();
  const d = {
    AuditError: RealAuditError,
    checkedRecord,
    showParts: () => ({ head: () => '[', item: () => '', tail: () => ']' }),
    readRecords: async function* () {
      yield { error: 'bad_json', lineNo: 1 };
    },
  };
  assert.equal(await run(['show', 'l'], io, d), 2);
  assert.equal(io.stderr.value, 'joons-mcp-audit-trail: log_corrupt\n');
});
