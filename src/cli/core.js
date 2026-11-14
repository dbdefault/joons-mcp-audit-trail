import { parseArgs } from './args.js';
import { hasDuplicateKeys } from './strict-json.js';
import { checkPath } from '../log/paths.js';
const name = 'joons-mcp-audit-trail';
const kinds = new Set([
  'input_unreadable',
  'invalid_record',
  'log_corrupt',
  'limit_exceeded',
  'credential_detected',
  'key_required',
  'key_invalid',
  'usage_error',
  'output_error',
  'lock_timeout',
  'internal_error',
]);
const outputKinds = new Set(['output_error', 'lock_timeout']);
export const help = `Usage: joons-mcp-audit-trail <command> <log> [options]
  append <log> --type TYPE [--actor A] [--tool T] [--outcome OUTCOME] [--data FILE] [--time ISO] [--key-file FILE]
  verify <log> [--anchor FILE] [--key-file FILE] [--require-keyed] [--format terminal|json]
  anchor <log> --out FILE [--key-file FILE] [--force]
  show <log> [--from N] [--to N] [--format terminal|json]
  summary <log> [--details] [--format terminal|json|markdown]
  export <log> --out FILE --format json|csv [--force]
  --help | --version
`;
async function writeOutput(stream, text) {
  if (!stream) throw new OutputFailure();
  if (typeof stream.once !== 'function') {
    try {
      stream.write(text);
      return;
    } catch {
      throw new OutputFailure();
    }
  }
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = (error) => {
      if (done) return;
      done = true;
      if (!error) stream.removeListener('error', onError);
      error ? reject(new OutputFailure()) : resolve();
    };
    const onError = () => finish(true);
    stream.once('error', onError);
    try {
      stream.write(text, (error) => finish(error));
    } catch {
      finish(true);
    }
  });
}
export async function run(argv, io, deps) {
  let parsed;
  const err = (kind) => {
    try {
      io.stderr?.write(`${name}: ${kind}\n`);
    } catch {}
    return kind === 'usage_error' ? 3 : outputKinds.has(kind) ? 4 : 2;
  };
  const write = (text) => writeOutput(io.stdout, text);
  try {
    parsed = parseArgs(argv);
  } catch {
    return err('usage_error');
  }
  try {
    const { command, log, options: o } = parsed;
    if (command === 'version') {
      await write('joons-mcp-audit-trail 0.1.0\n');
      return 0;
    }
    if (command === 'help') {
      await write(help);
      return 0;
    }
    const keyFile = o['key-file'];
    if (command === 'append') {
      const event = {
        type: o.type,
        actor: o.actor ?? null,
        tool: o.tool ?? null,
        outcome: o.outcome ?? null,
        data: o.data ? await readDataObject(o.data, deps) : null,
        ...(o.time ? { time: o.time } : {}),
      };
      const result = await deps.appendRecord(log, event, { keyFile, ...(o.time ? { now: o.time } : {}) });
      await write(JSON.stringify(result) + '\n');
    } else if (command === 'verify') {
      const report = await deps.verifyLog(log, { keyFile, anchorFile: o.anchor, requireKeyed: !!o['require-keyed'] });
      await write(deps.renderVerify(report, o.format || 'terminal'));
      return report.ok ? 0 : 1;
    } else if (command === 'anchor') {
      const anchor = await deps.createAnchor(log, { keyFile });
      await deps.writeFileAtomic(o.out, deps.canonicalize(anchor) + '\n', {
        force: !!o.force,
        protect: [log, keyFile],
      });
    } else if (command === 'summary') {
      await write(deps.renderSummary(await deps.summarize(log, { details: !!o.details }), o.format || 'terminal'));
    } else if (command === 'show') {
      await write(await collectShow(log, o, deps));
    } else {
      await streamExport(log, o, deps);
    }
    return 0;
  } catch (e) {
    if (e instanceof OutputFailure || e?.code === 'EPIPE') return err('output_error');
    const kind = e instanceof deps.AuditError && kinds.has(e.kind) ? e.kind : 'internal_error';
    return err(kind);
  }
}
class OutputFailure extends Error {}

async function readDataObject(path, deps) {
  const raw = await deps.readData(path);
  if (raw.length > 32768) throw new deps.AuditError('limit_exceeded');
  let data;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    data = JSON.parse(text);
    if (hasDuplicateKeys(text)) throw new Error('duplicate key');
  } catch {
    throw new deps.AuditError('invalid_record');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new deps.AuditError('invalid_record');
  return data;
}

const MAX_SHOW_RECORDS = 10000;
const MAX_SHOW_BYTES = 16 * 1024 * 1024;

// Renders the selected range piece by piece and stops as soon as the rendered output would pass 16 MiB.
async function collectShow(log, o, deps) {
  const parts = deps.showParts(o.format || 'terminal');
  const from = +(o.from || 1);
  const chunks = [parts.head()];
  let bytes = Buffer.byteLength(chunks[0]);
  let selected = 0;
  let lines = 0;
  for await (const item of deps.readRecords(log, {})) {
    lines++;
    const record = deps.checkedRecord(item);
    if (record.seq < from || (o.to && record.seq > +o.to)) continue;
    if (selected >= MAX_SHOW_RECORDS) throw new deps.AuditError('limit_exceeded');
    const piece = parts.item(record, selected++);
    bytes += Buffer.byteLength(piece);
    if (bytes > MAX_SHOW_BYTES) throw new deps.AuditError('limit_exceeded');
    chunks.push(piece);
  }
  if (lines === 0) throw new deps.AuditError('log_corrupt');
  const tail = parts.tail(selected);
  // The cap counts the whole output, the closing tail included.
  if (bytes + Buffer.byteLength(tail) > MAX_SHOW_BYTES) throw new deps.AuditError('limit_exceeded');
  chunks.push(tail);
  return chunks.join('');
}

async function streamExport(log, o, deps) {
  const parts = deps.exportParts(o.format);
  // The log path is checked as text before anything (the output writer included) touches it.
  checkPath(log, 'input_unreadable', { log: true });
  const writer = await deps.createAtomicWriter(o.out, { force: !!o.force, protect: [log] });
  try {
    await writer.write(parts.head());
    let count = 0;
    for await (const item of deps.readRecords(log, {})) {
      const record = deps.checkedRecord(item);
      if (count >= 1000000) throw new deps.AuditError('limit_exceeded');
      await writer.write(parts.item(record, count++));
    }
    if (count === 0) throw new deps.AuditError('log_corrupt');
    await writer.write(parts.tail(count));
    await writer.commit();
  } finally {
    await writer.abort();
  }
}
