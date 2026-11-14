import { readRecords } from '../log/index.js';
import { AuditError } from '../errors.js';
import { canonicalize, looksLikeRecord } from '../canon/index.js';

/**
 * Terminal sanitizer: control characters, bidirectional and invisible formatting characters, variation selectors,
 * tag characters, fillers, private-use characters and lone surrogates are replaced by "?".
 */
const UNSAFE = [
  // Default-ignorable, format (Cf), control (Cc), private-use (Co), surrogate (Cs) and unassigned (Cn) code points.
  /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Co}\p{Cs}\p{Cn}]/gu,
  // Format characters that older Unicode data lacks (22 code points), plus the explicit list of earlier versions.
  /[\u{110bd}\u{110cd}\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}]/gu,
  /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{ad}\u{34f}\u{600}-\u{605}\u{61c}\u{6dd}\u{70f}\u{890}\u{891}\u{8e2}]/gu,
  /[\u{115f}\u{1160}\u{17b4}\u{17b5}\u{180b}-\u{180f}\u{200b}-\u{200f}\u{2028}-\u{202e}\u{2060}-\u{2064}]/gu,
  /[\u{2066}-\u{206f}\u{2800}\u{3164}\u{fe00}-\u{fe0f}\u{feff}\u{ffa0}\u{fff9}-\u{fffc}]/gu,
  /[\u{d800}-\u{dfff}\u{e000}-\u{f8ff}\u{1d173}-\u{1d17a}\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu,
  /[\u{f0000}-\u{10ffff}]/gu,
  // Non-ASCII space separators (Zs other than U+0020).
  /[\u{a0}\u{1680}\u{2000}-\u{200a}\u{202f}\u{205f}\u{3000}]/gu,
];
const PLAIN_ASCII = /^[\u{20}-\u{7e}]*$/u;
export function sanitizeText(s) {
  const text = String(s);
  return PLAIN_ASCII.test(text) ? text : UNSAFE.reduce((t, pattern) => t.replace(pattern, '?'), text);
}

const OTHER = '(other)';
const dimensions = ['type', 'actor', 'tool', 'outcome'];
const MAX_DISTINCT = 10000;
// A name longer than this many code points is never stored: it is counted under "(other)". Together with the
// distinct-name cap this bounds the memory of `summary` on any log, also on a forged one.
const MAX_NAME_POINTS = 128;
const tooLong = (name) => name.length > 2 * MAX_NAME_POINTS || [...name].length > MAX_NAME_POINTS;
const byName = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);

function checkedRecord(item) {
  if (item.error || !item.canonical || !looksLikeRecord(item.record)) throw new AuditError('log_corrupt');
  return item.record;
}
export { checkedRecord };

export async function summarize(path, { details = false } = {}) {
  const counts = Object.fromEntries(dimensions.map((d) => [d, { map: new Map(), other: 0 }]));
  let records = 0;
  let from = null;
  let to = null;
  let fromMs = Infinity;
  let toMs = -Infinity;
  let lines = 0;
  for await (const item of readRecords(path)) {
    lines++;
    const r = checkedRecord(item);
    if (item.lineNo === 1) continue;
    records++;
    const ms = Date.parse(r.time);
    if (Number.isFinite(ms)) {
      if (ms < fromMs) {
        fromMs = ms;
        from = r.time;
      }
      if (ms > toMs) {
        toMs = ms;
        to = r.time;
      }
    }
    for (const dim of dimensions) {
      const v = r[dim];
      if (v === null || v === undefined) continue;
      const bucket = counts[dim];
      // Only strings are names. Any other stored value, and the literal "(other)", is counted in the overflow bucket.
      if (typeof v !== 'string' || v === OTHER) {
        bucket.other++;
        continue;
      }
      const name = v;
      if (bucket.map.has(name)) bucket.map.set(name, bucket.map.get(name) + 1);
      else if (!tooLong(name) && bucket.map.size < MAX_DISTINCT) bucket.map.set(name, 1);
      else bucket.other++;
    }
  }
  if (lines === 0) throw new AuditError('log_corrupt');
  const result = { records, from, to };
  for (const dim of dimensions) {
    const { map, other } = counts[dim];
    if (details) {
      const merged = new Map(map);
      if (other) merged.set(OTHER, other);
      result[dim] = Object.fromEntries([...merged].sort(byName));
    } else result[dim] = { distinct: map.size };
  }
  return result;
}

/**
 * JSON text with object keys in UTF-16 code unit order at every depth (the canonical order). JSON.stringify cannot do
 * this: it always lists integer-like keys first. indent === null gives the compact form, a number the pretty form.
 */
function serialize(x, indent = null, pad = '', budget = null) {
  if (x === null || typeof x !== 'object') return JSON.stringify(x);
  const inner = indent === null ? '' : pad + ' '.repeat(indent);
  const colon = indent === null ? ':' : ': ';
  const [open, close] = Array.isArray(x) ? ['[', ']'] : ['{', '}'];
  const parts = Array.isArray(x)
    ? x.map((v) => serialize(v, indent, inner, budget))
    : Object.keys(x).sort().map((k) => {
      const part = JSON.stringify(k) + colon + serialize(x[k], indent, inner, budget);
      if (budget && (x[k] === null || typeof x[k] !== 'object')) budget.add(part, inner.length + 2);
      return part;
    });
  if (parts.length === 0) return open + close;
  if (indent === null) return open + parts.join(',') + close;
  return open + '\n' + parts.map((p) => inner + p).join(',\n') + '\n' + pad + close;
}
// JSON text additionally escapes DEL and the C1 controls (still valid JSON, same value).
const escapeC1 = (text) =>
  text.replace(/[\u007f-\u009f]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const jsonText = (x) => escapeC1(serialize(x, 2));
const json = (x) => jsonText(x) + '\n';
const clean = (x) =>
  typeof x === 'string'
    ? sanitizeText(x)
    : Array.isArray(x)
    ? x.map(clean)
    : x && typeof x === 'object'
    ? Object.fromEntries(Object.entries(x).map(([k, v]) => [sanitizeText(k), clean(v)]))
    : x;
const terminal = (x) => serialize(clean(x), 2) + '\n';
// Markdown: every cell is one inline code span, so no markup, link or bare address is interpreted. The fence is longer
// than any run of backticks inside; a pipe becomes the JSON escape | (cells are JSON text, so the value is kept).
function md(value) {
  const text = sanitizeText(String(value).replace(/[\r\n]+/g, ' ')).replaceAll('|', '\\u007c');
  if (text === '') return '';
  let longest = 0;
  for (const run of text.match(/`+/g) ?? []) if (run.length > longest) longest = run.length;
  const fence = '`'.repeat(longest + 1);
  return fence + ' ' + text + ' ' + fence;
}

// A summary (with --details, any format) renders at most 16 MiB. Pieces are counted while they are built, so that
// an oversized output stops early; the exact total is checked once more at the end.
export const MAX_SUMMARY_BYTES = 16 * 1024 * 1024;
function summaryBudget(measure = (text) => text) {
  let used = 0;
  return {
    add(text, overhead = 0) {
      used += Buffer.byteLength(measure(text)) + overhead;
      if (used > MAX_SUMMARY_BYTES) throw new AuditError('limit_exceeded');
    },
  };
}

export function renderSummary(summary, format = 'terminal') {
  let out;
  if (format === 'json') out = escapeC1(serialize(summary, 2, '', summaryBudget())) + '\n';
  else if (format === 'terminal') out = serialize(clean(summary), 2, '', summaryBudget()) + '\n';
  else if (format === 'markdown') {
    out = '| Field | Value |\n| --- | --- |\n';
    for (const [k, v] of Object.entries(summary)) {
      out += `| ${md(k)} | ${md(typeof v === 'object' ? serialize(v, null, '', summaryBudget(sanitizeText)) : v)} |\n`;
    }
  } else throw new AuditError('usage_error');
  if (Buffer.byteLength(out) > MAX_SUMMARY_BYTES) throw new AuditError('limit_exceeded');
  return out;
}

function markdownRows(rows) {
  let out = '| Value |\n| --- |\n';
  for (const row of rows) out += '| ' + md(serialize(row)) + ' |\n';
  return out;
}

export const MAX_SHOW_RECORDS = 10000;
export const MAX_SHOW_BYTES = 16 * 1024 * 1024;

/** Pieces of a show output (head, one item per record, tail), so that the caller can count bytes while reading. */
export function showParts(format = 'terminal') {
  const list = (render) => ({
    head: () => '[',
    item: (record, index) => (index ? ',' : '') + '\n  ' + render(record).replace(/\n/g, '\n  '),
    tail: (count) => (count ? '\n]\n' : ']\n'),
  });
  if (format === 'json') return list(jsonText);
  if (format === 'terminal') return list((r) => serialize(clean(r), 2));
  if (format === 'markdown') {
    return {
      head: () => '| Value |\n| --- |\n',
      item: (record) => '| ' + md(serialize(record)) + ' |\n',
      tail: () => '',
    };
  }
  throw new AuditError('usage_error');
}

export function renderShow(records, format = 'terminal') {
  if (records.length > MAX_SHOW_RECORDS) throw new AuditError('limit_exceeded');
  const parts = showParts(format);
  const chunks = [parts.head()];
  let bytes = Buffer.byteLength(chunks[0]);
  records.forEach((record, index) => {
    const piece = parts.item(record, index);
    bytes += Buffer.byteLength(piece);
    if (bytes > MAX_SHOW_BYTES) throw new AuditError('limit_exceeded');
    chunks.push(piece);
  });
  const tail = parts.tail(records.length);
  // The cap counts every byte of the output, the closing tail included.
  if (bytes + Buffer.byteLength(tail) > MAX_SHOW_BYTES) throw new AuditError('limit_exceeded');
  chunks.push(tail);
  return chunks.join('');
}

function verifyText(r) {
  const t = (v) => sanitizeText(v === null || v === undefined ? '-' : v);
  let o = 'verify: ' + (r.ok ? 'OK' : 'FAILED') + '\n' + 'records: ' + t(r.records) + '\n' + 'mode: ' + t(r.mode) +
    '\n' + 'head: ' + t(r.headHash) + '\n';
  for (const f of r.findings) o += 'finding: ' + t(f.kind) + ' seq=' + t(f.seq) + ' ' + t(f.detail) + '\n';
  if (r.anchor) o += 'anchor: ' + (r.anchor.ok ? 'OK' : 'FAILED ' + t(r.anchor.detail)) + '\n';
  return o;
}

export function renderVerify(report, format = 'terminal') {
  if (format === 'json') return json(report);
  if (format === 'terminal') {
    return report && Array.isArray(report.findings) && typeof report.ok === 'boolean'
      ? verifyText(report)
      : terminal(report);
  }
  if (format === 'markdown') return markdownRows([report]);
  throw new AuditError('usage_error');
}

const CSV_KEYS = ['seq', 'time', 'type', 'actor', 'tool', 'outcome', 'data', 'prev', 'hash'];
// A cell that a spreadsheet could read as a formula (after leading spaces; tab, CR and LF are
// already escaped before this check) gets a leading quote.
// Every code point that the terminal sanitizer replaces (the same predicate, UNSAFE) is written as \uXXXX text in a
// cell (BMP: four digits, astral: braces). This covers C0 and C1 controls, DEL, line and paragraph separators,
// U+2800, U+FFFC, invisible and bidirectional characters, private use and unassigned code points.
const escapePoint = (c) => {
  const cp = c.codePointAt(0);
  return '\\u' + (cp > 0xffff ? '{' + cp.toString(16) + '}' : cp.toString(16).padStart(4, '0'));
};
const escapeCell = (text) =>
  PLAIN_ASCII.test(text) ? text : UNSAFE.reduce((t, pattern) => t.replace(pattern, escapePoint), text);
function cell(v) {
  let s = v === null || v === undefined ? '' : typeof v === 'object' ? canonicalize(v) : String(v);
  s = escapeCell(s);
  if (/^ *[=+\-@]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

/** Pieces of an export, so that the CLI can stream it (head, one item per record, tail). */
export function exportParts(format) {
  if (format === 'json') {
    return {
      head: () => '[',
      item: (record, index) => (index ? ',' : '') + '\n  ' + jsonText(record).replace(/\n/g, '\n  '),
      tail: (count) => (count ? '\n]\n' : ']\n'),
    };
  }
  if (format === 'csv') {
    return {
      head: () => CSV_KEYS.map(cell).join(',') + '\r\n',
      item: (record) => CSV_KEYS.map((k) => cell(record[k])).join(',') + '\r\n',
      tail: () => '',
    };
  }
  throw new AuditError('usage_error');
}

export function renderExport(records, format = 'json') {
  if (records.length > 1000000) throw new AuditError('limit_exceeded');
  const parts = exportParts(format);
  let out = parts.head();
  records.forEach((r, i) => {
    out += parts.item(r, i);
  });
  return out + parts.tail(records.length);
}
