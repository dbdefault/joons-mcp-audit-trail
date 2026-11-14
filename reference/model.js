import { createHash, createHmac } from 'node:crypto';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
export const FORMAT = 'joons-mcp-audit-trail/log', ANCHOR = 'joons-mcp-audit-trail/anchor', ZERO = '0'.repeat(64);
export function canonicalize(v) {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number' && Number.isSafeInteger(v)) return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  throw Error('invalid_record');
}
export function hashRecord(record, key = null) {
  const { hash, ...body } = record;
  return (key ? createHmac('sha256', key) : createHash('sha256')).update(canonicalize(body), 'utf8').digest('hex');
}
export function keyId(key) {
  return createHash('sha256').update(createHash('sha256').update(key).digest()).digest('hex').slice(0, 16);
}
export function header(time, key = null) {
  const r = {
    format: FORMAT,
    version: 1,
    seq: 0,
    time,
    mode: key ? 'hmac-sha256' : 'sha256',
    keyId: key ? keyId(key) : null,
    prev: ZERO,
  };
  return { ...r, hash: hashRecord(r, key) };
}
export function event(seq, time, type, prev, data = null, actor = null, tool = null, outcome = null, key = null) {
  validateEvent({ type, actor, tool, outcome, data, time });
  const r = { seq, time, type, actor, tool, outcome, data, prev };
  return { ...r, hash: hashRecord(r, key) };
}
export function create(path, time, key = null) {
  const h = header(time, key);
  writeFileSync(path, canonicalize(h) + '\n');
  return h;
}
export function append(path, e, key = null) {
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n');
  const p = JSON.parse(lines.at(-1));
  const r = event(
    p.seq + 1,
    e.time,
    e.type,
    p.hash,
    e.data ?? null,
    e.actor ?? null,
    e.tool ?? null,
    e.outcome ?? null,
    key,
  );
  appendFileSync(path, canonicalize(r) + '\n');
  return r;
}
export function anchor(records, time, key = null) {
  const h = records[0];
  const a = {
    format: ANCHOR,
    version: 1,
    count: records.length,
    headHash: records.at(-1).hash,
    mode: h.mode,
    keyId: h.keyId,
    time,
  };
  return { ...a, hash: hashRecord(a, key) };
}
const iso = (s) =>
  typeof s === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(s) && Number.isFinite(Date.parse(s));
const keys = (o, k) =>
  o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).sort().join('|') === k.split(' ').sort().join('|');
export function verify(text, key = null, a = null, opts = {}) {
  const details = {
    bad_header: 'header_invalid',
    bad_record: 'record_invalid',
    hash_mismatch: 'hash_differs',
    chain_break: 'prev_differs',
    seq_gap: 'seq_not_contiguous',
    time_regress: 'time_earlier_than_previous',
    mode_change: 'anchor_mode_differs',
    key_mismatch: 'key_id_differs',
    truncated_tail: 'log_shorter_than_anchor',
    anchor_mismatch: 'anchor_head_differs',
    trailing_garbage: 'unterminated_or_extra_line',
    truncated_report: 'more_than_100_findings',
  };
  const findings = [];
  const seen = new Set();
  let overflow = false;
  const add = (kind, seq, detail = details[kind]) => {
    const id = [kind, seq, detail].join('|');
    if (seen.has(id)) return;
    seen.add(id);
    if (findings.length < 100) findings.push({ kind, seq, detail });
    else overflow = true;
  };
  if (opts.requireKeyed && !key) throw Error('usage_error');
  const records = [];
  if (text && !text.endsWith('\n')) {
    add('trailing_garbage', null);
    return { ok: false, records: 0, headHash: null, mode: null, findings, anchor: null };
  }
  const lines = text.slice(0, -1).split('\n');
  let prev = ZERO, lastTime = null, mode = null;
  for (let i = 0; i < lines.length; i++) {
    let r;
    try {
      if (
        Buffer.byteLength(lines[i]) > 65536 || !lines[i] || lines[i].startsWith(String.fromCharCode(0xfeff)) ||
        lines[i].includes('\0') ||
        lines[i].endsWith('\r')
      ) throw Error();
      r = JSON.parse(lines[i]);
    } catch {
      add(i ? 'bad_record' : 'bad_header', i);
      continue;
    }
    let canon = null;
    try {
      canon = canonicalize(r);
    } catch {}
    if (canon !== lines[i]) add(i ? 'bad_record' : 'bad_header', i, 'line_not_canonical');
    const shape = i === 0
      ? keys(r, 'format version seq time mode keyId prev hash')
      : keys(r, 'seq time type actor tool outcome data prev hash');
    if (
      !shape || !iso(r.time) || !Number.isSafeInteger(r.seq) || !/^[0-9a-f]{64}$/.test(r.hash ?? '') ||
      !/^[0-9a-f]{64}$/.test(r.prev ?? '')
    ) add(i ? 'bad_record' : 'bad_header', i);
    if (i === 0) {
      mode = r.mode;
      if (
        r.format !== FORMAT || r.version !== 1 || !['sha256', 'hmac-sha256'].includes(mode) ||
        (mode === 'sha256' && r.keyId !== null) || (mode === 'hmac-sha256' && !/^[0-9a-f]{16}$/.test(r.keyId ?? ''))
      ) add('bad_header', i);
      if (mode === 'hmac-sha256' && !key) throw Error('key_required');
      if (key && mode !== 'hmac-sha256') add('key_mismatch', i, 'header_not_keyed');
      else if (mode === 'hmac-sha256' && keyId(key) !== r.keyId) add('key_mismatch', i);
    } else {try {
        validateEvent(
          { type: r.type, actor: r.actor, tool: r.tool, outcome: r.outcome, data: r.data, time: r.time },
          true,
        );
      } catch {
        add('bad_record', i);
      }}
    if (r.seq !== i) add('seq_gap', i);
    if (r.prev !== prev) add('chain_break', i);
    if (lastTime && Date.parse(r.time) < Date.parse(lastTime)) add('time_regress', i);
    try {
      if (hashRecord(r, mode === 'hmac-sha256' ? key : null) !== r.hash) add('hash_mismatch', i);
    } catch {
      add('bad_record', i);
    }
    records.push(r);
    prev = r.hash;
    lastTime = r.time;
  }
  let ar = null;
  if (a) {
    let reason = null;
    if (
      !keys(a, 'format version count headHash mode keyId time hash') || a.format !== ANCHOR || a.version !== 1 ||
      !Number.isSafeInteger(a.count) || a.count < 1 || !iso(a.time)
    ) reason = 'anchor_invalid';
    else if (a.mode !== mode || a.keyId !== records[0]?.keyId) {
      add('mode_change', null);
      reason = 'anchor_mode_differs';
    } else if (hashRecord(a, mode === 'hmac-sha256' ? key : null) !== a.hash) reason = 'anchor_hash_invalid';
    else if (a.count > records.length) {
      add('truncated_tail', null);
      reason = 'log_shorter_than_anchor';
    } else if (records[a.count - 1]?.hash !== a.headHash) reason = 'anchor_head_differs';
    if (reason && !['anchor_mode_differs', 'log_shorter_than_anchor'].includes(reason)) {
      add('anchor_mismatch', null, reason);
    }
    ar = { ok: reason === null, detail: reason ?? 'ok' };
  }
  if (overflow) findings.push({ kind: 'truncated_report', seq: null, detail: details.truncated_report });
  return {
    ok: !findings.length,
    records: records.length,
    headHash: records.at(-1)?.hash ?? null,
    mode,
    findings,
    anchor: ar,
  };
}
const bad = () => {
  throw Error('invalid_record');
};
export function credential(text) {
  const patterns = [
    /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/i,
    /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
    /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    /(?<![A-Za-z0-9_-])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}/,
    /(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9]{20}/,
    /(?<![A-Za-z0-9_-])glpat-/,
    /(?<![A-Za-z0-9_-])xox[abprs]-/,
    /(?<![A-Za-z0-9_-])(?:sk_live_|pk_live_|rk_live_)[A-Za-z0-9]{10}/,
    /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}/,
    /\bSG\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{16}/,
    /npm_[A-Za-z0-9]{30}/,
  ];
  for (let i = 0; i < 3; i++) {
    if (patterns.some((p) => p.test(text))) return true;
    try {
      text = decodeURIComponent(text);
    } catch {
      break;
    }
  }
  return false;
}
function checkData(value, depth) {
  if (typeof value === 'string') {
    if ([...value].length > 4096) bad();
    if (credential(value)) throw Error('credential_detected');
    return;
  }
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) bad();
    return;
  }
  if (!value || typeof value !== 'object' || depth > 6) bad();
  if (Array.isArray(value)) {
    if (value.length > 64) bad();
    for (const x of value) checkData(x, depth + 1);
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) bad();
  const keys = Object.keys(value);
  if (keys.length > 64) bad();
  for (const k of keys) {
    if (['__proto__', 'prototype', 'constructor'].includes(k)) bad();
    if (credential(k)) throw Error('credential_detected');
    checkData(value[k], depth + 1);
  }
}
const hiddenChars = [
  /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u,
  /[^\P{Zs} ]/u,
  /[\u{34f}\u{115f}\u{1160}\u{17b4}\u{17b5}\u{180b}-\u{180f}\u{2800}\u{3164}]/u,
  /[\u{fe00}-\u{fe0f}\u{ffa0}\u{fffc}\u{e0100}-\u{e01ef}]/u,
];
// Fixed, version-independent table used when reading stored records: [first, last] code point pairs.
const STABLE = [
  [0, 0x1f],
  [0x7f, 0xa0],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x600, 0x605],
  [0x61c, 0x61c],
  [0x6dd, 0x6dd],
  [0x70f, 0x70f],
  [0x890, 0x891],
  [0x8e2, 0x8e2],
  [0x115f, 0x1160],
  [0x1680, 0x1680],
  [0x17b4, 0x17b5],
  [0x180b, 0x180f],
  [0x2000, 0x200f],
  [0x2028, 0x202f],
  [0x205f, 0x206f],
  [0x2800, 0x2800],
  [0x3000, 0x3000],
  [0x3164, 0x3164],
  [0xd800, 0xf8ff],
  [0xfdd0, 0xfdef],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff0, 0xfffc],
  [0xfffe, 0xffff],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0000, 0xe0fff],
  [0xf0000, 0x10ffff],
  ...Array.from({ length: 14 }, (_, i) => [(i + 1) * 0x10000 + 0xfffe, (i + 1) * 0x10000 + 0xffff]),
];
const stableHidden = (x) =>
  [...x].some((c) => STABLE.some(([lo, hi]) => c.codePointAt(0) >= lo && c.codePointAt(0) <= hi));
export function validateEvent(e, stored = false) {
  if (
    !e || typeof e !== 'object' || Array.isArray(e) || Object.getPrototypeOf(e) !== Object.prototype ||
    Object.keys(e).some((k) => !['type', 'actor', 'tool', 'outcome', 'data', 'time'].includes(k))
  ) bad();
  if (typeof e.type !== 'string' || !/^[A-Za-z0-9._:-]{1,64}$/.test(e.type)) bad();
  const r = {
    type: e.type,
    actor: e.actor ?? null,
    tool: e.tool ?? null,
    outcome: e.outcome ?? null,
    data: e.data ?? null,
    time: e.time ?? null,
  };
  for (const k of ['type', 'actor', 'tool']) {
    const x = r[k];
    if (
      x !== null &&
      (typeof x !== 'string' || ![...x].length || [...x].length > (k === 'type' ? 64 : 128) ||
        (stored ? stableHidden(x) : hiddenChars.some((p) => p.test(x)) ||
          (k !== 'type' && (x === '(other)' || x.startsWith(' ') || x.endsWith(' ')))))
    ) bad();
    if (x !== null && credential(x)) throw Error('credential_detected');
  }
  if (![null, 'ok', 'allow', 'deny', 'error', 'info'].includes(r.outcome)) bad();
  if (r.time !== null && !iso(r.time)) bad();
  if (r.data !== null) {
    if (!r.data || Array.isArray(r.data) || typeof r.data !== 'object') bad();
    checkData(r.data, 1);
    if (Buffer.byteLength(canonicalize(r.data)) > 32768) bad();
  }
  return r;
}
export function sanitize(s) {
  return String(s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '?');
}
export function summarize(records) {
  const counts = { type: {}, actor: {}, tool: {}, outcome: {} };
  for (const r of records.slice(1)) {
    for (const k of Object.keys(counts)) if (r[k] !== null) counts[k][r[k]] = (counts[k][r[k]] ?? 0) + 1;
  }
  return { records: records.length, events: Math.max(0, records.length - 1), counts };
}
export function show(records, from = 0, to = records.length - 1) {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from || to - from + 1 > 10000) {
    throw Error('usage_error');
  }
  return records.filter((r) => r.seq >= from && r.seq <= to);
}
export function exportJson(records) {
  return JSON.stringify(records);
}
export function exportCsv(records) {
  const columns = ['seq', 'time', 'type', 'actor', 'tool', 'outcome', 'data', 'prev', 'hash'];
  const cell = (v) => {
    let s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replaceAll('"', '""') + '"';
  };
  return columns.join(',') + '\n' + records.map((r) => columns.map((k) => cell(r[k])).join(',')).join('\n') + '\n';
}
