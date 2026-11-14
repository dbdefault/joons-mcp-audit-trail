import { AuditError } from '../errors.js';
import { internal, loadKey, readSmallFile } from '../log/index.js';
import {
  ANCHOR_FORMAT,
  FORMAT,
  GENESIS_HASH,
  hashRecord,
  isIsoUtc,
  keyIdOf,
  validateRecordShape,
} from '../canon/index.js';

const hex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);
const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const DETAILS = {
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
const ANCHOR_KEYS = ['count', 'format', 'hash', 'headHash', 'keyId', 'mode', 'time', 'version'];

async function anchorFromFile(path) {
  const bytes = await readSmallFile(path, 65536, 'input_unreadable');
  if (bytes.length > 65536) throw new AuditError('input_unreadable');
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    return null;
  }
}

function validAnchor(a) {
  return isObject(a) && Object.keys(a).sort().join(',') === ANCHOR_KEYS.join(',') && a.format === ANCHOR_FORMAT &&
    a.version === 1 && Number.isSafeInteger(a.count) && a.count > 0 && hex(a.headHash, 64) &&
    ['sha256', 'hmac-sha256'].includes(a.mode) && (a.mode === 'sha256' ? a.keyId === null : hex(a.keyId, 16)) &&
    isIsoUtc(a.time) && hex(a.hash, 64);
}

async function verifyWithLimits(path, { keyFile, anchorFile, requireKeyed = false } = {}, limits) {
  if (requireKeyed && !keyFile) throw new AuditError('usage_error');
  const key = keyFile ? await loadKey(keyFile) : null;
  const anchor = anchorFile ? await anchorFromFile(anchorFile) : null;
  const findings = [];
  const seen = new Set();
  let overflow = false;
  let records = 0;
  let headHash = null;
  let mode = null;
  let keyId = null;
  let prev = GENESIS_HASH;
  let time = null;
  let target = null;
  const add = (kind, seq, detail = DETAILS[kind]) => {
    if (findings.length >= 100) {
      overflow = true;
      return;
    }
    const id = [kind, seq, detail].join('|');
    if (seen.has(id)) return;
    seen.add(id);
    findings.push({ kind, seq, detail });
  };
  for await (const item of internal.readRecords(path, limits, { capAsItem: true })) {
    const idx = records++;
    if (item.error) {
      if (item.error === 'partial_last_line' || item.error === 'too_many_lines') add('trailing_garbage', idx);
      else add('bad_record', idx);
      if (item.error === 'too_many_lines') break;
      continue;
    }
    const r = item.record;
    if (idx === 0) {
      mode = isObject(r) ? (r.mode ?? null) : null;
      keyId = isObject(r) ? (r.keyId ?? null) : null;
      if (!isObject(r) || r.format !== FORMAT || r.version !== 1 || r.seq !== 0) add('bad_header', 0);
      if (mode === 'hmac-sha256' && !key) throw new AuditError('key_required');
      if (isObject(r) && key && mode !== 'hmac-sha256') add('key_mismatch', 0, 'header_not_keyed');
      else if (mode === 'hmac-sha256' && keyId !== keyIdOf(key)) add('key_mismatch', 0);
    }
    if (item.canonical === false) add(idx === 0 ? 'bad_header' : 'bad_record', idx, 'line_not_canonical');
    try {
      validateRecordShape(r, idx === 0 ? 0 : (Number.isSafeInteger(r?.seq) && r.seq > 0 ? r.seq : idx));
    } catch {
      add(idx === 0 ? 'bad_header' : 'bad_record', idx);
    }
    if (!isObject(r)) continue;
    if (r.seq !== idx) add('seq_gap', idx);
    if (r.prev !== prev) add('chain_break', idx);
    if (isIsoUtc(r.time)) {
      if (time !== null && Date.parse(r.time) < Date.parse(time)) add('time_regress', idx);
      time = r.time;
    }
    try {
      const keyed = mode === 'hmac-sha256';
      if ((mode === 'sha256' || keyed) && hashRecord(r, keyed ? key : null) !== r.hash) add('hash_mismatch', idx);
    } catch {
      add(idx === 0 ? 'bad_header' : 'bad_record', idx);
    }
    prev = r.hash;
    headHash = typeof r.hash === 'string' ? r.hash : null;
    if (isObject(anchor) && idx === anchor.count - 1) target = r.hash;
  }
  if (records === 0) add('bad_header', 0);
  let anchorResult = null;
  if (anchorFile) {
    let ok = true;
    let detail = 'ok';
    if (!validAnchor(anchor)) {
      detail = 'anchor_invalid';
      add('anchor_mismatch', null, detail);
      ok = false;
    } else {
      if (anchor.mode === 'hmac-sha256' && !key) throw new AuditError('key_required');
      if (anchor.mode !== mode || anchor.keyId !== keyId) {
        add('mode_change', null);
        detail = 'anchor_mode_differs';
        ok = false;
      }
      if (hashRecord(anchor, anchor.mode === 'hmac-sha256' ? key : null) !== anchor.hash) {
        add('anchor_mismatch', null, 'anchor_hash_invalid');
        detail = 'anchor_hash_invalid';
        ok = false;
      }
      if (anchor.count > records) {
        add('truncated_tail', null);
        detail = 'log_shorter_than_anchor';
        ok = false;
      } else if (target !== anchor.headHash) {
        add('anchor_mismatch', null);
        detail = 'anchor_head_differs';
        ok = false;
      }
    }
    anchorResult = { ok, detail };
  }
  if (overflow) findings.push({ kind: 'truncated_report', seq: null, detail: DETAILS.truncated_report });
  return { ok: findings.length === 0, records, headHash, mode, findings, anchor: anchorResult };
}

export const verifyLog = (path, options) => verifyWithLimits(path, options, internal.DEFAULT_LIMITS);

export async function createAnchor(path, { keyFile } = {}) {
  const report = await verifyLog(path, { keyFile });
  // A key that does not belong to the log (wrong key, or a key given for a plain log) is a key problem.
  if (report.findings.some((f) => f.kind === 'key_mismatch')) throw new AuditError('key_invalid');
  if (!report.ok) throw new AuditError('log_corrupt');
  const keyed = report.mode === 'hmac-sha256';
  const key = keyFile ? await loadKey(keyFile) : null;
  const a = {
    format: ANCHOR_FORMAT,
    version: 1,
    count: report.records,
    headHash: report.headHash,
    mode: report.mode,
    keyId: keyed ? keyIdOf(key) : null,
    time: new Date().toISOString(),
  };
  return { ...a, hash: hashRecord(a, keyed ? key : null) };
}

export const internalVerify = Object.freeze({ verifyLog: verifyWithLimits });
