import { createHash, createHmac } from 'node:crypto';
import { AuditError } from '../errors.js';

export const GENESIS_HASH = '0'.repeat(64);
export const FORMAT = 'joons-mcp-audit-trail/log';
export const ANCHOR_FORMAT = 'joons-mcp-audit-trail/anchor';

const MAX_NODES = 100000;
const invalid = () => {
  throw new AuditError('invalid_record');
};
const isPlain = (x) =>
  x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const INDEX = /^(0|[1-9]\d*)$/;

/** Canonical JSON: sorted keys, no whitespace, JSON.stringify string escaping, safe integers only. */
export function canonicalize(value) {
  const active = new Set();
  let nodes = 0;
  function visit(v, depth) {
    if (depth > 32 || ++nodes > MAX_NODES) return invalid();
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number') return Number.isSafeInteger(v) ? JSON.stringify(v) : invalid();
    if (typeof v !== 'object' || (!Array.isArray(v) && !isPlain(v)) || active.has(v)) return invalid();
    active.add(v);
    let result;
    if (Array.isArray(v)) {
      const parts = [];
      for (let i = 0; i < v.length; i++) {
        if (!Object.hasOwn(v, i)) return invalid();
        parts.push(visit(v[i], depth + 1));
      }
      if (Reflect.ownKeys(v).some((k) => typeof k === 'symbol' || (k !== 'length' && !INDEX.test(k)))) {
        return invalid();
      }
      result = `[${parts.join(',')}]`;
    } else {
      if (Object.getOwnPropertySymbols(v).length) return invalid();
      const keys = Object.keys(v).sort();
      result = `{${keys.map((k) => `${JSON.stringify(k)}:${visit(v[k], depth + 1)}`).join(',')}}`;
    }
    active.delete(v);
    return result;
  }
  return visit(value, 0);
}

export function hashRecord(record, keyBuf = null) {
  if (!isPlain(record)) return invalid();
  const copy = Object.create(null);
  for (const k of Object.keys(record)) if (k !== 'hash') copy[k] = record[k];
  const bytes = Buffer.from(canonicalize(copy), 'utf8');
  return (keyBuf === null ? createHash('sha256') : createHmac('sha256', keyBuf)).update(bytes).digest('hex');
}

export function keyIdOf(keyBuf) {
  const inner = createHash('sha256').update(keyBuf).digest();
  return createHash('sha256').update(inner).digest('hex').slice(0, 16);
}

const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
export function isIsoUtc(s) {
  if (typeof s !== 'string') return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/.exec(s);
  if (!m) return false;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = mo >= 1 && mo <= 12 ? DAYS[mo - 1] + (mo === 2 && leap ? 1 : 0) : 0;
  return mo >= 1 && mo <= 12 && d >= 1 && d <= days && h <= 23 && mi <= 59 && se <= 59;
}

// Credential-shaped text scan. Heuristic: it cannot guarantee detection of every secret and may refuse benign text.
// Before a prefix family the previous character must not be a letter, digit, "_" or "-" (the prefix starts a token).
const patterns = [
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/i,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  /(?<![A-Za-z0-9_-])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}/,
  /(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9]{20,}/,
  /(?<![A-Za-z0-9_-])glpat-/,
  /(?<![A-Za-z0-9_-])xox[abprs]-/,
  /(?<![A-Za-z0-9_-])[psr]k_live_[A-Za-z0-9]{10,}/,
  /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}/,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
  /npm_[A-Za-z0-9]{30,}/,
];

function scanString(s) {
  let current = s;
  for (let round = 0; round < 3; round++) {
    if (patterns.some((p) => p.test(current))) return true;
    current = current.replace(/(?:%[0-9a-fA-F]{2})+/g, (part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return part;
      }
    });
  }
  return false;
}

export function scanForCredential(value) {
  const seen = new Set();
  let nodes = 0;
  function scan(v) {
    if (typeof v === 'string') return scanString(v);
    if (!v || typeof v !== 'object' || seen.has(v)) return false;
    if (++nodes > MAX_NODES) return true;
    seen.add(v);
    return Object.keys(v).some((k) => scanString(k) || scan(v[k]));
  }
  return scan(value);
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const EVENT_KEYS = ['type', 'actor', 'tool', 'outcome', 'data', 'time'];
const OUTCOMES = ['ok', 'allow', 'deny', 'error', 'info'];

function dataValue(obj, key) {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return undefined;
  if (!('value' in d)) return invalid();
  return d.value;
}

/** Copies a JSON-like value into a plain snapshot, enforcing every data limit. Never calls getters. */
function snapshot(v, depth, budget) {
  if (++budget.nodes > MAX_NODES) invalid();
  if (typeof v === 'string') {
    if (v.length > 8192 || [...v].length > 4096) invalid();
    return v;
  }
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) invalid();
    return v === 0 ? 0 : v;
  }
  if (typeof v !== 'object' || (!Array.isArray(v) && !isPlain(v)) || depth > 6) return invalid();
  const keys = Reflect.ownKeys(v);
  if (keys.some((k) => typeof k === 'symbol')) invalid();
  const read = (k) => {
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (!d || !('value' in d) || !d.enumerable) invalid();
    return d.value;
  };
  if (Array.isArray(v)) {
    if (v.length > 64 || keys.length !== v.length + 1) invalid();
    const out = [];
    for (let i = 0; i < v.length; i++) out.push(snapshot(read(String(i)), depth + 1, budget));
    return out;
  }
  if (keys.length > 64 || keys.some((k) => FORBIDDEN_KEYS.has(k))) invalid();
  const out = {};
  for (const k of keys) out[k] = snapshot(read(k), depth + 1, budget);
  return out;
}

// Names (type, actor, tool). WRITING (validateEvent) is strict by the Unicode data of the running Node.js: invisible,
// reordering and combining characters are refused, and so are every non-ASCII space separator, every
// default-ignorable code point and every code point that Unicode has not assigned (which depends on the version).
const HIDDEN = [
  /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u,
  /(?!\u{20})\p{Zs}/u,
  /[\u{34f}\u{115f}\u{1160}\u{17b4}\u{17b5}\u{180b}-\u{180f}\u{2800}\u{3164}]/u,
  /[\u{fe00}-\u{fe0f}\u{ffa0}\u{fffc}\u{e0100}-\u{e01ef}]/u,
];
// READING stored records uses only this fixed table, which does not depend on the Unicode data of the running
// Node.js: ASCII and C1 controls, soft hyphen, non-ASCII spaces, format and bidirectional characters, line and
// paragraph separators, fillers, variation selectors, tag characters, the 22 later format characters, noncharacters,
// surrogates and private use. A log written on a newer Node.js therefore verifies on an older one.
const STABLE_HIDDEN = [
  /[\u{0}-\u{1f}\u{7f}-\u{a0}\u{ad}\u{34f}\u{600}-\u{605}\u{61c}\u{6dd}\u{70f}\u{890}\u{891}\u{8e2}]/u,
  /[\u{115f}\u{1160}\u{1680}\u{17b4}\u{17b5}\u{180b}-\u{180f}\u{2000}-\u{200f}\u{2028}-\u{202f}]/u,
  /[\u{205f}-\u{206f}\u{2800}\u{3000}\u{3164}]/u,
  /[\u{d800}-\u{f8ff}\u{fdd0}-\u{fdef}\u{fe00}-\u{fe0f}\u{feff}\u{ffa0}\u{fff0}-\u{fffc}\u{fffe}\u{ffff}]/u,
  /[\u{110bd}\u{110cd}\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/u,
  /[\u{1fffe}\u{1ffff}\u{2fffe}\u{2ffff}\u{3fffe}\u{3ffff}\u{4fffe}\u{4ffff}\u{5fffe}\u{5ffff}]/u,
  /[\u{6fffe}\u{6ffff}\u{7fffe}\u{7ffff}\u{8fffe}\u{8ffff}\u{9fffe}\u{9ffff}\u{afffe}\u{affff}]/u,
  /[\u{bfffe}\u{bffff}\u{cfffe}\u{cffff}\u{dfffe}\u{dffff}\u{efffe}\u{effff}\u{f0000}-\u{10ffff}]/u,
];
const NAME_OTHER = '(other)';
const nameLength = (s) => typeof s === 'string' && [...s].length >= 1 && [...s].length <= 128;
// Look-alike names are refused when writing: the literal name of the summary overflow bucket, and a name that
// starts or ends with a space (a name made only of spaces is covered by both). Readers do not apply these rules.
const printable = (s) =>
  nameLength(s) && !HIDDEN.some((p) => p.test(s)) && s !== NAME_OTHER && !s.startsWith(' ') && !s.endsWith(' ');
const printableStored = (s) => nameLength(s) && !STABLE_HIDDEN.some((p) => p.test(s));

function checkEvent(event, stored) {
  if (!isPlain(event)) return invalid();
  if (Reflect.ownKeys(event).some((k) => typeof k !== 'string' || !EVENT_KEYS.includes(k))) invalid();
  const type = dataValue(event, 'type');
  const actor = dataValue(event, 'actor') ?? null;
  const tool = dataValue(event, 'tool') ?? null;
  const outcome = dataValue(event, 'outcome') ?? null;
  const rawData = dataValue(event, 'data') ?? null;
  const time = dataValue(event, 'time') ?? null;
  if (typeof type !== 'string' || !/^[A-Za-z0-9._:-]{1,64}$/.test(type)) invalid();
  const ok = stored ? printableStored : printable;
  if ((actor !== null && !ok(actor)) || (tool !== null && !ok(tool))) invalid();
  if (outcome !== null && !OUTCOMES.includes(outcome)) invalid();
  if (time !== null && !isIsoUtc(time)) invalid();
  let data = null;
  if (rawData !== null) {
    if (!isPlain(rawData)) invalid();
    data = snapshot(rawData, 1, { nodes: 0 });
    if (Buffer.byteLength(canonicalize(data), 'utf8') > 32768) invalid();
  }
  if (scanForCredential({ type, actor, tool, data })) throw new AuditError('credential_detected');
  return { type, actor, tool, outcome, data, time };
}

/** Validates an event for writing and returns the normalized snapshot that the log layer writes. */
export const validateEvent = (event) => checkEvent(event, false);
/** Validates the event fields of a stored record. Names are checked with the fixed, version-independent table. */
export const validateStoredEvent = (event) => checkEvent(event, true);

const HEX64 = /^[0-9a-f]{64}$/;
const HEADER_KEYS = ['format', 'version', 'seq', 'time', 'mode', 'keyId', 'prev', 'hash'];
const RECORD_KEYS = ['seq', 'time', 'type', 'actor', 'tool', 'outcome', 'data', 'prev', 'hash'];

/** Cheap structural test used by readers that do not verify hashes (show, summary, export). */
export function looksLikeRecord(obj) {
  if (!isPlain(obj) || !Number.isSafeInteger(obj.seq)) return false;
  const keys = obj.seq === 0 ? HEADER_KEYS : RECORD_KEYS;
  return Object.keys(obj).length === keys.length && keys.every((k) => Object.hasOwn(obj, k));
}

export function validateRecordShape(obj, expectedSeq) {
  if (!isPlain(obj) || !Number.isSafeInteger(expectedSeq) || expectedSeq < 0 || obj.seq !== expectedSeq) invalid();
  const header = expectedSeq === 0;
  const keys = header ? HEADER_KEYS : RECORD_KEYS;
  const hexOk = typeof obj.prev === 'string' && typeof obj.hash === 'string' && HEX64.test(obj.prev) &&
    HEX64.test(obj.hash);
  if (Object.keys(obj).length !== keys.length || !keys.every((k) => Object.hasOwn(obj, k)) || !isIsoUtc(obj.time)) {
    invalid();
  }
  if (!hexOk) invalid();
  if (header) {
    const keyed = obj.mode === 'hmac-sha256';
    const modeOk = obj.mode === 'sha256' || keyed;
    const keyIdOk = keyed ? typeof obj.keyId === 'string' && /^[0-9a-f]{16}$/.test(obj.keyId) : obj.keyId === null;
    if (obj.format !== FORMAT || obj.version !== 1 || obj.prev !== GENESIS_HASH || !modeOk || !keyIdOk) invalid();
  } else {
    try {
      const { type, actor, tool, outcome, data, time } = obj;
      validateStoredEvent({ type, actor, tool, outcome, data, time });
    } catch {
      invalid();
    }
  }
  return obj;
}
