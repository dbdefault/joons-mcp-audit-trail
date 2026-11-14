import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { AuditError } from '../errors.js';
import {
  canonicalize,
  FORMAT,
  GENESIS_HASH,
  hashRecord,
  isIsoUtc,
  keyIdOf,
  validateEvent,
  validateRecordShape,
} from '../canon/index.js';
import {
  checkPath,
  fail,
  identityLockName,
  lockPathFor,
  openRegular,
  readSmallFile,
  safeStat,
  statLogSafe,
} from './paths.js';

export { createAtomicWriter, writeFileAtomic } from './atomic.js';
export { checkPath, readSmallFile, sameFile, statLogSafe } from './paths.js';

const DEFAULT_LIMITS = Object.freeze({ line: 65536, size: 256 * 1024 * 1024, count: 1000000 });
// Strict UTF-8, and a byte order mark is kept in the decoded text (never silently stripped).
const strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const hasBom = (b) => b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf;

export async function loadKey(p) {
  const bytes = await readSmallFile(p, 4096, 'key_invalid');
  if (bytes.length > 4096) fail('key_invalid');
  // Exactly one trailing line terminator (LF or CRLF) is removed. A key made only of terminators is refused.
  let end = bytes.length;
  if (end && bytes[end - 1] === 10) end -= end > 1 && bytes[end - 2] === 13 ? 2 : 1;
  const key = bytes.subarray(0, end);
  if (key.length < 16 || key.every((b) => b === 10 || b === 13)) fail('key_invalid');
  return key;
}

/** Decodes one stored line; it must be exactly canonicalize(parsed record). Anything else is log_corrupt. */
function parseStoredLine(bytes) {
  if (bytes.includes(0) || hasBom(bytes)) fail('log_corrupt');
  let text, record;
  try {
    text = strict.decode(bytes);
    record = JSON.parse(text);
    if (canonicalize(record) !== text) fail('log_corrupt');
  } catch {
    fail('log_corrupt');
  }
  return record;
}

async function readTail(h, size, limits) {
  const len = Math.min(size, limits.line + 2);
  const b = Buffer.alloc(len);
  const { bytesRead } = await h.read(b, 0, len, size - len);
  if (bytesRead !== len || !len || b[len - 1] !== 10) fail('log_corrupt');
  const i = b.lastIndexOf(10, len - 2);
  const start = i + 1;
  if ((i < 0 && size > len) || len - 1 - start > limits.line) fail('log_corrupt');
  return parseStoredLine(b.subarray(start, len - 1));
}

async function readHeader(h, size, limits) {
  const b = Buffer.alloc(Math.min(size, limits.line + 1));
  const { bytesRead } = await h.read(b, 0, b.length, 0);
  const n = b.subarray(0, bytesRead).indexOf(10);
  if (n < 0 || n > limits.line) fail('log_corrupt');
  return parseStoredLine(b.subarray(0, n));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WINDOWS = process.platform === 'win32';
const TRANSIENT = new Set(['EPERM', 'EACCES', 'EBUSY', 'ENOENT']);

/** Removes a file we created; on Windows a short sharing violation (scanner, concurrent open) is retried. */
async function unlinkWithRetry(path) {
  for (let attempt = 0;; attempt++) {
    try {
      return await fs.unlink(path);
    } catch (e) {
      if (!WINDOWS || !TRANSIENT.has(e.code) || e.code === 'ENOENT' || attempt >= 50) throw e;
      await sleep(20);
    }
  }
}

/** The lock file holds a random token (no secrets). It is removed only while it still holds our token. */
async function acquireLock(lock) {
  const token = randomBytes(16).toString('hex');
  const deadline = Date.now() + 5000;
  for (;;) {
    let h;
    try {
      h = await fs.open(lock, 'wx');
    } catch (e) {
      // Windows reports a lock file that is being deleted as EPERM, EACCES, EBUSY or even ENOENT: retry those too.
      const busy = e.code === 'EEXIST' || (WINDOWS && TRANSIENT.has(e.code));
      if (Date.now() >= deadline) fail(e.code === 'EEXIST' ? 'lock_timeout' : 'output_error');
      if (!busy) fail('output_error');
      await sleep(Math.min(50, Math.max(1, deadline - Date.now())));
      continue;
    }
    try {
      await h.writeFile(token);
    } catch {
      await h.close().catch(() => {});
      await fs.unlink(lock).catch(() => {});
      fail('output_error');
    }
    await h.close().catch(() => {});
    return token;
  }
}

async function releaseLock(lock, token) {
  try {
    const h = await fs.open(lock, 'r');
    let content;
    try {
      const b = Buffer.alloc(64);
      const { bytesRead } = await h.read(b, 0, 64, 0);
      content = b.subarray(0, bytesRead).toString('utf8');
    } finally {
      await h.close();
    }
    if (content === token) await unlinkWithRetry(lock);
  } catch (e) {
    if (e?.code !== 'ENOENT') fail('output_error');
  }
}

/** Default clock: sampled only while the lock is held, so that it can be compared with the tail. */
function clockTime(now) {
  let value;
  try {
    value = typeof now === 'function' ? now() : (now ?? new Date().toISOString());
    if (value instanceof Date) value = value.toISOString();
  } catch {
    fail('invalid_record');
  }
  if (!isIsoUtc(value)) fail('invalid_record');
  return value;
}

/** Second lock named after the file identity (device and inode), so that two spellings of one name share it. */
async function acquireIdentityLock(lock, handle) {
  const name = identityLockName(await handle.stat({ bigint: true }));
  if (name === null) return null;
  const path = join(dirname(lock), name);
  return { path, token: await acquireLock(path) };
}

async function appendWithLimits(path, event, { keyFile, now } = {}, limits = DEFAULT_LIMITS) {
  const normalized = validateEvent(event);
  checkPath(path, 'output_error', { log: true });
  const key = keyFile == null ? null : await loadKey(keyFile);
  const lock = await lockPathFor(path);
  const token = await acquireLock(lock);
  let h;
  let idLock = null;
  try {
    // An explicit time is refused when it is earlier than the tail. The default clock is clamped to the tail.
    const explicit = normalized.time !== null;
    let time = explicit ? normalized.time : clockTime(now);
    const st = await safeStat(path, 'output_error', { log: true });
    if (st && st.size > limits.size) fail('limit_exceeded');
    try {
      h = await fs.open(
        path,
        constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW || 0) |
          (constants.O_NONBLOCK || 0),
        0o600,
      );
    } catch {
      fail('output_error');
    }
    idLock = await acquireIdentityLock(lock, h);
    const actual = await h.stat();
    if (!actual.isFile() || actual.nlink > 1) fail('output_error');
    let prev = GENESIS_HASH;
    let seq = 0;
    let lines = '';
    if (actual.size) {
      const first = await readHeader(h, actual.size, limits);
      const last = await readTail(h, actual.size, limits);
      try {
        validateRecordShape(first, 0);
        validateRecordShape(last, last.seq);
      } catch {
        fail('log_corrupt');
      }
      if (first.mode === 'hmac-sha256' && !key) fail('key_required');
      if ((first.mode === 'sha256' && key) || (key && first.keyId !== keyIdOf(key))) fail('key_invalid');
      if (hashRecord(first, key) !== first.hash || hashRecord(last, key) !== last.hash) fail('log_corrupt');
      if (Date.parse(time) < Date.parse(last.time)) {
        if (explicit) fail('invalid_record');
        time = last.time;
      }
      seq = last.seq + 1;
      prev = last.hash;
    } else {
      const first = {
        format: FORMAT,
        version: 1,
        seq: 0,
        time,
        mode: key ? 'hmac-sha256' : 'sha256',
        keyId: key ? keyIdOf(key) : null,
        prev: GENESIS_HASH,
      };
      first.hash = hashRecord(first, key);
      lines = canonicalize(first) + '\n';
      seq = 1;
      prev = first.hash;
    }
    if (seq >= limits.count) fail('limit_exceeded');
    const { time: ignored, ...fields } = normalized;
    void ignored;
    const record = { seq, time, ...fields, prev };
    record.hash = hashRecord(record, key);
    const line = canonicalize(record) + '\n';
    const data = Buffer.from(lines + line, 'utf8');
    if (Buffer.byteLength(line) - 1 > limits.line || Buffer.byteLength(lines) - 1 > limits.line) {
      fail('limit_exceeded');
    }
    if (actual.size + data.length > limits.size) fail('limit_exceeded');
    const result = await h.write(data, 0, data.length, null);
    if (result.bytesWritten !== data.length) fail('output_error');
    await h.sync();
    return { seq, hash: record.hash };
  } catch (e) {
    if (e instanceof AuditError) throw e;
    return fail('output_error');
  } finally {
    try {
      if (h) await h.close();
    } finally {
      try {
        if (idLock) await releaseLock(idLock.path, idLock.token);
      } finally {
        await releaseLock(lock, token);
      }
    }
  }
}

/**
 * Streams the lines of a log. Items are { record, line, lineNo, canonical } for parsable lines (`line` is the raw
 * decoded text, `canonical` tells whether it equals canonicalize(record)) and { error, lineNo } otherwise.
 * Hashes are never validated here.
 */
async function* readWithLimits(path, limits = DEFAULT_LIMITS, { capAsItem = false } = {}) {
  const st = await statLogSafe(path);
  if (!st) fail('input_unreadable');
  if (st.size > limits.size) fail('limit_exceeded');
  const { handle } = await openRegular(path, 'input_unreadable', { log: true });
  let count = 0;
  let pending = Buffer.alloc(0);
  let total = 0;
  let long = false;
  const parse = (bytes) => {
    if (hasBom(bytes)) return { error: 'bad_encoding', lineNo: count };
    let line;
    try {
      line = strict.decode(bytes);
    } catch {
      return { error: 'bad_encoding', lineNo: count };
    }
    if (bytes.includes(0) || line.endsWith('\r')) return { error: 'bad_json', lineNo: count };
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      return { error: 'bad_json', lineNo: count };
    }
    let canonical = false;
    try {
      canonical = canonicalize(record) === line;
    } catch {
      canonical = false;
    }
    return { record, line, lineNo: count, canonical };
  };
  try {
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      total += chunk.length;
      if (total > limits.size) fail('limit_exceeded');
      let start = 0;
      while (start < chunk.length) {
        const end = chunk.indexOf(10, start);
        const stop = end < 0 ? chunk.length : end;
        const part = chunk.subarray(start, stop);
        if (!long) {
          if (pending.length + part.length > limits.line) {
            long = true;
            pending = Buffer.alloc(0);
          } else pending = Buffer.concat([pending, part]);
        }
        if (end < 0) break;
        if (++count > limits.count) {
          if (!capAsItem) fail('limit_exceeded');
          yield { error: 'too_many_lines', lineNo: count };
          return;
        }
        yield long ? { error: 'long_line', lineNo: count } : parse(pending);
        pending = Buffer.alloc(0);
        long = false;
        start = end + 1;
      }
    }
    if (long || pending.length) {
      if (++count > limits.count) {
        if (!capAsItem) fail('limit_exceeded');
        yield { error: 'too_many_lines', lineNo: count };
        return;
      }
      yield { error: 'partial_last_line', lineNo: count };
    }
  } catch (e) {
    if (e instanceof AuditError) throw e;
    fail('input_unreadable');
  } finally {
    await handle.close().catch(() => {});
  }
}

// `null` options behave like `undefined` (no options).
export const appendRecord = (path, event, options) => appendWithLimits(path, event, options ?? undefined);
export const readRecords = (path) => readWithLimits(path);

/** Internal hooks for the test suite and the verifier. Not re-exported by src/index.js. */
export const internal = Object.freeze({
  DEFAULT_LIMITS,
  appendRecord: appendWithLimits,
  readRecords: readWithLimits,
  acquireLock,
  releaseLock,
});
