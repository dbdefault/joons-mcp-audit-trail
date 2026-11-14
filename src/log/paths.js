import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { AuditError } from '../errors.js';

export const fail = (kind) => {
  throw new AuditError(kind);
};

const CASE_FOLD = process.platform === 'win32' || process.platform === 'darwin';
/** File name as a case-folding file system compares it: NFC, then full case folding (upper, then lower). */
export const foldName = (name) => (CASE_FOLD ? name.normalize('NFC').toUpperCase().toLowerCase() : name);
// COM and LPT with the superscript digits are reserved device names on Windows as well.
const RESERVED =
  /^(?:CON|PRN|AUX|NUL|COM[1-9\u{b9}\u{b2}\u{b3}]|LPT[1-9\u{b9}\u{b2}\u{b3}]|CONIN\$|CONOUT\$|CLOCK\$)$/iu;

/**
 * One path checker for every path the tool is given (log, --out, --key-file, --data, --anchor).
 * It looks only at the text of the path. Parent directory components are NOT inspected (documented limitation).
 */
export function checkPath(p, kind, { log = false } = {}) {
  if (typeof p !== 'string' || p.length === 0 || p.includes('\0')) fail(kind);
  const n = p.replaceAll('\\', '/');
  // UNC, device namespace and every mixed-separator spelling of them start with two separators.
  if (n.startsWith('//')) fail(kind);
  // A colon is allowed only as the drive-letter colon of an absolute drive path (this refuses NTFS data streams).
  const colon = n.indexOf(':');
  if (colon !== -1 && !(colon === 1 && /^[A-Za-z]:[/]/.test(n) && n.indexOf(':', 2) === -1)) fail(kind);
  const name = n.slice(n.lastIndexOf('/') + 1);
  if (name === '' || name === '.' || name === '..' || /[. ]$/.test(name)) fail(kind);
  if (RESERVED.test(name.split('.')[0].trimEnd())) fail(kind);
  if (log && process.platform === 'win32' && /~\d/.test(name)) fail(kind);
}

/** Real location of a path as far as it can be known: realpath of the parent directory plus the file name. */
export async function realLocation(p) {
  const abs = resolve(p);
  const dir = await fs.realpath(dirname(abs));
  const name = basename(abs);
  return join(dir, foldName(name));
}

const isRegular = (s) => s.isFile() && !s.isSymbolicLink() && s.nlink === 1;

/** lstat of an existing regular file, or null when absent. Everything else is refused with the given kind. */
export async function safeStat(p, kind, options) {
  checkPath(p, kind, options);
  try {
    const s = await fs.lstat(p);
    if (!isRegular(s)) fail(kind);
    return s;
  } catch (e) {
    if (e instanceof AuditError) throw e;
    if (e.code === 'ENOENT') return null;
    return fail(kind);
  }
}

export const statLogSafe = (p) => safeStat(p, 'input_unreadable', { log: true });

const READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0);

/** Opens an existing regular file for reading without ever blocking on a pipe or device. */
export async function openRegular(p, kind, options) {
  checkPath(p, kind, options);
  let h;
  try {
    const before = await fs.lstat(p, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) fail(kind);
    h = await fs.open(p, READ_FLAGS);
    const after = await h.stat({ bigint: true });
    const sameFile = before.ino === 0n || (after.ino === before.ino && after.dev === before.dev);
    if (!after.isFile() || after.nlink !== 1n || !sameFile) fail(kind);
    return { handle: h, size: Number(after.size) };
  } catch (e) {
    if (h) await h.close().catch(() => {});
    if (e instanceof AuditError) throw e;
    return fail(kind);
  }
}

/** Reads at most max + 1 bytes of a regular file (the extra byte lets the caller detect an oversized file). */
export async function readSmallFile(p, max, kind) {
  const { handle } = await openRegular(p, kind);
  try {
    const buffer = Buffer.alloc(max + 1);
    let used = 0;
    while (used < buffer.length) {
      const { bytesRead } = await handle.read(buffer, used, buffer.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    return buffer.subarray(0, used);
  } catch {
    return fail(kind);
  } finally {
    await handle.close().catch(() => {});
  }
}

/** True when two paths denote the same file (device and inode when both exist, else the real location). */
export async function sameFile(a, b) {
  const stat = (p) => fs.stat(p, { bigint: true }).catch(() => null);
  const [sa, sb] = [await stat(a), await stat(b)];
  if (sa && sb && sa.ino !== 0n && sa.ino === sb.ino && sa.dev === sb.dev) return true;
  try {
    return (await realLocation(a)) === (await realLocation(b));
  } catch {
    return false;
  }
}

/** File name of the identity lock for a file with this (bigint) stat, or null when the file system has no inodes. */
export function identityLockName(st) {
  if (st.ino === 0n) return null;
  return `.audit-id-${createHash('sha256').update(`${st.dev}:${st.ino}`).digest('hex').slice(0, 32)}.lock`;
}

/** Name-based lock file for a log (parent realpath, folded name where file names fold case). */
export async function lockPathFor(p) {
  const abs = resolve(p);
  let dir;
  try {
    dir = await fs.realpath(dirname(abs));
  } catch {
    return fail('output_error');
  }
  const name = basename(abs);
  return join(dir, foldName(name) + '.lock');
}
