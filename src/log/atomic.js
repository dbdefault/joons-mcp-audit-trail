import * as fs from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { AuditError } from '../errors.js';
import { checkPath, fail, identityLockName, lockPathFor, realLocation, safeStat, sameFile } from './paths.js';

const FLUSH_AT = 64 * 1024;

const ID_LOCK_NAME = /^\.audit-id-[0-9a-f]+\.lock$/i;

/**
 * An output may never be a lock file: not the name lock `<input>.lock` or the identity lock `.audit-id-<hex>.lock`
 * of any input, and no file named like an identity lock (a held lock would be replaced, a stale one hidden).
 */
async function refuseLockFiles(path, protect) {
  if (ID_LOCK_NAME.test(basename(path))) fail('output_error');
  let here;
  try {
    here = await realLocation(path);
  } catch {
    return;
  }
  for (const other of protect) {
    if (typeof other !== 'string') continue;
    try {
      if ((await lockPathFor(other)) === here) fail('output_error');
      const st = await fs.stat(other, { bigint: true });
      const name = identityLockName(st);
      if (name !== null && join(dirname(here), name) === here) fail('output_error');
    } catch (e) {
      if (e instanceof AuditError) throw e;
    }
  }
}

/**
 * Streaming atomic output: data goes to a temp file in the same directory, then is moved into place.
 * Without force the target is created exclusively (hard link), so an existing file is never replaced.
 * `protect` lists input paths that must never be the output (log, key file, anchor, data).
 * A killed process can leave a stale `.name.<hex>.tmp` next to the target; the tool never deletes anything else.
 */
export async function createAtomicWriter(path, { force = false, protect = [] } = {}) {
  checkPath(path, 'output_error');
  // Every protected input is checked as text before any file system call touches it.
  for (const other of protect) if (typeof other === 'string') checkPath(other, 'input_unreadable');
  for (const other of protect) {
    if (typeof other === 'string' && (await sameFile(path, other))) fail('output_error');
  }
  await refuseLockFiles(path, protect);
  const existing = await safeStat(path, 'output_error');
  if (existing && !force) fail('output_error');
  // An existing file that looks like a lock file is never replaced, not even with force.
  if (existing && /\.lock$/i.test(basename(path))) fail('output_error');
  const temp = join(dirname(path), '.' + basename(path) + '.' + randomBytes(16).toString('hex') + '.tmp');
  let handle;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
  } catch {
    return fail('output_error');
  }
  let pending = [];
  let pendingSize = 0;
  let done = false;
  const flush = async () => {
    if (pendingSize === 0) return;
    const data = Buffer.from(pending.join(''), 'utf8');
    pending = [];
    pendingSize = 0;
    let offset = 0;
    while (offset < data.length) {
      const { bytesWritten } = await handle.write(data, offset, data.length - offset, null);
      offset += bytesWritten;
    }
  };
  const cleanup = async () => {
    done = true;
    await handle.close().catch(() => {});
    await fs.unlink(temp).catch(() => {});
  };
  return {
    async write(text) {
      try {
        pending.push(text);
        pendingSize += text.length;
        if (pendingSize >= FLUSH_AT) await flush();
      } catch {
        await cleanup();
        fail('output_error');
      }
    },
    async commit() {
      try {
        await flush();
        await handle.sync();
        await handle.close();
        if (force) {
          await safeStat(path, 'output_error');
          await fs.rename(temp, path);
        } else {
          await fs.link(temp, path);
          await fs.unlink(temp);
        }
        done = true;
      } catch (e) {
        await cleanup();
        if (e instanceof AuditError) throw e;
        fail('output_error');
      }
    },
    async abort() {
      if (!done) await cleanup();
    },
  };
}

export async function writeFileAtomic(path, content, options = {}) {
  const writer = await createAtomicWriter(path, options);
  try {
    await writer.write(content);
    await writer.commit();
  } finally {
    await writer.abort();
  }
}
