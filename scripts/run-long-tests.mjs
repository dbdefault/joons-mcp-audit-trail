// Runs the slow real-limits test group. It creates test/long-tests.enabled for the duration of the run.
import { spawnSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const marker = fileURLToPath(new URL('../test/long-tests.enabled', import.meta.url));
const file = fileURLToPath(new URL('../test/long-limits.test.js', import.meta.url));
writeFileSync(marker, 'on\n');
try {
  const result = spawnSync(process.execPath, ['--test', file], { stdio: 'inherit' });
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(marker, { force: true });
}
