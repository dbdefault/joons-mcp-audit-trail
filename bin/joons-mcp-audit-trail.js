#!/usr/bin/env node
let stdout = null, stderr = null;
try {
  stdout = process.stdout;
} catch {}
try {
  stderr = process.stderr;
} catch {}
try {
  const { main } = await import('../src/cli/index.js');
  process.exitCode = await main(process.argv.slice(2), { stdout, stderr });
} catch {
  try {
    stderr?.write('joons-mcp-audit-trail: internal_error\n');
  } catch {}
  process.exitCode = 2;
}
