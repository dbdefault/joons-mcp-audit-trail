import {
  appendRecord,
  createAtomicWriter,
  loadKey,
  readRecords,
  readSmallFile,
  writeFileAtomic,
} from '../log/index.js';
import { createAnchor, verifyLog } from '../verify/index.js';
import {
  checkedRecord,
  exportParts,
  renderExport,
  renderShow,
  renderSummary,
  renderVerify,
  sanitizeText,
  showParts,
  summarize,
} from '../report/index.js';
import { canonicalize } from '../canon/index.js';
import { AuditError } from '../errors.js';
import { run } from './core.js';
export { parseArgs } from './args.js';

// One extra byte lets the caller notice an oversized data file.
const readData = (path) => readSmallFile(path, 32768, 'input_unreadable');
const defaultDeps = {
  appendRecord,
  readRecords,
  loadKey,
  writeFileAtomic,
  createAtomicWriter,
  verifyLog,
  createAnchor,
  summarize,
  checkedRecord,
  exportParts,
  canonicalize,
  renderSummary,
  renderShow,
  showParts,
  renderVerify,
  renderExport,
  sanitizeText,
  AuditError,
  readData,
};
export function main(argv, io, deps = defaultDeps) {
  return run(argv, io, deps);
}
