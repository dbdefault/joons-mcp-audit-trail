export const ERROR_KINDS = Object.freeze([
  'input_unreadable',
  'invalid_record',
  'log_corrupt',
  'limit_exceeded',
  'credential_detected',
  'key_required',
  'key_invalid',
  'usage_error',
  'output_error',
  'lock_timeout',
  'internal_error',
]);
export class AuditError extends Error {
  constructor(kind) {
    const safe = ERROR_KINDS.includes(kind) ? kind : 'internal_error';
    super(safe);
    this.name = 'AuditError';
    this.kind = safe;
  }
}
