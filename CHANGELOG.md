# Changelog

## 0.1.0 Preview (2026-11-14)

Initial preview: append-only hash-chained audit log with optional HMAC key mode and anchor files; commands `append`, `verify`, `anchor`, `show`, `summary` and `export`; library entry point.

Behaviour and limits of this release:

- Stored line format: every line is exactly the canonical JSON of its record (sorted keys, no whitespace, hash included). `verify` reads raw bytes with a strict UTF-8 decoder and reports any other spelling as `line_not_canonical`.
- Keyed mode: `verify --key-file` on a log whose header is not keyed reports `key_mismatch` (`header_not_keyed`); `verify --require-keyed` (library option `requireKeyed`) asks for the same explicitly.
- `append` refuses an explicit event time earlier than the last record (`invalid_record`). Without an explicit time the default clock is sampled after the lock is acquired and clamped to the last record's time, so concurrent appends cannot be refused for time order and a backwards clock step drops no event. A time fraction must have exactly three digits.
- Two locks: a name-based lock (real parent directory, NFC and case-folded name where file names ignore case) and a second lock named from the file's device and inode numbers.
- `show` is bounded by 16 MiB of rendered output as well as by 10,000 records; `summary`, `show` and `export` fail with `log_corrupt` on a zero-byte file.
- Names: `actor` and `tool` refuse non-ASCII spaces, default-ignorable and unassigned code points; reserved names also cover `COM` and `LPT` with superscript digits and `CLOCK$`.
- Output: the terminal sanitizer follows Unicode properties (Default_Ignorable_Code_Point, Cf, Cc, Co, Cs, Cn) plus 22 listed format characters; CSV cells are sanitized and the CSV data cell and the JSON output use the canonical key order; Markdown cells are inline code spans.
- Names, reading: the fixed table of stored-name classes holds only explicit stable classes, a subset of what the writer rejects, and is applied only by `verify` and the append tail check; `show`, `summary` and `export` do not use it. It is exact (U+2000 to U+200F, U+2028 to U+202F and U+205F to U+206F instead of the whole U+2000 to U+206F block), so visible punctuation such as curly quotes, dashes and the ellipsis is accepted by `verify` and the append tail check; a test sweeps every code point (writer accepts implies reader accepts). `summary --details --format markdown` no longer fails on logs with many backtick runs. The sanitizer also replaces non-ASCII space separators. The summary counts non-string stored values and the literal `(other)` under `(other)`.
- Key file: exactly one trailing LF or CRLF is removed; a key made only of line terminators is `key_invalid`. `--data` files with duplicate keys are refused (`invalid_record`).
- Summary bounds: names longer than 128 code points are counted under `(other)` and never stored; `summary --details` output is limited to 16 MiB (`limit_exceeded`). A forged log of 4,000 records with 64,000-character actors no longer needs hundreds of megabytes.
- Names: writing refuses the literal `(other)` and names that start or end with a space; reading stored records no longer applies any Unicode-version dependent rule (a fixed table of stable classes only), so a log written on a newer Node.js verifies on an older one.
- CSV: every column escapes exactly the code points that the terminal sanitizer replaces (C0 controls, U+2028, U+2029, U+2800, U+FFFC included); the `show` cap counts the closing tail; `anchor` and `export` refuse an `--out` that is a lock file; `appendRecord` accepts `null` options.
- Tests: `npm run test:long` adds real 1,000,000-record and forged-summary groups (script `scripts/run-long-tests.mjs`).
- Paths: one checker for log, `--out`, `--key-file`, `--data` and `--anchor`; every path is checked as text before any file system call touches it, on every command (the log of `export` and the protected inputs of the output writers included); input files must be regular files with one link and are never opened if they are pipes, sockets or devices; output may never be an input file.
- `export` streams to a temporary file and holds no more than a few chunks in memory.
- Limits: 65,536 bytes per line, 256 MiB per log, 1,000,000 records, 32 KiB of data per event (depth 6, 64 keys, 64 elements, 4,096 characters), 10,000 records per `show`, 10,000 distinct names per summary field, 100 findings per report.
- Error kinds: `input_unreadable`, `invalid_record`, `log_corrupt`, `limit_exceeded`, `credential_detected`, `key_required`, `key_invalid`, `usage_error`, `output_error`, `lock_timeout`, `internal_error`. Exit codes: 0 success, 1 verification findings, 2 input, limit, credential, key or damaged-log errors, 3 usage, 4 output or lock errors.
- Known limits are listed in LIMITATIONS.md and SECURITY.md (no key entropy check, key identifier shared by logs that use one key, parent directories not checked, stale lock and temporary files after a kill, `fs.link` needs hard links).
