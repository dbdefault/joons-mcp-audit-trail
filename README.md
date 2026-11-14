# JOONS MCP Audit Trail

An append-only, tamper-evident audit log for AI-agent and MCP tool activity. Every record carries a hash of its own content and of the previous record, so edits, deletions, reordering and insertions are found by `verify`. An optional key file (HMAC-SHA256) means that only someone who holds the key can build a chain that verifies with that key, as long as you verify with the key (best with `--require-keyed`). An optional anchor file detects removal of the newest records. It is an offline command-line tool and a small library for Node.js 20 or later, with no runtime or development dependencies, no network access and no telemetry.

Korean version: [README.ko.md](README.ko.md).

## Honest scope

This tool detects modification; it does not prevent it. An attacker who can rewrite the log and has the key, or can recompute hashes in unkeyed mode, can forge a log. Tail truncation is detected only against an anchor or a known count. Timestamps are caller-supplied claims, not trusted time. It does not authenticate who wrote a record and is not a replacement for write-once storage.

Without a key or an anchor, a plain-looking rewrite of a log cannot be told from a genuine plain log: `verify` holds a log to the mode its own header declares. If you rely on keyed mode, always verify with `--key-file` and `--require-keyed`, or compare against an anchor that you keep elsewhere.

## Install

```sh
npm install -g github:dbdefault/joons-mcp-audit-trail#v0.1.0
joons-mcp-audit-trail --version
```

The tool is not published to the npm registry. To try it without installing, run `node bin/joons-mcp-audit-trail.js` from a checkout.

## Commands

```text
joons-mcp-audit-trail append <log> --type TYPE [--actor A] [--tool T] [--outcome OUTCOME] [--data FILE] [--time ISO] [--key-file FILE]
joons-mcp-audit-trail verify <log> [--anchor FILE] [--key-file FILE] [--require-keyed] [--format terminal|json]
joons-mcp-audit-trail anchor <log> --out FILE [--key-file FILE] [--force]
joons-mcp-audit-trail show <log> [--from N] [--to N] [--format terminal|json]
joons-mcp-audit-trail summary <log> [--details] [--format terminal|json|markdown]
joons-mcp-audit-trail export <log> --out FILE --format json|csv [--force]
joons-mcp-audit-trail --help | --version
```

Options accept `--name=value` or `--name value`, and they may come before or after the `<log>` argument (`summary --details audit.jsonl` works as well as `summary audit.jsonl --details`). Unknown, repeated, missing or inappropriate options (an option that the command does not take), a bare `--`, and extra positional arguments are usage errors. There is no standard input, no configuration file and no environment variable behaviour. `--help` and `--version` must be the only argument.

| Option | Meaning |
| --- | --- |
| `--type TYPE` | Required for `append`. 1 to 64 characters from letters, digits, `.`, `_`, `:` and `-`. |
| `--actor A`, `--tool T` | Optional names, 1 to 128 printable characters. Control, invisible, bidirectional, format, variation-selector, tag and private-use characters, every default-ignorable and every unassigned code point, and every space other than the ASCII space (no-break space, ideographic space, line and paragraph separators and so on) are refused, so `agent` and `agent` plus a no-break space cannot become two names. The literal name `(other)` (the label of the summary overflow bucket) and a name that starts or ends with an ASCII space (a name of only spaces included) are refused as look-alikes. These checks apply when writing; the Unicode checks follow the Unicode data of the Node.js that runs `append`, while stored records are read with a fixed table that does not depend on it (see LIMITATIONS.md). Usability note: the writer also refuses the zero-width joiner and non-joiner (U+200D, U+200C) and variation selectors, so family and other joined emoji, emoji that need U+FE0F (such as the red heart and keycaps) and Persian or Indic names that need a joiner cannot be used as actor or tool names; flags, skin tones, CJK, Hangul, Arabic, Hebrew and combining marks work. |
| `--outcome OUTCOME` | Optional: `ok`, `allow`, `deny`, `error` or `info`. |
| `--data FILE` | Optional JSON object file (UTF-8, no byte-order mark), at most 32 KiB, depth 6, 64 keys per object, 64 elements per array, strings of at most 4,096 characters. It must be a regular file. Numbers are read by value: `1.0` and `1e2` denote safe integers and are accepted (stored as `1` and `100`); a non-integer is refused with `invalid_record`. A file larger than 32 KiB is `limit_exceeded`; a smaller file whose canonical form is larger than 32 KiB (a number such as `1e9` is rewritten as `1000000000`) is `invalid_record`. A key that appears twice in one object, at any depth, is refused with `invalid_record` (a duplicate is never resolved silently). |
| `--time ISO` | UTC time such as `2026-01-01T00:00:00Z` or `2026-01-01T00:00:00.123Z`. When a fraction is present it must have exactly three digits (`.123`, not `.1` or `.1234`). Default: the current time, taken after the lock is acquired and never earlier than the time of the last record, so concurrent appends without `--time` all succeed; if the system clock steps backwards the record gets the time of the last record instead of being dropped. An explicit `--time` must not be earlier than the last record (equal is fine); otherwise `append` fails with `invalid_record` and writes nothing. On the first append it also sets the header time. |
| `--key-file FILE` | A key file of 4 KiB or less and at least 16 bytes (exactly one trailing line terminator, `\n` or `\r\n`, is removed, so a key saved with CRLF equals the same key saved with LF; a file that holds only line terminators is `key_invalid`). It must be a regular file. |
| `--require-keyed` | For `verify`: needs `--key-file`, and reports a finding if the log header is not keyed. |
| `--anchor FILE` | An anchor file to check the log against. |
| `--out FILE`, `--force` | Output file for `anchor` and `export`. An existing file is refused unless `--force` is given, and the output may never be the log, the key file or another input, even with `--force`. |
| `--format` | `terminal` or `json` for `verify` and `show`; `terminal`, `json` or `markdown` for `summary`; `json` or `csv` for `export` (required there). |
| `--from N`, `--to N` | Inclusive sequence numbers for `show`, 1 or higher, at most 10,000 records per call. |
| `--details` | Make `summary` list every name with its count instead of only the number of distinct names. |

## Quick start (plain mode)

The package ships the same event data as `examples/event.json` and the same commands as `examples/session.txt` (with fixed `--time` values, so the log is reproducible). Run the commands of `session.txt` from the package root: they refer to `examples/event.json` by a relative path. To create the JSON file yourself, use the form for your shell. In a POSIX shell (Linux, macOS, Git Bash):

```sh
printf '%s\n' '{"action":"read","path":"report"}' > event.json
```

In Windows `cmd` (no space before the `>`):

```bat
echo {"action":"read","path":"report"}> event.json
```

In PowerShell, write the file explicitly as UTF-8 without a byte-order mark. Do not use `>` or `Out-File` for this: Windows PowerShell 5.1 redirects as UTF-16, which `--data` refuses with `invalid_record`:

```powershell
[IO.File]::WriteAllText("$PWD\event.json", '{"action":"read","path":"report"}', [Text.UTF8Encoding]::new($false))
```

Then, in any shell:

```text
joons-mcp-audit-trail append audit.jsonl --type tool.call --actor agent --tool search --outcome ok --data event.json --time 2026-01-01T00:00:00Z
joons-mcp-audit-trail append audit.jsonl --type tool.result --time 2026-01-01T00:00:01Z
joons-mcp-audit-trail verify audit.jsonl
```

`append` creates the log if it does not exist (the directory must exist) and prints `{"seq":1,"hash":"..."}`. The first append fixes the mode: with `--key-file` the log is keyed, otherwise it is plain, and later appends must match. Each append reads and checks the header and the last record under a lock; only `verify` walks the whole chain. Every stored line is the canonical form of its record (sorted keys, no spaces), so a log is byte-for-byte reproducible.

## Keyed mode

Create a key file with at least 16 random bytes through your normal secret handling, keep it away from the log, and pass it to every command that touches the log:

```sh
joons-mcp-audit-trail append keyed.jsonl --type tool.call --key-file key.bin
joons-mcp-audit-trail verify keyed.jsonl --key-file key.bin --require-keyed
```

Only a short key identifier is stored in the header, never the key. Verifying a keyed log without a key fails with `key_required`; verifying with a different key reports a `key_mismatch` finding (`key_id_differs`); appending with a wrong key is `key_invalid`.

Keyed mode only helps when the key is used to verify. If someone rewrites a keyed log as a plain log (a plain header and recomputed plain hashes), then `verify --key-file` reports `key_mismatch` with detail `header_not_keyed` (exit code 1) and `append --key-file` fails with `key_invalid`. `--require-keyed` makes the same demand explicit in scripts. Verifying that rewritten log without a key, and without an anchor, succeeds, because nothing distinguishes it from a genuine plain log.

A key is used as given: there is no check of its entropy, and the stored key identifier is the same in every log that uses the key (it links such logs to each other and lets anyone who holds a log test key guesses offline), so use a long random key. Losing the key means the keyed hashes can no longer be checked. To change keys, start a new log.

## Anchors

An anchor records how many lines the log had and the hash of the newest one. Keep it somewhere the log's writer cannot change.

```text
joons-mcp-audit-trail anchor audit.jsonl --out checkpoint.json
joons-mcp-audit-trail append audit.jsonl --type session.end --time 2026-01-01T00:00:02Z
joons-mcp-audit-trail verify audit.jsonl --anchor checkpoint.json
```

A log that has grown since the anchor still matches it. A log that is shorter than the anchor is reported as `truncated_tail`; a log whose anchored line differs, or an anchor that is malformed or fails its own hash, is `anchor_mismatch`; an anchor whose mode or key differs from the log is `mode_change`. `anchor` refuses to anchor a log that does not verify, a keyed log needs `--key-file` for both `anchor` and `verify --anchor`, and a key that does not belong to the log (wrong key, or a key given for a plain log) is `key_invalid`.

## Tamper demonstration

The commands above leave a log with four lines (header plus three events) and `checkpoint.json` (made when the log had three lines). Keep a copy, change one value in an event, and verify again. The one-line `node` commands work the same in every shell:

```text
node -e "const fs=require('fs');fs.copyFileSync('audit.jsonl','good.jsonl')"
node -e "const fs=require('fs'),p='audit.jsonl';fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('agent','other'))"
joons-mcp-audit-trail verify audit.jsonl --anchor checkpoint.json
```

Output (exit code 1):

```text
verify: FAILED
records: 4
mode: sha256
head: 88e247c1bbfa12ac73c9f31902c823f913796c475eec9f66f576cff4ffdc59dc
finding: hash_mismatch seq=1 hash_differs
anchor: OK
```

The anchor still says OK here because the edited record's stored hash was not touched; the changed content no longer matches that hash. If the copy is cut back to its first two lines instead, the output is:

```text
node -e "const fs=require('fs'),p='good.jsonl';fs.writeFileSync(p,fs.readFileSync(p,'utf8').split('\n').slice(0,2).join('\n')+'\n')"
joons-mcp-audit-trail verify good.jsonl --anchor checkpoint.json

verify: FAILED
records: 2
mode: sha256
head: 9c50db729e8ae085d57ae152d3827cb6bab5d089342f003455a340f75df77a5e
finding: truncated_tail seq=- log_shorter_than_anchor
anchor: FAILED log_shorter_than_anchor
```

The format is strict. Re-indenting a stored line, changing the order of its keys, writing a key twice, spelling a number or an escape differently, adding a byte-order mark or padding a line with spaces all change the stored bytes and are reported as `bad_record` (or `bad_header`) with detail `line_not_canonical`, even though the hashes still match.

In plain mode someone who recomputes every hash after an edit produces a log that verifies; use keyed mode with `--require-keyed` and an independent anchor to raise that bar. Do not run this demonstration on real evidence.

## Reading a log

- `show` prints records with `--from` and `--to` (default: from 1, up to 10,000 records; the default range over a log with more records is `limit_exceeded`, exit 2, while a range wider than 10,000 records is a usage error, exit 3, only when both `--from` and `--to` are given; with only one of them, a selection of more than 10,000 records is `limit_exceeded`, exit 2). The rendered output is also capped at 16 MiB (16,777,216 bytes): `show` counts the bytes while it reads and stops with `limit_exceeded` as soon as the selected range would pass the cap, before it builds the output. The cap counts every byte that would be written, the closing `\n]\n` of the JSON and terminal forms included: a total of exactly 16,777,216 bytes is shown, one byte more is `limit_exceeded`. The header (seq 0) is not shown.
- `summary` counts events (the header is not counted) and reports the earliest and latest time (compared as instants, so `...01Z` and `...01.500Z` order correctly) plus, per type, actor, tool and outcome, either the number of distinct names or, with `--details`, each name with its count. A field holds at most 10,000 distinct names; further names are counted under `(other)`, which is not itself counted as a name. A name longer than 128 code points is never stored (a forged log cannot make `summary` use much memory); it is counted under `(other)` as well. The rendered `--details` output, in any format, is capped at 16 MiB in total bytes; a larger one stops with `limit_exceeded` (only possible for a log that `append` could not have produced). The output without `--details` is small.
- `export` writes every line including the header (`seq` 0) as pretty JSON, or as CSV with the columns `seq,time,type,actor,tool,outcome,data,prev,hash`. It streams records to a temporary file in the same directory and then moves it into place, so memory use stays small even for the largest allowed log, and a failed export leaves no output. CSV cells that begin with `=`, `+`, `-` or `@`, also after leading spaces, get a leading `'` so spreadsheets do not run them as formulas. The `data` cell is the canonical JSON of the data (keys in code unit order, the same order as the JSON output). CSV cells are sanitized with the same rule as the terminal output, in every column (the type, actor, tool and outcome columns of a forged log included, not only the data column): each code point that the terminal replaces is written as `\uXXXX` (or `\u{XXXXX}`) text. That covers C0 and C1 control characters (tab, carriage return and line feed too, so a cell never holds a raw line break), DEL, the line and paragraph separators U+2028 and U+2029, U+2800, U+FFFC, invisible and bidirectional characters, private-use and unassigned code points, and the terminal, Markdown and CSV output also replace every space separator other than the ASCII space (U+00A0, U+1680, U+2000 to U+200A, U+202F, U+205F, U+3000) with `?` (CSV: escape text). A literal backslash-u in a cell cannot be told from that escape.

`show`, `summary` and `export` require every line to be a well-formed record in canonical form (a damaged or unexpected line, including a bare `null`, a number, an array or a very deeply nested line, stops them with `log_corrupt`), but they do not check hashes: tampering that keeps each line well-formed is only found by `verify`. A zero-byte file is not a log: `summary`, `show` and `export` fail with `log_corrupt`, `verify` reports `bad_header`, and `append` treats it as a new log. Terminal output replaces every code point that is default-ignorable or of general category Cf, Cc, Co, Cs or unassigned (Cn), the 22 format characters U+110BD, U+110CD, U+13430 to U+1343F and U+1BCA0 to U+1BCA3, and the older explicit list of invisible and bidirectional characters with `?`; which code points count as unassigned depends on the Unicode version of the Node.js that runs the tool. Two names (or two object keys) that differ only by replaced characters print as the same text in terminal output and collapse into one entry there (only one of them is shown, so counts are not added); JSON output and exports keep them apart and are exact. JSON output is plain JSON escaping with object keys in code unit order, and DEL and the C1 control characters (U+007F to U+009F) escaped as `\u00XX`; bidirectional and other format characters pass through raw by design, so treat it as data and do not paste it into a terminal or an editor unchecked. Markdown output writes every cell as one inline code span (the fence is longer than any run of backticks inside), so markup, links, bare URLs and e-mail addresses are not interpreted; a pipe is written as the JSON escape `\u007c` and newlines become spaces. Exports contain the log's content; protect them like the log.

## Exit codes and errors

| Code | Meaning |
| --- | --- |
| 0 | Success (`verify`: no findings). |
| 1 | `verify` found tampering or an anchor mismatch. This is a report on standard output, not an error line. |
| 2 | Input, limit, credential, key or damaged-log error. |
| 3 | Usage error. |
| 4 | Output, write or lock error. |

Errors print exactly one line, `joons-mcp-audit-trail: KIND`, to standard error. The line never contains a path, record content or key material.

`append` prints its result (`{"seq":N,"hash":"..."}`) after the record is on disk. If that write to standard output fails (a closed pipe, for example), the command exits with 4 although the record is durable; a wrapper that retries on exit code 4 can add the record twice. Look at the log (`show` or `verify`) before retrying.

| Kind | Code | When |
| --- | --- | --- |
| `input_unreadable` | 2 | A file to read is missing, unreadable, or not a plain regular file (pipes, sockets, devices, symbolic links, hard-linked files and directories are refused without being opened). |
| `invalid_record` | 2 | An event, time or data file breaks the field rules, or the event time is earlier than the last record. |
| `log_corrupt` | 2 | The log has a damaged, unfinished or non-canonical line (append, show, summary, export, anchor), or it is empty (zero bytes) for show, summary and export. |
| `limit_exceeded` | 2 | A size, count or range limit was hit. |
| `credential_detected` | 2 | A value looks like a credential and was refused. |
| `key_required` | 2 | A keyed log or anchor was used without a key. |
| `key_invalid` | 2 | The key file is missing, too short or too long, or does not belong to the log. |
| `usage_error` | 3 | The command line is wrong. |
| `output_error` | 4 | A file could not be written, an output file already exists, or the output is the same file as an input. |
| `lock_timeout` | 4 | The lock file stayed in place for 5 seconds. |
| `internal_error` | 2 | An unexpected failure. |

Verification findings are `bad_header`, `bad_record`, `hash_mismatch`, `chain_break`, `seq_gap`, `time_regress`, `mode_change`, `key_mismatch`, `truncated_tail`, `anchor_mismatch` and `trailing_garbage`; at most 100 are listed, followed by `truncated_report` if there were more. The same problem is reported once. Their `detail` text comes from a fixed vocabulary and never contains record content. If a log has more than 1,000,000 lines because of junk after the records, `verify` reports it as findings (exit code 1) rather than as an error.

## Credentials are refused, heuristically

`append` refuses values that look like private key headers, bearer tokens, JWTs, or keys from AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid and npm, in `type`, `actor`, `tool` and every string and key name in `data`, also after up to two rounds of percent-decoding. A bearer token needs at least 16 token characters after `Bearer `, a JWT needs three base64url segments of at least 10 characters that begin with `eyJ`, and the prefix families (for example AWS or GitHub) must start a token, so ordinary words such as `Bearer of good news`, `npm_install` or `ESG.report` are accepted. This is a heuristic and not a guarantee: do not put secrets in records.

## Locks, safety and limits

`append` takes a lock file next to the log (the name is derived from the real directory of the log, with the file name Unicode-normalized (NFC) and case-folded where file names ignore case), creating it exclusively, writing a random token into it, and removing it afterwards only while it still holds that token. Once it has the log open it also takes a second lock, a hidden `.audit-id-<hex>.lock` file next to the log named from the log file's device and inode numbers, so that two spellings of one file name that the first lock does not recognise still take turns. It waits up to 5 seconds for each lock and flushes the new line to disk before it releases them. The default time is read only while both locks are held. A lock left behind by a killed process is never removed automatically. After a kill both files can remain, `<log>.lock` and `.audit-id-<hex>.lock`, and the next `append` waits 5 seconds and fails with `lock_timeout` until both are gone: after you have confirmed that no writer is active, delete both by hand. A log whose own name ends in `.lock` (a log called `x.lock`) blocks appends to `x`, because `x.lock` is the lock name of `x`. `anchor` and `export` refuse an `--out` that is a lock file (the name lock or the identity lock of any input, any name of the form `.audit-id-<hex>.lock`, and any existing file whose name ends in `.lock`), also with `--force`, so a held lock is never replaced. A killed export or anchor can leave a stale `.name.<hex>.tmp` file next to its target, which you may delete. An unfinished or non-canonical last line makes `append` fail with `log_corrupt`; nothing is repaired automatically.

Paths are checked as text before any file is touched. Refused: UNC and device-namespace paths in any mixture of slashes and backslashes, NUL bytes, alternate data streams (a colon other than in `C:\`), Windows device names such as `CON`, `NUL`, `COM1`, `COM` or `LPT` with a superscript digit, and `CLOCK$` (with or without an extension, on every platform), names ending in a dot or space, and on Windows `~` followed by a digit in the log name (8.3 aliases). Existing input files (log, `--data`, `--anchor`, `--key-file`) must be regular files with one hard link; symbolic links, directories, pipes and devices are refused without being opened. Parent directory components are not checked: a log inside a symlinked or junctioned directory is accepted. Creating an output file without `--force` uses `fs.link` to put it in place without ever replacing a file, which needs a filesystem that supports hard links (for example not FAT).

A line is at most 65,536 bytes, a log at most 256 MiB or 1,000,000 records, and the rendered output of `show` at most 16 MiB. `verify`, `summary` and `export` stream the file, so memory use depends on the longest line and the number of distinct names rather than on the log size.

## Library

```js
import {appendRecord, verifyLog, createAnchor} from 'joons-mcp-audit-trail';

await appendRecord('audit.jsonl', {type: 'tool.call', actor: 'agent'}, {});
const checkpoint = await createAnchor('audit.jsonl', {});
const report = await verifyLog('audit.jsonl', {});
if (!report.ok) console.error('verification found a problem');
```

The third argument of `appendRecord` is an options object (`keyFile`, `now`); leaving it out, `undefined` and `null` all mean no options.

Rejected promises carry a `kind` property with one of the error kinds above. The whole interface is described in [docs/API.md](docs/API.md).

## Shell notes

In PowerShell, quote paths with spaces in single quotes. Put event JSON in a file rather than on the command line, and write it as UTF-8 without a byte-order mark (see the quick start). In Windows `cmd`, use double quotes around paths. Names such as `CON`, `NUL` and `log:stream` are refused as log, output, key, anchor and data paths on every platform.

## Development

These commands work in a source checkout (a clone of the repository); the installed package ships no tests or scripts. `npm test` runs the fast suite. `npm run test:long` (it runs `scripts/run-long-tests.mjs`) also runs the long real-limits group: a real log of 1,000,000 records (about 250 MB) in the temporary directory, checked for the append limit, `verify` and `export` under a 256 MB heap cap, plus a 262 MB log of 8,100 large records for the `show` byte cap and a forged 257 MB log of 4,000 records with 64,000-character actors for `summary`. It is skipped when less than 1 GB of disk is free, and it runs only while a `test/long-tests.enabled` file exists, which the script creates for the run.

## More

- [docs/FORMAT.md](docs/FORMAT.md) the record and anchor format with test vectors
- [docs/API.md](docs/API.md) the library interface
- [ARCHITECTURE.md](ARCHITECTURE.md) how the parts fit together
- [SECURITY.md](SECURITY.md) and [LIMITATIONS.md](LIMITATIONS.md) what this tool does and does not protect against
- [CHANGELOG.md](CHANGELOG.md)

Copyright 2026 JOONS contributors. Licensed under Apache-2.0.
