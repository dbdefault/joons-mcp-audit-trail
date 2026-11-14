# Architecture

The package is an offline Node.js library and command-line tool. It has no dependencies, opens no network connections, starts no subprocesses and reads no environment variables. The only supported import is `src/index.js`.

## Modules

- `src/errors.js` defines `AuditError`, which carries one of eleven fixed error kinds and nothing else.
- `src/canon` defines the canonical JSON form, hashing (SHA-256 or HMAC-SHA256), key identifiers, time validation, event and record validation (events are copied into a plain snapshot first), and the credential scan.
- `src/log` does the file work. `paths.js` holds the shared path checker and the regular-file reader, `atomic.js` the streaming atomic output writer, and `index.js` the key-file loading, the exclusive lock (a file holding a random token), reading the head and tail of a log, the append itself with a flush to disk, and the streaming line reader.
- `src/verify` walks a whole log and produces the verification report; it also creates and checks anchors.
- `src/report` produces the summary (names longer than 128 code points are counted, not stored) and renders reports and records for the terminal, JSON, Markdown and CSV (as a whole list or streamed), including the sanitizer for terminal text, whose predicate the CSV cell escape reuses.
- `src/cli` parses arguments, runs one command, and turns results and errors into output and exit codes.
- `bin/joons-mcp-audit-trail.js` is the launcher.

## Data flow

A log is a hash chain: a header names the mode and key identifier, and each event carries the hash of the line before it. Every stored line is the canonical JSON of its record. `append` validates the event and its time first, then takes the lock, checks the header and the last record (which must be in canonical form), refuses a time earlier than the last record, builds and hashes the new line and writes it with a single write followed by a flush. `verify` streams the file once and records findings; the reader reports line-level problems (bad JSON, over-long line, bad encoding, unfinished last line) as items instead of throwing, and flags lines that are not canonical, so one damaged line does not hide later findings. `export` streams the same reader into a temporary file that is moved into place when it is complete. An anchor stores a record count and head hash apart from the log, so a shorter or rewritten log can be told from the original.

## Boundaries

Event contents are claims made by the caller. The tool does not authenticate the caller, supply trusted time or provide write-once storage. Filesystem behaviour, access control, backups and key custody remain the operator's responsibility. See [docs/FORMAT.md](docs/FORMAT.md), [SECURITY.md](SECURITY.md) and [LIMITATIONS.md](LIMITATIONS.md).
