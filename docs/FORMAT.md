# Format version 1

A log is a UTF-8 text file in JSON Lines form: one JSON object per line, each line ended by a single `\n`, no byte-order mark, no blank lines, at most 65,536 bytes per line. Lines ending in `\r\n`, NUL bytes and a missing final newline are all treated as damage.

## Exact line format

The writer stores each record as its canonical form (see below), including the `hash` key, followed by `\n`. The stored line must therefore be exactly `canonicalize(record)`: keys sorted, no whitespace, strings escaped as `JSON.stringify` escapes them, integers spelled without a fraction or exponent.

The verifier reads each line as raw bytes, decodes it with a strict UTF-8 decoder that does not strip a byte-order mark, parses it and compares the text with `canonicalize(parsed)`. A line that parses but differs (whitespace, reordered keys, a key written twice, a different spelling of a character (a backslash-u escape instead of the letter itself) or of a number (`1.0` or `1e0` for `1`), padding with spaces up to the 65,536-byte limit, a byte-order mark) is reported as `bad_record` (`bad_header` for line 0) with the detail `line_not_canonical`, and the hash chain checks continue with the parsed record. A line that is not valid UTF-8, does not parse, or begins with a byte-order mark is reported as `bad_record` with the detail `record_invalid`. `append` refuses (`log_corrupt`) when the header line or the last line is not in this exact form.

## Records

Line 0 is the header. Its keys are exactly `format` (`joons-mcp-audit-trail/log`), `version` (`1`), `seq` (`0`), `time`, `mode` (`sha256` or `hmac-sha256`), `keyId` (`null` in plain mode, 16 lowercase hexadecimal characters in keyed mode), `prev` (64 zeros) and `hash`.

Every later line is an event. Its keys are exactly `seq`, `time`, `type`, `actor`, `tool`, `outcome`, `data`, `prev` and `hash`. The sequence number starts at 0 for the header and grows by one per line, so the first event has `seq` 1. `prev` repeats the `hash` of the preceding line; for the header it is 64 zeros (the genesis value).

Field rules:

- `time` is UTC in the form `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.fffZ` and must be a real calendar moment. Times may repeat but must not move backward, counting the header and comparing parsed instants (so `...:01Z` equals `...:01.000Z` and is earlier than `...:01.500Z`). `append` refuses an explicit event time earlier than the last record with `invalid_record`; without an explicit time the default clock is sampled while the lock is held and clamped to the last record's time. A fraction, when present, has exactly three digits. The value is supplied by the caller and is not trusted time.
- `type` has 1 to 64 characters from `A-Z a-z 0-9 . _ : -`.
- `actor` and `tool` are `null` or strings of 1 to 128 Unicode code points without control characters, unassigned code points, default-ignorable code points, space separators other than U+0020, format characters (including bidirectional and zero-width characters), variation selectors, tag characters, private-use characters, line or paragraph separators, or the invisible fillers U+034F, U+115F, U+1160, U+17B4, U+17B5, U+2800, U+3164, U+FFA0 and U+FFFC. Besides that, `append` refuses the literal name `(other)` (the label of the summary overflow bucket) and a name that starts or ends with U+0020. These rules are applied when a record is written, and the unassigned-code-point rule follows the Unicode data of the running Node.js. The stored-name check (`verify` and the tail check of `append`, through the record shape check) uses a fixed table that does not depend on that data and does not apply the `(other)` and space rules; `show`, `summary` and `export` check only the key set and the canonical form of each line and sanitize their output. The fixed table holds only explicit stable classes, and every entry is a class that the writer rejects on every Node.js: ASCII and C1 controls (U+0000 to U+001F, U+007F to U+009F), U+00A0, soft hyphen U+00AD, U+034F, the Arabic and Syriac format characters U+0600 to U+0605, U+061C, U+06DD, U+070F, U+0890, U+0891, U+08E2, the fillers U+115F, U+1160, U+3164, U+FFA0, U+1680, U+17B4, U+17B5, U+180B to U+180F, the space separators and format characters U+2000 to U+200F, the line and paragraph separators and bidirectional controls U+2028 to U+202F, U+205F to U+206F, U+2800, U+3000, surrogates and the BMP private-use area (U+D800 to U+F8FF), U+FDD0 to U+FDEF, variation selectors U+FE00 to U+FE0F, U+FEFF, U+FFF0 to U+FFFC, the noncharacters U+FFFE and U+FFFF of every plane, U+110BD, U+110CD, U+13430 to U+1343F, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, U+E0000 to U+E0FFF and planes 15 and 16. It is a subset of what the writer rejects: all visible punctuation (hyphens, dashes, curly quotes, bullets, ellipsis, per mille and prime signs, U+2010 to U+2027 and U+2030 to U+205E), symbols, letters, marks and numbers that the writer accepts are outside it, which a test checks over every code point. Because the table does not depend on the Unicode data of the running Node.js, a log written on a newer Node.js verifies on an older one.
- `outcome` is `null` or one of `ok`, `allow`, `deny`, `error`, `info`.
- `data` is `null` or a JSON object: at most 32 KiB in canonical form, at most depth 6 (the root object is depth 1), at most 64 keys per object, at most 64 elements per array, strings of at most 4,096 code points. The key names `__proto__`, `constructor` and `prototype` are refused. Numbers must be safe integers and are read by value: `1.0` and `1e2` denote the integers 1 and 100 and are stored as `1` and `100`, while a non-integer such as `1.5` is refused. Values are copied into a plain snapshot before validation; getters, symbols, holes and non-plain objects are refused, and the walk is limited to 100,000 nodes.
- `hash` is 64 lowercase hexadecimal characters.

## Canonical form and hashing

The canonical form of a JSON value has object keys sorted in UTF-16 code-unit order, array order kept, no whitespace, and strings escaped exactly as `JSON.stringify` does. Numbers are finite safe integers only.

The hash of a record is computed over the UTF-8 bytes of the canonical form of the record with its `hash` key removed. In plain mode it is SHA-256. In keyed mode it is HMAC-SHA256 with the raw key bytes. A key file's content is the key, with exactly one trailing line terminator (`\n` or `\r\n`) removed, at least 16 bytes and not made only of line terminators. `keyId` is the first 16 hexadecimal characters of SHA-256 applied to the SHA-256 digest of the key bytes; it identifies the key without revealing it (and is identical in every log that uses the same key).

The hash does not depend on how a line is written, but the stored line is required to be the canonical form, so two different spellings of the same record cannot both be accepted. The stored line is the hash input plus the `hash` key at its sorted position.

## Anchor file

An anchor is a small JSON file kept apart from the log, written in the same canonical form followed by `\n`. Its keys are exactly `format` (`joons-mcp-audit-trail/anchor`), `version` (`1`), `count` (number of lines in the log, header included), `headHash` (hash of the line at index `count - 1`), `mode`, `keyId`, `time` (UTC time the anchor was made) and `hash`. The anchor hash uses the same algorithm over the other fields, so a keyed anchor needs the key to be checked. The reader is lenient about spelling in an anchor file, because every field is covered by its hash.

`verify --anchor` reports `truncated_tail` when the log has fewer lines than `count`, and `anchor_mismatch` when the line at `count - 1` has a different hash, when the anchor's own hash does not match, or when the anchor file is malformed. A log that is longer than the anchor still matches it. An anchor whose mode or key identifier differs from the log's header is reported as `mode_change`.

## Verification findings

`verify` never stops at the first finding. Each finding is `{kind, seq, detail}`, reported once per kind, line and detail, with at most 100 listed and `truncated_report` after them. Detail strings come from a fixed vocabulary: `header_invalid`, `record_invalid`, `line_not_canonical`, `hash_differs`, `prev_differs`, `seq_not_contiguous`, `time_earlier_than_previous`, `anchor_mode_differs`, `key_id_differs`, `header_not_keyed`, `log_shorter_than_anchor`, `anchor_head_differs`, `anchor_hash_invalid`, `anchor_invalid`, `unterminated_or_extra_line` and `more_than_100_findings`. `header_not_keyed` is the detail of a `key_mismatch` finding that says a key was supplied (or required) but the header is not in keyed mode.

## Test vectors

These values were computed with a separate small canonicalizer and `node:crypto`, not with the package. The test suite recomputes every line below on each run. Key bytes for the keyed header: the 16 ASCII characters `0123456789abcdef`.

Plain header (hash input is the canonical form without `hash`):

```text
{"format":"joons-mcp-audit-trail/log","keyId":null,"mode":"sha256","prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":0,"time":"2026-01-01T00:00:00Z","version":1}
```

SHA-256 of that text: `e8d1ea03078e0d86d1b328e94ba7b44d04b174c94cce10efeab37fff7de17b89`

Complete stored log lines (header, event) and anchor, exactly as written to disk:

```jsonl
{"format":"joons-mcp-audit-trail/log","hash":"e8d1ea03078e0d86d1b328e94ba7b44d04b174c94cce10efeab37fff7de17b89","keyId":null,"mode":"sha256","prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":0,"time":"2026-01-01T00:00:00Z","version":1}
{"actor":"agent","data":{"action":"read"},"hash":"4dbe11f9802038b64d5795af3f2aaf4bc9bf8190cfbb0b76c9604e39f3899390","outcome":"ok","prev":"e8d1ea03078e0d86d1b328e94ba7b44d04b174c94cce10efeab37fff7de17b89","seq":1,"time":"2026-01-01T00:00:01Z","tool":"search","type":"tool.call"}
```

```json
{"count":2,"format":"joons-mcp-audit-trail/anchor","hash":"027b7431a360a1f68dbfcc9482ca0b1050346c5f67fb9348922ee4911cba60ad","headHash":"4dbe11f9802038b64d5795af3f2aaf4bc9bf8190cfbb0b76c9604e39f3899390","keyId":null,"mode":"sha256","time":"2026-01-01T00:00:02Z","version":1}
```

Keyed header for the key above (key identifier `5dbd4f6e325e5a87`, HMAC-SHA256 hash):

```json
{"format":"joons-mcp-audit-trail/log","hash":"c174827ef8bc16fd8368120a53baa018a00b9f42abf3ecb84b2336e7ea6a3a29","keyId":"5dbd4f6e325e5a87","mode":"hmac-sha256","prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":0,"time":"2026-01-01T00:00:00Z","version":1}
```

## Reference algorithm

Recursively: `null`, booleans, numbers and strings are encoded with `JSON.stringify`; an array is `[` plus its encoded elements joined by `,` plus `]`; an object is `{` plus `JSON.stringify(key) + ':' + encoded value` for each key from `Object.keys(value).sort()`, joined by `,`, plus `}`. Pass the UTF-8 bytes to `createHash('sha256')` or `createHmac('sha256', key)`. To store a record, add the lowercase hexadecimal result as the `hash` key, encode the whole record the same way, and append `\n`.

## What the format does not give you

The chain shows that the lines are consistent with each other and with a head hash you kept. It does not prove who wrote a line, when it was written, or that nothing after the last retained anchor was removed. A log rewritten completely in plain mode cannot be told from a genuine plain log without a key or an anchor. See [security](../SECURITY.md) and [limitations](../LIMITATIONS.md).
