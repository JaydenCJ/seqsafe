# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Streaming ECMA-48 tokenizer: CSI, OSC, DCS, APC, PM, SOS and plain ESC sequences, chunk-boundary safe, with bounded memory (128-byte CSI cap, 8 KiB string-payload cap) and abort-and-reprocess handling of control bytes spliced into sequences.
- Raw 8-bit C1 introducer detection (`0x9B` CSI, `0x9D` OSC, ...) with UTF-8 awareness, so continuation bytes of multilingual text are never misread as controls and the classic ESC-only-filter bypass is closed.
- Sixteen-class semantic taxonomy (`sgr`, `hyperlink`, `cursor`, `screen`, `mode`, `title`, `clipboard`, `palette`, `query`, `dcs`, `charset`, `reset`, `control`, `c1`, `unknown`, `malformed`) with per-finding severity (`low` → `critical`) and specific labels (`clipboard-write`, `alt-screen`, `decrqss`, `tmux-passthrough`...).
- Allowlist policy engine with three presets (`default` keeps SGR + safe-scheme hyperlinks, `strict` keeps SGR only and drops lone CR, `plain` strips everything) refinable via `--allow` / `--deny`; `malformed` can never be allowed.
- Hyperlink (OSC 8) URI validation: scheme allowlist (`http`/`https`/`mailto`, override with `--link-schemes`), control-byte/whitespace rejection, 2048-byte cap; the empty-URI close form always passes.
- Kept sequences re-emitted with C1 introducers normalized to 7-bit ESC form; sanitized output re-scans clean (idempotence covered by tests).
- CLI: `seqsafe clean` (streaming filter, `--mark` visible placeholders, `--summary`, `-o`), `seqsafe scan` (human or `--json` report, `--fail-on` exit-code gate), `seqsafe explain` (per-finding rationale), `seqsafe classes` (policy reference table, honoring `--policy`/`--allow`/`--deny`); on a pipe, `seqsafe` without a subcommand is `seqsafe clean`, options included.
- Findings with byte offset, line number, class, severity, label and a control-escaped excerpt; bounded at 1000 stored findings with overflow counted, so hostile inputs cannot balloon memory.
- Examples: `examples/poisoned.log`, a seven-line attack corpus with a walkthrough README; `docs/classes.md` reference of every class → sequence mapping.
- Test suite: 81 unit tests, 9 CLI integration tests, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/seqsafe/releases/tag/v0.1.0
