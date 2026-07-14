# Contributing to seqsafe

Thanks for your interest in improving seqsafe. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain).

```bash
git clone https://github.com/JaydenCJ/seqsafe.git
cd seqsafe
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` pushes a realistic poisoned log through the real CLI end to end (clean, scan, explain, classes, policies, JSON gating, byte-dribbled pipe streaming) in a temporary directory. It finishes in well under a minute and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. The pipeline is deliberately layered into pure modules (`parser` → `classify` → `policy` → `sanitize` → `report`); please keep classification knowledge out of the parser and policy decisions out of the classifier.

## Ground rules

- Zero runtime dependencies is a hard feature, not an accident: a security filter should not widen the supply chain it guards. PRs adding a dependency will be declined.
- Fail closed. A sequence seqsafe does not recognize is stripped, never passed through; a malformed sequence can never be allowlisted. New classification must follow the same principle.
- No network calls, no telemetry, ever. seqsafe reads stdin/files and writes stdout/files; that is its entire I/O surface.
- Code comments and doc comments are written in English.
- Streaming correctness is non-negotiable: any parser or sanitizer change must keep the "identical output across all chunkings" tests passing.

## Reporting bugs

Please include the `seqsafe --version` output, the exact command line, and a reproducer input — ideally as a `printf` one-liner or a base64 blob, since raw escape bytes rarely survive an issue tracker. For filter-bypass reports, `seqsafe scan --json` output of the offending input is the most useful evidence.

## Security

seqsafe is a security tool: a bypass (a sequence that reaches the terminal despite the policy saying it should not) is a vulnerability, not a bug. Please do not open a public issue for bypasses — use GitHub's private vulnerability reporting on this repository instead.
