# Sequence classes

seqsafe's policy engine reasons about *classes* of escape sequences, not
individual byte patterns. This is the full mapping from wire sequences to
classes, with each class's default treatment and severity when stripped.
Class names are the values accepted by `--allow` and `--deny`; the same table
is available at runtime via `seqsafe classes`.

Both the 7-bit form (`ESC [`, `ESC ]`, ...) and the raw 8-bit C1 form
(`0x9B`, `0x9D`, ...) of every introducer are recognized. An 8-bit introducer
is only treated as such when it is *not* a continuation byte of well-formed
UTF-8 text, so multilingual output is never corrupted.

| Class | Sequences covered | default | strict | plain | Severity |
|---|---|---|---|---|---|
| `sgr` | `CSI ... m` with numeric/`;`/`:` params only | keep | keep | strip | none |
| `hyperlink` | `OSC 8 ; params ; uri` | keep¹ | strip | strip | none / medium¹ |
| `cursor` | `CSI A B C D E F G H a d e f `` ` `` s u`, `ESC 7/8` | strip | strip | strip | medium |
| `screen` | `CSI J K L M P S T X @ b r`, `ESC D E M`, `ESC # ...` | strip | strip | strip | medium |
| `mode` | `CSI ... h/l` (alt screen 1047/1049, mouse 1000–1016, bracketed paste 2004...), `ESC = >`, `CSI SP q` | strip | strip | strip | medium–high |
| `title` | `OSC 0/1/2`, `CSI 22/23 t` (title stack) | strip | strip | strip | high |
| `clipboard` | `OSC 52` (write, and `?` read-back) | strip | strip | strip | critical |
| `palette` | `OSC 4/5/104/105`, `OSC 10–19/110–119` | strip | strip | strip | medium |
| `query` | `CSI c/n/x/t`, `ESC Z`, `ENQ` (0x05), `OSC 10;?`... | strip | strip | strip | high |
| `dcs` | DCS/APC/PM/SOS bodies: DECRQSS, XTGETTCAP, tmux passthrough, sixel, kitty graphics, `OSC 1337` | strip | strip | strip | medium–critical |
| `charset` | `ESC ( ) * + - . /` designations, `ESC %`, SO/SI, SS2/SS3, locking shifts | strip | strip | strip | medium–high |
| `reset` | `ESC c` (RIS), `CSI ! p` (DECSTR) | strip | strip | strip | high |
| `control` | bare C0 bytes and DEL: BEL, BS, VT, FF, NUL... | strip² | strip² | strip² | low–medium |
| `c1` | standalone raw 0x80–0x9F bytes outside UTF-8 text | strip | strip | strip | high |
| `unknown` | well-formed sequences not otherwise recognized | strip | strip | strip | low–medium |
| `malformed` | truncated / control-spliced / oversized sequences | strip³ | strip³ | strip³ | medium–high |

¹ Under `default`, a hyperlink is kept only if its URI uses an allowlisted
scheme (`http`, `https`, `mailto`; override with `--link-schemes`), contains
no control bytes or whitespace, and is ≤ 2048 bytes. Anything else is
stripped with a `medium` finding. The empty-URI close form (`OSC 8 ;;`) is
always harmless and kept.

² `\n`, `\t` and `\r` are hardwired safe and always pass. Exception: under
`strict`, a `\r` **not** immediately followed by `\n` ("lone CR", the
overwrite-the-line-you-just-read trick) is dropped with a `medium` finding.

³ `malformed` can never be allowed — there is no well-formed sequence to
re-emit. `--allow malformed` is a usage error.

## Severity levels

`scan --fail-on <level>` exits 1 when any finding is at or above the level:

| Level | Meaning | Examples |
|---|---|---|
| `critical` | Direct compromise primitive | clipboard write/read, DECRQSS, XTGETTCAP, tmux passthrough, iTerm2 OSC 1337 |
| `high` | State that outlives the output, or terminal-answers-on-stdin | title set, device queries, mode switches, charset remap, resets, raw C1 |
| `medium` | Rewrites or hides what you already read | cursor moves, erases, palette, lone CR, backspace, malformed sequences |
| `low` | Annoyance / noise | BEL, stray terminators, unknown low-risk OSC |

## Normalization of kept sequences

Kept sequences are re-emitted with 8-bit C1 introducers/terminators
normalized to their 7-bit `ESC`-prefixed equivalents (`0x9B 31 6D` becomes
`ESC [ 3 1 m`), so downstream consumers of sanitized output never need to
handle raw C1 bytes. A BEL terminator on a kept OSC is preserved as BEL.
Sanitized output re-scans clean: `clean` is idempotent by construction and
by test.
