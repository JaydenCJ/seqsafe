//! Streaming ECMA-48 tokenizer.
//!
//! Splits an untrusted byte stream into plain-text runs, C0/C1 controls and
//! complete escape sequences (CSI, OSC, DCS, SOS, PM, APC, plain ESC forms).
//! The parser is push-based and chunk-boundary safe: feed it arbitrary slices
//! and call [`Parser::finish`] at end of input to flush a dangling sequence.
//!
//! Security posture over leniency: a control byte inside a sequence aborts it
//! (sequence-splicing is a known filter-evasion trick), oversized sequences
//! are cut off with bounded memory, and raw 8-bit C1 introducers (`0x9B` for
//! CSI, `0x9D` for OSC, ...) are recognized — but only when they are not
//! continuation bytes of well-formed UTF-8 text, so multilingual output is
//! never corrupted.

/// Longest CSI sequence accepted before it is declared oversized.
pub const CSI_MAX: usize = 128;
/// Longest string-sequence payload (OSC/DCS/APC/PM/SOS) that is retained.
pub const STR_MAX: usize = 8192;
/// Longest ESC-sequence intermediate run accepted.
const ESC_INTERM_MAX: usize = 4;

/// Which string-style sequence a [`Token::Str`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrKind {
    /// Operating System Command — `ESC ]` (titles, clipboard, hyperlinks...).
    Osc,
    /// Device Control String — `ESC P` (DECRQSS, sixel, XTGETTCAP...).
    Dcs,
    /// Application Program Command — `ESC _` (kitty graphics, tmux...).
    Apc,
    /// Privacy Message — `ESC ^`.
    Pm,
    /// Start Of String — `ESC X`.
    Sos,
}

/// Why a sequence was rejected as malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// Input ended in the middle of the sequence.
    Truncated,
    /// A control byte (ESC, CAN, SUB, newline...) spliced into the sequence.
    AbortedByControl,
    /// The sequence exceeded [`CSI_MAX`].
    Oversized,
    /// A byte that is illegal at its position (e.g. a parameter byte after an
    /// intermediate byte, or a high byte inside a CSI sequence).
    BadByte,
}

/// One lexical unit of the input stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A run of ordinary bytes (UTF-8 text passes through untouched).
    Text(Vec<u8>),
    /// A single C0 control byte (except ESC) or DEL (`0x7F`).
    Control(u8),
    /// A standalone 8-bit C1 control byte that is not valid UTF-8 text and
    /// does not introduce a sequence handled elsewhere.
    C1(u8),
    /// A complete CSI sequence: `ESC [ params intermediates final`.
    Csi {
        params: Vec<u8>,
        intermediates: Vec<u8>,
        final_byte: u8,
        raw: Vec<u8>,
    },
    /// A complete non-CSI escape sequence: `ESC intermediates final`.
    Esc {
        intermediates: Vec<u8>,
        final_byte: u8,
        raw: Vec<u8>,
    },
    /// A complete, properly terminated string sequence.
    Str {
        kind: StrKind,
        /// Payload between introducer and terminator, capped at [`STR_MAX`].
        payload: Vec<u8>,
        /// Raw bytes including introducer and terminator (capped like payload).
        raw: Vec<u8>,
        /// True byte length consumed from the input (uncapped).
        len: usize,
        /// Payload exceeded [`STR_MAX`] and was truncated in `payload`/`raw`.
        overlong: bool,
    },
    /// A sequence that never completed correctly. Always stripped downstream.
    Malformed {
        raw: Vec<u8>,
        /// True byte length consumed from the input (uncapped).
        len: usize,
        reason: MalformedReason,
    },
}

impl Token {
    /// Number of input bytes this token accounts for.
    pub fn byte_len(&self) -> usize {
        match self {
            Token::Text(t) => t.len(),
            Token::Control(_) | Token::C1(_) => 1,
            Token::Csi { raw, .. } | Token::Esc { raw, .. } => raw.len(),
            Token::Str { len, .. } | Token::Malformed { len, .. } => *len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    /// After ESC, possibly with intermediates collected.
    Escape,
    /// Inside a CSI sequence.
    Csi,
    /// Inside a string sequence payload.
    Str,
}

/// Push-based streaming tokenizer. Create once per stream; call
/// [`Parser::feed`] per chunk and [`Parser::finish`] exactly once at EOF.
#[derive(Debug)]
pub struct Parser {
    state: State,
    text: Vec<u8>,
    raw: Vec<u8>,
    params: Vec<u8>,
    intermediates: Vec<u8>,
    /// CSI: an intermediate byte has been seen (param bytes now illegal).
    csi_in_interm: bool,
    str_kind: StrKind,
    payload: Vec<u8>,
    /// True consumed length of the in-flight string sequence.
    str_len: usize,
    str_overlong: bool,
    /// Inside a string: an ESC was seen and may be the first half of ST.
    str_esc: bool,
    /// Remaining UTF-8 continuation bytes expected in ground text.
    utf8_remaining: u8,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            state: State::Ground,
            text: Vec::new(),
            raw: Vec::new(),
            params: Vec::new(),
            intermediates: Vec::new(),
            csi_in_interm: false,
            str_kind: StrKind::Osc,
            payload: Vec::new(),
            str_len: 0,
            str_overlong: false,
            str_esc: false,
            utf8_remaining: 0,
        }
    }

    /// Tokenize a chunk, appending tokens to `out`. Sequences spanning chunk
    /// boundaries are held internally until complete.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<Token>) {
        for &b in input {
            self.push_byte(b, out);
        }
    }

    /// Flush end-of-input: emits pending text and turns any half-open
    /// sequence into [`Token::Malformed`] (a dangling introducer is itself a
    /// known trick to eat the bytes that follow it on a lenient terminal).
    pub fn finish(&mut self, out: &mut Vec<Token>) {
        match self.state {
            State::Ground => self.flush_text(out),
            State::Escape | State::Csi => self.emit_malformed(MalformedReason::Truncated, out),
            State::Str => {
                if self.str_esc {
                    // Count the held ESC as part of the doomed sequence.
                    self.str_len += 1;
                }
                self.emit_str_malformed(MalformedReason::Truncated, out);
            }
        }
        self.state = State::Ground;
    }

    fn push_byte(&mut self, b: u8, out: &mut Vec<Token>) {
        match self.state {
            State::Ground => self.ground(b, out),
            State::Escape => self.escape(b, out),
            State::Csi => self.csi(b, out),
            State::Str => self.string(b, out),
        }
    }

    // --- ground state -----------------------------------------------------

    fn ground(&mut self, b: u8, out: &mut Vec<Token>) {
        // UTF-8 continuation tracking: a byte in 0x80..=0xBF that a preceding
        // lead byte announced is text, never a C1 control.
        if self.utf8_remaining > 0 {
            if (0x80..=0xBF).contains(&b) {
                self.utf8_remaining -= 1;
                self.text.push(b);
                return;
            }
            // Invalid UTF-8: drop the expectation and reclassify this byte.
            self.utf8_remaining = 0;
        }
        match b {
            0x1B => {
                self.flush_text(out);
                self.begin_escape(&[0x1B]);
            }
            0x00..=0x1F | 0x7F => {
                self.flush_text(out);
                out.push(Token::Control(b));
            }
            0x80..=0x9F => self.c1(b, out),
            0xC0..=0xDF => {
                self.utf8_remaining = 1;
                self.text.push(b);
            }
            0xE0..=0xEF => {
                self.utf8_remaining = 2;
                self.text.push(b);
            }
            0xF0..=0xF7 => {
                self.utf8_remaining = 3;
                self.text.push(b);
            }
            _ => self.text.push(b),
        }
    }

    /// A raw 8-bit C1 control outside UTF-8 text. The five string/CSI
    /// introducers open their sequence exactly like their ESC-prefixed twins
    /// — naive filters that only look for `0x1B` miss these entirely.
    fn c1(&mut self, b: u8, out: &mut Vec<Token>) {
        self.flush_text(out);
        match b {
            0x9B => self.begin_csi(&[b]),
            0x90 => self.begin_str(StrKind::Dcs, &[b]),
            0x98 => self.begin_str(StrKind::Sos, &[b]),
            0x9D => self.begin_str(StrKind::Osc, &[b]),
            0x9E => self.begin_str(StrKind::Pm, &[b]),
            0x9F => self.begin_str(StrKind::Apc, &[b]),
            _ => out.push(Token::C1(b)),
        }
    }

    // --- escape state -----------------------------------------------------

    fn escape(&mut self, b: u8, out: &mut Vec<Token>) {
        match b {
            // A fresh control byte aborts the half-built sequence.
            0x00..=0x1F | 0x7F | 0x80..=0xFF => {
                self.emit_malformed(MalformedReason::AbortedByControl, out);
                self.push_byte(b, out);
            }
            0x20..=0x2F => {
                if self.intermediates.len() >= ESC_INTERM_MAX {
                    self.raw.push(b);
                    self.emit_malformed(MalformedReason::Oversized, out);
                } else {
                    self.intermediates.push(b);
                    self.raw.push(b);
                }
            }
            b'[' if self.intermediates.is_empty() => {
                self.raw.push(b);
                let raw = std::mem::take(&mut self.raw);
                self.begin_csi(&raw);
            }
            b']' if self.intermediates.is_empty() => self.escape_to_str(StrKind::Osc, b),
            b'P' if self.intermediates.is_empty() => self.escape_to_str(StrKind::Dcs, b),
            b'X' if self.intermediates.is_empty() => self.escape_to_str(StrKind::Sos, b),
            b'^' if self.intermediates.is_empty() => self.escape_to_str(StrKind::Pm, b),
            b'_' if self.intermediates.is_empty() => self.escape_to_str(StrKind::Apc, b),
            _ => {
                self.raw.push(b);
                out.push(Token::Esc {
                    intermediates: std::mem::take(&mut self.intermediates),
                    final_byte: b,
                    raw: std::mem::take(&mut self.raw),
                });
                self.state = State::Ground;
            }
        }
    }

    fn escape_to_str(&mut self, kind: StrKind, b: u8) {
        self.raw.push(b);
        let raw = std::mem::take(&mut self.raw);
        self.intermediates.clear();
        self.begin_str(kind, &raw);
    }

    // --- CSI state ----------------------------------------------------------

    fn csi(&mut self, b: u8, out: &mut Vec<Token>) {
        if self.raw.len() >= CSI_MAX {
            self.raw.push(b);
            self.emit_malformed(MalformedReason::Oversized, out);
            return;
        }
        match b {
            0x30..=0x3F => {
                if self.csi_in_interm {
                    // Parameter byte after an intermediate byte is illegal.
                    self.emit_malformed(MalformedReason::BadByte, out);
                    self.push_byte(b, out);
                } else {
                    self.params.push(b);
                    self.raw.push(b);
                }
            }
            0x20..=0x2F => {
                self.csi_in_interm = true;
                self.intermediates.push(b);
                self.raw.push(b);
            }
            0x40..=0x7E => {
                self.raw.push(b);
                out.push(Token::Csi {
                    params: std::mem::take(&mut self.params),
                    intermediates: std::mem::take(&mut self.intermediates),
                    final_byte: b,
                    raw: std::mem::take(&mut self.raw),
                });
                self.state = State::Ground;
            }
            _ => {
                // Control or high byte spliced into the sequence: abort and
                // reprocess the byte on its own.
                self.emit_malformed(MalformedReason::AbortedByControl, out);
                self.push_byte(b, out);
            }
        }
    }

    // --- string state -------------------------------------------------------

    fn string(&mut self, b: u8, out: &mut Vec<Token>) {
        if self.str_esc {
            self.str_esc = false;
            if b == b'\\' {
                // ESC \ = ST, the proper terminator.
                self.str_len += 2;
                self.str_push_raw(0x1B);
                self.str_push_raw(b);
                self.emit_str(out);
            } else {
                // The ESC belonged to a new sequence: the string never ended.
                self.emit_str_malformed(MalformedReason::AbortedByControl, out);
                self.begin_escape(&[0x1B]);
                self.push_byte(b, out);
            }
            return;
        }
        match b {
            0x1B => self.str_esc = true,
            0x07 if self.str_kind == StrKind::Osc => {
                // BEL terminates OSC only (an xterm extension).
                self.str_len += 1;
                self.str_push_raw(b);
                self.emit_str(out);
            }
            0x9C => {
                // Raw 8-bit ST. Inside a sequence we are no longer in text,
                // so UTF-8 leniency does not apply here.
                self.str_len += 1;
                self.str_push_raw(b);
                self.emit_str(out);
            }
            0x00..=0x06 | 0x08..=0x1F | 0x7F => {
                // A bare control byte (newline splice, CAN, SUB...) aborts.
                self.emit_str_malformed(MalformedReason::AbortedByControl, out);
                self.push_byte(b, out);
            }
            _ => {
                self.str_len += 1;
                if self.payload.len() >= STR_MAX {
                    self.str_overlong = true;
                } else {
                    self.payload.push(b);
                    self.raw.push(b);
                }
            }
        }
    }

    // --- helpers ------------------------------------------------------------

    fn flush_text(&mut self, out: &mut Vec<Token>) {
        self.utf8_remaining = 0;
        if !self.text.is_empty() {
            out.push(Token::Text(std::mem::take(&mut self.text)));
        }
    }

    fn begin_escape(&mut self, intro: &[u8]) {
        self.raw.clear();
        self.raw.extend_from_slice(intro);
        self.intermediates.clear();
        self.state = State::Escape;
    }

    fn begin_csi(&mut self, intro: &[u8]) {
        self.raw.clear();
        self.raw.extend_from_slice(intro);
        self.params.clear();
        self.intermediates.clear();
        self.csi_in_interm = false;
        self.state = State::Csi;
    }

    fn begin_str(&mut self, kind: StrKind, intro: &[u8]) {
        self.raw.clear();
        self.raw.extend_from_slice(intro);
        self.payload.clear();
        self.str_kind = kind;
        self.str_len = intro.len();
        self.str_overlong = false;
        self.str_esc = false;
        self.state = State::Str;
    }

    fn str_push_raw(&mut self, b: u8) {
        if self.raw.len() < STR_MAX {
            self.raw.push(b);
        }
    }

    fn emit_str(&mut self, out: &mut Vec<Token>) {
        out.push(Token::Str {
            kind: self.str_kind,
            payload: std::mem::take(&mut self.payload),
            raw: std::mem::take(&mut self.raw),
            len: self.str_len,
            overlong: self.str_overlong,
        });
        self.state = State::Ground;
    }

    fn emit_str_malformed(&mut self, reason: MalformedReason, out: &mut Vec<Token>) {
        self.payload.clear();
        out.push(Token::Malformed {
            raw: std::mem::take(&mut self.raw),
            len: self.str_len,
            reason,
        });
        self.state = State::Ground;
    }

    fn emit_malformed(&mut self, reason: MalformedReason, out: &mut Vec<Token>) {
        let raw = std::mem::take(&mut self.raw);
        let len = raw.len();
        self.params.clear();
        self.intermediates.clear();
        out.push(Token::Malformed { raw, len, reason });
        self.state = State::Ground;
    }
}

/// Convenience for tests and one-shot callers: tokenize a complete buffer.
pub fn tokenize(input: &[u8]) -> Vec<Token> {
    let mut p = Parser::new();
    let mut out = Vec::new();
    p.feed(input, &mut out);
    p.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    //! Parser unit tests: chunk-boundary safety, UTF-8/C1 disambiguation,
    //! abort-and-reprocess on spliced controls, and size caps.

    use super::*;

    fn one(input: &[u8]) -> Token {
        let toks = tokenize(input);
        assert_eq!(toks.len(), 1, "expected one token, got {toks:?}");
        toks.into_iter().next().unwrap()
    }

    #[test]
    fn sgr_sequence_parses_with_params_and_raw() {
        match one(b"\x1b[1;32m") {
            Token::Csi {
                params,
                final_byte,
                raw,
                ..
            } => {
                assert_eq!(params, b"1;32");
                assert_eq!(final_byte, b'm');
                assert_eq!(raw, b"\x1b[1;32m");
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn osc_terminated_by_bel() {
        match one(b"\x1b]0;evil title\x07") {
            Token::Str {
                kind,
                payload,
                len,
                overlong,
                ..
            } => {
                assert_eq!(kind, StrKind::Osc);
                assert_eq!(payload, b"0;evil title");
                assert_eq!(len, b"\x1b]0;evil title\x07".len());
                assert!(!overlong);
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn osc_terminated_by_st() {
        match one(b"\x1b]52;c;aGk=\x1b\\") {
            Token::Str {
                kind, payload, raw, ..
            } => {
                assert_eq!(kind, StrKind::Osc);
                assert_eq!(payload, b"52;c;aGk=");
                assert_eq!(raw, b"\x1b]52;c;aGk=\x1b\\");
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn dcs_apc_pm_sos_kinds_are_distinguished() {
        for (input, kind) in [
            (&b"\x1bPq#0\x1b\\"[..], StrKind::Dcs),
            (b"\x1b_Ga=T\x1b\\", StrKind::Apc),
            (b"\x1b^hi\x1b\\", StrKind::Pm),
            (b"\x1bXhi\x1b\\", StrKind::Sos),
        ] {
            match one(input) {
                Token::Str { kind: k, .. } => assert_eq!(k, kind),
                t => panic!("unexpected {t:?} for {input:?}"),
            }
        }
    }

    #[test]
    fn plain_esc_sequence_with_charset_intermediate() {
        match one(b"\x1b(0") {
            Token::Esc {
                intermediates,
                final_byte,
                ..
            } => {
                assert_eq!(intermediates, b"(");
                assert_eq!(final_byte, b'0');
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn text_runs_and_control_bytes_tokenize_cleanly() {
        assert_eq!(one(b"hello world"), Token::Text(b"hello world".to_vec()));
        let toks = tokenize(b"a\x07b");
        assert_eq!(
            toks,
            vec![
                Token::Text(b"a".to_vec()),
                Token::Control(0x07),
                Token::Text(b"b".to_vec()),
            ]
        );
    }

    #[test]
    fn raw_c1_introducers_open_sequences() {
        // 0x9B after ASCII is a real C1 CSI, the classic naive-filter bypass;
        // 0x9D..0x9C is the 8-bit OSC form.
        match one(b"\x9b31m") {
            Token::Csi {
                params, final_byte, ..
            } => {
                assert_eq!(params, b"31");
                assert_eq!(final_byte, b'm');
            }
            t => panic!("unexpected {t:?}"),
        }
        match one(b"\x9d52;c;x\x9c") {
            Token::Str { kind, payload, .. } => {
                assert_eq!(kind, StrKind::Osc);
                assert_eq!(payload, b"52;c;x");
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn utf8_continuation_bytes_are_never_c1_controls() {
        // "曖" is E6 9B 96: the 0x9B here must NOT open a CSI sequence...
        let toks = tokenize("曖昧".as_bytes());
        assert_eq!(toks, vec![Token::Text("曖昧".as_bytes().to_vec())]);
        // ...but the same byte after a *complete* UTF-8 char is a real C1.
        let mut input = "é".as_bytes().to_vec();
        input.extend_from_slice(b"\x9b1m");
        let toks = tokenize(&input);
        assert!(
            matches!(toks.last(), Some(Token::Csi { .. })),
            "got {toks:?}"
        );
    }

    #[test]
    fn sequence_split_across_feeds_is_reassembled() {
        let mut p = Parser::new();
        let mut out = Vec::new();
        p.feed(b"\x1b]0;ti", &mut out);
        assert!(out.is_empty(), "no token before the terminator");
        p.feed(b"tle\x07after", &mut out);
        p.finish(&mut out);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], Token::Str { payload, .. } if payload == b"0;title"));
        assert_eq!(out[1], Token::Text(b"after".to_vec()));
    }

    #[test]
    fn every_chunking_of_a_mixed_stream_yields_identical_tokens() {
        let input = b"pre\x1b[1mred\x1b]0;t\x07\x9b0mpost\n";
        let reference = tokenize(input);
        for cut in 1..input.len() {
            let mut p = Parser::new();
            let mut out = Vec::new();
            p.feed(&input[..cut], &mut out);
            p.feed(&input[cut..], &mut out);
            p.finish(&mut out);
            assert_eq!(out, reference, "cut at {cut}");
        }
    }

    #[test]
    fn truncated_sequences_at_eof_are_malformed_with_true_length() {
        for (input, len) in [(&b"\x1b[31"[..], 4), (b"\x1b]52;c;abc", 10)] {
            match one(input) {
                Token::Malformed { reason, len: l, .. } => {
                    assert_eq!(reason, MalformedReason::Truncated, "{input:?}");
                    assert_eq!(l, len, "{input:?}");
                }
                t => panic!("unexpected {t:?}"),
            }
        }
    }

    #[test]
    fn newline_spliced_into_osc_aborts_and_survives_as_control() {
        // An OSC that "eats" the rest of the line must not swallow real
        // newlines: the splice aborts the sequence and the \n is reprocessed.
        let toks = tokenize(b"\x1b]0;x\nrest");
        assert!(matches!(
            toks[0],
            Token::Malformed {
                reason: MalformedReason::AbortedByControl,
                ..
            }
        ));
        assert_eq!(toks[1], Token::Control(b'\n'));
        assert_eq!(toks[2], Token::Text(b"rest".to_vec()));
    }

    #[test]
    fn esc_inside_osc_starts_a_new_sequence() {
        let toks = tokenize(b"\x1b]0;x\x1b[1mtext");
        assert!(matches!(
            toks[0],
            Token::Malformed {
                reason: MalformedReason::AbortedByControl,
                ..
            }
        ));
        assert!(matches!(
            &toks[1],
            Token::Csi {
                final_byte: b'm',
                ..
            }
        ));
        assert_eq!(toks[2], Token::Text(b"text".to_vec()));
    }

    #[test]
    fn size_caps_bound_csi_and_string_sequences() {
        let mut input = b"\x1b[".to_vec();
        input.extend(std::iter::repeat(b'1').take(CSI_MAX + 10));
        input.push(b'm');
        let toks = tokenize(&input);
        assert!(matches!(
            toks[0],
            Token::Malformed {
                reason: MalformedReason::Oversized,
                ..
            }
        ));
        let mut input = b"\x1b]52;c;".to_vec();
        input.extend(std::iter::repeat(b'A').take(STR_MAX + 100));
        input.extend_from_slice(b"\x1b\\");
        let total = input.len();
        match one(&input) {
            Token::Str {
                overlong,
                payload,
                len,
                ..
            } => {
                assert!(overlong);
                assert_eq!(payload.len(), STR_MAX);
                assert_eq!(len, total);
            }
            t => panic!("unexpected {t:?}"),
        }
    }

    #[test]
    fn param_byte_after_intermediate_is_bad() {
        let toks = tokenize(b"\x1b[!1p");
        assert!(matches!(
            toks[0],
            Token::Malformed {
                reason: MalformedReason::BadByte,
                ..
            }
        ));
    }

    #[test]
    fn esc_esc_yields_malformed_then_a_sequence() {
        let toks = tokenize(b"\x1b\x1b[1m");
        assert!(matches!(toks[0], Token::Malformed { .. }));
        assert!(matches!(
            &toks[1],
            Token::Csi {
                final_byte: b'm',
                ..
            }
        ));
    }

    #[test]
    fn byte_len_accounts_for_every_input_byte() {
        let input = b"a\x1b[1mb\x1b]0;t\x07\x08\x9bXc\xffd";
        let toks = tokenize(input);
        let total: usize = toks.iter().map(|t| t.byte_len()).sum();
        assert_eq!(total, input.len());
    }
}
