//! The streaming sanitizer: parser → classifier → policy → clean bytes.
//!
//! [`Sanitizer`] is fed arbitrary chunks and writes sanitized bytes plus a
//! bounded list of [`Finding`]s describing everything it removed. Kept
//! sequences are re-emitted with their introducer normalized to the 7-bit
//! `ESC`-prefixed form, so downstream consumers never see raw C1 bytes even
//! when the input used them.

use crate::classify::{classify, hyperlink_uri, Class, Severity};
use crate::parser::{Parser, StrKind, Token};
use crate::policy::Policy;

/// Cap on individually recorded findings; past this they are only counted.
pub const MAX_FINDINGS: usize = 1000;
/// Cap on excerpt length (in visible characters) inside a finding.
const EXCERPT_CAP: usize = 48;

/// What the sanitizer did about one offending token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Removed from the output entirely.
    Stripped,
    /// Replaced with a visible `⟨stripped:label⟩` marker (`--mark`).
    Marked,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Stripped => "stripped",
            Action::Marked => "marked",
        }
    }
}

/// One removed (or marked) sequence, with enough context to audit it.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Byte offset of the sequence start in the original input.
    pub offset: usize,
    /// 1-based input line the sequence started on.
    pub line: usize,
    pub class: Class,
    pub severity: Severity,
    /// Specific identifier (`clipboard-write`, `alt-screen`, `unsafe-link`...).
    pub label: &'static str,
    pub action: Action,
    /// Human-readable rendering of the raw bytes, controls escaped.
    pub excerpt: String,
}

/// Aggregate statistics over one sanitizer run.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub bytes_in: usize,
    pub bytes_out: usize,
    /// Escape sequences re-emitted because the policy allows them.
    pub kept: usize,
    /// Tokens removed, including benign ones (e.g. SGR under `plain`).
    pub stripped: usize,
    /// Findings recorded or counted (stripped tokens with severity > none).
    pub findings: usize,
    /// Findings beyond [`MAX_FINDINGS`] that were counted but not stored.
    pub suppressed: usize,
    /// Count of findings per severity: [low, medium, high, critical].
    pub by_severity: [usize; 4],
}

/// Streaming sanitizer. One instance per input stream.
pub struct Sanitizer {
    parser: Parser,
    policy: Policy,
    mark: bool,
    findings: Vec<Finding>,
    summary: Summary,
    max_severity: Severity,
    offset: usize,
    line: usize,
    /// A held carriage return waiting to learn whether an LF follows
    /// (only used when the policy forbids lone CR).
    pending_cr: Option<(usize, usize)>,
    tokens: Vec<Token>,
}

impl Sanitizer {
    pub fn new(policy: Policy) -> Sanitizer {
        Sanitizer {
            parser: Parser::new(),
            policy,
            mark: false,
            findings: Vec::new(),
            summary: Summary::default(),
            max_severity: Severity::None,
            offset: 0,
            line: 1,
            pending_cr: None,
            tokens: Vec::new(),
        }
    }

    /// Replace stripped sequences with visible markers instead of deleting.
    pub fn with_mark(mut self, mark: bool) -> Sanitizer {
        self.mark = mark;
        self
    }

    /// Sanitize a chunk, appending clean bytes to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.summary.bytes_in += chunk.len();
        let mut tokens = std::mem::take(&mut self.tokens);
        tokens.clear();
        self.parser.feed(chunk, &mut tokens);
        for token in &tokens {
            self.process(token, out);
        }
        self.tokens = tokens;
    }

    /// Flush end-of-input. Must be called exactly once.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let mut tokens = std::mem::take(&mut self.tokens);
        tokens.clear();
        self.parser.finish(&mut tokens);
        for token in &tokens {
            self.process(token, out);
        }
        self.tokens = tokens;
        // A CR at EOF with no LF after it is a lone CR.
        self.resolve_pending_cr(None, out);
        self.summary.findings = self.findings.len() + self.summary.suppressed;
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Highest severity among all findings (for `--fail-on` gating).
    pub fn max_severity(&self) -> Severity {
        self.max_severity
    }

    // --- internals ----------------------------------------------------------

    fn process(&mut self, token: &Token, out: &mut Vec<u8>) {
        let start_offset = self.offset;
        let start_line = self.line;
        self.offset += token.byte_len();
        if matches!(token, Token::Control(b'\n')) {
            self.line += 1;
        }

        // Lone-CR tracking (strict policies): hold each CR until we know
        // whether an LF immediately follows it.
        if !self.policy.allow_lone_cr {
            if matches!(token, Token::Control(b'\r')) {
                self.resolve_pending_cr(None, out);
                self.pending_cr = Some((start_offset, start_line));
                return;
            }
            let followed_by_lf = matches!(token, Token::Control(b'\n'));
            self.resolve_pending_cr(Some(followed_by_lf), out);
        }

        match token {
            Token::Text(bytes) => {
                out.extend_from_slice(bytes);
                self.summary.bytes_out += bytes.len();
            }
            Token::Control(b) if matches!(b, b'\n' | b'\t' | b'\r') => {
                // Hardwired-safe whitespace (lone CR was intercepted above).
                out.push(*b);
                self.summary.bytes_out += 1;
            }
            _ => self.apply_policy(token, start_offset, start_line, out),
        }
    }

    fn apply_policy(&mut self, token: &Token, offset: usize, line: usize, out: &mut Vec<u8>) {
        let verdict = classify(token);

        // Hyperlinks get URI-level validation on top of the class switch.
        if verdict.class == Class::Hyperlink && self.policy.allows(Class::Hyperlink) {
            let payload = match token {
                Token::Str { payload, .. } => payload.as_slice(),
                _ => unreachable!("hyperlink verdicts only come from Str tokens"),
            };
            match hyperlink_uri(payload) {
                // `OSC 8 ;;` (empty URI) closes a link: always harmless.
                Some(uri) if uri.is_empty() || self.policy.allows_link(uri) => {
                    self.keep(token, out);
                }
                Some(_) => self.strip(
                    token,
                    offset,
                    line,
                    Class::Hyperlink,
                    Severity::Medium,
                    "unsafe-link",
                    out,
                ),
                None => self.strip(
                    token,
                    offset,
                    line,
                    Class::Hyperlink,
                    Severity::Medium,
                    "malformed-hyperlink",
                    out,
                ),
            }
            return;
        }

        if self.policy.allows(verdict.class) {
            self.keep(token, out);
        } else {
            self.strip(
                token,
                offset,
                line,
                verdict.class,
                verdict.severity,
                verdict.label,
                out,
            );
        }
    }

    /// Re-emit a kept sequence, normalizing any 8-bit C1 introducer or
    /// terminator to its 7-bit ESC-prefixed equivalent.
    fn keep(&mut self, token: &Token, out: &mut Vec<u8>) {
        let before = out.len();
        match token {
            Token::Text(bytes) => out.extend_from_slice(bytes),
            Token::Control(b) | Token::C1(b) => out.push(*b),
            Token::Csi { raw, .. } => {
                if raw.first() == Some(&0x9B) {
                    out.extend_from_slice(b"\x1b[");
                    out.extend_from_slice(&raw[1..]);
                } else {
                    out.extend_from_slice(raw);
                }
            }
            Token::Esc { raw, .. } => out.extend_from_slice(raw),
            Token::Str {
                kind, payload, raw, ..
            } => {
                let intro: &[u8] = match kind {
                    StrKind::Osc => b"\x1b]",
                    StrKind::Dcs => b"\x1bP",
                    StrKind::Apc => b"\x1b_",
                    StrKind::Pm => b"\x1b^",
                    StrKind::Sos => b"\x1bX",
                };
                out.extend_from_slice(intro);
                out.extend_from_slice(payload);
                // Preserve a BEL terminator (OSC), normalize everything
                // else — including raw 0x9C — to ESC backslash.
                if *kind == StrKind::Osc && raw.last() == Some(&0x07) {
                    out.push(0x07);
                } else {
                    out.extend_from_slice(b"\x1b\\");
                }
            }
            Token::Malformed { .. } => unreachable!("malformed is never kept"),
        }
        self.summary.bytes_out += out.len() - before;
        self.summary.kept += 1;
    }

    #[allow(clippy::too_many_arguments)]
    fn strip(
        &mut self,
        token: &Token,
        offset: usize,
        line: usize,
        class: Class,
        severity: Severity,
        label: &'static str,
        out: &mut Vec<u8>,
    ) {
        self.summary.stripped += 1;
        if self.mark {
            let marker = format!("\u{27E8}stripped:{label}\u{27E9}");
            out.extend_from_slice(marker.as_bytes());
            self.summary.bytes_out += marker.len();
        }
        if severity == Severity::None {
            // Benign removal (e.g. SGR under `plain`): not a finding.
            return;
        }
        if severity > self.max_severity {
            self.max_severity = severity;
        }
        let sev_idx = match severity {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
            Severity::None => unreachable!(),
        };
        self.summary.by_severity[sev_idx] += 1;
        if self.findings.len() >= MAX_FINDINGS {
            self.summary.suppressed += 1;
            return;
        }
        let action = if self.mark {
            Action::Marked
        } else {
            Action::Stripped
        };
        self.findings.push(Finding {
            offset,
            line,
            class,
            severity,
            label,
            action,
            excerpt: visible(token_raw(token), EXCERPT_CAP),
        });
    }

    /// Emit or drop a held CR. `followed_by_lf: Some(true)` means the next
    /// token is an LF (the CR is part of a CRLF pair and is kept).
    fn resolve_pending_cr(&mut self, followed_by_lf: Option<bool>, out: &mut Vec<u8>) {
        let Some((offset, line)) = self.pending_cr.take() else {
            return;
        };
        if followed_by_lf == Some(true) {
            out.push(b'\r');
            self.summary.bytes_out += 1;
            return;
        }
        // Lone CR: the classic overwrite-the-line-you-just-read trick.
        self.strip(
            &Token::Control(b'\r'),
            offset,
            line,
            Class::Control,
            Severity::Medium,
            "lone-cr",
            out,
        );
    }
}

/// Raw bytes of a token, for excerpts.
fn token_raw(token: &Token) -> &[u8] {
    match token {
        Token::Text(t) => t,
        Token::Control(b) | Token::C1(b) => std::slice::from_ref(b),
        Token::Csi { raw, .. }
        | Token::Esc { raw, .. }
        | Token::Str { raw, .. }
        | Token::Malformed { raw, .. } => raw,
    }
}

/// Render bytes with every control/high byte made visible (`⟨ESC⟩`,
/// `⟨BEL⟩`, `⟨0x9B⟩`), capped at `cap` visible units with a `…` tail. The
/// rendering itself can never smuggle a sequence.
pub fn visible(bytes: &[u8], cap: usize) -> String {
    let mut s = String::new();
    for (units, &b) in bytes.iter().enumerate() {
        if units >= cap {
            s.push('\u{2026}');
            break;
        }
        match b {
            0x1B => s.push_str("\u{27E8}ESC\u{27E9}"),
            0x07 => s.push_str("\u{27E8}BEL\u{27E9}"),
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\u{27E8}0x{b:02X}\u{27E9}")),
        }
    }
    s
}

/// One-shot convenience: sanitize a full buffer with a policy.
pub fn sanitize_bytes(input: &[u8], policy: &Policy) -> (Vec<u8>, Vec<Finding>, Summary) {
    let mut s = Sanitizer::new(policy.clone());
    let mut out = Vec::new();
    s.feed(input, &mut out);
    s.finish(&mut out);
    let summary = s.summary().clone();
    let findings = std::mem::take(&mut s.findings);
    (out, findings, summary)
}

#[cfg(test)]
mod tests {
    //! Sanitizer unit tests: the end-to-end keep/strip behavior each preset
    //! promises, chunk-boundary stability, marking, and CR discipline.

    use super::*;
    use crate::policy::{Policy, Preset};

    fn clean(input: &[u8]) -> Vec<u8> {
        sanitize_bytes(input, &Policy::preset(Preset::Default)).0
    }

    #[test]
    fn colors_survive_the_default_policy() {
        let input = b"\x1b[1;32mPASS\x1b[0m done\n";
        assert_eq!(clean(input), input.to_vec());
    }

    #[test]
    fn clipboard_write_is_stripped_with_a_critical_finding() {
        let (out, findings, _) = sanitize_bytes(
            b"before\x1b]52;c;ZXZpbA==\x07after",
            &Policy::preset(Preset::Default),
        );
        assert_eq!(out, b"beforeafter");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class, Class::Clipboard);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].offset, 6);
    }

    #[test]
    fn titles_cursor_moves_and_erase_are_stripped_but_text_kept() {
        assert_eq!(clean(b"a\x1b]0;pwned\x1b\\b"), b"ab");
        assert_eq!(clean(b"x\x1b[2A\x1b[2Ky"), b"xy");
    }

    #[test]
    fn raw_c1_csi_attack_is_stripped_too() {
        // 0x9B 2 J = erase display via 8-bit CSI; naive ESC-only filters miss it.
        assert_eq!(clean(b"x\x9b2Jy"), b"xy");
    }

    #[test]
    fn kept_c1_introduced_sgr_is_normalized_to_seven_bit() {
        let out = clean(b"\x9b31mred");
        assert_eq!(out, b"\x1b[31mred");
    }

    #[test]
    fn safe_hyperlink_is_kept_and_terminator_style_preserved() {
        let st = b"\x1b]8;;https://example.test\x1b\\click\x1b]8;;\x1b\\";
        assert_eq!(clean(st), st.to_vec());
        let bel = b"\x1b]8;;https://example.test\x07x\x1b]8;;\x07";
        assert_eq!(clean(bel), bel.to_vec());
    }

    #[test]
    fn file_scheme_hyperlink_is_stripped_as_unsafe() {
        let (out, findings, _) = sanitize_bytes(
            b"\x1b]8;;file:///etc/passwd\x1b\\x\x1b]8;;\x1b\\",
            &Policy::preset(Preset::Default),
        );
        // The open is stripped; the close (empty URI) is a harmless no-op.
        assert_eq!(out, b"x\x1b]8;;\x1b\\");
        assert_eq!(findings[0].label, "unsafe-link");
    }

    #[test]
    fn plain_policy_strips_sgr_without_findings() {
        let (out, findings, summary) =
            sanitize_bytes(b"\x1b[31mred\x1b[0m", &Policy::preset(Preset::Plain));
        assert_eq!(out, b"red");
        assert!(findings.is_empty(), "benign styling is not a finding");
        assert_eq!(summary.stripped, 2);
    }

    #[test]
    fn strict_policy_drops_lone_cr_but_keeps_crlf() {
        let (out, findings, _) =
            sanitize_bytes(b"total 100%\rdone\r\nnext", &Policy::preset(Preset::Strict));
        assert_eq!(out, b"total 100%done\r\nnext");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "lone-cr");
        // A CR at EOF has no LF after it: also lone.
        let (out, findings, _) = sanitize_bytes(b"tail\r", &Policy::preset(Preset::Strict));
        assert_eq!(out, b"tail");
        assert_eq!(findings[0].label, "lone-cr");
    }

    #[test]
    fn default_policy_keeps_lone_cr_for_progress_bars() {
        assert_eq!(clean(b"50%\r100%\n"), b"50%\r100%\n");
    }

    #[test]
    fn mark_mode_leaves_a_visible_placeholder() {
        let policy = Policy::preset(Preset::Default);
        let mut s = Sanitizer::new(policy).with_mark(true);
        let mut out = Vec::new();
        s.feed(b"a\x1b]52;c;xx\x07b", &mut out);
        s.finish(&mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "a\u{27E8}stripped:clipboard-write\u{27E9}b"
        );
        assert_eq!(s.findings()[0].action, Action::Marked);
    }

    #[test]
    fn allowing_cursor_class_keeps_cursor_sequences() {
        let policy = Policy::preset(Preset::Default)
            .refine(&["cursor".into(), "screen".into()], &[])
            .unwrap();
        let (out, _, _) = sanitize_bytes(b"\x1b[2A\x1b[2K.", &policy);
        assert_eq!(out, b"\x1b[2A\x1b[2K.");
    }

    #[test]
    fn output_is_identical_across_all_chunkings() {
        let input =
            b"log \x1b[32mok\x1b[0m\x1b]0;t\x07 \x9b1mB\x1b]8;;https://example.test\x1b\\L\r\n";
        let reference = clean(input);
        for cut in 1..input.len() {
            let mut s = Sanitizer::new(Policy::preset(Preset::Default));
            let mut out = Vec::new();
            s.feed(&input[..cut], &mut out);
            s.feed(&input[cut..], &mut out);
            s.finish(&mut out);
            assert_eq!(out, reference, "cut at {cut}");
        }
    }

    #[test]
    fn sanitizing_is_idempotent() {
        let input = b"\x1b[1mB\x1b]52;c;x\x07\x1b(0\x1b[5n\x05text\x7f\n";
        let once = clean(input);
        let twice = clean(&once);
        assert_eq!(once, twice);
        let (_, findings, _) = sanitize_bytes(&once, &Policy::preset(Preset::Default));
        assert!(findings.is_empty(), "clean output re-scans clean");
    }

    #[test]
    fn line_numbers_and_offsets_are_reported() {
        let (_, findings, _) = sanitize_bytes(
            b"line one\nline two \x1b]2;t\x07\n",
            &Policy::preset(Preset::Default),
        );
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].offset, 18);
    }

    #[test]
    fn summary_counts_add_up() {
        let (out, _, summary) = sanitize_bytes(
            b"\x1b[1mx\x1b[0m\x1b]0;t\x07\x1b[c",
            &Policy::preset(Preset::Default),
        );
        assert_eq!(summary.kept, 2);
        assert_eq!(summary.stripped, 2);
        assert_eq!(summary.findings, 2);
        assert_eq!(summary.by_severity, [0, 0, 2, 0]);
        assert_eq!(summary.bytes_out, out.len());
    }

    #[test]
    fn findings_beyond_the_cap_are_counted_not_stored() {
        let mut input = Vec::new();
        for _ in 0..(MAX_FINDINGS + 25) {
            input.extend_from_slice(b"\x1b]2;t\x07");
        }
        let (_, findings, summary) = sanitize_bytes(&input, &Policy::preset(Preset::Default));
        assert_eq!(findings.len(), MAX_FINDINGS);
        assert_eq!(summary.suppressed, 25);
        assert_eq!(summary.findings, MAX_FINDINGS + 25);
    }

    #[test]
    fn truncated_sequence_at_eof_is_removed() {
        // A dangling OSC would make a lenient terminal eat following bytes.
        let (out, findings, _) = sanitize_bytes(
            b"safe\x1b]52;c;never-terminated",
            &Policy::preset(Preset::Default),
        );
        assert_eq!(out, b"safe");
        assert_eq!(findings[0].class, Class::Malformed);
    }

    #[test]
    fn utf8_text_passes_byte_identical() {
        let input = "日本語テキスト🎉 émoji\n".as_bytes();
        assert_eq!(clean(input), input.to_vec());
    }

    #[test]
    fn visible_rendering_escapes_all_controls() {
        assert_eq!(
            visible(b"\x1b]52;c;\x07", 48),
            "\u{27E8}ESC\u{27E9}]52;c;\u{27E8}BEL\u{27E9}"
        );
        assert_eq!(visible(&[0x9B], 48), "\u{27E8}0x9B\u{27E9}");
        let long = visible(&[b'a'; 100], 10);
        assert!(long.ends_with('\u{2026}'));
        assert_eq!(long.chars().count(), 11);
    }
}
