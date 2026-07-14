//! Rendering of findings and summaries: human-readable text and JSON.
//!
//! JSON output is hand-rolled (seqsafe is std-only); the escaper covers the
//! full JSON string grammar including control characters, so excerpts can
//! never break the document.

use crate::classify::{Severity, ALL_CLASSES};
use crate::policy::Policy;
use crate::sanitize::{Finding, Summary};

/// Escape a string for embedding in a JSON document.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn severity_of(summary: &Summary) -> Severity {
    let sevs = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let mut max = Severity::None;
    for (i, sev) in sevs.iter().enumerate() {
        if summary.by_severity[i] > 0 {
            max = *sev;
        }
    }
    max
}

/// One human-readable line per finding, e.g.
/// `L2 @18 critical clipboard clipboard-write stripped  ⟨ESC⟩]52;c;...`
pub fn finding_line(f: &Finding) -> String {
    format!(
        "L{} @{} [{}] {} ({}) {}  {}",
        f.line,
        f.offset,
        f.severity.name(),
        f.class.name(),
        f.label,
        f.action.name(),
        f.excerpt
    )
}

/// Full human report for `seqsafe scan`.
pub fn render_human(findings: &[Finding], summary: &Summary) -> String {
    let mut out = String::new();
    for f in findings {
        out.push_str(&finding_line(f));
        out.push('\n');
    }
    if summary.suppressed > 0 {
        out.push_str(&format!(
            "... and {} more finding(s) not shown\n",
            summary.suppressed
        ));
    }
    out.push_str(&render_summary(summary));
    out
}

/// The trailing summary block shared by `scan` and `clean --summary`.
pub fn render_summary(summary: &Summary) -> String {
    let [low, medium, high, critical] = summary.by_severity;
    format!(
        "{} finding(s): {} critical, {} high, {} medium, {} low; \
         {} sequence(s) kept, {} stripped; {} bytes in, {} bytes out\n",
        summary.findings,
        critical,
        high,
        medium,
        low,
        summary.kept,
        summary.stripped,
        summary.bytes_in,
        summary.bytes_out
    )
}

/// Verbose per-finding report for `seqsafe explain`: each finding plus the
/// one-line rationale for its class.
pub fn render_explain(findings: &[Finding], summary: &Summary) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        out.push_str("no findings: input is clean under this policy\n");
    }
    for f in findings {
        out.push_str(&finding_line(f));
        out.push('\n');
        out.push_str(&format!("    why: {}\n", f.class.describe()));
    }
    if summary.suppressed > 0 {
        out.push_str(&format!(
            "... and {} more finding(s) not shown\n",
            summary.suppressed
        ));
    }
    out.push_str(&render_summary(summary));
    out
}

/// Machine-readable report for `seqsafe scan --json`.
pub fn render_json(findings: &[Finding], summary: &Summary) -> String {
    let [low, medium, high, critical] = summary.by_severity;
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"version\": \"{}\",\n  \"max_severity\": \"{}\",\n",
        crate::VERSION,
        severity_of(summary).name()
    ));
    out.push_str(&format!(
        "  \"summary\": {{\"bytes_in\": {}, \"bytes_out\": {}, \"kept\": {}, \"stripped\": {}, \
         \"findings\": {}, \"suppressed\": {}, \"by_severity\": {{\"low\": {}, \"medium\": {}, \
         \"high\": {}, \"critical\": {}}}}},\n",
        summary.bytes_in,
        summary.bytes_out,
        summary.kept,
        summary.stripped,
        summary.findings,
        summary.suppressed,
        low,
        medium,
        high,
        critical
    ));
    out.push_str("  \"findings\": [");
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "\n    {{\"offset\": {}, \"line\": {}, \"class\": \"{}\", \"severity\": \"{}\", \
             \"label\": \"{}\", \"action\": \"{}\", \"excerpt\": \"{}\"}}",
            f.offset,
            f.line,
            f.class.name(),
            f.severity.name(),
            f.label,
            f.action.name(),
            json_escape(&f.excerpt)
        ));
    }
    if findings.is_empty() {
        out.push_str("]\n}\n");
    } else {
        out.push_str("\n  ]\n}\n");
    }
    out
}

/// Reference table for `seqsafe classes`: every class, whether the given
/// policy keeps it, and what it means.
pub fn render_classes(policy: &Policy) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<10} {:<8} {}\n{:-<10} {:-<8} {:-<60}\n",
        "CLASS", "ACTION", "DESCRIPTION", "", "", ""
    ));
    for class in ALL_CLASSES {
        let action = if policy.allows(class) {
            "keep"
        } else {
            "strip"
        };
        out.push_str(&format!(
            "{:<10} {:<8} {}\n",
            class.name(),
            action,
            class.describe()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    //! Report unit tests: JSON escaping correctness and stable human output.

    use super::*;
    use crate::policy::Preset;
    use crate::sanitize::sanitize_bytes;

    fn scan(input: &[u8]) -> (Vec<Finding>, Summary) {
        let (_, f, s) = sanitize_bytes(input, &Policy::preset(Preset::Default));
        (f, s)
    }

    #[test]
    fn json_escape_handles_quotes_backslashes_and_controls() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn json_report_contains_finding_fields() {
        let (f, s) = scan(b"\x1b]52;c;eHg=\x07");
        let json = render_json(&f, &s);
        assert!(json.contains("\"class\": \"clipboard\""));
        assert!(json.contains("\"severity\": \"critical\""));
        assert!(json.contains("\"label\": \"clipboard-write\""));
        assert!(json.contains("\"max_severity\": \"critical\""));
        assert!(json.contains("\"bytes_in\": 12"));
    }

    #[test]
    fn json_report_for_clean_input_has_empty_findings_array() {
        let (f, s) = scan(b"nothing to see\n");
        let json = render_json(&f, &s);
        assert!(json.contains("\"findings\": []"));
        assert!(json.contains("\"max_severity\": \"none\""));
    }

    #[test]
    fn human_report_shows_line_offset_and_excerpt() {
        let (f, s) = scan(b"ok\n\x1b]0;t\x07");
        let human = render_human(&f, &s);
        assert!(human.contains("L2 @3 [high] title (title-set) stripped"));
        assert!(human.contains("\u{27E8}ESC\u{27E9}]0;t\u{27E8}BEL\u{27E9}"));
        assert!(human.contains("1 finding(s): 0 critical, 1 high"));
    }

    #[test]
    fn explain_includes_class_rationale() {
        let (f, s) = scan(b"\x1b]52;c;eHg=\x07");
        let text = render_explain(&f, &s);
        assert!(text.contains("why: OSC 52 writes"));
    }

    #[test]
    fn explain_says_clean_when_clean() {
        let (f, s) = scan(b"fine\n");
        assert!(render_explain(&f, &s).starts_with("no findings"));
    }

    #[test]
    fn classes_table_lists_all_classes_with_policy_action() {
        let table = render_classes(&Policy::preset(Preset::Default));
        for class in ALL_CLASSES {
            assert!(table.contains(class.name()), "missing {}", class.name());
        }
        assert!(table.contains("sgr        keep"));
        assert!(table.contains("clipboard  strip"));
    }
}
