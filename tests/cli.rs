//! End-to-end CLI integration tests against the compiled binary.
//!
//! Everything runs offline on pipes and temp files; no terminal is harmed.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seqsafe"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn seqsafe");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn version_matches_the_manifest() {
    let out = run(&["--version"], b"");
    assert!(out.status.success());
    assert_eq!(
        stdout_str(&out).trim(),
        format!("seqsafe {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_lists_the_commands() {
    let out = run(&["help"], b"");
    assert!(out.status.success());
    let text = stdout_str(&out);
    assert!(text.contains("COMMANDS:"));
    for cmd in ["clean", "scan", "explain", "classes"] {
        assert!(text.contains(cmd), "help missing {cmd}");
    }
}

#[test]
fn clean_keeps_colors_and_strips_the_attack() {
    let input = b"\x1b[32mok\x1b[0m \x1b]52;c;ZXZpbA==\x07\x1b]0;pwned\x07done\n";
    let out = run(&["clean"], input);
    assert!(out.status.success());
    assert_eq!(out.stdout, b"\x1b[32mok\x1b[0m done\n");
}

#[test]
fn bare_invocation_on_a_pipe_cleans_too() {
    let out = run(&[], b"\x1b[31mred\x1b[0m\x1b[2J\n");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"\x1b[31mred\x1b[0m\n");
    // Options without a command imply `clean` as well.
    let out = run(&["--policy", "plain"], b"\x1b[31mred\x1b[0m\n");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"red\n");
}

#[test]
fn clean_reads_a_file_and_writes_with_dash_o() {
    let dir = std::env::temp_dir().join(format!("seqsafe-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("in.log");
    let output_path = dir.join("out.log");
    std::fs::write(&input_path, b"a\x1b]2;t\x07b\n").unwrap();
    let out = run(
        &[
            "clean",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "--summary",
        ],
        b"",
    );
    assert!(out.status.success());
    assert_eq!(std::fs::read(&output_path).unwrap(), b"ab\n");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("1 finding(s)"),
        "summary on stderr: {stderr}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn scan_gates_on_critical_by_default() {
    // Clipboard write is critical: exit 1, JSON names it.
    let out = run(&["scan", "--json"], b"\x1b]52;c;ZXZpbA==\x07");
    assert_eq!(out.status.code(), Some(1));
    let json = stdout_str(&out);
    assert!(json.contains("\"label\": \"clipboard-write\""));
    assert!(json.contains("\"max_severity\": \"critical\""));
    // A title change is only high: exit 0 under the default gate...
    let out = run(&["scan"], b"\x1b]0;t\x07");
    assert_eq!(out.status.code(), Some(0));
    // ...and exit 1 when the gate is lowered.
    let out = run(&["scan", "--fail-on", "high"], b"\x1b]0;t\x07");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn scan_of_clean_input_exits_zero_with_empty_findings() {
    let out = run(&["scan", "--json"], b"\x1b[1mbold\x1b[0m plain\n");
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_str(&out).contains("\"findings\": []"));
}

#[test]
fn explain_and_classes_render_reference_text() {
    let out = run(&["explain"], b"\x1b]52;c;eHg=\x07");
    assert!(out.status.success());
    let text = stdout_str(&out);
    assert!(text.contains("why: OSC 52"));
    let out = run(&["classes", "--policy", "strict"], b"");
    assert!(out.status.success());
    let table = stdout_str(&out);
    assert!(table.contains("sgr        keep"));
    assert!(table.contains("hyperlink  strip"));
    // --allow / --deny refinements show up in the table too.
    let out = run(&["classes", "--allow", "cursor", "--deny", "sgr"], b"");
    let table = stdout_str(&out);
    assert!(table.contains("cursor     keep"));
    assert!(table.contains("sgr        strip"));
}

#[test]
fn usage_errors_exit_two() {
    let out = run(&["scrub"], b"");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
    let out = run(&["clean", "--allow", "bogus-class"], b"");
    assert_eq!(out.status.code(), Some(2));
}
