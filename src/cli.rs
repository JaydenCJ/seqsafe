//! Command-line interface: argument parsing and the four subcommands.
//!
//! Parsing is a pure function from argv to a [`Cmd`] so it can be unit
//! tested without a process; I/O happens only in [`run`].

use std::io::{IsTerminal, Read, Write};

use crate::classify::Severity;
use crate::policy::{Policy, Preset};
use crate::report;
use crate::sanitize::Sanitizer;

/// Read chunk size: large enough to amortize syscalls, small enough to
/// stream gigabyte inputs with flat memory.
const CHUNK: usize = 64 * 1024;

const USAGE: &str = "seqsafe — sanitize untrusted terminal output (keep colors, strip attacks)

USAGE:
    seqsafe <COMMAND> [OPTIONS] [FILE]
    ... | seqsafe [OPTIONS]  (no command: same as `seqsafe clean`)

COMMANDS:
    clean      Sanitize input to stdout (the filter; default when piped)
    scan       Report what would be stripped; gate with --fail-on
    explain    Like scan, with a rationale for every finding
    classes    List sequence classes and what the policy does with them
    help       Show this help

OPTIONS (clean/scan/explain/classes):
    --policy <default|strict|plain>   Base policy preset [default: default]
    --allow <class,...>               Additionally keep these classes
    --deny <class,...>                Strip these classes even if preset keeps them
    --link-schemes <s,...>            Allowed hyperlink URI schemes [http,https,mailto]

OPTIONS (clean):
    --mark                            Replace stripped sequences with visible markers
    --summary                         Print a summary line to stderr
    -o, --output <FILE>               Write to FILE instead of stdout

OPTIONS (scan):
    --json                            Machine-readable JSON report
    --fail-on <low|medium|high|critical|any>
                                      Exit 1 at/above this severity [default: critical]

FILE defaults to stdin ('-' also means stdin). Exit codes: 0 ok,
1 scan gate tripped, 2 usage or I/O error.
";

/// A fully parsed invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Clean {
        common: Common,
        mark: bool,
        summary: bool,
        output: Option<String>,
    },
    Scan {
        common: Common,
        json: bool,
        fail_on: Severity,
    },
    Explain {
        common: Common,
    },
    Classes {
        common: Common,
    },
    Help,
    Version,
}

/// Options shared by clean/scan/explain/classes.
#[derive(Debug, PartialEq, Eq)]
pub struct Common {
    pub file: Option<String>,
    pub preset: Preset,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub link_schemes: Option<Vec<String>>,
}

impl Default for Common {
    fn default() -> Self {
        Common {
            file: None,
            preset: Preset::Default,
            allow: Vec::new(),
            deny: Vec::new(),
            link_schemes: None,
        }
    }
}

impl Common {
    fn build_policy(&self) -> Result<Policy, String> {
        let mut policy = Policy::preset(self.preset)
            .refine(&self.allow, &self.deny)
            .map_err(|e| e.to_string())?;
        if let Some(schemes) = &self.link_schemes {
            policy.link_schemes = schemes.clone();
        }
        Ok(policy)
    }
}

/// Parse argv (without the program name). `stdin_is_tty` decides what a
/// bare `seqsafe` means: help on a terminal, `clean` in a pipeline.
pub fn parse(args: &[String], stdin_is_tty: bool) -> Result<Cmd, String> {
    let mut it = args.iter().peekable();
    let cmd = match it.peek().map(|s| s.as_str()) {
        None => {
            return if stdin_is_tty {
                Ok(Cmd::Help)
            } else {
                Ok(Cmd::Clean {
                    common: Common::default(),
                    mark: false,
                    summary: false,
                    output: None,
                })
            };
        }
        Some("--help") | Some("-h") | Some("help") => return Ok(Cmd::Help),
        Some("--version") | Some("-V") => return Ok(Cmd::Version),
        // A leading option (or a bare `-` for stdin) implies `clean`, so
        // `... | seqsafe --policy strict` works as the help promises.
        Some(name) if name.starts_with('-') => {
            let rest: Vec<&String> = it.collect();
            return parse_clean(&rest);
        }
        Some(name) => name.to_string(),
    };
    it.next();
    let rest: Vec<&String> = it.collect();
    match cmd.as_str() {
        "clean" => parse_clean(&rest),
        "scan" => parse_scan(&rest),
        "explain" => {
            let (common, extra) = parse_common(&rest)?;
            reject_extra(&extra)?;
            Ok(Cmd::Explain { common })
        }
        "classes" => parse_classes(&rest),
        other => Err(format!("unknown command '{other}' (try `seqsafe help`)")),
    }
}

/// Extract common options; returns leftover flags for the subcommand.
#[allow(clippy::type_complexity)]
fn parse_common<'a>(
    args: &[&'a String],
) -> Result<(Common, Vec<(&'a str, Option<&'a str>)>), String> {
    fn take_value<'b>(args: &[&'b String], i: &mut usize, name: &str) -> Result<&'b str, String> {
        *i += 1;
        args.get(*i)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("{name} requires a value"))
    }
    let mut common = Common::default();
    let mut extra = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--policy" => {
                let value = take_value(args, &mut i, "--policy")?;
                common.preset = Preset::from_name(value)
                    .ok_or_else(|| format!("unknown policy '{value}' (default|strict|plain)"))?;
            }
            "--allow" => {
                let value = take_value(args, &mut i, "--allow")?;
                common.allow.extend(split_list(value));
            }
            "--deny" => {
                let value = take_value(args, &mut i, "--deny")?;
                common.deny.extend(split_list(value));
            }
            "--link-schemes" => {
                let value = take_value(args, &mut i, "--link-schemes")?;
                common.link_schemes = Some(split_list(value));
            }
            "--mark" | "--summary" | "--json" => extra.push((arg, None)),
            "--fail-on" | "-o" | "--output" => {
                let value = take_value(args, &mut i, arg)?;
                extra.push((arg, Some(value)));
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(format!("unknown option '{arg}'"));
            }
            _ => {
                if common.file.is_some() {
                    return Err("more than one input file given".to_string());
                }
                common.file = Some(arg.to_string());
            }
        }
        i += 1;
    }
    Ok((common, extra))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn reject_extra(extra: &[(&str, Option<&str>)]) -> Result<(), String> {
    if let Some((flag, _)) = extra.first() {
        return Err(format!("option '{flag}' is not valid for this command"));
    }
    Ok(())
}

fn parse_clean(args: &[&String]) -> Result<Cmd, String> {
    let (common, extra) = parse_common(args)?;
    let mut mark = false;
    let mut summary = false;
    let mut output = None;
    for (flag, value) in extra {
        match flag {
            "--mark" => mark = true,
            "--summary" => summary = true,
            "-o" | "--output" => output = Some(value.unwrap().to_string()),
            other => return Err(format!("option '{other}' is not valid for clean")),
        }
    }
    Ok(Cmd::Clean {
        common,
        mark,
        summary,
        output,
    })
}

fn parse_scan(args: &[&String]) -> Result<Cmd, String> {
    let (common, extra) = parse_common(args)?;
    let mut json = false;
    let mut fail_on = Severity::Critical;
    for (flag, value) in extra {
        match flag {
            "--json" => json = true,
            "--fail-on" => {
                let value = value.unwrap();
                fail_on = Severity::from_name(value)
                    .ok_or_else(|| format!("unknown --fail-on level '{value}'"))?;
            }
            other => return Err(format!("option '{other}' is not valid for scan")),
        }
    }
    Ok(Cmd::Scan {
        common,
        json,
        fail_on,
    })
}

fn parse_classes(args: &[&String]) -> Result<Cmd, String> {
    let (common, extra) = parse_common(args)?;
    reject_extra(&extra)?;
    if common.file.is_some() {
        return Err("classes takes no input file".to_string());
    }
    Ok(Cmd::Classes { common })
}

// --- execution ---------------------------------------------------------------

/// Entry point. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let stdin_is_tty = std::io::stdin().is_terminal();
    let cmd = match parse(args, stdin_is_tty) {
        Ok(cmd) => cmd,
        Err(msg) => {
            eprintln!("seqsafe: {msg}");
            return 2;
        }
    };
    match execute(cmd) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("seqsafe: {msg}");
            2
        }
    }
}

fn execute(cmd: Cmd) -> Result<i32, String> {
    match cmd {
        Cmd::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Cmd::Version => {
            println!("seqsafe {}", crate::VERSION);
            Ok(0)
        }
        Cmd::Classes { common } => {
            print!("{}", report::render_classes(&common.build_policy()?));
            Ok(0)
        }
        Cmd::Clean {
            common,
            mark,
            summary,
            output,
        } => {
            let policy = common.build_policy()?;
            let mut sanitizer = Sanitizer::new(policy).with_mark(mark);
            let mut writer: Box<dyn Write> = match &output {
                Some(path) => Box::new(
                    std::fs::File::create(path)
                        .map_err(|e| format!("cannot create {path}: {e}"))?,
                ),
                None => Box::new(std::io::stdout().lock()),
            };
            stream(&common.file, &mut sanitizer, &mut writer)?;
            if summary {
                eprint!("{}", report::render_summary(sanitizer.summary()));
            }
            Ok(0)
        }
        Cmd::Scan {
            common,
            json,
            fail_on,
        } => {
            let policy = common.build_policy()?;
            let mut sanitizer = Sanitizer::new(policy);
            let mut sink = std::io::sink();
            stream(&common.file, &mut sanitizer, &mut sink)?;
            let rendered = if json {
                report::render_json(sanitizer.findings(), sanitizer.summary())
            } else {
                report::render_human(sanitizer.findings(), sanitizer.summary())
            };
            print!("{rendered}");
            Ok(if sanitizer.max_severity() >= fail_on {
                1
            } else {
                0
            })
        }
        Cmd::Explain { common } => {
            let policy = common.build_policy()?;
            let mut sanitizer = Sanitizer::new(policy);
            let mut sink = std::io::sink();
            stream(&common.file, &mut sanitizer, &mut sink)?;
            print!(
                "{}",
                report::render_explain(sanitizer.findings(), sanitizer.summary())
            );
            Ok(0)
        }
    }
}

/// Pump input through the sanitizer in fixed-size chunks.
fn stream(
    file: &Option<String>,
    sanitizer: &mut Sanitizer,
    writer: &mut dyn Write,
) -> Result<(), String> {
    let mut reader: Box<dyn Read> = match file.as_deref() {
        Some("-") | None => Box::new(std::io::stdin().lock()),
        Some(path) => {
            Box::new(std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?)
        }
    };
    let mut buf = vec![0u8; CHUNK];
    let mut out = Vec::with_capacity(CHUNK + 64);
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        out.clear();
        sanitizer.feed(&buf[..n], &mut out);
        writer
            .write_all(&out)
            .map_err(|e| format!("write error: {e}"))?;
    }
    out.clear();
    sanitizer.finish(&mut out);
    writer
        .write_all(&out)
        .map_err(|e| format!("write error: {e}"))?;
    writer.flush().map_err(|e| format!("write error: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! CLI parsing unit tests: subcommand routing, option validation, and
    //! the piped-vs-terminal default behavior.

    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bare_invocation_cleans_when_piped_and_helps_on_a_terminal() {
        assert!(matches!(parse(&[], false), Ok(Cmd::Clean { .. })));
        assert_eq!(parse(&[], true), Ok(Cmd::Help));
        // A leading option implies clean, matching the pipeline promise.
        match parse(&argv(&["--policy", "strict", "--mark"]), false).unwrap() {
            Cmd::Clean { common, mark, .. } => {
                assert_eq!(common.preset, Preset::Strict);
                assert!(mark);
            }
            other => panic!("unexpected {other:?}"),
        }
        // ...and so does a bare `-` (stdin).
        match parse(&argv(&["-"]), false).unwrap() {
            Cmd::Clean { common, .. } => assert_eq!(common.file.as_deref(), Some("-")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn version_and_help_flags() {
        assert_eq!(parse(&argv(&["--version"]), true), Ok(Cmd::Version));
        assert_eq!(parse(&argv(&["-V"]), true), Ok(Cmd::Version));
        assert_eq!(parse(&argv(&["help"]), true), Ok(Cmd::Help));
        assert_eq!(parse(&argv(&["-h"]), false), Ok(Cmd::Help));
    }

    #[test]
    fn clean_parses_policy_file_and_flags() {
        let cmd = parse(
            &argv(&[
                "clean",
                "in.log",
                "--policy",
                "strict",
                "--mark",
                "--summary",
            ]),
            true,
        )
        .unwrap();
        match cmd {
            Cmd::Clean {
                common,
                mark,
                summary,
                output,
            } => {
                assert_eq!(common.file.as_deref(), Some("in.log"));
                assert_eq!(common.preset, Preset::Strict);
                assert!(mark);
                assert!(summary);
                assert_eq!(output, None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allow_and_deny_lists_are_split_and_accumulated() {
        let cmd = parse(
            &argv(&[
                "scan",
                "--allow",
                "cursor, screen",
                "--allow",
                "mode",
                "--deny",
                "hyperlink",
            ]),
            false,
        )
        .unwrap();
        match cmd {
            Cmd::Scan { common, .. } => {
                assert_eq!(common.allow, vec!["cursor", "screen", "mode"]);
                assert_eq!(common.deny, vec!["hyperlink"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn scan_fail_on_levels_parse() {
        for (level, sev) in [
            ("low", Severity::Low),
            ("any", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            match parse(&argv(&["scan", "--fail-on", level]), false).unwrap() {
                Cmd::Scan { fail_on, .. } => assert_eq!(fail_on, sev, "{level}"),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(parse(&argv(&["scan", "--fail-on", "sky-high"]), false).is_err());
    }

    #[test]
    fn dash_means_stdin() {
        match parse(&argv(&["clean", "-"]), true).unwrap() {
            Cmd::Clean { common, .. } => assert_eq!(common.file.as_deref(), Some("-")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_command_option_and_policy_are_errors() {
        assert!(parse(&argv(&["scrub"]), false).is_err());
        assert!(parse(&argv(&["clean", "--frobnicate"]), false).is_err());
        assert!(parse(&argv(&["clean", "--policy", "paranoid"]), false).is_err());
        assert!(parse(&argv(&["clean", "--policy"]), false).is_err());
        assert!(parse(&argv(&["clean", "a", "b"]), false).is_err());
    }

    #[test]
    fn flags_are_rejected_on_the_wrong_subcommand() {
        assert!(parse(&argv(&["scan", "--mark"]), false).is_err());
        assert!(parse(&argv(&["clean", "--json"]), false).is_err());
        assert!(parse(&argv(&["explain", "--fail-on", "high"]), false).is_err());
        assert!(parse(&argv(&["classes", "somefile"]), false).is_err());
        // classes accepts policy options and validates the class names.
        match parse(&argv(&["classes", "--allow", "cursor"]), false).unwrap() {
            Cmd::Classes { common } => {
                assert!(common
                    .build_policy()
                    .unwrap()
                    .allows(crate::classify::Class::Cursor));
            }
            other => panic!("unexpected {other:?}"),
        }
        let cmd = parse(&argv(&["classes", "--allow", "bogus"]), false).unwrap();
        match cmd {
            Cmd::Classes { common } => assert!(common.build_policy().is_err()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn link_schemes_override_reaches_the_policy() {
        match parse(&argv(&["clean", "--link-schemes", "https"]), false).unwrap() {
            Cmd::Clean { common, .. } => {
                let policy = common.build_policy().unwrap();
                assert!(policy.allows_link(b"https://example.test"));
                assert!(!policy.allows_link(b"http://example.test"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn build_policy_surfaces_unknown_class_errors() {
        let common = Common {
            allow: vec!["nonsense".into()],
            ..Common::default()
        };
        let err = common.build_policy().unwrap_err();
        assert!(err.contains("unknown class"), "{err}");
    }
}
