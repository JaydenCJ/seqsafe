//! Allowlist policy: which classes survive, and under what conditions.
//!
//! A policy starts from a named preset and is refined with `--allow` /
//! `--deny` class lists. The design is allowlist-first: everything the
//! policy does not explicitly permit is stripped, so a new escape sequence
//! invented tomorrow is stripped by default, not waved through.

use crate::classify::{Class, ALL_CLASSES};

/// Named starting points for a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Keep colors/styling and safe-scheme hyperlinks. The sane default for
    /// piping build logs, LLM output and `curl`ed files through.
    Default,
    /// Keep colors/styling only; additionally drop lone carriage returns so
    /// nothing can rewrite the current line after you read it.
    Strict,
    /// Strip every escape sequence including styling — plain text out.
    Plain,
}

impl Preset {
    pub fn from_name(name: &str) -> Option<Preset> {
        match name {
            "default" => Some(Preset::Default),
            "strict" => Some(Preset::Strict),
            "plain" => Some(Preset::Plain),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Preset::Default => "default",
            Preset::Strict => "strict",
            Preset::Plain => "plain",
        }
    }
}

/// Errors from building a policy out of CLI input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnknownClass(String),
    /// `malformed` can never be allowed: there is nothing safe to re-emit.
    MalformedNotAllowable,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnknownClass(name) => {
                write!(f, "unknown class '{name}' (see `seqsafe classes`)")
            }
            PolicyError::MalformedNotAllowable => {
                write!(f, "class 'malformed' cannot be allowed")
            }
        }
    }
}

/// The compiled keep/strip decision table.
#[derive(Debug, Clone)]
pub struct Policy {
    allowed: [bool; ALL_CLASSES.len()],
    /// URI schemes a kept hyperlink may use (lowercase, no colon).
    pub link_schemes: Vec<String>,
    /// Keep a carriage return that is not part of a CRLF pair.
    pub allow_lone_cr: bool,
}

fn idx(class: Class) -> usize {
    ALL_CLASSES.iter().position(|c| *c == class).unwrap()
}

impl Policy {
    /// Build the base policy for a preset.
    pub fn preset(preset: Preset) -> Policy {
        let mut allowed = [false; ALL_CLASSES.len()];
        let (classes, lone_cr): (&[Class], bool) = match preset {
            Preset::Default => (&[Class::Sgr, Class::Hyperlink], true),
            Preset::Strict => (&[Class::Sgr], false),
            Preset::Plain => (&[], true),
        };
        for c in classes {
            allowed[idx(*c)] = true;
        }
        Policy {
            allowed,
            link_schemes: vec![
                "http".to_string(),
                "https".to_string(),
                "mailto".to_string(),
            ],
            allow_lone_cr: lone_cr,
        }
    }

    /// Apply `--allow` / `--deny` refinements. Deny wins over allow.
    pub fn refine(mut self, allow: &[String], deny: &[String]) -> Result<Policy, PolicyError> {
        for name in allow {
            let class =
                Class::from_name(name).ok_or_else(|| PolicyError::UnknownClass(name.clone()))?;
            if class == Class::Malformed {
                return Err(PolicyError::MalformedNotAllowable);
            }
            self.allowed[idx(class)] = true;
        }
        for name in deny {
            let class =
                Class::from_name(name).ok_or_else(|| PolicyError::UnknownClass(name.clone()))?;
            self.allowed[idx(class)] = false;
        }
        Ok(self)
    }

    /// Is this class kept by the policy? (Hyperlinks additionally pass
    /// through [`Policy::allows_link`]; malformed is never kept.)
    pub fn allows(&self, class: Class) -> bool {
        class != Class::Malformed && self.allowed[idx(class)]
    }

    /// Validate a hyperlink URI against the scheme allowlist. The URI must
    /// be non-empty, contain no bytes below `0x20`, no whitespace, and use
    /// an allowlisted scheme.
    pub fn allows_link(&self, uri: &[u8]) -> bool {
        if uri.is_empty() || uri.len() > 2048 {
            return false;
        }
        if uri.iter().any(|b| *b <= 0x20 || *b == 0x7F) {
            return false;
        }
        let Some(colon) = uri.iter().position(|b| *b == b':') else {
            return false;
        };
        let scheme = &uri[..colon];
        if !scheme
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'-' || *b == b'.')
        {
            return false;
        }
        let scheme = String::from_utf8_lossy(scheme).to_lowercase();
        self.link_schemes.contains(&scheme)
    }
}

#[cfg(test)]
mod tests {
    //! Policy unit tests: preset tables, allow/deny refinement precedence,
    //! and the hyperlink scheme allowlist.

    use super::*;

    #[test]
    fn default_preset_keeps_styling_and_links_only() {
        let p = Policy::preset(Preset::Default);
        assert!(p.allows(Class::Sgr));
        assert!(p.allows(Class::Hyperlink));
        for c in [
            Class::Clipboard,
            Class::Title,
            Class::Query,
            Class::Dcs,
            Class::Cursor,
            Class::Charset,
            Class::Mode,
            Class::C1,
            Class::Unknown,
        ] {
            assert!(!p.allows(c), "{c:?} must be stripped by default");
        }
        assert!(p.allow_lone_cr);
    }

    #[test]
    fn strict_preset_drops_hyperlinks_and_lone_cr() {
        let p = Policy::preset(Preset::Strict);
        assert!(p.allows(Class::Sgr));
        assert!(!p.allows(Class::Hyperlink));
        assert!(!p.allow_lone_cr);
    }

    #[test]
    fn plain_preset_strips_even_sgr() {
        let p = Policy::preset(Preset::Plain);
        assert!(!p.allows(Class::Sgr));
        assert!(!p.allows(Class::Hyperlink));
    }

    #[test]
    fn allow_widens_and_deny_narrows() {
        let p = Policy::preset(Preset::Default)
            .refine(&["cursor".into(), "screen".into()], &["hyperlink".into()])
            .unwrap();
        assert!(p.allows(Class::Cursor));
        assert!(p.allows(Class::Screen));
        assert!(!p.allows(Class::Hyperlink));
    }

    #[test]
    fn deny_wins_over_allow_for_the_same_class() {
        let p = Policy::preset(Preset::Default)
            .refine(&["title".into()], &["title".into()])
            .unwrap();
        assert!(!p.allows(Class::Title));
    }

    #[test]
    fn unknown_class_name_is_an_error() {
        let err = Policy::preset(Preset::Default)
            .refine(&["colours".into()], &[])
            .unwrap_err();
        assert!(matches!(err, PolicyError::UnknownClass(_)));
    }

    #[test]
    fn malformed_can_never_be_allowed() {
        let err = Policy::preset(Preset::Default)
            .refine(&["malformed".into()], &[])
            .unwrap_err();
        assert_eq!(err, PolicyError::MalformedNotAllowable);
        // ...and even a hand-patched table refuses at query time.
        let p = Policy::preset(Preset::Default);
        assert!(!p.allows(Class::Malformed));
    }

    #[test]
    fn link_scheme_allowlist() {
        let p = Policy::preset(Preset::Default);
        assert!(p.allows_link(b"https://example.test/path?q=1"));
        assert!(p.allows_link(b"HTTP://example.test")); // scheme case-folded
        assert!(p.allows_link(b"mailto:user@example.test"));
        assert!(!p.allows_link(b"file:///etc/passwd"));
        assert!(!p.allows_link(b"javascript:alert(1)"));
        assert!(!p.allows_link(b"ftp://example.test"));
    }

    #[test]
    fn link_rejects_control_bytes_whitespace_and_schemeless() {
        let p = Policy::preset(Preset::Default);
        assert!(!p.allows_link(b""));
        assert!(!p.allows_link(b"no-scheme-here"));
        assert!(!p.allows_link(b"https://example.test/\x07bel"));
        assert!(!p.allows_link(b"https://example.test/a b"));
        let long = [b'a'; 3000];
        let mut uri = b"https://".to_vec();
        uri.extend_from_slice(&long);
        assert!(!p.allows_link(&uri));
    }

    #[test]
    fn custom_link_schemes_are_respected() {
        let mut p = Policy::preset(Preset::Default);
        p.link_schemes = vec!["ftp".into()];
        assert!(p.allows_link(b"ftp://example.test"));
        assert!(!p.allows_link(b"https://example.test"));
    }
}
