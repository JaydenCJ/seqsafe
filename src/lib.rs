//! seqsafe — a policy-based sanitizer for untrusted terminal output.
//!
//! The pipeline is: [`parser`] tokenizes a byte stream into escape sequences
//! and text runs, [`classify`] assigns each token a semantic class and a
//! severity, [`policy`] decides which classes survive, and [`sanitize`] wires
//! the three together into a streaming filter that emits clean bytes plus a
//! list of findings. [`report`] renders findings for humans and machines.

pub mod classify;
pub mod cli;
pub mod parser;
pub mod policy;
pub mod report;
pub mod sanitize;

/// Package version, single source of truth for `--version` and reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
