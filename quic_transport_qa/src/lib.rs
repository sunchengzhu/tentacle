//! Shared helpers for the QUIC transport QA programs.
//!
//! These programs are intentionally separated from the per-fix `quic_qa_*`
//! examples under `tentacle/examples/`. Those examples lock the contract of
//! PR #435; the programs here exercise tentacle QUIC the way CKB / Fiber will
//! use it as a real transport: many sessions, sustained traffic, churn, and
//! TCP/QUIC parity.

pub mod env;
pub mod proto;
pub mod resources;
pub mod runner;
