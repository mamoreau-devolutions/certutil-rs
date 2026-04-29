//! Read-only certificate chain diagnostics for Windows (CryptoAPI).
//!
//! The CLI binary is [`certutil_rs`](crate) when built as an executable; library surface exists mainly for testing and embedding.

pub mod cli;
pub mod win;
