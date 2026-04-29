//! Thin wrappers around Win32 CryptoAPI/CNG entry points used by `certutil`-style tooling.

pub mod cert_urls;
pub mod dump;
pub mod encoding;
pub mod names;
pub mod tls_fetch;
pub mod url;
pub mod verify;
mod verify_format;
