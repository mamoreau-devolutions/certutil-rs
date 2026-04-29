use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Read-only certificate diagnostics (no store changes). Inspired by `certutil.exe` verify/dump/URL flows.
#[derive(Debug, Parser)]
#[command(name = "certutil-rs", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Dump certificate structure (encoded file: PEM or DER).
    #[command(name = "-dump")]
    Dump {
        #[arg(value_name = "INFILE")]
        infile: PathBuf,
    },
    /// Build and validate certificate chains (`CertGetCertificateChain` + `CERT_CHAIN_POLICY_BASE`).
    #[command(name = "-verify")]
    Verify {
        /// Retrieve and validate AIA certs and CDP CRLs during chain building (`certutil -verify -urlfetch`).
        #[arg(long = "urlfetch")]
        urlfetch: bool,
        /// URL retrieval timeout in milliseconds (`certutil -t`).
        #[arg(short = 't', long = "timeout-ms", value_name = "milliseconds")]
        timeout_ms: Option<u32>,
        #[arg(value_name = "CRTBLOB")]
        crtblob: PathBuf,
    },
    /// Verify certificate or CRL URLs (`CryptRetrieveObjectByUrl`; `certutil -URL`).
    #[command(name = "-URL")]
    Url {
        /// HTTP(S) URL, a text file listing URLs, or an encoded certificate whose AIA lists URLs.
        #[arg(value_name = "InFile | URL")]
        target: String,
        #[arg(short = 't', long = "timeout-ms", value_name = "milliseconds")]
        timeout_ms: Option<u32>,
    },
}
