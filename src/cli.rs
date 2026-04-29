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
        /// After BASE policy, run `CERT_CHAIN_POLICY_SSL` with this DNS name (certutil-rs extension).
        #[arg(long = "ssl-dns-name", value_name = "DNS")]
        ssl_dns_name: Option<String>,
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
    /// TLS utilities: fetch peer leaf certificate for export (certutil-rs extension; not in stock certutil.exe).
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum TlsAction {
    /// Connect with TLS, save the server leaf certificate (PEM or DER) for `certutil.exe -verify` or `-dump`.
    Fetch {
        /// Hostname, IPv4, IPv6 in brackets, or `host:port` (use `--port` when omitting `:port`).
        #[arg(value_name = "HOST")]
        host: String,
        /// Port when `HOST` does not include `:port` (default 443).
        #[arg(long = "port", value_name = "PORT")]
        explicit_port: Option<u16>,
        /// Output path; format from extension (`.pem`/`.crt` vs `.der`/`.cer`) unless `--format` is set.
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: PathBuf,
        /// SNI and TLS hostname verification name (defaults to `HOST` without `:port`, brackets stripped for IPv6).
        #[arg(long = "server-name", value_name = "NAME")]
        server_name: Option<String>,
        /// Disable TLS certificate (and hostname) validation (diagnostics only).
        #[arg(long)]
        insecure: bool,
        /// Force PEM or DER regardless of file extension.
        #[arg(long, value_name = "pem|der")]
        format: Option<String>,
    },
}
