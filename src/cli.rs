use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Read-only certificate diagnostics (no store changes). Inspired by `certutil.exe` verify/dump/URL flows.
#[derive(Debug, Parser)]
#[command(name = "certutil-rs", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Dump certificate, CRL, CSR, or PKCS#7 (PEM or DER file).
    #[command(name = "-dump")]
    Dump {
        #[arg(value_name = "INFILE")]
        infile: PathBuf,
    },
    /// Build and validate certificate chains (`CertGetCertificateChain` + chain policies).
    #[command(name = "-verify")]
    Verify {
        /// Retrieve and validate AIA certs and CDP CRLs during chain building (`certutil -verify -urlfetch`).
        #[arg(long = "urlfetch")]
        urlfetch: bool,
        /// URL retrieval timeout in milliseconds (`certutil -t`).
        #[arg(short = 't', long = "timeout-ms", value_name = "milliseconds")]
        timeout_ms: Option<u32>,
        /// After BASE policy, run `CERT_CHAIN_POLICY_SSL` with this DNS name (HTTPS server profile).
        #[arg(long = "ssl-dns-name", value_name = "DNS")]
        ssl_dns_name: Option<String>,
        /// SSL **client** profile: `CERT_CHAIN_POLICY_SSL` with `AUTHTYPE_CLIENT` and this expected DNS name.
        #[arg(long = "ssl-client-dns-name", value_name = "DNS")]
        ssl_client_dns_name: Option<String>,
        /// Run **Authenticode** chain policy pass (`CERT_CHAIN_POLICY_AUTHENTICODE`).
        #[arg(long = "policy-authenticode")]
        policy_authenticode: bool,
        /// Run **Authenticode timestamping** chain policy pass (`CERT_CHAIN_POLICY_AUTHENTICODE_TS`).
        #[arg(long = "policy-authenticode-ts")]
        policy_authenticode_ts: bool,
        /// Run **basic constraints** chain policy pass (`CERT_CHAIN_POLICY_BASIC_CONSTRAINTS`).
        #[arg(long = "policy-basic-constraints")]
        policy_basic_constraints: bool,
        /// Run **NT authentication** chain policy pass (`CERT_CHAIN_POLICY_NT_AUTH`).
        #[arg(long = "policy-nt-auth")]
        policy_nt_auth: bool,
        /// Probe each AIA/CDP URL with **CryptRetrieveObjectByUrl** (live network; uses `-t` / default timeout).
        #[arg(long = "probe-urls")]
        probe_urls: bool,
        /// Call **CertVerifyRevocation** for each chain cert with its parent issuer (live network or cache).
        #[arg(long = "probe-revocation")]
        probe_revocation: bool,
        #[arg(value_name = "CRTBLOB")]
        crtblob: PathBuf,
    },
    /// Encode a binary file as hex or PEM-style base64 (`certutil -encode` subset).
    #[command(name = "-encode")]
    Encode {
        #[arg(value_name = "INFILE")]
        infile: PathBuf,
        #[arg(value_name = "OUTFILE")]
        outfile: PathBuf,
        #[arg(long, value_enum, default_value_t = EncodeCliFmt::Base64Pem)]
        fmt: EncodeCliFmt,
        /// Group hex as space-separated byte pairs (only with `--fmt hex`).
        #[arg(long, default_value_t = false)]
        hex_spaced: bool,
    },
    /// Decode PEM/base64/hex text file to binary (`certutil -decode` subset).
    #[command(name = "-decode")]
    Decode {
        #[arg(value_name = "INFILE")]
        infile: PathBuf,
        #[arg(value_name = "OUTFILE")]
        outfile: PathBuf,
    },
    /// Print file digest (`certutil -hashfile`): MD5, SHA1, SHA256, or SHA384.
    #[command(name = "-hashfile")]
    Hashfile {
        #[arg(value_name = "INFILE")]
        path: PathBuf,
        #[arg(value_name = "ALG")]
        alg: String,
    },
    /// List certificates in a system store (read-only; `certutil -store` view subset).
    #[command(name = "-store")]
    Store {
        #[arg(value_name = "STORE")]
        store: String,
        /// System store location (default: current user).
        #[arg(long, value_enum, default_value_t = StoreLocation::CurrentUser)]
        location: StoreLocation,
        /// Match certs whose subject or issuer contains this substring (case-insensitive).
        #[arg(long = "filter")]
        filter: Option<String>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EncodeCliFmt {
    Hex,
    Base64Pem,
    Base64Raw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum StoreLocation {
    CurrentUser,
    LocalMachine,
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
        /// Verbose: TCP endpoints, ALPN, session resumption, peer chain store size, Schannel protocol/cipher info.
        #[arg(long)]
        verbose: bool,
        /// Force PEM or DER regardless of file extension.
        #[arg(long, value_name = "pem|der")]
        format: Option<String>,
    },
}
