//! TLS client handshake: fetch the server leaf certificate (DER) for export and offline `certutil -verify`.
//!
//! Uses the OS TLS stack via **`native-tls`** (Schannel on Windows).

use std::io::Write;
use std::net::TcpStream;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use native_tls::TlsConnector;

/// Split `host:port` when `port` is numeric after the last colon; support `[IPv6]:port`.
pub fn split_host_and_port(input: &str, default_port: u16) -> Result<(String, u16)> {
    let input = input.trim();
    if input.is_empty() {
        return Err(anyhow!("empty host"));
    }

    if input.starts_with('[') {
        let close = input
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 address in {:?}", input))?;
        let inner = &input[1..close];
        let rest = &input[close + 1..];
        if rest.is_empty() {
            return Ok((format!("[{inner}]"), default_port));
        }
        if let Some(p) = rest.strip_prefix(':') {
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid port in {:?}", input))?;
            return Ok((format!("[{inner}]"), port));
        }
        return Err(anyhow!("unexpected characters after ] in {:?}", input));
    }

    if let Some((h, p)) = input.rsplit_once(':') {
        if !h.is_empty()
            && !h.contains(':')
            && p.chars().all(|c| c.is_ascii_digit())
            && !p.is_empty()
        {
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid port in {:?}", input))?;
            return Ok((h.to_string(), port));
        }
    }

    Ok((input.to_string(), default_port))
}

/// Default name used for TLS SNI / hostname verification when `--server-name` is omitted.
/// Strips IPv6 brackets so `[]::1` becomes `::1` (native-tls / Schannel behavior for literals).
pub fn default_server_name(host_for_tcp: &str) -> &str {
    host_for_tcp
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_for_tcp)
}

/// Perform a TLS handshake and return the peer **leaf** certificate in DER form.
pub fn fetch_tls_leaf_der(
    host_spec: &str,
    default_port: u16,
    server_name: Option<&str>,
    insecure: bool,
) -> Result<Vec<u8>> {
    let (host, port) = split_host_and_port(host_spec, default_port)?;
    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).with_context(|| format!("TCP connect to {addr}"))?;

    let mut builder = TlsConnector::builder();
    if insecure {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    let connector = builder.build().context("TlsConnector::build")?;

    let sn = server_name.unwrap_or_else(|| default_server_name(&host));
    let tls = connector
        .connect(sn, tcp)
        .with_context(|| format!("TLS handshake with server name {sn:?}"))?;

    let cert = tls
        .peer_certificate()
        .context("no peer certificate returned from TLS stack")?
        .ok_or_else(|| anyhow!("peer_certificate() was empty"))?;

    cert.to_der().context("encode leaf certificate as DER")
}

/// PEM text (`BEGIN CERTIFICATE`) for a single DER blob.
pub fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut lines = String::from("-----BEGIN CERTIFICATE-----\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        lines.push_str(&String::from_utf8_lossy(chunk));
        lines.push_str("\r\n");
    }
    lines.push_str("-----END CERTIFICATE-----\r\n");
    lines
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafOutputFormat {
    Pem,
    Der,
}

pub fn leaf_format_from_path_and_flag(
    path: &Path,
    format_override: Option<&str>,
) -> Result<LeafOutputFormat> {
    if let Some(f) = format_override {
        return match f.to_ascii_lowercase().as_str() {
            "pem" => Ok(LeafOutputFormat::Pem),
            "der" => Ok(LeafOutputFormat::Der),
            other => Err(anyhow!("unknown --format {other:?} (expected pem or der)")),
        };
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pem" => Ok(LeafOutputFormat::Pem),
        "der" => Ok(LeafOutputFormat::Der),
        "crt" => Ok(LeafOutputFormat::Pem),
        "cer" => Ok(LeafOutputFormat::Der),
        "" => Err(anyhow!(
            "output path {:?} has no extension; use --format pem|der",
            path.display()
        )),
        _ => Ok(LeafOutputFormat::Der),
    }
}

/// Write leaf DER to `path` as PEM or raw DER.
pub fn write_leaf_certificate(
    path: &Path,
    der: &[u8],
    format_override: Option<&str>,
) -> Result<()> {
    let fmt = leaf_format_from_path_and_flag(path, format_override)?;
    let bytes: Vec<u8> = match fmt {
        LeafOutputFormat::Pem => der_to_pem(der).into_bytes(),
        LeafOutputFormat::Der => der.to_vec(),
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    std::fs::File::create(path)
        .and_then(|mut f| f.write_all(&bytes))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_plain_host_uses_default_port() {
        let (h, p) = split_host_and_port("example.com", 443).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn split_host_port_embedded() {
        let (h, p) = split_host_and_port("example.com:8443", 443).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn split_ipv6_bracket_port() {
        let (h, p) = split_host_and_port("[::1]:8443", 443).unwrap();
        assert_eq!(h, "[::1]");
        assert_eq!(p, 8443);
    }

    #[test]
    fn pem_wraps_base64() {
        let der = [0u8; 1];
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }
}
