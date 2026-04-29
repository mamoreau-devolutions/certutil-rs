//! TLS client handshake: fetch the server leaf certificate (DER) for export and offline `certutil -verify`.
//!
//! Uses **Schannel** via the [`schannel`] crate (same stack as Windows TLS).

use std::io::Write;
use std::net::TcpStream;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use schannel::schannel_cred::{Direction, SchannelCred};
use schannel::tls_stream::{Builder as TlsBuilder, HandshakeError};

use super::tls_names::{describe_ai_cipher, describe_dw_protocol};

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
/// Strips IPv6 brackets so `[::1]` becomes `::1`.
pub fn default_server_name(host_for_tcp: &str) -> &str {
    host_for_tcp
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_for_tcp)
}

fn fetch_tls_inner(
    host_spec: &str,
    default_port: u16,
    server_name: Option<&str>,
    insecure: bool,
    verbose: bool,
) -> Result<(Vec<u8>, Option<String>)> {
    let (host, port) = split_host_and_port(host_spec, default_port)?;
    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).with_context(|| format!("TCP connect to {addr}"))?;

    let sn = server_name.unwrap_or_else(|| default_server_name(&host));

    let cred = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .context("SchannelCred::acquire (Outbound)")?;

    let mut tls_builder = TlsBuilder::new();
    tls_builder.domain(sn);
    if insecure {
        tls_builder.accept_invalid_hostnames(true);
    }
    let insecure_cb = insecure;
    tls_builder.verify_callback(move |v| {
        if insecure_cb {
            Ok(())
        } else {
            v.result()
        }
    });

    if verbose {
        tls_builder.request_application_protocols(&[b"h2", b"http/1.1"]);
    }

    let tls = tls_builder.connect(cred, tcp).map_err(|e: HandshakeError<_>| match e {
        HandshakeError::Failure(e) => anyhow!("{e}"),
        HandshakeError::Interrupted(_) => anyhow!(
            "TLS handshake interrupted on a blocking socket (unexpected)"
        ),
    })?;

    let peer = tls
        .peer_certificate()
        .context("peer_certificate (TLS)")?;
    let der = peer.to_der().to_vec();

    let diag = if verbose {
        let tcp = tls.get_ref();
        let mut lines = String::new();
        lines.push_str("TLS diagnostics:\r\n");
        lines.push_str(&format!(
            "  TCP local:  {}\r\n",
            tcp.local_addr().map(|a| a.to_string()).unwrap_or_else(|e| e.to_string())
        ));
        lines.push_str(&format!(
            "  TCP peer:   {}\r\n",
            tcp.peer_addr().map(|a| a.to_string()).unwrap_or_else(|e| e.to_string())
        ));
        lines.push_str(&format!("  Server name (SNI / validation): {sn}\r\n"));
        match tls.negotiated_application_protocol() {
            Ok(Some(alpn)) => {
                lines.push_str(&format!(
                    "  ALPN negotiated: {}\r\n",
                    String::from_utf8_lossy(&alpn)
                ));
            }
            Ok(None) => {
                lines.push_str("  ALPN negotiated: (none)\r\n");
            }
            Err(e) => {
                lines.push_str(&format!("  ALPN negotiated: (query failed: {e})\r\n"));
            }
        }
        match tls.session_resumed() {
            Ok(r) => lines.push_str(&format!("  Session resumed: {r}\r\n")),
            Err(e) => lines.push_str(&format!("  Session resumed: (query failed: {e})\r\n")),
        }
        if let Some(store) = peer.cert_store() {
            let n = store.certs().count();
            lines.push_str(&format!(
                "  Certificates in peer message store (leaf + intermediates): {n}\r\n"
            ));
        }
        match tls.connection_info() {
            Ok(ci) => {
                lines.push_str(&format!(
                    "  TLS protocol (dwProtocol): 0x{:08x} — {}\r\n",
                    ci.dwProtocol,
                    describe_dw_protocol(ci.dwProtocol)
                ));
                lines.push_str(&format!(
                    "  Cipher ALG_ID (aiCipher): {} — {}\r\n",
                    ci.aiCipher,
                    describe_ai_cipher(ci.aiCipher)
                ));
                lines.push_str(&format!(
                    "  Cipher strength (bits): {}\r\n",
                    ci.dwCipherStrength
                ));
                lines.push_str(
                    "  Schannel fields reference: https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo\r\n",
                );
            }
            Err(e) => lines.push_str(&format!(
                "  Schannel connection info (QueryContextAttributes): {e}\r\n"
            )),
        }
        lines.push_str("\r\n");
        Some(lines)
    } else {
        None
    };

    Ok((der, diag))
}

/// Perform a TLS handshake and return the peer **leaf** certificate in DER form.
pub fn fetch_tls_leaf_der(
    host_spec: &str,
    default_port: u16,
    server_name: Option<&str>,
    insecure: bool,
) -> Result<Vec<u8>> {
    fetch_tls_inner(host_spec, default_port, server_name, insecure, false).map(|(d, _)| d)
}

/// Same as [`fetch_tls_leaf_der`], plus optional diagnostic lines (TCP, ALPN, session resumption, chain count).
pub fn fetch_tls_leaf_der_with_diagnostics(
    host_spec: &str,
    default_port: u16,
    server_name: Option<&str>,
    insecure: bool,
    verbose: bool,
) -> Result<(Vec<u8>, Option<String>)> {
    fetch_tls_inner(host_spec, default_port, server_name, insecure, verbose)
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
