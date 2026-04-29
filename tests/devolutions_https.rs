//! Live HTTPS integration test: fetch the leaf certificate from **devolutions.net** and assert our Win32 chain validation succeeds.
//!
//! Disabled by default (`#[ignore]`) so `cargo test` works offline. Run:
//!
//! ```text
//! cargo test -- --ignored --nocapture devolutions_net_https_leaf_validates
//! ```

#![cfg(windows)]

use certutil_rs::win::verify::verify_der;
use native_tls::TlsConnector;
use std::net::TcpStream;

fn tls_leaf_der(host: &str, port: u16) -> Vec<u8> {
    let connector = TlsConnector::new().expect("TlsConnector::new");
    let tcp = TcpStream::connect((host, port)).unwrap_or_else(|e| panic!("TCP {host}:{port}: {e}"));
    let tls = connector
        .connect(host, tcp)
        .unwrap_or_else(|e| panic!("TLS handshake with {host}: {e}"));
    let cert = tls
        .peer_certificate()
        .expect("peer_certificate")
        .unwrap_or_else(|| panic!("no leaf certificate from {host}"));
    cert.to_der().expect("Certificate::to_der")
}

#[test]
#[ignore = "live network: TLS fetch from devolutions.net:443"]
fn devolutions_net_https_leaf_validates() {
    let der = tls_leaf_der("devolutions.net", 443);
    let report = verify_der(&der).unwrap_or_else(|e| panic!("verify_der: {e:#}"));

    assert!(
        report.contains("dwErrorStatus: 0x00000000"),
        "expected global CERT_TRUST dwErrorStatus clean (chain errors):\n{report}"
    );
    assert!(
        report.contains("Policy dwError: 0x00000000"),
        "expected CERT_CHAIN_POLICY_BASE success:\n{report}"
    );
    assert!(
        report.contains("Subject: devolutions.net"),
        "expected leaf subject from devolutions.net:\n{report}"
    );
}
