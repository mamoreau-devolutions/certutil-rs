//! Live HTTPS integration test: fetch the leaf certificate from **devolutions.net** and assert our Win32 chain validation succeeds.
//!
//! Disabled by default (`#[ignore]`) so `cargo test` works offline. Run:
//!
//! ```text
//! cargo test -- --ignored --nocapture devolutions_net_https_leaf_validates
//! ```

#![cfg(windows)]

use certutil_rs::win::tls_fetch::fetch_tls_leaf_der;
use certutil_rs::win::verify::{verify_der, verify_der_with_options, VerifyOptions};

#[test]
#[ignore = "live network: TLS fetch from devolutions.net:443"]
fn devolutions_net_https_leaf_validates() {
    let der = fetch_tls_leaf_der("devolutions.net", 443, None, false)
        .unwrap_or_else(|e| panic!("fetch_tls_leaf_der: {e:#}"));
    let report = verify_der(&der).unwrap_or_else(|e| panic!("verify_der: {e:#}"));

    assert!(
        report.contains("dwErrorStatus=0") && report.contains("0x00000000"),
        "expected global CERT_TRUST dwErrorStatus clean (chain errors):\n{report}"
    );
    assert!(
        report.contains("Policy dwError: 0x00000000"),
        "expected CERT_CHAIN_POLICY_BASE success:\n{report}"
    );
    assert!(
        report.contains("Subject:") && report.contains("devolutions.net"),
        "expected leaf subject line with devolutions.net:\n{report}"
    );
    assert!(
        report.contains("Name Hash(sha1)"),
        "expected issuer/subject DER name hashes:\n{report}"
    );
    assert!(
        report.contains("Authority Information Access:")
            || report.contains("CRL Distribution Points:"),
        "expected WebPKI AIA and/or CDP extension blocks:\n{report}"
    );
}

#[test]
#[ignore = "live network: CryptRetrieveObjectByUrl probes from -verify --probe-urls"]
fn devolutions_net_https_probe_urls_section() {
    let der = fetch_tls_leaf_der("devolutions.net", 443, None, false)
        .unwrap_or_else(|e| panic!("fetch_tls_leaf_der: {e:#}"));
    let report = verify_der_with_options(
        &der,
        VerifyOptions {
            probe_urls: true,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("verify_der_with_options: {e:#}"));

    assert!(
        report.contains("probe-urls: true"),
        "expected probe flag in Verify options section:\n{report}"
    );
    assert!(
        report.contains("Retrieval probes (CryptRetrieveObjectByUrl):"),
        "expected retrieval probe section header:\n{report}"
    );
}

#[test]
#[ignore = "live network: CertVerifyRevocation probe from -verify --probe-revocation"]
fn devolutions_net_https_probe_revocation_section() {
    let der = fetch_tls_leaf_der("devolutions.net", 443, None, false)
        .unwrap_or_else(|e| panic!("fetch_tls_leaf_der: {e:#}"));
    let report = verify_der_with_options(
        &der,
        VerifyOptions {
            probe_revocation: true,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("verify_der_with_options: {e:#}"));

    assert!(
        report.contains("probe-revocation: true"),
        "expected probe flag in Verify options section:\n{report}"
    );
    assert!(
        report.contains("Revocation probe (CertVerifyRevocation):"),
        "expected revocation probe section header:\n{report}"
    );
}
