//! Parity checks between **`certutil.exe -verify`** and **`certutil-rs -verify`** on the **same** leaf file.
//!
//! The leaf is **prefetched** with [`certutil_rs::win::tls_fetch`] (same path as manual `tls fetch`), then both tools verify it.
//!
//! Requires **`certutil.exe` on `PATH`** (Windows system binary). Disabled by default (`#[ignore]`) for offline CI.
//!
//! ```text
//! cargo test --test parity_certutil_verify -- --ignored --nocapture
//! ```

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use certutil_rs::win::tls_fetch::{fetch_tls_leaf_der, write_leaf_certificate};
use certutil_rs::win::verify::{verify_cert_file_with_options, VerifyOptions};

/// Host used for TLS prefetch and for `-sslpolicy` / `--ssl-dns-name` parity.
const HOST: &str = "devolutions.net";

fn temp_leaf_cer(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "certutil_rs_parity_{}_{}.cer",
        std::process::id(),
        label
    ))
}

fn prefetch_leaf_der_to(path: &Path) {
    let der = fetch_tls_leaf_der(HOST, 443, None, false).unwrap_or_else(|e| {
        panic!("TLS prefetch (certutil-rs fetch_tls_leaf_der): {e:#}");
    });
    write_leaf_certificate(path, &der, None).unwrap_or_else(|e| {
        panic!("write leaf to {}: {e:#}", path.display());
    });
}

fn certutil_missing_hint() -> String {
    "certutil.exe not found on PATH (install Windows or add System32 to PATH)".into()
}

fn run_certutil_verify(args_before_file: &[&str], cert_path: &Path) -> std::process::Output {
    let mut cmd = Command::new("certutil");
    for a in args_before_file {
        cmd.arg(a);
    }
    cmd.arg(cert_path);
    cmd.output()
        .unwrap_or_else(|e| panic!("{}: {e}", certutil_missing_hint()))
}

/// **`certutil -verify`** prints this on success (English Windows).
fn assert_certutil_verify_succeeded(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "certutil exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("dwErrorStatus=0"),
        "certutil stdout should contain leaf element dwErrorStatus=0:\n{stdout}"
    );
    assert!(
        stdout.contains("CertUtil: -verify command completed successfully."),
        "certutil success banner missing (locale may differ — adjust test if needed):\n{stdout}"
    );
    let _ = stderr;
}

fn assert_certutil_rs_base_ok(report: &str) {
    assert!(
        report.contains("dwErrorStatus=0") && report.contains("0x00000000"),
        "expected chain dwErrorStatus clean (decimal + hex):\n{report}"
    );
    assert!(
        report.contains("Policy dwError: 0x00000000"),
        "expected CERT_CHAIN_POLICY_BASE success:\n{report}"
    );
}

fn assert_certutil_rs_extension_dump(report: &str) {
    assert!(
        report.contains("Name Hash(sha1)"),
        "expected name hashes on leaf/elements:\n{report}"
    );
    assert!(
        report.contains("Authority Information Access:")
            || report.contains("CRL Distribution Points:"),
        "expected AIA and/or CDP blocks for public TLS leaf:\n{report}"
    );
}

#[test]
#[ignore = "live network + certutil.exe on PATH: parity default -verify"]
fn parity_default_verify_certutil_and_certutil_rs() {
    let path = temp_leaf_cer("default");
    prefetch_leaf_der_to(&path);

    let cu = run_certutil_verify(&["-verify"], &path);
    assert_certutil_verify_succeeded(&cu);

    let report = verify_cert_file_with_options(&path, VerifyOptions::default())
        .expect("certutil-rs -verify");
    assert_certutil_rs_base_ok(&report);
    assert_certutil_rs_extension_dump(&report);

    let _ = std::fs::remove_file(&path);
}

#[test]
#[ignore = "live network + certutil.exe on PATH: parity -verify -urlfetch -t"]
fn parity_urlfetch_verify_certutil_and_certutil_rs() {
    let path = temp_leaf_cer("urlfetch");
    prefetch_leaf_der_to(&path);

    let cu = run_certutil_verify(&["-verify", "-urlfetch", "-t", "30000"], &path);
    assert_certutil_verify_succeeded(&cu);

    let opts = VerifyOptions {
        urlfetch: true,
        timeout_ms: Some(30_000),
        ssl_dns_name: None,
        probe_urls: false,
        probe_revocation: false,
    };
    let report = verify_cert_file_with_options(&path, opts).expect("certutil-rs -verify");
    assert_certutil_rs_base_ok(&report);
    assert_certutil_rs_extension_dump(&report);
    assert!(
        report.contains("urlfetch: true"),
        "expected urlfetch echoed in report:\n{report}"
    );
    assert!(
        report.contains("URL retrieval timeout (ms): 30000"),
        "expected timeout echoed:\n{report}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
#[ignore = "live network + certutil.exe on PATH: parity SSL hostname policy"]
fn parity_sslpolicy_verify_certutil_and_certutil_rs() {
    let path = temp_leaf_cer("ssl");
    prefetch_leaf_der_to(&path);

    let cu = run_certutil_verify(&["-verify", "-sslpolicy", HOST], &path);
    assert_certutil_verify_succeeded(&cu);

    let opts = VerifyOptions {
        urlfetch: false,
        timeout_ms: None,
        ssl_dns_name: Some(HOST.into()),
        probe_urls: false,
        probe_revocation: false,
    };
    let report = verify_cert_file_with_options(&path, opts).expect("certutil-rs -verify");
    assert_certutil_rs_base_ok(&report);
    assert_certutil_rs_extension_dump(&report);
    assert!(
        report.contains("CERT_CHAIN_POLICY_SSL"),
        "expected SSL policy section:\n{report}"
    );
    assert!(
        report.contains(&format!("Expected DNS name: {HOST}")),
        "expected ssl-dns-name in report:\n{report}"
    );
    assert!(
        report.contains("Policy dwError: 0x00000000"),
        "expected CERT_CHAIN_POLICY_SSL dwError success:\n{report}"
    );

    let _ = std::fs::remove_file(&path);
}
