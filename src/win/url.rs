//! URL retrieval diagnostics (`CryptRetrieveObjectByUrl`), aligned with `certutil.exe -URL`.

use std::collections::HashSet;
use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::core::{Error as WinError, PCSTR};
use windows::Win32::Networking::WinHttp::WinHttpGetIEProxyConfigForCurrentUser;
use windows::Win32::Networking::WinHttp::WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
use windows::Win32::Security::Cryptography::{
    szOID_PKIX_CA_ISSUERS, CertCreateCRLContext, CertCreateCertificateContext, CertFreeCRLContext,
    CertFreeCertificateContext, CryptMemFree, CryptRetrieveObjectByUrlA, CERT_CHAIN_CONTEXT,
    CERT_CONTEXT, CRL_CONTEXT, CRYPT_INTEGER_BLOB, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};

use super::cert_urls::{collect_cert_retrieval_urls, CertUrlKind};
use super::encoding::CERT_ENCODING;

/// Default URL retrieval timeout (ms) when `-t` is omitted (`certutil` uses engine defaults; we pick a sane network bound).
pub const DEFAULT_URL_TIMEOUT_MS: u32 = 30_000;

/// Outer DER TLV length (certificate / CRL SEQUENCE).
fn der_outer_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let mut i = 1usize;
    let lb = data[i];
    i += 1;
    let content_len = if lb < 0x80 {
        lb as usize
    } else if lb == 0x80 {
        return None;
    } else {
        let n = (lb - 0x80) as usize;
        if data.len() < i + n {
            return None;
        }
        let mut v = 0usize;
        for j in 0..n {
            v = (v << 8) | data[i + j] as usize;
        }
        i += n;
        v
    };
    Some(i + content_len)
}

const MAX_ENCODED_OBJECT: u32 = 16 * 1024 * 1024;

/// Bytes from `ptr` to the end of the virtual memory region (so we never read past allocation).
unsafe fn bytes_remaining_in_region(ptr: *const c_void) -> Option<usize> {
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let n = VirtualQuery(Some(ptr), &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>());
    if n == 0 {
        return None;
    }
    let base = mbi.BaseAddress as usize;
    let region_end = base.checked_add(mbi.RegionSize)?;
    let p = ptr as usize;
    if p < base || p >= region_end {
        return None;
    }
    Some(region_end - p)
}

fn doc_cert_encoding(dw: u32) -> bool {
    let mask = PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0;
    dw == mask || dw == X509_ASN_ENCODING.0
}

/// Report a [`CERT_CONTEXT`] returned by `CryptRetrieveObjectByUrl`.
///
/// CryptNet-backed contexts have faulted here with `CertGetNameStringW` / `CertGetCertificateContextProperty`
/// in testing; avoid those APIs and summarize encoding + a short encoded-byte preview instead.
unsafe fn report_cryptretrieve_cert_context(pv: *const CERT_CONTEXT) -> Result<String> {
    let ctx = &*pv;
    let rem = bytes_remaining_in_region(ctx.pbCertEncoded.cast()).unwrap_or(0);
    let take = (ctx.cbCertEncoded as usize).min(rem).min(48);
    let head = if take > 0 && !ctx.pbCertEncoded.is_null() {
        format!(
            "{:02x?}",
            std::slice::from_raw_parts(ctx.pbCertEncoded, take)
        )
    } else {
        "(none)".to_string()
    };

    Ok(format!(
        "Retrieved object: X.509 certificate\r\n  Encoding type: {}\r\n  Encoded size (bytes): {}\r\n  Encoded prefix: {head}\r\n",
        ctx.dwCertEncodingType.0, ctx.cbCertEncoded,
    ))
}

/// If `pv` begins with a documented cert encoding DWORD, treat it as [`CERT_CONTEXT`].
unsafe fn try_report_cert_or_crl_context(pv: *mut c_void) -> Result<Option<String>> {
    let ctx = std::ptr::read(pv as *const CERT_CONTEXT);
    if !doc_cert_encoding(ctx.dwCertEncodingType.0) {
        return Ok(None);
    }

    if ctx.pbCertEncoded.is_null()
        || ctx.cbCertEncoded == 0
        || ctx.cbCertEncoded > MAX_ENCODED_OBJECT
    {
        CryptMemFree(Some(pv));
        return Err(anyhow!(
            "CryptRetrieveObjectByUrl returned pointer with cert encoding type but invalid length/pointer"
        ));
    }

    let rem = bytes_remaining_in_region(ctx.pbCertEncoded.cast()).unwrap_or(0);
    let scan_len = (ctx.cbCertEncoded as usize).min(rem).min(512);
    if scan_len > 0 {
        let scan = std::slice::from_raw_parts(ctx.pbCertEncoded, scan_len);
        if scan.contains(&b'<') {
            CryptMemFree(Some(pv));
            return Err(anyhow!(
                "URL retrieval returned non-DER bytes (HTML/XML markers in payload)"
            ));
        }
    }

    match report_cryptretrieve_cert_context(pv as *const CERT_CONTEXT) {
        Ok(r) => {
            CryptMemFree(Some(pv));
            Ok(Some(r))
        }
        Err(e) => {
            CryptMemFree(Some(pv));
            Err(e)
        }
    }
}

/// Raw DER at `pv`, or [`CRYPT_INTEGER_BLOB`] (`cbData` first). Returns [`None`] when the first DWORD is a
/// certificate encoding mask (`CERT_CONTEXT`), so callers try [`try_report_cert_or_crl_context`] next.
unsafe fn blob_or_raw_der(pv: *mut c_void) -> Option<Vec<u8>> {
    let rem = bytes_remaining_in_region(pv)?;
    if rem < 4 {
        return None;
    }

    let d0 = std::ptr::read(pv as *const u32);
    if doc_cert_encoding(d0) {
        return None;
    }

    let p = pv as *const u8;
    if std::ptr::read(p) == 0x30 {
        let probe_len = rem.min(65536);
        let probe = std::slice::from_raw_parts(p, probe_len);
        let n = der_outer_length(probe)?;
        if n > rem {
            return None;
        }
        return Some(std::slice::from_raw_parts(p, n).to_vec());
    }

    if rem < size_of::<CRYPT_INTEGER_BLOB>() {
        return None;
    }
    let blob = std::ptr::read(pv as *const CRYPT_INTEGER_BLOB);
    if blob.pbData.is_null() || blob.cbData == 0 || blob.cbData > MAX_ENCODED_OBJECT {
        return None;
    }
    let inner_rem = bytes_remaining_in_region(blob.pbData.cast())?;
    if blob.cbData as usize > inner_rem {
        return None;
    }
    let der = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize);
    if der.first().copied() != Some(0x30) {
        return None;
    }
    Some(der.to_vec())
}

fn der_byte_preview_hex(der: &[u8], prefix_octets: usize) -> (usize, String) {
    let take = der.len().min(prefix_octets);
    let hex = der[..take]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (der.len(), hex)
}

/// OCSP/SCEP/other PKIX blobs often arrive as raw DER `SEQUENCE` bytes — not parseable as cert or CRL.
fn opaque_der_retrieval_report(der: &[u8]) -> String {
    let (total, hex) = der_byte_preview_hex(der, 32);
    let prefix_len = (hex.len() / 2).min(total);
    format!(
        "Retrieved object: opaque DER (not X.509 certificate or CRL)\r\n  Size (bytes): {total}\r\n  First {prefix_len} octets (hex): {hex}\r\n"
    )
}

unsafe fn report_der_cert_or_crl(der: &[u8]) -> Result<String> {
    let cert = CertCreateCertificateContext(CERT_ENCODING, der);
    if !cert.is_null() {
        let r = report_cert_context(cert);
        let _ = CertFreeCertificateContext(Some(cert));
        return r;
    }
    let win = WinError::from_win32();
    let crl = CertCreateCRLContext(CERT_ENCODING, der);
    if !crl.is_null() {
        let r = report_crl_context(crl);
        let _ = CertFreeCRLContext(Some(crl));
        return r;
    }
    Err(anyhow!(
        "CertCreateCertificateContext failed ({win}); CertCreateCRLContext also failed — {} bytes DER",
        der.len()
    ))
}

unsafe fn report_cert_context(ctx: *const CERT_CONTEXT) -> Result<String> {
    use super::names::cert_simple_display_name;
    let subj = cert_simple_display_name(ctx, false)?;
    let iss = cert_simple_display_name(ctx, true)?;
    Ok(format!(
        "Retrieved object: X.509 certificate\r\n  Subject: {subj}\r\n  Issuer: {iss}\r\n"
    ))
}

unsafe fn report_crl_context(ctx: *const CRL_CONTEXT) -> Result<String> {
    Ok(format!(
        "Retrieved object: CRL (encoding type {}, {} bytes)\r\n",
        (*ctx).dwCertEncodingType.0,
        (*ctx).cbCrlEncoded
    ))
}

/// PKIX OCSP access / OCSP-responder hint (`1.3.6.1.5.5.7.48.1`) — not always exported as `szOID_PKIX_OCSP` across SDK bindings.
static SZ_PKIX_OCSP_48_1: &[u8] = b"1.3.6.1.5.5.7.48.1\0";

#[inline]
fn pkix_ocsp_oid() -> PCSTR {
    PCSTR(SZ_PKIX_OCSP_48_1.as_ptr())
}

/// [`CryptRetrieveObjectByUrlA`] with optional object OID hint; frees result appropriately.
///
/// Second return value is **DER payload** length and hex prefix (when the response was decoded from raw
/// bytes at `pv`), for OCSP diagnostics (`--probe-urls`).
unsafe fn retrieve_one_url(
    url: &str,
    timeout_ms: u32,
    oid: PCSTR,
) -> Result<(String, Option<(usize, String)>)> {
    let c_url = CString::new(url).with_context(|| format!("URL contains NUL: {url:?}"))?;
    let mut pv: *mut c_void = std::ptr::null_mut();

    CryptRetrieveObjectByUrlA(
        PCSTR(c_url.as_ptr() as *mut u8),
        oid,
        0,
        timeout_ms,
        &mut pv,
        None,
        None,
        None,
        None,
    )
    .ok()?;

    if pv.is_null() {
        return Err(anyhow!(
            "CryptRetrieveObjectByUrl returned empty object pointer"
        ));
    }

    let fb = std::ptr::read(pv as *const u8);
    if fb == b'<' {
        CryptMemFree(Some(pv));
        return Err(anyhow!(
            "URL retrieval returned HTML or XML (expected DER certificate or CRL bytes)"
        ));
    }

    if let Some(der) = blob_or_raw_der(pv) {
        CryptMemFree(Some(pv));
        let preview = der_byte_preview_hex(der.as_slice(), 32);
        match report_der_cert_or_crl(der.as_slice()) {
            Ok(report) => Ok((report, Some(preview))),
            Err(_) => Ok((opaque_der_retrieval_report(der.as_slice()), Some(preview))),
        }
    } else if let Some(s) = try_report_cert_or_crl_context(pv)? {
        Ok((s, None))
    } else {
        CryptMemFree(Some(pv));
        Err(anyhow!(
            "CryptRetrieveObjectByUrl returned data we could not decode as DER blob or certificate context"
        ))
    }
}

/// One-stop URL retrieval with PKIX CA Issuers hint first (common HTTPS), then auto OID.
pub fn retrieve_url_report(url: &str, timeout_ms: u32) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!("URL: {url}\r\nTimeout: {timeout_ms} ms\r\n\r\n"));

    unsafe {
        // Prefer auto OID first: many HTTPS CA URLs return `CRYPT_INTEGER_BLOB` at `pv` (cbData first).
        // PKIX `szOID_PKIX_CA_ISSUERS` often yields `PCCERT_CONTEXT`, which we handle second.
        match retrieve_one_url(url, timeout_ms, PCSTR::null()) {
            Ok((s, _)) => {
                out.push_str(&s);
                Ok(out)
            }
            Err(e_auto) => {
                out.push_str(&format!(
                    "Attempt with default object type: {e_auto}\r\n\r\n"
                ));
                let (s, _) = retrieve_one_url(url, timeout_ms, szOID_PKIX_CA_ISSUERS)?;
                out.push_str(&s);
                Ok(out)
            }
        }
    }
}

fn summary_first_line(report: &str) -> String {
    report
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no detail)")
        .trim()
        .to_string()
}

fn probe_oid_attempts(kind: &CertUrlKind) -> Vec<(&'static str, PCSTR)> {
    match kind {
        CertUrlKind::AiaOcsp => vec![
            ("PKIX OCSP OID (1.3.6.1.5.5.7.48.1)", pkix_ocsp_oid()),
            ("default (auto)", PCSTR::null()),
            ("PKIX CA Issuers OID", szOID_PKIX_CA_ISSUERS),
        ],
        CertUrlKind::AiaCaIssuers | CertUrlKind::AiaOther(_) => {
            vec![
                ("default (auto)", PCSTR::null()),
                ("PKIX CA Issuers OID", szOID_PKIX_CA_ISSUERS),
            ]
        }
        CertUrlKind::Cdp => vec![("default (auto)", PCSTR::null())],
    }
}

/// Live `CryptRetrieveObjectByUrl` probe for diagnostics (`-verify --probe-urls`). Returns lines without a trailing section header.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub unsafe fn format_retrieval_probes_for_cert(
    ctx: *const CERT_CONTEXT,
    timeout_ms: u32,
) -> String {
    let entries = collect_cert_retrieval_urls(ctx);
    format_retrieval_probes_for_entries(&entries, timeout_ms)
}

fn format_retrieval_probes_for_entries(
    entries: &[super::cert_urls::CertUrlEntry],
    timeout_ms: u32,
) -> String {
    let mut seen = HashSet::<String>::new();
    let deduped: Vec<_> = entries
        .iter()
        .filter(|e| seen.insert(e.url.clone()))
        .cloned()
        .collect();

    if deduped.is_empty() {
        return "  (no http/https/ldap/ftp URLs on this certificate)\r\n".to_string();
    }

    let mut out = String::new();
    for e in &deduped {
        let kind_hdr = url_kind_header(&e.kind);
        out.push_str(&format!("  {} — {}\r\n", e.url, kind_hdr));
        let attempts = probe_oid_attempts(&e.kind);
        let mut ok = false;
        for (label, oid) in attempts {
            match unsafe { retrieve_one_url(&e.url, timeout_ms, oid) } {
                Ok((report, der_preview)) => {
                    let line = summary_first_line(&report);
                    out.push_str(&format!("    OK ({label}) — {line}\r\n"));
                    if matches!(e.kind, CertUrlKind::AiaOcsp) {
                        if let Some((len, hex)) = der_preview {
                            let n = hex.len() / 2;
                            out.push_str(&format!(
                                "    DER payload: {len} byte(s) total; first {n} octet(s) (hex): {hex}\r\n"
                            ));
                        }
                    }
                    ok = true;
                    break;
                }
                Err(err) => {
                    out.push_str(&format!("    FAILED ({label}) — {err:#}\r\n"));
                }
            }
        }
        if !ok {
            out.push_str(&retrieval_failure_hint_lines());
        }
        out.push_str("\r\n");
    }
    out
}

/// Unique AIA/CDP URLs across every certificate in the built chain (leaf-first simple chain order).
///
/// # Safety
/// `chain` must be a valid `PCCERT_CHAIN_CONTEXT`.
pub unsafe fn collect_unique_retrieval_urls_from_chain(
    chain: &CERT_CHAIN_CONTEXT,
) -> Vec<super::cert_urls::CertUrlEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::<String>::new();
    if chain.cChain == 0 || chain.rgpChain.is_null() {
        return out;
    }
    for ci in 0..chain.cChain {
        let sch = &**chain.rgpChain.add(ci as usize);
        for ei in 0..sch.cElement {
            let el = *sch.rgpElement.add(ei as usize);
            if el.is_null() {
                continue;
            }
            let cert = (*el).pCertContext;
            if cert.is_null() {
                continue;
            }
            for e in collect_cert_retrieval_urls(cert) {
                if seen.insert(e.url.clone()) {
                    out.push(e);
                }
            }
        }
    }
    out
}

/// Full section for `-verify --probe-urls` using every URL in the chain (deduped).
///
/// # Safety
/// `chain` must be a valid `PCCERT_CHAIN_CONTEXT`.
pub unsafe fn format_retrieval_probes_for_chain(
    chain: &CERT_CHAIN_CONTEXT,
    timeout_ms: u32,
) -> String {
    let entries = collect_unique_retrieval_urls_from_chain(chain);
    format_retrieval_probes_for_entries(&entries, timeout_ms)
}

/// Non-secret hints when CryptNet retrieval fails (proxy env presence, IE auto-proxy flags).
pub fn retrieval_failure_hint_lines() -> String {
    let mut s = String::from("    Hints (no secrets):\r\n");
    for (name, present) in [
        ("HTTP_PROXY", option_env_present("HTTP_PROXY")),
        ("HTTPS_PROXY", option_env_present("HTTPS_PROXY")),
        ("ALL_PROXY", option_env_present("ALL_PROXY")),
        ("NO_PROXY", option_env_present("NO_PROXY")),
    ] {
        s.push_str(&format!(
            "      {name}: {}\r\n",
            if present { "set" } else { "not set" }
        ));
    }
    unsafe {
        let mut cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        if WinHttpGetIEProxyConfigForCurrentUser(&mut cfg).is_ok() {
            s.push_str(&format!(
                "      IE auto-detect proxy: {}\r\n",
                cfg.fAutoDetect.as_bool()
            ));
            s.push_str(&format!(
                "      IE manual proxy configured: {}\r\n",
                !cfg.lpszProxy.is_null()
            ));
            s.push_str(&format!(
                "      IE auto-config URL (PAC) configured: {}\r\n",
                !cfg.lpszAutoConfigUrl.is_null()
            ));
        } else {
            s.push_str(
                "      WinHttpGetIEProxyConfigForCurrentUser: failed (proxy hints unavailable)\r\n",
            );
        }
    }
    s
}

fn option_env_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

#[cfg(test)]
mod preview_tests {
    use super::der_byte_preview_hex;

    #[test]
    fn der_preview_truncates_and_hexes() {
        let der = [0x30u8, 0x80, 0x01, 0x02, 0x03];
        let (len, hex) = der_byte_preview_hex(&der, 32);
        assert_eq!(len, 5);
        assert_eq!(hex, "3080010203");
        let short = [0xabu8, 0xcd];
        let (l2, h2) = der_byte_preview_hex(&short, 1);
        assert_eq!(l2, 2);
        assert_eq!(h2, "ab");
    }
}

fn url_kind_header(kind: &CertUrlKind) -> &'static str {
    match kind {
        CertUrlKind::AiaOcsp => "AIA OCSP",
        CertUrlKind::AiaCaIssuers => "AIA CA Issuers",
        CertUrlKind::AiaOther(_) => "AIA (other)",
        CertUrlKind::Cdp => "CRL Distribution Point",
    }
}

fn looks_like_http_url(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("http://") || t.starts_with("https://")
}

fn collect_urls_from_text_file(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if looks_like_http_url(t) {
            v.push(t.to_string());
        }
    }
    v
}

/// `certutil -URL`-style target: HTTPS URL string, or a file containing URL(s) or an encoded cert with AIA URLs.
pub fn url_command_target(target: &str, timeout_ms: u32) -> Result<String> {
    let timeout_ms = if timeout_ms == 0 {
        DEFAULT_URL_TIMEOUT_MS
    } else {
        timeout_ms
    };

    if looks_like_http_url(target) {
        return retrieve_url_report(target.trim(), timeout_ms);
    }

    let path = Path::new(target);
    if !path.is_file() {
        return Err(anyhow!("not a URL and not an existing file: {target}"));
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read text from {}", path.display()))?;
    let from_lines = collect_urls_from_text_file(&text);
    if !from_lines.is_empty() {
        let mut out = String::new();
        for (i, u) in from_lines.iter().enumerate() {
            out.push_str(&format!("=== URL [{i}] from file ===\r\n"));
            out.push_str(&retrieve_url_report(u, timeout_ms)?);
            out.push_str("\r\n");
        }
        return Ok(out);
    }

    let der = super::dump::read_cert_file(path)?;
    unsafe {
        let ctx = CertCreateCertificateContext(CERT_ENCODING, &der);
        if ctx.is_null() {
            return Err(anyhow!(
                "{} is not a PEM/DER certificate and contains no http(s) URLs",
                path.display()
            ));
        }
        let entries = collect_cert_retrieval_urls(ctx);
        let _ = CertFreeCertificateContext(Some(ctx));
        if entries.is_empty() {
            return Err(anyhow!(
                "no AIA/CDP retrieval URLs (http/https/ldap/ftp) found in certificate {}",
                path.display()
            ));
        }
        let mut out = String::new();
        for (i, e) in entries.iter().enumerate() {
            let hdr = url_kind_header(&e.kind);
            out.push_str(&format!("=== URL [{i}] ({hdr}) ===\r\n"));
            out.push_str(&retrieve_url_report(&e.url, timeout_ms)?);
            out.push_str("\r\n");
        }
        Ok(out)
    }
}
