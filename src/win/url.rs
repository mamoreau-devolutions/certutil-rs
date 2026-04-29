//! URL retrieval diagnostics (`CryptRetrieveObjectByUrl`), aligned with `certutil.exe -URL`.

use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::core::{Error as WinError, PCSTR};
use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertCreateCRLContext, CertFindExtension,
    CertFreeCertificateContext, CertFreeCRLContext, CryptDecodeObjectEx, CryptMemFree,
    CryptRetrieveObjectByUrlA, CERT_AUTHORITY_INFO_ACCESS, CERT_CONTEXT, CRL_CONTEXT,
    CRYPT_INTEGER_BLOB, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING, szOID_AUTHORITY_INFO_ACCESS, szOID_PKIX_CA_ISSUERS,
};

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

/// [`CryptRetrieveObjectByUrlA`] with optional OID hint; frees result appropriately.
unsafe fn retrieve_one_url(url: &str, timeout_ms: u32, pkix_ca_issuers: bool) -> Result<String> {
    let c_url = CString::new(url).with_context(|| format!("URL contains NUL: {url:?}"))?;
    let mut pv: *mut c_void = std::ptr::null_mut();
    let oid = if pkix_ca_issuers {
        szOID_PKIX_CA_ISSUERS
    } else {
        PCSTR::null()
    };

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
        return Err(anyhow!("CryptRetrieveObjectByUrl returned empty object pointer"));
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
        return report_der_cert_or_crl(der.as_slice());
    }

    if let Some(s) = try_report_cert_or_crl_context(pv)? {
        return Ok(s);
    }

    CryptMemFree(Some(pv));
    Err(anyhow!(
        "CryptRetrieveObjectByUrl returned data we could not decode as DER blob or certificate context"
    ))
}

/// One-stop URL retrieval with PKIX CA Issuers hint first (common HTTPS), then auto OID.
pub fn retrieve_url_report(url: &str, timeout_ms: u32) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!("URL: {url}\r\nTimeout: {timeout_ms} ms\r\n\r\n"));

    unsafe {
        // Prefer auto OID first: many HTTPS CA URLs return `CRYPT_INTEGER_BLOB` at `pv` (cbData first).
        // PKIX `szOID_PKIX_CA_ISSUERS` often yields `PCCERT_CONTEXT`, which we handle second.
        match retrieve_one_url(url, timeout_ms, false) {
            Ok(s) => {
                out.push_str(&s);
                Ok(out)
            }
            Err(e_auto) => {
                out.push_str(&format!(
                    "Attempt with default object type: {e_auto}\r\n\r\n"
                ));
                let s = retrieve_one_url(url, timeout_ms, true)?;
                out.push_str(&s);
                Ok(out)
            }
        }
    }
}

unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    let mut q = p.0;
    let mut n = 0usize;
    while *q != 0 && n < 8192 {
        n += 1;
        q = q.add(1);
    }
    let sl = std::slice::from_raw_parts(p.0, n);
    Some(String::from_utf16_lossy(sl))
}

unsafe fn decode_authority_info_access(
    pb: *const u8,
    cb: u32,
) -> Result<Vec<String>> {
    let mut cb_struct: u32 = 0;
    CryptDecodeObjectEx(
        CERT_ENCODING,
        szOID_AUTHORITY_INFO_ACCESS,
        std::slice::from_raw_parts(pb, cb as usize),
        0,
        None,
        None,
        &mut cb_struct,
    )
    .map_err(|e| anyhow!("CryptDecodeObjectEx (AIA size): {e}"))?;

    let mut buf = vec![0u8; cb_struct as usize];
    CryptDecodeObjectEx(
        CERT_ENCODING,
        szOID_AUTHORITY_INFO_ACCESS,
        std::slice::from_raw_parts(pb, cb as usize),
        0,
        None,
        Some(buf.as_mut_ptr().cast()),
        &mut cb_struct,
    )
    .map_err(|e| anyhow!("CryptDecodeObjectEx (AIA decode): {e}"))?;

    let aia = &*(buf.as_ptr() as *const CERT_AUTHORITY_INFO_ACCESS);
    let mut urls = Vec::new();
    if aia.cAccDescr == 0 || aia.rgAccDescr.is_null() {
        return Ok(urls);
    }
    let descs = std::slice::from_raw_parts(aia.rgAccDescr, aia.cAccDescr as usize);
    const ALT_NAME_URL: u32 = 7;
    for d in descs {
        if d.AccessLocation.dwAltNameChoice != ALT_NAME_URL {
            continue;
        }
        let pwsz = d.AccessLocation.Anonymous.pwszURL;
        if pwsz.0.is_null() {
            continue;
        }
        if let Some(s) = pwstr_to_string(pwsz) {
            urls.push(s);
        }
    }
    Ok(urls)
}

unsafe fn http_urls_from_cert_extensions(ctx: *const CERT_CONTEXT) -> Result<Vec<String>> {
    let pinfo = (*ctx).pCertInfo;
    if pinfo.is_null() || (*pinfo).cExtension == 0 || (*pinfo).rgExtension.is_null() {
        return Ok(Vec::new());
    }
    let exts = std::slice::from_raw_parts((*pinfo).rgExtension, (*pinfo).cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_AUTHORITY_INFO_ACCESS, exts);
    if ext_ptr.is_null() {
        return Ok(Vec::new());
    }
    let ext = &*ext_ptr;
    decode_authority_info_access(ext.Value.pbData, ext.Value.cbData)
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
        return Err(anyhow!(
            "not a URL and not an existing file: {target}"
        ));
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
        let urls = http_urls_from_cert_extensions(ctx)?;
        let _ = CertFreeCertificateContext(Some(ctx));
        if urls.is_empty() {
            return Err(anyhow!(
                "no Authority Information Access HTTP URLs found in certificate {}",
                path.display()
            ));
        }
        let mut out = String::new();
        for (i, u) in urls.iter().enumerate() {
            out.push_str(&format!("=== URL [{i}] from AIA extension ===\r\n"));
            out.push_str(&retrieve_url_report(u, timeout_ms)?);
            out.push_str("\r\n");
        }
        Ok(out)
    }
}
