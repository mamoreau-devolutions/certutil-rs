//! Formatting helpers for `certutil.exe`-shaped chain verify output.

use std::ffi::c_void;

use anyhow::{anyhow, Result};
use windows::core::{PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::Globalization::{
    GetDateFormatEx, GetTimeFormatEx, DATE_SHORTDATE, TIME_FORMAT_FLAGS,
};
use windows::Win32::Security::Cryptography::{
    szOID_SUBJECT_ALT_NAME2, CertFindExtension, CertGetNameStringW, CryptDecodeObject,
    CryptHashCertificate, CALG_SHA1, CERT_ALT_NAME_ENTRY, CERT_ALT_NAME_INFO, CERT_CHAIN_ELEMENT,
    CERT_CONTEXT, CERT_EXTENSION, CERT_INFO, CERT_NAME_ISSUER_FLAG, CERT_NAME_RDN_TYPE,
    CERT_NAME_STR_COMMA_FLAG, CERT_OTHER_NAME, CERT_REVOCATION_CRL_INFO,
    CERT_TRUST_HAS_EXACT_MATCH_ISSUER, CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY,
    CERT_TRUST_HAS_KEY_MATCH_ISSUER, CERT_TRUST_HAS_NAME_MATCH_ISSUER,
    CERT_TRUST_HAS_PREFERRED_ISSUER, CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS,
    CERT_TRUST_IS_CA_TRUSTED, CERT_TRUST_IS_COMPLEX_CHAIN, CERT_TRUST_IS_EXPLICIT_DISTRUST,
    CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE, CERT_TRUST_IS_NOT_SIGNATURE_VALID,
    CERT_TRUST_IS_NOT_TIME_NESTED, CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_NOT_VALID_FOR_USAGE,
    CERT_TRUST_IS_PARTIAL_CHAIN, CERT_TRUST_IS_PEER_TRUSTED, CERT_TRUST_IS_REVOKED,
    CERT_TRUST_IS_SELF_SIGNED, CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
    CERT_TRUST_SSL_HANDSHAKE_OCSP, CERT_TRUST_SSL_RECONNECT_OCSP, CERT_TRUST_SSL_TIME_VALID,
    CERT_TRUST_SSL_TIME_VALID_OCSP, CRYPT_INTEGER_BLOB, X509_ALTERNATE_NAME,
};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

use super::cert_urls::{decode_aia_rows, decode_cdp_urls, friendly_access_method_label};
use super::cert_hash::cert_sha1_thumbprint_bytes;
use super::encoding::CERT_ENCODING;

/// Comma-separated RDN string (closest match to certutil’s multi-component DN lines).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn cert_rdn_comma(ctx: *const CERT_CONTEXT, issuer: bool) -> Result<String> {
    let mut str_type = CERT_NAME_STR_COMMA_FLAG;
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    let pv = Some(std::ptr::addr_of_mut!(str_type).cast::<c_void>() as *const c_void);
    let cch = CertGetNameStringW(ctx, CERT_NAME_RDN_TYPE, flags, pv, None);
    if cch == 0 {
        return Err(anyhow!("CertGetNameStringW sizing failed"));
    }
    let mut buf = vec![0u16; cch as usize];
    let got = CertGetNameStringW(ctx, CERT_NAME_RDN_TYPE, flags, pv, Some(buf.as_mut_slice()));
    if got == 0 {
        return Err(anyhow!("CertGetNameStringW failed"));
    }
    while matches!(buf.last(), Some(0)) {
        buf.pop();
    }
    Ok(String::from_utf16_lossy(&buf))
}

fn format_systemtime_local_fallback(st: &SYSTEMTIME) -> String {
    format!(
        "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
        st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond
    )
}

/// Local wall-clock string for a certificate [`FILETIME`] using the **current user locale**
/// (`GetDateFormatEx` / `GetTimeFormatEx`), with US-style numeric fallback if formatting fails.
pub(crate) fn filetime_local_string(ft: &FILETIME) -> Result<String> {
    unsafe {
        let mut utc = SYSTEMTIME::default();
        FileTimeToSystemTime(ft, &mut utc)?;
        let mut local = SYSTEMTIME::default();
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local)?;
        Ok(format_local_wall_clock(&local)
            .unwrap_or_else(|| format_systemtime_local_fallback(&local)))
    }
}

/// User locale date + time (matches certutil-style localized timestamps when APIs succeed).
unsafe fn format_local_wall_clock(local: &SYSTEMTIME) -> Option<String> {
    let locale = PCWSTR::null();
    let cal = PCWSTR::null();

    let nd = GetDateFormatEx(
        locale,
        DATE_SHORTDATE,
        Some(local),
        PCWSTR::null(),
        None,
        cal,
    );
    if nd <= 0 {
        return None;
    }
    let mut date_buf = vec![0u16; nd as usize];
    let gd = GetDateFormatEx(
        locale,
        DATE_SHORTDATE,
        Some(local),
        PCWSTR::null(),
        Some(&mut date_buf[..]),
        cal,
    );
    if gd <= 0 {
        return None;
    }
    trim_trailing_nuls(&mut date_buf);

    let nt = GetTimeFormatEx(
        locale,
        TIME_FORMAT_FLAGS(0),
        Some(local),
        PCWSTR::null(),
        None,
    );
    if nt <= 0 {
        return None;
    }
    let mut time_buf = vec![0u16; nt as usize];
    let gt = GetTimeFormatEx(
        locale,
        TIME_FORMAT_FLAGS(0),
        Some(local),
        PCWSTR::null(),
        Some(&mut time_buf[..]),
    );
    if gt <= 0 {
        return None;
    }
    trim_trailing_nuls(&mut time_buf);

    let date = String::from_utf16_lossy(&date_buf);
    let time = String::from_utf16_lossy(&time_buf);
    Some(format!("{date} {time}"))
}

fn trim_trailing_nuls(buf: &mut Vec<u16>) {
    while matches!(buf.last(), Some(0)) {
        buf.pop();
    }
}

/// SHA-1 over the DER-encoded issuer / subject name blobs (same inputs certutil uses for name hashes).
pub(crate) fn name_hash_sha1_lines(info: &CERT_INFO) -> Option<String> {
    let ih = hash_der_sha1_hex_lower(&info.Issuer)?;
    let sh = hash_der_sha1_hex_lower(&info.Subject)?;
    Some(format!(
        "  Name Hash(sha1) — Issuer: {ih}\r\n  Name Hash(sha1) — Subject: {sh}\r\n"
    ))
}

fn hash_der_sha1_hex_lower(blob: &CRYPT_INTEGER_BLOB) -> Option<String> {
    if blob.cbData == 0 || blob.pbData.is_null() {
        return None;
    }
    unsafe {
        let der = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize);
        let mut hash = [0u8; 20];
        let mut cb = 20u32;
        CryptHashCertificate(None, CALG_SHA1, 0, der, Some(hash.as_mut_ptr()), &mut cb).ok()?;
        let n = (cb as usize).min(20);
        Some(hex_lower(&hash[..n]))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn serial_hex(blob: &CRYPT_INTEGER_BLOB) -> String {
    if blob.cbData == 0 || blob.pbData.is_null() {
        return "(none)".to_string();
    }
    let sl = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
    let mut start = 0usize;
    while start + 1 < sl.len() && sl[start] == 0 {
        start += 1;
    }
    sl[start..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

pub(crate) unsafe fn sha1_thumbprint_lower_hex(ctx: *const CERT_CONTEXT) -> Result<String> {
    let raw = cert_sha1_thumbprint_bytes(ctx)?;
    Ok(hex_lower(&raw))
}

// Subject Alternative Name `dwAltNameChoice` values (wincrypt.h).
const ALT_OTHER: u32 = 1;
const ALT_RFC822: u32 = 2;
const ALT_DNS: u32 = 3;
const ALT_X400: u32 = 4;
const ALT_DIR: u32 = 5;
const ALT_EDI: u32 = 6;
const ALT_URL: u32 = 7;
const ALT_IP: u32 = 8;
const ALT_REGID: u32 = 9;

/// Subject Alternative Name lines (`DNS Name=`, etc.), matching certutil’s extension dump.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn subject_alt_name_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let info = &*(*ctx).pCertInfo;
    if info.cExtension == 0 || info.rgExtension.is_null() {
        return None;
    }
    let exts: &[CERT_EXTENSION] =
        std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_SUBJECT_ALT_NAME2, exts);
    if ext_ptr.is_null() {
        return None;
    }
    let ext = &*ext_ptr;
    if ext.Value.cbData == 0 || ext.Value.pbData.is_null() {
        return None;
    }
    let enc = std::slice::from_raw_parts(ext.Value.pbData, ext.Value.cbData as usize);

    let mut cb = 0u32;
    CryptDecodeObject(CERT_ENCODING, X509_ALTERNATE_NAME, enc, 0, None, &mut cb).ok()?;
    if cb == 0 {
        return None;
    }
    let mut buf = vec![0u8; cb as usize];
    CryptDecodeObject(
        CERT_ENCODING,
        X509_ALTERNATE_NAME,
        enc,
        0,
        Some(buf.as_mut_ptr().cast()),
        &mut cb,
    )
    .ok()?;

    let san = &*(buf.as_ptr() as *const CERT_ALT_NAME_INFO);
    if san.cAltEntry == 0 || san.rgAltEntry.is_null() {
        return None;
    }

    let mut lines: Vec<String> = Vec::new();
    for i in 0..san.cAltEntry {
        let entry = &*san.rgAltEntry.add(i as usize);
        if let Some(l) = alt_entry_line(entry) {
            lines.push(l);
        }
    }
    if lines.is_empty() {
        return None;
    }

    let mut out = String::from("  Subject Alternative Name:\r\n");
    for l in lines {
        out.push_str("    ");
        out.push_str(&l);
        out.push_str("\r\n");
    }
    Some(out)
}

/// CRL Distribution Point HTTP/LDAP URLs from extension **2.5.29.31** (certutil-style `URL=` lines).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn cdp_distribution_points_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let urls = decode_cdp_urls(ctx);
    if urls.is_empty() {
        return None;
    }
    let mut out = String::from("  CRL Distribution Points:\r\n");
    for u in urls {
        out.push_str(&format!("    URL={u}\r\n"));
    }
    Some(out)
}

unsafe fn format_access_location_entry(entry: &CERT_ALT_NAME_ENTRY) -> Option<String> {
    match entry.dwAltNameChoice {
        ALT_URL => pwstr_to_string(entry.Anonymous.pwszURL),
        ALT_DNS => pwstr_to_string(entry.Anonymous.pwszDNSName),
        ALT_RFC822 => pwstr_to_string(entry.Anonymous.pwszRfc822Name),
        ALT_DIR => directory_alt_line(&entry.Anonymous.DirectoryName),
        ALT_X400 => Some(format!(
            "X400 ({} bytes DER)",
            entry.Anonymous.DirectoryName.cbData
        )),
        _ => Some(format!("(AltName choice {})", entry.dwAltNameChoice)),
    }
}

/// **Authority Information Access** (1.3.6.1.5.5.7.1.1) — OCSP + CA issuer URLs.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn authority_info_access_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let rows = decode_aia_rows(ctx)?;
    let mut sections = Vec::new();
    for row in rows {
        let oid = row.method_oid;
        let label = friendly_access_method_label(oid.as_str());
        let Some(loc) = format_access_location_entry(&row.location) else {
            continue;
        };
        sections.push(format!(
            "    Access Method={oid} ({label})\r\n    Access Location={loc}\r\n"
        ));
    }
    if sections.is_empty() {
        return None;
    }
    let mut out = String::from("  Authority Information Access:\r\n");
    for s in sections {
        out.push_str(&s);
    }
    Some(out)
}

unsafe fn pcstr_to_lossy_string(p: PCSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let ptr = p.as_ptr();
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 1024 {
        len += 1;
    }
    Some(String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned())
}

/// Revocation summary from [`CERT_CHAIN_ELEMENT::pRevocationInfo`] when the chain engine populated it.
pub(crate) unsafe fn revocation_info_lines(el: &CERT_CHAIN_ELEMENT) -> Option<String> {
    let p = el.pRevocationInfo;
    if p.is_null() {
        return None;
    }
    let r = &*p;
    let mut out = String::from("  Revocation:\r\n");
    out.push_str(&format!(
        "    dwRevocationResult: {} (0x{:08x})\r\n",
        r.dwRevocationResult, r.dwRevocationResult
    ));
    if !r.pszRevocationOid.is_null() {
        if let Some(s) = pcstr_to_lossy_string(r.pszRevocationOid) {
            out.push_str(&format!("    pszRevocationOid: {s}\r\n"));
            if s.contains("1.3.6.1.5.5.7.48.1") {
                out.push_str("    Note: OID indicates OCSP-style revocation checking.\r\n");
            }
        }
    }
    if r.fHasFreshnessTime.as_bool() {
        out.push_str(&format!(
            "    dwFreshnessTime: {} seconds — {}\r\n",
            r.dwFreshnessTime,
            format_revocation_freshness(r.dwFreshnessTime)
        ));
    }
    if !r.pCrlInfo.is_null() {
        append_revocation_crl_engine_details(&mut out, &*r.pCrlInfo);
    }
    Some(out)
}

unsafe fn append_revocation_crl_engine_details(out: &mut String, ci: &CERT_REVOCATION_CRL_INFO) {
    if ci.pBaseCrlContext.is_null() && ci.pDeltaCrlContext.is_null() && !ci.fDeltaCrlEntry.as_bool()
    {
        out.push_str(
            "    CRL info: chain engine pointer present (no CRL contexts on element).\r\n",
        );
        return;
    }
    out.push_str("    CRL engine:\r\n");
    if !ci.pBaseCrlContext.is_null() {
        let crl = &*ci.pBaseCrlContext;
        if !crl.pCrlInfo.is_null() {
            let inf = &*crl.pCrlInfo;
            let tu = filetime_local_string(&inf.ThisUpdate).unwrap_or_else(|_| "?".into());
            let nu = filetime_local_string(&inf.NextUpdate).unwrap_or_else(|_| "?".into());
            out.push_str(&format!("      Base CRL ThisUpdate: {tu}\r\n"));
            out.push_str(&format!("      Base CRL NextUpdate: {nu}\r\n"));
        }
    }
    if !ci.pDeltaCrlContext.is_null() {
        let crl = &*ci.pDeltaCrlContext;
        if !crl.pCrlInfo.is_null() {
            let inf = &*crl.pCrlInfo;
            let tu = filetime_local_string(&inf.ThisUpdate).unwrap_or_else(|_| "?".into());
            let nu = filetime_local_string(&inf.NextUpdate).unwrap_or_else(|_| "?".into());
            out.push_str(&format!("      Delta CRL ThisUpdate: {tu}\r\n"));
            out.push_str(&format!("      Delta CRL NextUpdate: {nu}\r\n"));
        }
    }
    if ci.fDeltaCrlEntry.as_bool() {
        out.push_str("      fDeltaCrlEntry: true (delta CRL entry matched)\r\n");
    }
}

/// When SSL OCSP-related [`CERT_TRUST_*`] bits are set on an element, echo them (helps compare with certutil OCSP lines).
pub(crate) fn ocsp_ssl_trust_notes(dw_info: u32) -> Option<String> {
    let mut parts = Vec::new();
    if dw_info & CERT_TRUST_SSL_HANDSHAKE_OCSP != 0 {
        parts.push("CERT_TRUST_SSL_HANDSHAKE_OCSP");
    }
    if dw_info & CERT_TRUST_SSL_TIME_VALID_OCSP != 0 {
        parts.push("CERT_TRUST_SSL_TIME_VALID_OCSP");
    }
    if dw_info & CERT_TRUST_SSL_RECONNECT_OCSP != 0 {
        parts.push("CERT_TRUST_SSL_RECONNECT_OCSP");
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!(
            "  OCSP-related dwInfoStatus bits: {}\r\n",
            parts.join(", ")
        ))
    }
}

fn alt_entry_line(entry: &CERT_ALT_NAME_ENTRY) -> Option<String> {
    unsafe {
        match entry.dwAltNameChoice {
            ALT_DNS => pwstr_alt_line("DNS Name", entry.Anonymous.pwszDNSName),
            ALT_RFC822 => pwstr_alt_line("RFC822 Name", entry.Anonymous.pwszRfc822Name),
            ALT_URL => pwstr_alt_line("URL", entry.Anonymous.pwszURL),
            ALT_IP => ip_alt_line(&entry.Anonymous.IPAddress),
            ALT_REGID => pstr_alt_line("Registered ID", entry.Anonymous.pszRegisteredID),
            ALT_DIR => directory_alt_line(&entry.Anonymous.DirectoryName),
            ALT_X400 => Some(format!(
                "X400 Address=({} byte DER)",
                entry.Anonymous.DirectoryName.cbData
            )),
            ALT_EDI => Some("EDI Party Name=(present)".to_string()),
            ALT_OTHER => other_alt_line(entry.Anonymous.pOtherName),
            _ => Some(format!("Unknown AltName choice={}", entry.dwAltNameChoice)),
        }
    }
}

unsafe fn other_alt_line(p: *mut CERT_OTHER_NAME) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let o = &*p;
    let oid = pstr_to_string_lossy(o.pszObjId).unwrap_or_else(|| "(?)".into());
    let v = &o.Value;
    let n = if v.cbData == 0 || v.pbData.is_null() {
        0usize
    } else {
        v.cbData as usize
    };
    Some(format!("Other Name: OID={oid} ({n} byte value)"))
}

unsafe fn pwstr_alt_line(label: &str, p: PWSTR) -> Option<String> {
    let s = pwstr_to_string(p)?;
    Some(format!("{label}={s}"))
}

unsafe fn pstr_alt_line(label: &str, p: PSTR) -> Option<String> {
    let s = pstr_to_string_lossy(p).unwrap_or_default();
    Some(format!("{label}={s}"))
}

unsafe fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 && len < 4096 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        p.0, len,
    )))
}

unsafe fn pstr_to_string_lossy(p: PSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 && len < 4096 {
        len += 1;
    }
    let sl = std::slice::from_raw_parts(p.0.cast::<u8>(), len);
    Some(String::from_utf8_lossy(sl).into_owned())
}

fn directory_alt_line(blob: &CRYPT_INTEGER_BLOB) -> Option<String> {
    if blob.cbData == 0 || blob.pbData.is_null() {
        return None;
    }
    Some(format!("Directory Address=(DER {} bytes)", blob.cbData))
}

fn ip_alt_line(blob: &CRYPT_INTEGER_BLOB) -> Option<String> {
    if blob.cbData == 0 || blob.pbData.is_null() {
        return None;
    }
    unsafe {
        let s = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize);
        let formatted = match s.len() {
            4 => format!("{}.{}.{}.{}", s[0], s[1], s[2], s[3]),
            16 => s
                .chunks(2)
                .map(|c| {
                    if c.len() == 2 {
                        format!("{:02x}{:02x}", c[0], c[1])
                    } else {
                        format!("{:02x}", c[0])
                    }
                })
                .collect::<Vec<_>>()
                .join(":"),
            _ => s
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        };
        Some(format!("IP Address={formatted}"))
    }
}

pub(crate) fn format_revocation_freshness(seconds: u32) -> String {
    let mut s = seconds as u64;
    let weeks = s / (7 * 24 * 3600);
    s %= 7 * 24 * 3600;
    let days = s / (24 * 3600);
    s %= 24 * 3600;
    let hours = s / 3600;
    s %= 3600;
    let mins = s / 60;
    let secs = s % 60;

    let mut parts = Vec::new();
    if weeks > 0 {
        parts.push(format!(
            "{} Week{}",
            weeks,
            if weeks == 1 { "" } else { "s" }
        ));
    }
    if days > 0 {
        parts.push(format!("{} Day{}", days, if days == 1 { "" } else { "s" }));
    }
    if hours > 0 {
        parts.push(format!(
            "{} Hour{}",
            hours,
            if hours == 1 { "" } else { "s" }
        ));
    }
    if mins > 0 {
        parts.push(format!(
            "{} Minute{}",
            mins,
            if mins == 1 { "" } else { "s" }
        ));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!(
            "{} Second{}",
            secs,
            if secs == 1 { "" } else { "s" }
        ));
    }
    format!("{} ({seconds} seconds)", parts.join(", "))
}

pub(crate) fn describe_chain_build_flags(flags: u32) -> String {
    use windows::Win32::Security::Cryptography::{
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT, CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        CERT_CHAIN_REVOCATION_CHECK_END_CERT, CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT,
    };
    const PAIRS: &[(u32, &str)] = &[
        (
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            "CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT",
        ),
        (
            CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,
            "CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT",
        ),
        (
            CERT_CHAIN_REVOCATION_CHECK_CHAIN,
            "CERT_CHAIN_REVOCATION_CHECK_CHAIN",
        ),
        (
            CERT_CHAIN_REVOCATION_CHECK_END_CERT,
            "CERT_CHAIN_REVOCATION_CHECK_END_CERT",
        ),
        (
            CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT,
            "CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT",
        ),
        (
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
            "CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY",
        ),
    ];

    let mut names = Vec::new();
    for &(mask, name) in PAIRS {
        if flags & mask != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        format!("0x{flags:08x} (no recognized bits)")
    } else {
        format!("0x{flags:08x}\r\n  {}", names.join("\r\n  "))
    }
}

fn push_matching_bits(dw: u32, pairs: &[(u32, &'static str)], out: &mut Vec<&'static str>) {
    let mut seen = 0u32;
    for &(mask, label) in pairs {
        if dw & mask != 0 && seen & mask == 0 {
            out.push(label);
            seen |= mask;
        }
    }
}

pub(crate) fn explain_cert_trust_error_status(dw: u32) -> String {
    const PAIRS: &[(u32, &str)] = &[
        (CERT_TRUST_IS_NOT_TIME_VALID, "CERT_TRUST_IS_NOT_TIME_VALID"),
        (
            CERT_TRUST_IS_NOT_TIME_NESTED,
            "CERT_TRUST_IS_NOT_TIME_NESTED",
        ),
        (CERT_TRUST_IS_REVOKED, "CERT_TRUST_IS_REVOKED"),
        (
            CERT_TRUST_IS_NOT_SIGNATURE_VALID,
            "CERT_TRUST_IS_NOT_SIGNATURE_VALID",
        ),
        (
            CERT_TRUST_IS_NOT_VALID_FOR_USAGE,
            "CERT_TRUST_IS_NOT_VALID_FOR_USAGE",
        ),
        (CERT_TRUST_IS_UNTRUSTED_ROOT, "CERT_TRUST_IS_UNTRUSTED_ROOT"),
        (CERT_TRUST_IS_PARTIAL_CHAIN, "CERT_TRUST_IS_PARTIAL_CHAIN"),
        (
            CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
            "CERT_TRUST_REVOCATION_STATUS_UNKNOWN",
        ),
        (
            CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE,
            "CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE",
        ),
        (
            CERT_TRUST_IS_EXPLICIT_DISTRUST,
            "CERT_TRUST_IS_EXPLICIT_DISTRUST",
        ),
        (CERT_TRUST_IS_COMPLEX_CHAIN, "CERT_TRUST_IS_COMPLEX_CHAIN"),
    ];
    let mut parts = Vec::new();
    push_matching_bits(dw, PAIRS, &mut parts);
    if parts.is_empty() {
        "  (no common error bits matched)\r\n".to_string()
    } else {
        format!("  Flags: {}\r\n", parts.join(", "))
    }
}

pub(crate) fn explain_cert_trust_info_status(dw: u32) -> String {
    const PAIRS: &[(u32, &str)] = &[
        (
            CERT_TRUST_HAS_EXACT_MATCH_ISSUER,
            "CERT_TRUST_HAS_EXACT_MATCH_ISSUER",
        ),
        (
            CERT_TRUST_HAS_KEY_MATCH_ISSUER,
            "CERT_TRUST_HAS_KEY_MATCH_ISSUER",
        ),
        (
            CERT_TRUST_HAS_NAME_MATCH_ISSUER,
            "CERT_TRUST_HAS_NAME_MATCH_ISSUER",
        ),
        (
            CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY,
            "CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY",
        ),
        (
            CERT_TRUST_HAS_PREFERRED_ISSUER,
            "CERT_TRUST_HAS_PREFERRED_ISSUER",
        ),
        (
            CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS,
            "CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS",
        ),
        (CERT_TRUST_IS_PEER_TRUSTED, "CERT_TRUST_IS_PEER_TRUSTED"),
        (CERT_TRUST_IS_CA_TRUSTED, "CERT_TRUST_IS_CA_TRUSTED"),
        (CERT_TRUST_IS_SELF_SIGNED, "CERT_TRUST_IS_SELF_SIGNED"),
        (CERT_TRUST_SSL_TIME_VALID, "CERT_TRUST_SSL_TIME_VALID"),
        (
            CERT_TRUST_SSL_TIME_VALID_OCSP,
            "CERT_TRUST_SSL_TIME_VALID_OCSP",
        ),
        (
            CERT_TRUST_SSL_HANDSHAKE_OCSP,
            "CERT_TRUST_SSL_HANDSHAKE_OCSP",
        ),
        (
            CERT_TRUST_SSL_RECONNECT_OCSP,
            "CERT_TRUST_SSL_RECONNECT_OCSP",
        ),
    ];
    let mut parts = Vec::new();
    push_matching_bits(dw, PAIRS, &mut parts);
    if parts.is_empty() {
        "  (no common info bits matched)\r\n".to_string()
    } else {
        format!("  Flags: {}\r\n", parts.join(", "))
    }
}
