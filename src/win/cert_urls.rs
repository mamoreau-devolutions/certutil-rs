//! Unified extraction of HTTP(S)/LDAP URLs from AIA and CDP extensions for display and retrieval probes.

use windows::core::{PSTR, PWSTR};
use windows::Win32::Security::Cryptography::{
    szOID_AUTHORITY_INFO_ACCESS, szOID_CRL_DIST_POINTS, CertFindExtension, CryptDecodeObject,
    CERT_ACCESS_DESCRIPTION, CERT_ALT_NAME_ENTRY, CERT_ALT_NAME_INFO, CERT_AUTHORITY_INFO_ACCESS,
    CERT_CONTEXT, CERT_EXTENSION, CRL_DIST_POINTS_INFO, CRL_DIST_POINT_FULL_NAME,
    X509_AUTHORITY_INFO_ACCESS, X509_CRL_DIST_POINTS,
};

use super::encoding::CERT_ENCODING;

/// PKIX / CDP classification for [`CryptRetrieveObjectByUrl`] OID hints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertUrlKind {
    /// Access method OID `1.3.6.1.5.5.7.48.1` (OCSP).
    AiaOcsp,
    /// Access method OID `1.3.6.1.5.5.7.48.2` (CA Issuers).
    AiaCaIssuers,
    /// Other registered access method OID string.
    AiaOther(String),
    /// CRL Distribution Point URL.
    Cdp,
}

/// One URL discovered on the certificate for CryptNet retrieval diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertUrlEntry {
    pub kind: CertUrlKind,
    pub url: String,
}

const ALT_URL: u32 = 7;

pub(crate) fn friendly_access_method_label(oid: &str) -> &'static str {
    match oid {
        "1.3.6.1.5.5.7.48.1" => "OCSP",
        "1.3.6.1.5.5.7.48.2" => "CA Issuers",
        _ => "Other",
    }
}

/// True if `CryptRetrieveObjectByUrl` commonly accepts this URL scheme.
pub(crate) fn looks_like_cryptretrieve_url(url: &str) -> bool {
    let t = url.trim();
    let lower = t.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ldap://")
        || lower.starts_with("ldaps://")
        || lower.starts_with("ftp://")
}

unsafe fn pstr_to_string_lossy(p: PSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 && len < 1024 {
        len += 1;
    }
    let sl = std::slice::from_raw_parts(p.0.cast::<u8>(), len);
    Some(String::from_utf8_lossy(sl).into_owned())
}

unsafe fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.0.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 && len < 8192 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        p.0, len,
    )))
}

/// Extract `http(s)/ldap` URLs from a decoded [`CERT_ALT_NAME_INFO`].
pub(crate) unsafe fn urls_from_alt_name_info(alt: &CERT_ALT_NAME_INFO) -> Vec<String> {
    let mut out = Vec::new();
    if alt.cAltEntry == 0 || alt.rgAltEntry.is_null() {
        return out;
    }
    for i in 0..alt.cAltEntry {
        let entry = &*alt.rgAltEntry.add(i as usize);
        if entry.dwAltNameChoice == ALT_URL {
            if let Some(u) = pwstr_to_string(entry.Anonymous.pwszURL) {
                out.push(u);
            }
        }
    }
    out
}

/// Decoded AIA row for verify output formatting.
pub(crate) struct AiaAccessRow {
    pub method_oid: String,
    pub location: CERT_ALT_NAME_ENTRY,
}

/// Decode Authority Information Access extension from `ctx`.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn decode_aia_rows(ctx: *const CERT_CONTEXT) -> Option<Vec<AiaAccessRow>> {
    let info = &*(*ctx).pCertInfo;
    if info.cExtension == 0 || info.rgExtension.is_null() {
        return None;
    }
    let exts: &[CERT_EXTENSION] =
        std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_AUTHORITY_INFO_ACCESS, exts);
    if ext_ptr.is_null() {
        return None;
    }
    let ext = &*ext_ptr;
    if ext.Value.cbData == 0 || ext.Value.pbData.is_null() {
        return None;
    }
    let enc = std::slice::from_raw_parts(ext.Value.pbData, ext.Value.cbData as usize);

    let mut cb = 0u32;
    CryptDecodeObject(
        CERT_ENCODING,
        X509_AUTHORITY_INFO_ACCESS,
        enc,
        0,
        None,
        &mut cb,
    )
    .ok()?;
    if cb == 0 {
        return None;
    }
    let mut buf = vec![0u8; cb as usize];
    CryptDecodeObject(
        CERT_ENCODING,
        X509_AUTHORITY_INFO_ACCESS,
        enc,
        0,
        Some(buf.as_mut_ptr().cast()),
        &mut cb,
    )
    .ok()?;

    let aia = &*(buf.as_ptr() as *const CERT_AUTHORITY_INFO_ACCESS);
    if aia.cAccDescr == 0 || aia.rgAccDescr.is_null() {
        return None;
    }

    let mut rows = Vec::new();
    for i in 0..aia.cAccDescr {
        let d: &CERT_ACCESS_DESCRIPTION = &*aia.rgAccDescr.add(i as usize);
        let Some(oid) = pstr_to_string_lossy(d.pszAccessMethod) else {
            continue;
        };
        rows.push(AiaAccessRow {
            method_oid: oid,
            location: d.AccessLocation,
        });
    }
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

/// Decode CRL Distribution Points extension — HTTP(S)/LDAP URLs only (same as verify CDP block).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn decode_cdp_urls(ctx: *const CERT_CONTEXT) -> Vec<String> {
    let info = &*(*ctx).pCertInfo;
    if info.cExtension == 0 || info.rgExtension.is_null() {
        return Vec::new();
    }
    let exts: &[CERT_EXTENSION] =
        std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_CRL_DIST_POINTS, exts);
    if ext_ptr.is_null() {
        return Vec::new();
    }
    let ext = &*ext_ptr;
    if ext.Value.cbData == 0 || ext.Value.pbData.is_null() {
        return Vec::new();
    }
    let enc = std::slice::from_raw_parts(ext.Value.pbData, ext.Value.cbData as usize);

    let mut cb = 0u32;
    if CryptDecodeObject(CERT_ENCODING, X509_CRL_DIST_POINTS, enc, 0, None, &mut cb).is_err() {
        return Vec::new();
    }
    if cb == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; cb as usize];
    if CryptDecodeObject(
        CERT_ENCODING,
        X509_CRL_DIST_POINTS,
        enc,
        0,
        Some(buf.as_mut_ptr().cast()),
        &mut cb,
    )
    .is_err()
    {
        return Vec::new();
    }

    let cdp = &*(buf.as_ptr() as *const CRL_DIST_POINTS_INFO);
    if cdp.cDistPoint == 0 || cdp.rgDistPoint.is_null() {
        return Vec::new();
    }

    let mut urls = Vec::new();
    for i in 0..cdp.cDistPoint {
        let dp = &*cdp.rgDistPoint.add(i as usize);
        if dp.DistPointName.dwDistPointNameChoice != CRL_DIST_POINT_FULL_NAME {
            continue;
        }
        let alt = &dp.DistPointName.Anonymous.FullName;
        urls.extend(urls_from_alt_name_info(alt));
    }
    urls
}

fn kind_from_aia_oid(oid: &str) -> CertUrlKind {
    match oid {
        "1.3.6.1.5.5.7.48.1" => CertUrlKind::AiaOcsp,
        "1.3.6.1.5.5.7.48.2" => CertUrlKind::AiaCaIssuers,
        _ => CertUrlKind::AiaOther(oid.to_string()),
    }
}

/// All AIA (`ALT_URL`) and CDP URLs suitable for CryptNet probes (ordered: AIA rows, then CDP).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub unsafe fn collect_cert_retrieval_urls(ctx: *const CERT_CONTEXT) -> Vec<CertUrlEntry> {
    let mut v = Vec::new();
    if let Some(rows) = decode_aia_rows(ctx) {
        for row in rows {
            if row.location.dwAltNameChoice != ALT_URL {
                continue;
            }
            let Some(url) = pwstr_to_string(row.location.Anonymous.pwszURL) else {
                continue;
            };
            if !looks_like_cryptretrieve_url(&url) {
                continue;
            }
            let kind = kind_from_aia_oid(row.method_oid.as_str());
            v.push(CertUrlEntry { kind, url });
        }
    }
    for url in decode_cdp_urls(ctx) {
        if looks_like_cryptretrieve_url(&url) {
            v.push(CertUrlEntry {
                kind: CertUrlKind::Cdp,
                url,
            });
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Cryptography::{
        CertCreateCertificateContext, CertFreeCertificateContext,
    };

    use crate::win::encoding::CERT_ENCODING;

    #[test]
    fn looks_like_url_accepts_https_http_ldap() {
        assert!(looks_like_cryptretrieve_url("https://x.example/ocsp"));
        assert!(looks_like_cryptretrieve_url("HTTP://a"));
        assert!(looks_like_cryptretrieve_url("ldap://dc/cn=x"));
        assert!(!looks_like_cryptretrieve_url("dns:name"));
    }

    #[test]
    fn fixture_cert_collect_urls_no_panic() {
        let der = include_bytes!("../../tests/fixtures/test_leaf.der");
        unsafe {
            let ctx = CertCreateCertificateContext(CERT_ENCODING, der.as_slice());
            assert!(!ctx.is_null(), "fixture DER must parse");
            let list = collect_cert_retrieval_urls(ctx);
            let _ = CertFreeCertificateContext(Some(ctx));
            // Self-signed fixture may have no AIA/CDP; still must return a vec.
            assert!(list.iter().all(|e| looks_like_cryptretrieve_url(&e.url)));
        }
    }
}
