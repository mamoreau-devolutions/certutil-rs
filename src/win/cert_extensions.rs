//! Certificate extension and SPKI summaries for `-dump` / verify leaf sections.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use anyhow::Result;
use der_parser::ber::BerObjectContent;
use der_parser::oid::Oid;
use der_parser::parse_der;
use windows::Win32::Security::Cryptography::{
    CertFindExtension, CertGetIntendedKeyUsage, CertGetNameStringW, CertGetPublicKeyLength,
    CryptDecodeObject, CERT_BASIC_CONSTRAINTS2_INFO, CERT_CONTEXT, CERT_EXTENSION,
    CERT_NAME_RDN_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE, CRYPT_BIT_BLOB,
    CRYPT_INTEGER_BLOB,
    szOID_BASIC_CONSTRAINTS2, szOID_ENHANCED_KEY_USAGE, X509_BASIC_CONSTRAINTS2,
};

use super::encoding::CERT_ENCODING;

fn oid_to_string(oid: &Oid) -> String {
    oid.to_id_string()
}

/// X.509 Key Usage bits (first octet), high bit first per DER BIT STRING.
fn format_key_usage_bits(byte: u8) -> Vec<&'static str> {
    let mut v = Vec::new();
    const NAMES: [&str; 8] = [
        "digitalSignature",
        "contentCommitment",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
    ];
    for i in 0..8 {
        if (byte >> (7 - i)) & 1 != 0 {
            v.push(NAMES[i as usize]);
        }
    }
    v
}

/// Enhanced Key Usage: extension value is SEQUENCE OF OBJECT IDENTIFIER.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn enhanced_key_usage_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let info = &*(*ctx).pCertInfo;
    if info.cExtension == 0 || info.rgExtension.is_null() {
        return None;
    }
    let exts: &[CERT_EXTENSION] =
        std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_ENHANCED_KEY_USAGE, exts);
    if ext_ptr.is_null() {
        return None;
    }
    let ext = &*ext_ptr;
    if ext.Value.cbData == 0 || ext.Value.pbData.is_null() {
        return None;
    }
    let enc = std::slice::from_raw_parts(ext.Value.pbData, ext.Value.cbData as usize);
    let (_, obj) = parse_der(enc).ok()?;
    let seq = match &obj.content {
        BerObjectContent::Sequence(seq) => seq,
        _ => return None,
    };
    let mut oids = Vec::new();
    for o in seq {
        if let BerObjectContent::OID(oid) = &o.content {
            oids.push(oid_to_string(oid));
        }
    }
    if oids.is_empty() {
        return None;
    }
    let mut out = String::from("  Enhanced Key Usage:\r\n");
    for oid in oids {
        out.push_str(&format!("    {oid}\r\n"));
    }
    Some(out)
}

/// Key Usage extension bits via [`CertGetIntendedKeyUsage`].
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn key_usage_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let info = &*(*ctx).pCertInfo;
    let mut ku = [0u8; 4];
    CertGetIntendedKeyUsage(CERT_ENCODING, info, &mut ku[..]).ok()?;
    let byte = *ku.first()?;
    if byte == 0 {
        return None;
    }
    let bits = format_key_usage_bits(byte);
    if bits.is_empty() {
        return None;
    }
    let mut out = String::from("  Key Usage:\r\n");
    for b in bits {
        out.push_str(&format!("    {b}\r\n"));
    }
    Some(out)
}

/// Basic Constraints (`2.5.29.19`).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn basic_constraints_block(ctx: *const CERT_CONTEXT) -> Option<String> {
    let info = &*(*ctx).pCertInfo;
    if info.cExtension == 0 || info.rgExtension.is_null() {
        return None;
    }
    let exts: &[CERT_EXTENSION] =
        std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
    let ext_ptr = CertFindExtension(szOID_BASIC_CONSTRAINTS2, exts);
    if ext_ptr.is_null() {
        return None;
    }
    let ext = &*ext_ptr;
    if ext.Value.cbData == 0 || ext.Value.pbData.is_null() {
        return None;
    }
    let enc = std::slice::from_raw_parts(ext.Value.pbData, ext.Value.cbData as usize);
    let mut cb = 0u32;
    CryptDecodeObject(CERT_ENCODING, X509_BASIC_CONSTRAINTS2, enc, 0, None, &mut cb).ok()?;
    if cb == 0 {
        return None;
    }
    let mut buf = vec![0u8; cb as usize];
    CryptDecodeObject(
        CERT_ENCODING,
        X509_BASIC_CONSTRAINTS2,
        enc,
        0,
        Some(buf.as_mut_ptr().cast()),
        &mut cb,
    )
    .ok()?;
    let bc = &*(buf.as_ptr() as *const CERT_BASIC_CONSTRAINTS2_INFO);
    let mut out = String::from("  Basic Constraints:\r\n");
    out.push_str(&format!(
        "    CA: {}\r\n",
        if bc.fCA.as_bool() { "true" } else { "false" }
    ));
    if bc.fPathLenConstraint.as_bool() {
        out.push_str(&format!(
            "    PathLenConstraint: {}\r\n",
            bc.dwPathLenConstraint
        ));
    }
    Some(out)
}

/// Algorithm OID string + public key bit length.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub(crate) unsafe fn public_key_summary_line(ctx: *const CERT_CONTEXT) -> Option<String> {
    let info = &*(*ctx).pCertInfo;
    let spki = &info.SubjectPublicKeyInfo;
    let oid = if spki.Algorithm.pszObjId.is_null() {
        "?".into()
    } else {
        std::ffi::CStr::from_ptr(spki.Algorithm.pszObjId.as_ptr().cast())
            .to_string_lossy()
            .into_owned()
    };
    let bits = CertGetPublicKeyLength(CERT_ENCODING, spki);
    if bits == 0 {
        return Some(format!("  Public Key Algorithm: {oid}\r\n"));
    }
    Some(format!(
        "  Public Key Algorithm: {oid} ({bits} bits)\r\n"
    ))
}

#[inline]
unsafe fn blob_as_crypt_bit(blob: &CRYPT_INTEGER_BLOB) -> &CRYPT_BIT_BLOB {
    &*(std::ptr::from_ref(blob).cast::<CRYPT_BIT_BLOB>())
}

/// Decode issuer/subject name blob to a single-line display string (for CRL/CSR).
pub(crate) unsafe fn name_blob_to_display(blob: &CRYPT_INTEGER_BLOB) -> Result<String> {
    let blob = blob_as_crypt_bit(blob);
    if blob.cbData == 0 || blob.pbData.is_null() {
        return Ok("?".into());
    }
    let cch = CertGetNameStringW(
        std::ptr::null(),
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        Some(blob as *const _ as *const _),
        None,
    );
    if cch == 0 {
        return Ok("?".into());
    }
    let mut buf = vec![0u16; cch as usize];
    let got = CertGetNameStringW(
        std::ptr::null(),
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        Some(blob as *const _ as *const _),
        Some(buf.as_mut_slice()),
    );
    if got == 0 {
        return Ok("?".into());
    }
    while matches!(buf.last(), Some(0)) {
        buf.pop();
    }
    Ok(OsString::from_wide(&buf).to_string_lossy().into_owned())
}

/// Comma-RDN subject/issuer from an encoded name blob (CSR subject).
pub(crate) unsafe fn name_blob_to_rdn_comma(blob: &CRYPT_INTEGER_BLOB) -> Result<String> {
    let b = blob_as_crypt_bit(blob);
    if b.cbData == 0 || b.pbData.is_null() {
        return Ok("?".into());
    }
    let cch = CertGetNameStringW(
        std::ptr::null(),
        CERT_NAME_RDN_TYPE,
        0,
        Some(b as *const _ as *const _),
        None,
    );
    if cch == 0 {
        return name_blob_to_display(blob);
    }
    let mut buf = vec![0u16; cch as usize];
    let got = CertGetNameStringW(
        std::ptr::null(),
        CERT_NAME_RDN_TYPE,
        0,
        Some(b as *const _ as *const _),
        Some(buf.as_mut_slice()),
    );
    if got == 0 {
        return name_blob_to_display(blob);
    }
    while matches!(buf.last(), Some(0)) {
        buf.pop();
    }
    Ok(OsString::from_wide(&buf).to_string_lossy().into_owned())
}
