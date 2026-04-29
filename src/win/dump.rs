use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertCreateCertificateContext, CertCreateCRLContext, CertEnumCertificatesInStore,
    CertFreeCRLContext, CertFreeCertificateContext, CryptDecodeObject, CryptQueryObject,
    CryptStringToBinaryW, CRYPT_INTEGER_BLOB, CRYPT_STRING_ANY, CRL_CONTEXT, CERT_CONTEXT,
    CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_CONTENT_TYPE, CERT_QUERY_ENCODING_TYPE,
    CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_BLOB, CERT_REQUEST_INFO,
    HCERTSTORE, X509_CERT_REQUEST_TO_BE_SIGNED,
};

use super::cert_hash::cert_sha1_thumbprint_bytes;
use super::encoding::CERT_ENCODING;
use super::names::cert_simple_display_name;
use super::verify_format::{
    authority_info_access_block, cdp_distribution_points_block, cert_rdn_comma,
    filetime_local_string, name_hash_sha1_lines, serial_hex, sha1_thumbprint_lower_hex,
    subject_alt_name_block,
};

/// Load PEM (`BEGIN …`) or raw DER from disk.
pub fn read_cert_file(path: &Path) -> Result<Vec<u8>> {
    read_pem_or_der_file(path)
}

fn read_pem_or_der_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let head = String::from_utf8_lossy(raw.get(..256.min(raw.len())).unwrap_or(&raw));
    let h = head.trim_start();
    if h.starts_with("-----BEGIN") {
        let text = String::from_utf8_lossy(&raw);
        pem_to_der(text.trim_end())
    } else {
        Ok(raw)
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let wide: Vec<u16> = OsStr::new(pem).encode_wide().collect();
    unsafe {
        let mut cb: u32 = 0;
        CryptStringToBinaryW(&wide, CRYPT_STRING_ANY, None, &mut cb, None, None)?;
        let mut buf = vec![0u8; cb as usize];
        CryptStringToBinaryW(
            &wide,
            CRYPT_STRING_ANY,
            Some(buf.as_mut_ptr()),
            &mut cb,
            None,
            None,
        )?;
        buf.truncate(cb as usize);
        Ok(buf)
    }
}

fn format_hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Dump by auto-detecting X.509 certificate, CRL, CSR, or PKCS#7 (best-effort).
pub fn dump_file(path: &Path) -> Result<String> {
    let der = read_pem_or_der_file(path)?;
    if let Ok(s) = dump_cert_bytes(&der) {
        return Ok(s);
    }
    if let Ok(s) = dump_crl_bytes(&der) {
        return Ok(s);
    }
    if let Ok(s) = dump_csr_bytes(&der) {
        return Ok(s);
    }
    if let Ok(s) = dump_pkcs7_bytes(&der) {
        return Ok(s);
    }
    Err(anyhow!(
        "{} is not a recognized X.509 certificate, CRL, PKCS#10 CSR, or PKCS#7/CMS",
        path.display()
    ))
}

/// Human-readable certificate dump (certutil-style fields; shares decoders with `-verify`).
pub fn dump_cert_bytes(der: &[u8]) -> Result<String> {
    unsafe {
        let ctx = CertCreateCertificateContext(CERT_ENCODING, der);
        if ctx.is_null() {
            return Err(anyhow!("not an X.509 certificate"));
        }
        let _free = FreeCertContext(ctx);
        dump_certificate_context(ctx)
    }
}

unsafe fn dump_certificate_context(ctx: *const CERT_CONTEXT) -> Result<String> {
    let issuer = cert_rdn_comma(ctx, true)
        .unwrap_or_else(|_| cert_simple_display_name(ctx, true).unwrap_or_else(|_| "?".into()));
    let subject = cert_rdn_comma(ctx, false)
        .unwrap_or_else(|_| cert_simple_display_name(ctx, false).unwrap_or_else(|_| "?".into()));
    let info = &*(*ctx).pCertInfo;
    let serial = serial_hex(&info.SerialNumber);
    let nb = filetime_local_string(&info.NotBefore).unwrap_or_else(|_| "?".into());
    let na = filetime_local_string(&info.NotAfter).unwrap_or_else(|_| "?".into());
    let thumb = cert_sha1_thumbprint_bytes(ctx)?;
    let thumb_lower = sha1_thumbprint_lower_hex(ctx).unwrap_or_else(|_| "?".into());

    let mut out = String::new();
    out.push_str("Certificate:\r\n");
    out.push_str(&format!("  Issuer:\r\n    {issuer}\r\n"));
    out.push_str(&format!("  Subject:\r\n    {subject}\r\n"));
    if let Some(h) = name_hash_sha1_lines(info) {
        out.push_str(&h);
    }
    out.push_str(&format!("  Cert Serial Number: {serial}\r\n"));
    out.push_str(&format!(
        "  Cert Hash(sha1): {}\r\n",
        format_hex_upper(&thumb)
    ));
    out.push_str(&format!("  Cert (sha1): {thumb_lower}\r\n"));
    if let Some(san) = subject_alt_name_block(ctx) {
        out.push_str(&san);
    }
    if let Some(aia) = authority_info_access_block(ctx) {
        out.push_str(&aia);
    }
    if let Some(cdp) = cdp_distribution_points_block(ctx) {
        out.push_str(&cdp);
    }
    out.push_str(&format!("  NotBefore: {nb}\r\n"));
    out.push_str(&format!("  NotAfter: {na}\r\n"));
    Ok(out)
}

/// CRL dump (`CertCreateCRLContext`).
pub fn dump_crl_bytes(der: &[u8]) -> Result<String> {
    unsafe {
        let crl = CertCreateCRLContext(CERT_ENCODING, der);
        if crl.is_null() {
            return Err(anyhow!("not a CRL"));
        }
        let _free = FreeCrlContext(crl);
        let inf = &*(*crl).pCrlInfo;
        let this_u = filetime_local_string(&inf.ThisUpdate).unwrap_or_else(|_| "?".into());
        let next_u = filetime_local_string(&inf.NextUpdate).unwrap_or_else(|_| "?".into());
        let mut out = String::from("CRL:\r\n");
        out.push_str(&format!("  ThisUpdate: {this_u}\r\n"));
        out.push_str(&format!("  NextUpdate: {next_u}\r\n"));
        out.push_str(&format!(
            "  cCRLEntry (revoked certs listed): {}\r\n",
            inf.cCRLEntry
        ));
        Ok(out)
    }
}

struct FreeCrlContext(*const CRL_CONTEXT);

impl Drop for FreeCrlContext {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCRLContext(Some(self.0));
        }
    }
}

/// PKCS#10 CSR dump via `CryptDecodeObject` → [`CERT_REQUEST_INFO`].
pub fn dump_csr_bytes(der: &[u8]) -> Result<String> {
    unsafe {
        let mut cb = 0u32;
        CryptDecodeObject(
            CERT_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            der,
            0,
            None,
            &mut cb,
        )
        .map_err(|_| anyhow!("not a PKCS#10 CSR"))?;
        if cb == 0 {
            return Err(anyhow!("not a PKCS#10 CSR"));
        }
        let mut buf = vec![0u8; cb as usize];
        CryptDecodeObject(
            CERT_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            der,
            0,
            Some(buf.as_mut_ptr().cast()),
            &mut cb,
        )
        .map_err(|e| anyhow!("CSR decode: {e}"))?;
        let csr = &*(buf.as_ptr() as *const CERT_REQUEST_INFO);
        let mut out = String::from("Certificate request (PKCS#10):\r\n");
        out.push_str(&format!("  Version: {}\r\n", csr.dwVersion));
        out.push_str(&format!(
            "  Subject name DER: {} bytes\r\n",
            csr.Subject.cbData
        ));
        out.push_str(&format!(
            "  SubjectPublicKeyInfo.Algorithm: {} bytes parameters\r\n",
            csr.SubjectPublicKeyInfo.Algorithm.Parameters.cbData
        ));
        out.push_str(&format!("  cAttribute: {}\r\n", csr.cAttribute));
        Ok(out)
    }
}

/// PKCS#7 / CMS: [`CryptQueryObject`] then count embedded certificates.
pub fn dump_pkcs7_bytes(der: &[u8]) -> Result<String> {
    unsafe {
        let blob = CRYPT_INTEGER_BLOB {
            cbData: der.len() as u32,
            pbData: der.as_ptr() as *mut u8,
        };
        let mut encoding = CERT_QUERY_ENCODING_TYPE::default();
        let mut content_type = CERT_QUERY_CONTENT_TYPE::default();
        let mut format_type = CERT_QUERY_FORMAT_TYPE::default();
        let mut store: HCERTSTORE = std::mem::zeroed();
        CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &blob as *const _ as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            Some(&mut encoding),
            Some(&mut content_type),
            Some(&mut format_type),
            Some(&mut store),
            None,
            None,
        )
        .map_err(|_| anyhow!("not PKCS#7 / CMS"))?;
        let _close = CloseStore(store);

        let mut n = 0u32;
        let mut prev: Option<*const CERT_CONTEXT> = None;
        loop {
            let p = CertEnumCertificatesInStore(store, prev);
            if p.is_null() {
                break;
            }
            n += 1;
            prev = Some(p);
        }

        let mut out = String::from("PKCS7 / CMS:\r\n");
        out.push_str(&format!(
            "  Query encoding type field: {}\r\n",
            encoding.0
        ));
        out.push_str(&format!(
            "  Query content type field: {}\r\n",
            content_type.0
        ));
        out.push_str(&format!(
            "  Certificates embedded (enumerated): {n}\r\n"
        ));
        Ok(out)
    }
}

struct CloseStore(HCERTSTORE);

impl Drop for CloseStore {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

struct FreeCertContext(*const CERT_CONTEXT);

impl Drop for FreeCertContext {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}
