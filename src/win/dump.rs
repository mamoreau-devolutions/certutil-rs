use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertFreeCertificateContext, CertGetCertificateContextProperty,
    CryptStringToBinaryW, CERT_HASH_PROP_ID, CRYPT_STRING_ANY,
};

use super::encoding::CERT_ENCODING;
use super::names::cert_simple_display_name;

/// Load PEM (`BEGIN CERTIFICATE`) or DER bytes from disk.
pub fn read_cert_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let head = String::from_utf8_lossy(raw.get(..128.min(raw.len())).unwrap_or(&raw));
    if head.trim_start().starts_with("-----BEGIN") {
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

/// Human-readable dump (subset of `certutil -dump`).
pub fn dump_cert_bytes(der: &[u8]) -> Result<String> {
    unsafe {
        let ctx = CertCreateCertificateContext(CERT_ENCODING, der);
        if ctx.is_null() {
            return Err(anyhow!(
                "CertCreateCertificateContext failed — file may not be a valid X.509 DER"
            ));
        }
        let _free = FreeCertContext(ctx);

        let thumbprint = cert_sha1_thumbprint_bytes(ctx)?;

        let subject = cert_simple_display_name(ctx, false)?;
        let issuer = cert_simple_display_name(ctx, true)?;

        let mut out = String::new();
        out.push_str("Certificate:\r\n");
        out.push_str(&format!("  Subject: {subject}\r\n"));
        out.push_str(&format!("  Issuer: {issuer}\r\n"));
        out.push_str(&format!(
            "  Cert Hash(sha1): {}\r\n",
            format_hex_upper(&thumbprint)
        ));
        Ok(out)
    }
}

struct FreeCertContext(*const windows::Win32::Security::Cryptography::CERT_CONTEXT);

impl Drop for FreeCertContext {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

/// SHA-1 thumbprint bytes via [`CERT_HASH_PROP_ID`] (shared with verify formatting).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT` for the duration of the call.
pub(super) unsafe fn cert_sha1_thumbprint_bytes(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Result<[u8; 20]> {
    let mut cb_hash: u32 = 0;
    CertGetCertificateContextProperty(ctx, CERT_HASH_PROP_ID, None, &mut cb_hash)?;
    let mut hash_buf = vec![0u8; cb_hash as usize];
    CertGetCertificateContextProperty(
        ctx,
        CERT_HASH_PROP_ID,
        Some(hash_buf.as_mut_ptr().cast()),
        &mut cb_hash,
    )?;
    hash_buf.truncate(cb_hash as usize);
    sha1_thumbprint_from_prop(&hash_buf)
}

/// `CERT_HASH_PROP_ID` returns a [`CERT_HASH`](https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-cert_hash)-style blob.
fn sha1_thumbprint_from_prop(prop_bytes: &[u8]) -> Result<[u8; 20]> {
    if prop_bytes.len() == 20 {
        let mut out = [0u8; 20];
        out.copy_from_slice(prop_bytes);
        return Ok(out);
    }
    if prop_bytes.len() < 4 {
        return Err(anyhow!(
            "unexpected CERT_HASH buffer length {}",
            prop_bytes.len()
        ));
    }
    let cb = u32::from_le_bytes(prop_bytes[0..4].try_into().unwrap()) as usize;
    if cb == 20 && prop_bytes.len() >= 4 + cb {
        let mut out = [0u8; 20];
        out.copy_from_slice(&prop_bytes[4..4 + 20]);
        return Ok(out);
    }
    Err(anyhow!(
        "could not parse SHA1 thumbprint from property (cb={cb}, len={})",
        prop_bytes.len()
    ))
}
