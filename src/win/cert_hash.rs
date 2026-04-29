//! SHA-1 thumbprint via [`CERT_HASH_PROP_ID`] (shared by dump and verify formatting).

use anyhow::{anyhow, Result};
use windows::Win32::Security::Cryptography::{
    CertGetCertificateContextProperty, CERT_CONTEXT, CERT_HASH_PROP_ID,
};

/// SHA-1 thumbprint bytes for a certificate context.
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT`.
pub unsafe fn cert_sha1_thumbprint_bytes(ctx: *const CERT_CONTEXT) -> Result<[u8; 20]> {
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
