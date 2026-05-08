use anyhow::{anyhow, Result};
use windows::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_CONTEXT, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};

/// CN-style display name (`CertGetNameStringW` + `CERT_NAME_SIMPLE_DISPLAY_TYPE`).
///
/// # Safety
/// `ctx` must be a valid `PCCERT_CONTEXT` for the duration of the call.
pub unsafe fn cert_simple_display_name(ctx: *const CERT_CONTEXT, issuer: bool) -> Result<String> {
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    let cch = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None);
    if cch == 0 {
        return Err(anyhow!("CertGetNameStringW sizing returned 0"));
    }
    let mut buf = vec![0u16; cch as usize];
    let got = CertGetNameStringW(
        ctx,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        flags,
        None,
        Some(buf.as_mut_slice()),
    );
    if got == 0 {
        return Err(anyhow!("CertGetNameStringW failed"));
    }
    while matches!(buf.last(), Some(0)) {
        buf.pop();
    }
    Ok(String::from_utf16_lossy(&buf))
}
