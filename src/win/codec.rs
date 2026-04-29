//! PEM/base64/hex encode and decode (`certutil -encode` / `-decode` subset).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result};
use windows::Win32::Security::Cryptography::{
    CryptBinaryToStringW, CryptStringToBinaryW, CRYPT_STRING_ANY, CRYPT_STRING_BASE64HEADER,
    CRYPT_STRING_HEXRAW,
};

/// Decode PEM or hex/base64 blob file to raw bytes.
pub fn decode_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = String::from_utf8_lossy(&raw);
    let wide: Vec<u16> = OsStr::new(text.trim()).encode_wide().collect();
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

/// Encode raw file as hex (no spaces) or PEM-style base64 with header.
#[derive(Clone, Copy, Debug)]
pub enum EncodeFormat {
    Hex,
    Base64Pem,
}

pub fn encode_file(path: &Path, fmt: EncodeFormat) -> Result<String> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    unsafe {
        let flags = match fmt {
            EncodeFormat::Hex => CRYPT_STRING_HEXRAW,
            EncodeFormat::Base64Pem => CRYPT_STRING_BASE64HEADER,
        };
        let mut cch: u32 = 0;
        CryptBinaryToStringW(raw.as_slice(), flags, None, &mut cch).ok()?;
        let mut buf = vec![0u16; cch as usize];
        CryptBinaryToStringW(
            raw.as_slice(),
            flags,
            Some(windows::core::PWSTR(buf.as_mut_ptr())),
            &mut cch,
        )
        .ok()?;
        while matches!(buf.last(), Some(0)) {
            buf.pop();
        }
        Ok(String::from_utf16_lossy(&buf))
    }
}
