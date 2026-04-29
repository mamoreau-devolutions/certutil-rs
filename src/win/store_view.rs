//! Read-only certificate store enumeration (`certutil -store` view subset).

use std::os::windows::ffi::OsStrExt;

use anyhow::{anyhow, Result};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
};

use super::cert_hash::cert_sha1_thumbprint_bytes;
use super::names::cert_simple_display_name;
use super::verify_format::filetime_local_string;

fn wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// List certificates in a system store (e.g. `ROOT`, `MY`, `CA`). Read-only.
pub fn view_system_store(store_name: &str, filter_substring: Option<&str>) -> Result<String> {
    let wide = wide_null(store_name);
    unsafe {
        let store = CertOpenSystemStoreW(None, PCWSTR(wide.as_ptr())).map_err(|e| anyhow!(e))?;

        let mut out = String::new();
        out.push_str(&format!(
            "Certificate store: {store_name} (read-only enumeration)\r\n\r\n"
        ));

        let mut prev: Option<*const CERT_CONTEXT> = None;
        let mut idx = 0u32;
        loop {
            let p = CertEnumCertificatesInStore(store, prev);
            if p.is_null() {
                break;
            }

            let include = if let Some(sub) = filter_substring {
                let sub_l = sub.to_ascii_lowercase();
                let sn = cert_simple_display_name(p, false).unwrap_or_default();
                let iss = cert_simple_display_name(p, true).unwrap_or_default();
                sn.to_ascii_lowercase().contains(&sub_l)
                    || iss.to_ascii_lowercase().contains(&sub_l)
            } else {
                true
            };

            if include {
                let tp = cert_sha1_thumbprint_bytes(p)
                    .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
                    .unwrap_or_else(|_| "?".into());
                let subj = cert_simple_display_name(p, false).unwrap_or_else(|_| "?".into());
                let nb = if (*p).pCertInfo.is_null() {
                    "?".into()
                } else {
                    let inf = &*(*p).pCertInfo;
                    filetime_local_string(&inf.NotBefore).unwrap_or_else(|_| "?".into())
                };
                out.push_str(&format!(
                    "================ Certificate {idx} ================\r\n"
                ));
                out.push_str(&format!("Subject: {subj}\r\n"));
                out.push_str(&format!("NotBefore: {nb}\r\n"));
                out.push_str(&format!("Cert Hash(sha1): {tp}\r\n\r\n"));
                idx += 1;
            }

            prev = Some(p);
        }

        let _ = CertCloseStore(Some(store), 0);

        if idx == 0 {
            out.push_str("(no certificates matched)\r\n");
        }

        Ok(out)
    }
}
