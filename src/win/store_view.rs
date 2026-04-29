//! Read-only certificate store enumeration (`certutil -store` view subset).

use std::os::windows::ffi::OsStrExt;

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT, CERT_OPEN_STORE_FLAGS,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, HCERTSTORE,
};

use super::cert_extensions::enhanced_key_usage_block;
use super::cert_hash::cert_sha1_thumbprint_bytes;
use super::encoding::CERT_ENCODING;
use super::names::cert_simple_display_name;
use super::verify_format::filetime_local_string;

fn wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreLocationKind {
    CurrentUser,
    LocalMachine,
}

fn sha256_hex_lower(ctx: *const CERT_CONTEXT) -> String {
    unsafe {
        let c = &*ctx;
        if c.pbCertEncoded.is_null() || c.cbCertEncoded == 0 {
            return "?".into();
        }
        let der = std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize);
        let mut h = Sha256::new();
        h.update(der);
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Open **CurrentUser** or **LocalMachine** system store via [`CertOpenStore`].
pub fn view_system_store(
    store_name: &str,
    location: StoreLocationKind,
    filter_substring: Option<&str>,
) -> Result<String> {
    let wide = wide_null(store_name);
    let loc_flag = match location {
        StoreLocationKind::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        StoreLocationKind::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };
    let flags = CERT_OPEN_STORE_FLAGS(
        loc_flag | CERT_STORE_OPEN_EXISTING_FLAG.0 | CERT_STORE_READONLY_FLAG.0,
    );
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_ENCODING,
            None,
            flags,
            Some(wide.as_ptr() as *const _),
        )
        .map_err(|e| anyhow!(e))?;
        let label = match location {
            StoreLocationKind::CurrentUser => "CurrentUser",
            StoreLocationKind::LocalMachine => "LocalMachine",
        };
        enumerate_store(store, store_name, label, filter_substring)
    }
}

unsafe fn enumerate_store(
    store: HCERTSTORE,
    store_name: &str,
    location_label: &str,
    filter_substring: Option<&str>,
) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!(
        "Certificate store: {store_name} @ {location_label} (read-only enumeration)\r\n\r\n"
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
            let sha256 = sha256_hex_lower(p);
            let subj = cert_simple_display_name(p, false).unwrap_or_else(|_| "?".into());
            let (nb, na) = if (*p).pCertInfo.is_null() {
                ("?".into(), "?".into())
            } else {
                let inf = &*(*p).pCertInfo;
                (
                    filetime_local_string(&inf.NotBefore).unwrap_or_else(|_| "?".into()),
                    filetime_local_string(&inf.NotAfter).unwrap_or_else(|_| "?".into()),
                )
            };
            let eku_short = enhanced_key_usage_block(p).map(|s| {
                s.lines()
                    .filter(|l| l.starts_with("    "))
                    .map(|l| l.trim())
                    .collect::<Vec<_>>()
                    .join(", ")
            });

            out.push_str(&format!(
                "================ Certificate {idx} ================\r\n"
            ));
            out.push_str(&format!("Subject: {subj}\r\n"));
            out.push_str(&format!("NotBefore: {nb}\r\n"));
            out.push_str(&format!("NotAfter: {na}\r\n"));
            out.push_str(&format!("Cert Hash(sha1): {tp}\r\n"));
            out.push_str(&format!("Cert Hash(sha256): {sha256}\r\n"));
            if let Some(ref e) = eku_short {
                if !e.is_empty() {
                    out.push_str(&format!("Enhanced Key Usage: {e}\r\n"));
                }
            }
            out.push_str("\r\n");
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
