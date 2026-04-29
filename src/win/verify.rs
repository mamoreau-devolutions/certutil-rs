//! Chain building + policy check (`CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`).

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::core::Error as WinError;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateContext,
    CertGetCertificateChain, CertVerifyCertificateChainPolicy, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    CERT_CONTEXT, CERT_SIMPLE_CHAIN, CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_PARTIAL_CHAIN,
    CERT_TRUST_IS_REVOKED, CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
};

use super::encoding::CERT_ENCODING;
use super::names::cert_simple_display_name;
use super::url::DEFAULT_URL_TIMEOUT_MS;

/// Options aligned with `certutil.exe -verify` modifiers **`urlfetch`** and **`-t`** (URL retrieval timeout).
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    /// Corresponds to **`certutil -verify -urlfetch`** (retrieve AIA certs / CDP CRLs during chain build).
    pub urlfetch: bool,
    /// **`certutil -t`** — URL retrieval timeout in milliseconds (`CERT_CHAIN_PARA::dwUrlRetrievalTimeout`).
    pub timeout_ms: Option<u32>,
}

/// Build a chain against trust stores and evaluate **BASE** chain policy (closest generic check to `certutil -verify` exploration).
pub fn verify_cert_file(path: &Path) -> Result<String> {
    verify_cert_file_with_options(path, VerifyOptions::default())
}

pub fn verify_cert_file_with_options(path: &Path, opts: VerifyOptions) -> Result<String> {
    let der =
        super::dump::read_cert_file(path).with_context(|| format!("read {}", path.display()))?;
    verify_der_with_options(&der, opts)
}

pub fn verify_der(der: &[u8]) -> Result<String> {
    verify_der_with_options(der, VerifyOptions::default())
}

pub fn verify_der_with_options(der: &[u8], opts: VerifyOptions) -> Result<String> {
    unsafe {
        let leaf = CertCreateCertificateContext(CERT_ENCODING, der);
        if leaf.is_null() {
            return Err(anyhow!(
                "CertCreateCertificateContext failed — expected an encoded certificate"
            ));
        }
        let _free_leaf = FreeCertContext(leaf);

        let url_timeout = match opts.timeout_ms {
            Some(t) => t,
            None if opts.urlfetch => DEFAULT_URL_TIMEOUT_MS,
            None => 0,
        };

        let chain_para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            dwUrlRetrievalTimeout: url_timeout,
            ..Default::default()
        };

        let mut chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
        if opts.urlfetch {
            chain_flags |= CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
        }

        let mut p_chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        CertGetCertificateChain(
            None,
            leaf,
            None,
            None,
            &chain_para,
            chain_flags,
            None,
            &mut p_chain,
        )?;

        if p_chain.is_null() {
            return Err(anyhow!("CertGetCertificateChain returned null chain"));
        }
        let _free_chain = FreeChainContext(p_chain);

        let chain = &*p_chain;
        let mut out = String::new();
        out.push_str("Verify options:\r\n");
        out.push_str(&format!(
            "  urlfetch: {}, URL retrieval timeout (ms): {}\r\n\r\n",
            opts.urlfetch, url_timeout
        ));
        out.push_str("Chain global trust status:\r\n");
        out.push_str(&format!(
            "  dwErrorStatus: 0x{:08x}\r\n",
            chain.TrustStatus.dwErrorStatus
        ));
        out.push_str(&format!(
            "  dwInfoStatus: 0x{:08x}\r\n",
            chain.TrustStatus.dwInfoStatus
        ));
        out.push_str(&explain_error_status(chain.TrustStatus.dwErrorStatus));

        let policy_para = CERT_CHAIN_POLICY_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
            ..Default::default()
        };

        let mut policy_status = CERT_CHAIN_POLICY_STATUS {
            cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
            ..Default::default()
        };

        let policy_ok: BOOL = CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE,
            p_chain,
            &policy_para,
            &mut policy_status,
        );

        out.push_str("\r\nCERT_CHAIN_POLICY_BASE:\r\n");
        if !policy_ok.as_bool() {
            let e = WinError::from_win32();
            out.push_str(&format!(
                "  CertVerifyCertificateChainPolicy failed: {e}\r\n"
            ));
        } else {
            out.push_str(&format!(
                "  Policy dwError: 0x{:08x} (0 = success)\r\n",
                policy_status.dwError
            ));
            if policy_status.dwError != 0 {
                out.push_str(&format!(
                    "  Chain index: {}, Element index: {}\r\n",
                    policy_status.lChainIndex, policy_status.lElementIndex
                ));
            }
        }

        if chain.cChain > 0 && !chain.rgpChain.is_null() {
            let simple: &CERT_SIMPLE_CHAIN = &**chain.rgpChain;
            out.push_str("\r\nChain elements:\r\n");
            for i in 0..simple.cElement {
                let el_ptr = *simple.rgpElement.add(i as usize);
                if el_ptr.is_null() {
                    continue;
                }
                let el = &*el_ptr;
                if el.pCertContext.is_null() {
                    continue;
                }
                let subj =
                    cert_simple_display_name(el.pCertContext, false).unwrap_or_else(|_| "?".into());
                let iss =
                    cert_simple_display_name(el.pCertContext, true).unwrap_or_else(|_| "?".into());
                out.push_str(&format!(
                    "  [{i}] Subject: {subj}\r\n      Issuer: {iss}\r\n"
                ));
                out.push_str(&format!(
                    "      Element error status: 0x{:08x}\r\n",
                    el.TrustStatus.dwErrorStatus
                ));
            }
        }

        Ok(out)
    }
}

fn explain_error_status(dw: u32) -> String {
    let mut parts = Vec::new();
    if dw & CERT_TRUST_IS_NOT_TIME_VALID != 0 {
        parts.push("CERT_TRUST_IS_NOT_TIME_VALID");
    }
    if dw & CERT_TRUST_IS_REVOKED != 0 {
        parts.push("CERT_TRUST_IS_REVOKED");
    }
    if dw & CERT_TRUST_IS_UNTRUSTED_ROOT != 0 {
        parts.push("CERT_TRUST_IS_UNTRUSTED_ROOT");
    }
    if dw & CERT_TRUST_IS_PARTIAL_CHAIN != 0 {
        parts.push("CERT_TRUST_IS_PARTIAL_CHAIN");
    }
    if dw & CERT_TRUST_REVOCATION_STATUS_UNKNOWN != 0 {
        parts.push("CERT_TRUST_REVOCATION_STATUS_UNKNOWN");
    }
    if parts.is_empty() {
        "  (no common error bits matched)\r\n".to_string()
    } else {
        format!("  Flags: {}\r\n", parts.join(", "))
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

struct FreeChainContext(*const CERT_CHAIN_CONTEXT);

impl Drop for FreeChainContext {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateChain(self.0);
        }
    }
}
