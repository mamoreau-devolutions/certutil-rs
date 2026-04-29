//! Chain building + policy check (`CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`).

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use windows::core::{Error as WinError, PCSTR};
use windows::Win32::Foundation::BOOL;
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateContext,
    CertGetCertificateChain, CertVerifyCertificateChainPolicy, CertVerifyRevocation,
    CERT_CHAIN_CONTEXT, CERT_CHAIN_ELEMENT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_AUTHENTICODE,
    CERT_CHAIN_POLICY_AUTHENTICODE_TS, CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
    CERT_CHAIN_POLICY_FLAGS, CERT_CHAIN_POLICY_NT_AUTH, CERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_SSL, CERT_CHAIN_POLICY_STATUS, CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,
    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, CERT_CONTEXT, CERT_CONTEXT_REVOCATION_TYPE,
    CERT_REVOCATION_PARA, CERT_REVOCATION_STATUS, CERT_SIMPLE_CHAIN,
};

use super::encoding::CERT_ENCODING;
use super::names::cert_simple_display_name;
use super::url::{format_retrieval_probes_for_chain, DEFAULT_URL_TIMEOUT_MS};
use super::cert_extensions::{
    basic_constraints_block, certificate_policies_block, enhanced_key_usage_block, key_usage_block,
    public_key_summary_line,
};
use super::verify_format::{
    authority_info_access_block, cdp_distribution_points_block, cert_rdn_comma,
    describe_chain_build_flags, explain_cert_trust_error_status, explain_cert_trust_info_status,
    filetime_local_string, format_revocation_freshness, name_hash_sha1_lines, ocsp_ssl_trust_notes,
    revocation_info_lines, serial_hex, sha1_thumbprint_lower_hex, subject_alt_name_block,
};

/// Options aligned with `certutil.exe -verify` modifiers **`urlfetch`** and **`-t`** (URL retrieval timeout).
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    /// Corresponds to **`certutil -verify -urlfetch`** (retrieve AIA certs / CDP CRLs during chain build).
    pub urlfetch: bool,
    /// **`certutil -t`** — URL retrieval timeout in milliseconds (`CERT_CHAIN_PARA::dwUrlRetrievalTimeout`).
    pub timeout_ms: Option<u32>,
    /// Optional DNS name for **`CERT_CHAIN_POLICY_SSL`** (HTTPS-style hostname policy; certutil-rs extension).
    pub ssl_dns_name: Option<String>,
    /// Live **CryptRetrieveObjectByUrl** probes for each AIA/CDP URL in the built chain (network I/O).
    pub probe_urls: bool,
    /// Call **CertVerifyRevocation** for each chain element with its parent issuer (network / cache I/O).
    pub probe_revocation: bool,
    /// Optional DNS name for **SSL client** profile (`AUTHTYPE_CLIENT` + `CERT_CHAIN_POLICY_SSL`).
    pub ssl_client_dns_name: Option<String>,
    /// Extra pass: **Authenticode** chain policy.
    pub policy_authenticode: bool,
    /// Extra pass: **Authenticode timestamping** chain policy.
    pub policy_authenticode_ts: bool,
    /// Extra pass: **basic constraints** chain policy (`CERT_CHAIN_POLICY_BASIC_CONSTRAINTS`).
    pub policy_basic_constraints: bool,
    /// Extra pass: **Windows NT authentication** / DC-style (`CERT_CHAIN_POLICY_NT_AUTH`).
    pub policy_nt_auth: bool,
}

/// [`HTTPSPolicyCallbackData`](https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-httpspolicycallbackdata) — server TLS validation (`AUTHTYPE_SERVER` = 2).
#[repr(C)]
struct HttpsPolicyCallbackData {
    cb_struct: u32,
    dw_auth_type: u32,
    fdw_checks: u32,
    pwsz_server_name: windows::core::PWSTR,
}

const AUTHTYPE_CLIENT: u32 = 1;
const AUTHTYPE_SERVER: u32 = 2;

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
            None if opts.urlfetch || opts.probe_urls || opts.probe_revocation => {
                DEFAULT_URL_TIMEOUT_MS
            }
            None => 0,
        };

        let probe_timeout_ms = opts.timeout_ms.unwrap_or(DEFAULT_URL_TIMEOUT_MS);

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

        append_leaf_certificate_section(&mut out, leaf)?;

        out.push_str("Verify options:\r\n");
        out.push_str(&format!(
            "  urlfetch: {}, URL retrieval timeout (ms): {}, ssl-dns-name: {:?}\r\n",
            opts.urlfetch, url_timeout, opts.ssl_dns_name
        ));
        out.push_str(&format!(
            "  probe-urls: {}, probe-revocation: {}, probe/chain timeout uses -t or default {} ms\r\n",
            opts.probe_urls, opts.probe_revocation, probe_timeout_ms
        ));
        out.push_str(&format!(
            "  ssl-client-dns-name: {:?}, policy-authenticode: {}, policy-authenticode-ts: {}\r\n",
            opts.ssl_client_dns_name,
            opts.policy_authenticode,
            opts.policy_authenticode_ts
        ));
        out.push_str(&format!(
            "  policy-basic-constraints: {}, policy-nt-auth: {}\r\n\r\n",
            opts.policy_basic_constraints, opts.policy_nt_auth
        ));

        out.push_str("CertGetCertificateChain flags:\r\n");
        out.push_str(&format!(
            "  {}\r\n\r\n",
            describe_chain_build_flags(chain_flags)
        ));

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

        out.push_str("CERT_CHAIN_POLICY_BASE:\r\n");
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
        out.push_str("\r\n");

        out.push_str("-------- CERT_CHAIN_CONTEXT --------\r\n\r\n");

        out.push_str("ChainContext TrustStatus:\r\n");
        out.push_str(&format_status_lines(
            chain.TrustStatus.dwErrorStatus,
            chain.TrustStatus.dwInfoStatus,
        ));
        out.push_str(&explain_cert_trust_error_status(
            chain.TrustStatus.dwErrorStatus,
        ));
        out.push_str(&explain_cert_trust_info_status(
            chain.TrustStatus.dwInfoStatus,
        ));

        if chain.fHasRevocationFreshnessTime.as_bool() {
            out.push_str(&format!(
                "ChainContext.dwRevocationFreshnessTime: {} seconds — {}\r\n\r\n",
                chain.dwRevocationFreshnessTime,
                format_revocation_freshness(chain.dwRevocationFreshnessTime)
            ));
        } else {
            out.push_str("\r\n");
        }

        if chain.cChain > 0 && !chain.rgpChain.is_null() {
            let simple: &CERT_SIMPLE_CHAIN = &**chain.rgpChain;
            out.push_str("SimpleChain TrustStatus:\r\n");
            out.push_str(&format_status_lines(
                simple.TrustStatus.dwErrorStatus,
                simple.TrustStatus.dwInfoStatus,
            ));
            out.push_str(&explain_cert_trust_error_status(
                simple.TrustStatus.dwErrorStatus,
            ));
            out.push_str(&explain_cert_trust_info_status(
                simple.TrustStatus.dwInfoStatus,
            ));

            if simple.fHasRevocationFreshnessTime.as_bool() {
                out.push_str(&format!(
                    "SimpleChain.dwRevocationFreshnessTime: {} seconds — {}\r\n\r\n",
                    simple.dwRevocationFreshnessTime,
                    format_revocation_freshness(simple.dwRevocationFreshnessTime)
                ));
            } else {
                out.push_str("\r\n");
            }

            for i in 0..simple.cElement {
                let el_ptr = *simple.rgpElement.add(i as usize);
                if el_ptr.is_null() {
                    continue;
                }
                let el = &*el_ptr;
                append_chain_element_section(&mut out, 0, i, el)?;
            }
        }

        if let Some(ref ssl_name) = opts.ssl_dns_name {
            let mut wide: Vec<u16> = OsStr::new(ssl_name.as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut https = HttpsPolicyCallbackData {
                cb_struct: std::mem::size_of::<HttpsPolicyCallbackData>() as u32,
                dw_auth_type: AUTHTYPE_SERVER,
                fdw_checks: 0,
                pwsz_server_name: windows::core::PWSTR(wide.as_mut_ptr()),
            };
            let policy_ssl_para = CERT_CHAIN_POLICY_PARA {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                dwFlags: CERT_CHAIN_POLICY_FLAGS(0),
                pvExtraPolicyPara: (&mut https as *mut HttpsPolicyCallbackData).cast(),
            };

            let mut policy_status_ssl = CERT_CHAIN_POLICY_STATUS {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                ..Default::default()
            };

            let policy_ssl_ok: BOOL = CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL,
                p_chain,
                &policy_ssl_para,
                &mut policy_status_ssl,
            );

            out.push_str("\r\nCERT_CHAIN_POLICY_SSL:\r\n");
            out.push_str(&format!("  Expected DNS name: {ssl_name}\r\n"));
            if !policy_ssl_ok.as_bool() {
                let e = WinError::from_win32();
                out.push_str(&format!(
                    "  CertVerifyCertificateChainPolicy (SSL) failed: {e}\r\n"
                ));
            } else {
                out.push_str(&format!(
                    "  Policy dwError: 0x{:08x} (0 = success)\r\n",
                    policy_status_ssl.dwError
                ));
                if policy_status_ssl.dwError != 0 {
                    out.push_str(&format!(
                        "  Chain index: {}, Element index: {}\r\n",
                        policy_status_ssl.lChainIndex, policy_status_ssl.lElementIndex
                    ));
                }
            }
        }

        if let Some(ref ssl_client) = opts.ssl_client_dns_name {
            let mut wide: Vec<u16> = OsStr::new(ssl_client.as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut https = HttpsPolicyCallbackData {
                cb_struct: std::mem::size_of::<HttpsPolicyCallbackData>() as u32,
                dw_auth_type: AUTHTYPE_CLIENT,
                fdw_checks: 0,
                pwsz_server_name: windows::core::PWSTR(wide.as_mut_ptr()),
            };
            let policy_ssl_para = CERT_CHAIN_POLICY_PARA {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                dwFlags: CERT_CHAIN_POLICY_FLAGS(0),
                pvExtraPolicyPara: (&mut https as *mut HttpsPolicyCallbackData).cast(),
            };

            let mut policy_status_ssl = CERT_CHAIN_POLICY_STATUS {
                cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                ..Default::default()
            };

            let policy_ssl_ok: BOOL = CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL,
                p_chain,
                &policy_ssl_para,
                &mut policy_status_ssl,
            );

            out.push_str("\r\nCERT_CHAIN_POLICY_SSL (client profile):\r\n");
            out.push_str(&format!("  Expected DNS name: {ssl_client}\r\n"));
            if !policy_ssl_ok.as_bool() {
                let e = WinError::from_win32();
                out.push_str(&format!(
                    "  CertVerifyCertificateChainPolicy (SSL client) failed: {e}\r\n"
                ));
            } else {
                out.push_str(&format!(
                    "  Policy dwError: 0x{:08x} (0 = success)\r\n",
                    policy_status_ssl.dwError
                ));
            }
        }

        run_optional_chain_policy(
            &mut out,
            opts.policy_authenticode,
            CERT_CHAIN_POLICY_AUTHENTICODE,
            "CERT_CHAIN_POLICY_AUTHENTICODE",
            p_chain,
        )?;
        run_optional_chain_policy(
            &mut out,
            opts.policy_authenticode_ts,
            CERT_CHAIN_POLICY_AUTHENTICODE_TS,
            "CERT_CHAIN_POLICY_AUTHENTICODE_TS",
            p_chain,
        )?;
        run_optional_chain_policy(
            &mut out,
            opts.policy_basic_constraints,
            CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
            "CERT_CHAIN_POLICY_BASIC_CONSTRAINTS",
            p_chain,
        )?;
        run_optional_chain_policy(
            &mut out,
            opts.policy_nt_auth,
            CERT_CHAIN_POLICY_NT_AUTH,
            "CERT_CHAIN_POLICY_NT_AUTH",
            p_chain,
        )?;

        if opts.probe_urls {
            out.push_str("\r\nRetrieval probes (CryptRetrieveObjectByUrl):\r\n");
            let probe_txt = format_retrieval_probes_for_chain(chain, probe_timeout_ms);
            out.push_str(&probe_txt);
        }

        if opts.probe_revocation {
            append_cert_verify_revocation_section(&mut out, chain)?;
        }

        out.push_str("\r\ncertutil-rs: -verify command completed successfully.\r\n");
        Ok(out)
    }
}

unsafe fn run_optional_chain_policy(
    out: &mut String,
    enabled: bool,
    policy_oid: PCSTR,
    title: &str,
    p_chain: *const CERT_CHAIN_CONTEXT,
) -> Result<()> {
    if !enabled {
        return Ok(());
    }
    let policy_para = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        ..Default::default()
    };
    let mut policy_status = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    let ok: BOOL = CertVerifyCertificateChainPolicy(
        policy_oid,
        p_chain,
        &policy_para,
        &mut policy_status,
    );
    out.push_str(&format!("\r\n{title}:\r\n"));
    if !ok.as_bool() {
        let e = WinError::from_win32();
        out.push_str(&format!(
            "  CertVerifyCertificateChainPolicy failed: {e}\r\n"
        ));
    } else {
        out.push_str(&format!(
            "  Policy dwError: 0x{:08x} (0 = success)\r\n",
            policy_status.dwError
        ));
    }
    Ok(())
}

fn append_cert_verify_revocation_section(
    out: &mut String,
    chain: &CERT_CHAIN_CONTEXT,
) -> Result<()> {
    out.push_str("\r\nRevocation probe (CertVerifyRevocation):\r\n");
    unsafe {
        if chain.cChain == 0 || chain.rgpChain.is_null() {
            out.push_str("  (no simple chain)\r\n");
            return Ok(());
        }
        let simple: &CERT_SIMPLE_CHAIN = &**chain.rgpChain;
        if simple.cElement < 2 {
            out.push_str("  (skipped — need at least two elements: leaf + issuer)\r\n");
            return Ok(());
        }
        for i in 0..simple.cElement.saturating_sub(1) {
            let el = *simple.rgpElement.add(i as usize);
            if el.is_null() {
                continue;
            }
            let iss_el = *simple.rgpElement.add((i + 1) as usize);
            if iss_el.is_null() {
                continue;
            }
            let cert = (*el).pCertContext;
            let issuer = (*iss_el).pCertContext;
            if cert.is_null() || issuer.is_null() {
                continue;
            }

            let mut para = CERT_REVOCATION_PARA::default();
            para.cbSize = std::mem::size_of::<CERT_REVOCATION_PARA>() as u32;
            para.pIssuerCert = issuer;

            let mut status = CERT_REVOCATION_STATUS::default();
            status.cbSize = std::mem::size_of::<CERT_REVOCATION_STATUS>() as u32;

            let ctx_slice = [cert.cast::<c_void>()];
            out.push_str(&format!("  Chain element [{i}] with issuer [{i}+1]:\r\n"));
            let rev_ok = CertVerifyRevocation(
                CERT_ENCODING.0,
                CERT_CONTEXT_REVOCATION_TYPE,
                &ctx_slice,
                0,
                Some(std::ptr::from_ref(&para)),
                &mut status,
            );
            if let Err(e) = rev_ok {
                out.push_str(&format!("    CertVerifyRevocation failed: {e}\r\n"));
                continue;
            }
            out.push_str(&format!(
                "    dwError={} (0x{:08x}), dwReason={:?}\r\n",
                status.dwError, status.dwError, status.dwReason
            ));
            if status.fHasFreshnessTime.as_bool() {
                out.push_str(&format!(
                    "    dwFreshnessTime: {} seconds\r\n",
                    status.dwFreshnessTime
                ));
            }
        }
    }
    Ok(())
}

fn format_status_lines(dw_err: u32, dw_info: u32) -> String {
    format!(
        "  dwErrorStatus={} (0x{:08x})\r\n  dwInfoStatus={} (0x{:08x})\r\n",
        dw_err, dw_err, dw_info, dw_info
    )
}

unsafe fn append_leaf_certificate_section(
    out: &mut String,
    leaf: *const CERT_CONTEXT,
) -> Result<()> {
    let issuer = cert_rdn_comma(leaf, true)
        .unwrap_or_else(|_| cert_simple_display_name(leaf, true).unwrap_or_else(|_| "?".into()));
    let subject = cert_rdn_comma(leaf, false)
        .unwrap_or_else(|_| cert_simple_display_name(leaf, false).unwrap_or_else(|_| "?".into()));
    let info = &*(*leaf).pCertInfo;
    let serial = serial_hex(&info.SerialNumber);
    let nb = filetime_local_string(&info.NotBefore).unwrap_or_else(|_| "?".into());
    let na = filetime_local_string(&info.NotAfter).unwrap_or_else(|_| "?".into());

    out.push_str("Leaf certificate:\r\n");
    out.push_str(&format!("  Issuer:\r\n    {issuer}\r\n"));
    out.push_str(&format!("  Subject:\r\n    {subject}\r\n"));
    if let Some(h) = name_hash_sha1_lines(info) {
        out.push_str(&h);
    }
    out.push_str(&format!("  Cert Serial Number: {serial}\r\n"));
    if let Some(line) = public_key_summary_line(leaf) {
        out.push_str(&line);
    }
    if let Some(ku) = key_usage_block(leaf) {
        out.push_str(&ku);
    }
    if let Some(bc) = basic_constraints_block(leaf) {
        out.push_str(&bc);
    }
    if let Some(eku) = enhanced_key_usage_block(leaf) {
        out.push_str(&eku);
    }
    if let Some(cp) = certificate_policies_block(leaf) {
        out.push_str(&cp);
    }
    if let Some(san) = subject_alt_name_block(leaf) {
        out.push_str(&san);
    }
    if let Some(aia) = authority_info_access_block(leaf) {
        out.push_str(&aia);
    }
    if let Some(cdp) = cdp_distribution_points_block(leaf) {
        out.push_str(&cdp);
    }
    out.push_str(&format!("  NotBefore: {nb}\r\n"));
    out.push_str(&format!("  NotAfter: {na}\r\n\r\n"));
    Ok(())
}

unsafe fn append_chain_element_section(
    out: &mut String,
    chain_idx: u32,
    elem_idx: u32,
    el: &CERT_CHAIN_ELEMENT,
) -> Result<()> {
    if el.pCertContext.is_null() {
        return Ok(());
    }
    let ctx = el.pCertContext;

    out.push_str(&format!(
        "CertContext[{chain_idx}][{elem_idx}] TrustStatus:\r\n"
    ));
    out.push_str(&format_status_lines(
        el.TrustStatus.dwErrorStatus,
        el.TrustStatus.dwInfoStatus,
    ));
    out.push_str(&explain_cert_trust_error_status(
        el.TrustStatus.dwErrorStatus,
    ));
    out.push_str(&explain_cert_trust_info_status(el.TrustStatus.dwInfoStatus));
    if let Some(note) = ocsp_ssl_trust_notes(el.TrustStatus.dwInfoStatus) {
        out.push_str(&note);
    }

    let issuer = cert_rdn_comma(ctx, true)
        .unwrap_or_else(|_| cert_simple_display_name(ctx, true).unwrap_or_else(|_| "?".into()));
    let subject = cert_rdn_comma(ctx, false)
        .unwrap_or_else(|_| cert_simple_display_name(ctx, false).unwrap_or_else(|_| "?".into()));
    let info = &*(*ctx).pCertInfo;
    let serial = serial_hex(&info.SerialNumber);
    let nb = filetime_local_string(&info.NotBefore).unwrap_or_else(|_| "?".into());
    let na = filetime_local_string(&info.NotAfter).unwrap_or_else(|_| "?".into());
    let thumb = sha1_thumbprint_lower_hex(ctx).unwrap_or_else(|_| "?".into());

    out.push_str(&format!("  Issuer:\r\n    {issuer}\r\n"));
    out.push_str(&format!("  NotBefore: {nb}\r\n"));
    out.push_str(&format!("  NotAfter: {na}\r\n"));
    out.push_str(&format!("  Subject:\r\n    {subject}\r\n"));
    if let Some(h) = name_hash_sha1_lines(info) {
        out.push_str(&h);
    }
    out.push_str(&format!("  Cert Serial Number: {serial}\r\n"));
    if let Some(san) = subject_alt_name_block(ctx) {
        out.push_str(&san);
    }
    if let Some(aia) = authority_info_access_block(ctx) {
        out.push_str(&aia);
    }
    if let Some(cdp) = cdp_distribution_points_block(ctx) {
        out.push_str(&cdp);
    }
    out.push_str(&format!("  Cert (sha1): {thumb}\r\n"));
    if let Some(rev) = revocation_info_lines(el) {
        out.push_str(&rev);
    }
    out.push_str(&format!(
        "Element.dwInfoStatus={} (0x{:08x})\r\n\r\n",
        el.TrustStatus.dwInfoStatus, el.TrustStatus.dwInfoStatus
    ));
    Ok(())
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
