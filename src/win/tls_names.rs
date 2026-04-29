//! Human-readable labels for Schannel [`SecPkgContext_ConnectionInfo`] fields.
//!
//! Raw numeric values are still printed by callers for script compatibility.
//!
//! # References
//! - [`SecPkgContext_ConnectionInfo`](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
//! - `SP_PROT_*` — Windows SDK `schannel.h`
//! - [`ALG_ID`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id) (`CALG_*`)

// SP_PROT_TLS1_x CLIENT | SERVER — schannel.h
const SP_PROT_TLS1_3_CLIENT: u32 = 0x0000_2000;
const SP_PROT_TLS1_3_SERVER: u32 = 0x0000_1000;
const SP_PROT_TLS1_2_CLIENT: u32 = 0x0000_0800;
const SP_PROT_TLS1_2_SERVER: u32 = 0x0000_0400;
const SP_PROT_TLS1_1_CLIENT: u32 = 0x0000_0200;
const SP_PROT_TLS1_1_SERVER: u32 = 0x0000_0100;
const SP_PROT_TLS1_0_CLIENT: u32 = 0x0000_0080;
const SP_PROT_TLS1_0_SERVER: u32 = 0x0000_0040;
const SP_PROT_SSL3_CLIENT: u32 = 0x0000_0020;
const SP_PROT_SSL3_SERVER: u32 = 0x0000_0010;

/// Highest negotiated TLS/SSL protocol implied by `dwProtocol` (bitflags).
pub fn describe_dw_protocol(dw_protocol: u32) -> &'static str {
    if dw_protocol & (SP_PROT_TLS1_3_CLIENT | SP_PROT_TLS1_3_SERVER) != 0 {
        return "TLS 1.3";
    }
    if dw_protocol & (SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER) != 0 {
        return "TLS 1.2";
    }
    if dw_protocol & (SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_1_SERVER) != 0 {
        return "TLS 1.1";
    }
    if dw_protocol & (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_0_SERVER) != 0 {
        return "TLS 1.0";
    }
    if dw_protocol & (SP_PROT_SSL3_CLIENT | SP_PROT_SSL3_SERVER) != 0 {
        return "SSL 3.0";
    }
    if dw_protocol == 0 {
        return "(none)";
    }
    "(unknown protocol bits — see raw dwProtocol)"
}

// CALG_* — winCrypt.h / windows-rs `ALG_ID`
const CALG_AES_128: u32 = 26_126;
const CALG_AES_192: u32 = 26_127;
const CALG_AES_256: u32 = 26_128;
const CALG_AES: u32 = 26_129;
const CALG_RC4: u32 = 26_625;
const CALG_RC2: u32 = 26_114;
const CALG_3DES: u32 = 26_115;
const CALG_DES: u32 = 26_113;
const CALG_NULLCIPHER: u32 = 24_576;

/// Bulk cipher / MAC identifier from `aiCipher` (connection cipher suite component).
pub fn describe_ai_cipher(ai_cipher: u32) -> &'static str {
    match ai_cipher {
        CALG_AES_256 => "AES-256 (CALG_AES_256)",
        CALG_AES_192 => "AES-192 (CALG_AES_192)",
        CALG_AES_128 => "AES-128 (CALG_AES_128)",
        CALG_AES => "AES (CALG_AES)",
        CALG_RC4 => "RC4 (CALG_RC4)",
        CALG_RC2 => "RC2 (CALG_RC2)",
        CALG_3DES => "3DES (CALG_3DES)",
        CALG_DES => "DES (CALG_DES)",
        CALG_NULLCIPHER => "NULL (CALG_NULLCIPHER)",
        0 => "(zero)",
        _ => "(see raw ALG_ID — not in built-in table)",
    }
}
