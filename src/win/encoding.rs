//! Certificate encoding constants shared across CryptoAPI helpers.

use windows::Win32::Security::Cryptography::{
    CERT_QUERY_ENCODING_TYPE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

pub const CERT_ENCODING: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0);
