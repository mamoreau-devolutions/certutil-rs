//! OCSP response DER summary using [`der-parser`] (RFC 6960 `responseStatus`).

use der_parser::ber::BerObjectContent;
use der_parser::parse_der;

fn ocsp_status_name(n: u64) -> &'static str {
    match n {
        0 => "successful (0)",
        1 => "malformedRequest (1)",
        2 => "internalError (2)",
        3 => "tryLater (3)",
        5 => "sigRequired (5)",
        6 => "unauthorized (6)",
        _ => "unknown",
    }
}

/// Summarize OCSP `responseStatus` (ENUMERATED). When successful, lists nested Basic OCSP octets presence.
pub fn summarize_ocsp_der(der: &[u8]) -> String {
    let (_, obj) = match parse_der(der) {
        Ok(x) => x,
        Err(e) => return format!("OCSP parse error: {e}\r\n"),
    };
    let seq = match &obj.content {
        BerObjectContent::Sequence(seq) => seq,
        _ => return "OCSP: outer object is not SEQUENCE\r\n".into(),
    };

    let mut out = String::from("OCSP response (ASN.1):\r\n");
    match seq.first().map(|o| &o.content) {
        Some(BerObjectContent::Enum(n)) => {
            out.push_str(&format!("  responseStatus: {}\r\n", ocsp_status_name(*n)));
            if *n == 0 && seq.len() > 1 {
                out.push_str("  responseBytes: present\r\n");
            }
        }
        Some(_) => out.push_str("  responseStatus: (unexpected type)\r\n"),
        None => out.push_str("  responseStatus: (empty)\r\n"),
    }
    out
}
