//! OCSP response DER summary using [`der-parser`] (RFC 6960).

use der_parser::ber::{BerObject, BerObjectContent, Class};
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

fn scan_cert_status(o: &BerObject<'_>, out: &mut String, found: &mut bool) {
    if *found {
        return;
    }
    match &o.content {
        BerObjectContent::Tagged(cls, tag_hdr, inner) if *cls == Class::ContextSpecific => {
            match tag_hdr.0 {
                0 if matches!(inner.content, BerObjectContent::Null) => {
                    out.push_str("  certStatus: good\r\n");
                    *found = true;
                }
                1 => {
                    out.push_str("  certStatus: revoked\r\n");
                    *found = true;
                }
                2 => {
                    out.push_str("  certStatus: unknown\r\n");
                    *found = true;
                }
                _ => {}
            }
        }
        BerObjectContent::Sequence(children) => {
            for c in children {
                scan_cert_status(c, out, found);
                if *found {
                    return;
                }
            }
        }
        BerObjectContent::Tagged(_, _, inner) => scan_cert_status(inner, out, found),
        _ => {}
    }
}

/// Summarize OCSP `responseStatus` and (when possible) `BasicOCSPResponse` fields.
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
    let status = match seq.first().map(|o| &o.content) {
        Some(BerObjectContent::Enum(n)) => *n,
        Some(_) => {
            out.push_str("  responseStatus: (unexpected type)\r\n");
            return out;
        }
        None => {
            out.push_str("  responseStatus: (empty)\r\n");
            return out;
        }
    };
    out.push_str(&format!("  responseStatus: {}\r\n", ocsp_status_name(status)));

    if status != 0 {
        return out;
    }
    if seq.len() < 2 {
        out.push_str("  responseBytes: (absent)\r\n");
        return out;
    }
    out.push_str("  responseBytes: present\r\n");

    let rb = match &seq[1].content {
        BerObjectContent::Sequence(s) if !s.is_empty() => &s[0],
        _ => {
            out.push_str("  (could not open responseBytes SEQUENCE)\r\n");
            return out;
        }
    };
    let rseq = match &rb.content {
        BerObjectContent::Sequence(s) => s,
        _ => {
            out.push_str("  (responseBytes not a SEQUENCE)\r\n");
            return out;
        }
    };
    if rseq.len() < 2 {
        out.push_str("  (responseBytes SEQUENCE too short)\r\n");
        return out;
    }
    if let BerObjectContent::OID(oid) = &rseq[0].content {
        out.push_str(&format!("  responseType OID: {}\r\n", oid.to_id_string()));
    }
    let inner = match &rseq[1].content {
        BerObjectContent::OctetString(b) => &b[..],
        _ => {
            out.push_str("  (no OCTET STRING inner response)\r\n");
            return out;
        }
    };
    out.push_str(&format!("  EncapsulatedResponse: {} byte(s)\r\n", inner.len()));

    if let Ok((_, basic)) = parse_der(inner) {
        if let BerObjectContent::Sequence(parts) = &basic.content {
            if let Some(tbs) = parts.first() {
                if let BerObjectContent::Sequence(tbs_seq) = &tbs.content {
                    for o in tbs_seq {
                        if let BerObjectContent::GeneralizedTime(gt) = &o.content {
                            out.push_str(&format!("  producedAt: {gt}\r\n"));
                            break;
                        }
                    }
                    let mut found = false;
                    for o in tbs_seq {
                        scan_cert_status(o, &mut out, &mut found);
                        if found {
                            break;
                        }
                    }
                }
            }
        }
    } else {
        out.push_str("  BasicOCSPResponse: (inner ASN.1 parse failed)\r\n");
    }
    out
}
