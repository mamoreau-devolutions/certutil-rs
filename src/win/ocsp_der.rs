//! OCSP response DER summary using [`der-parser`] (RFC 6960).

use der_parser::ber::{BerObject, BerObjectContent, Class};
use der_parser::parse_der;

const MAX_SINGLE_RESPONSES: usize = 32;

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

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn crl_reason_name(n: u64) -> &'static str {
    match n {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unknown",
    }
}

fn algorithm_identifier_oid(o: &BerObject<'_>) -> Option<String> {
    match &o.content {
        BerObjectContent::Sequence(s) => match s.first().map(|x| &x.content) {
            Some(BerObjectContent::OID(oid)) => Some(oid.to_id_string()),
            _ => None,
        },
        _ => None,
    }
}

fn looks_like_cert_id(parts: &[BerObject<'_>]) -> bool {
    parts.len() >= 4
        && algorithm_identifier_oid(&parts[0]).is_some()
        && matches!(parts[1].content, BerObjectContent::OctetString(_))
        && matches!(parts[2].content, BerObjectContent::OctetString(_))
        && matches!(parts[3].content, BerObjectContent::Integer(_))
}

fn octet_string_hex(o: &BerObject<'_>) -> Option<String> {
    match &o.content {
        BerObjectContent::OctetString(b) => Some(hex_lower(b)),
        _ => None,
    }
}

fn integer_hex(o: &BerObject<'_>) -> Option<String> {
    match &o.content {
        BerObjectContent::Integer(b) => Some(hex_lower(b)),
        _ => None,
    }
}

fn generalized_time_str(o: &BerObject<'_>) -> Option<String> {
    match &o.content {
        BerObjectContent::GeneralizedTime(gt) => Some(format!("{gt}")),
        _ => None,
    }
}

fn crl_reason_from_optional(o: &BerObject<'_>) -> Option<u64> {
    match &o.content {
        BerObjectContent::Tagged(cls, tag, inner)
            if *cls == Class::ContextSpecific && tag.0 == 0 =>
        {
            match &inner.content {
                BerObjectContent::Enum(n) => Some(*n),
                _ => None,
            }
        }
        _ => None,
    }
}

fn describe_revoked(info: &BerObject<'_>) -> String {
    let seq = match &info.content {
        BerObjectContent::Sequence(s) => s,
        _ => return "revoked (invalid RevokedInfo)".into(),
    };
    let rt = seq
        .first()
        .and_then(generalized_time_str)
        .unwrap_or_else(|| "?".into());
    let mut s = format!("revoked; revocationTime: {rt}");
    if let Some(extra) = seq.get(1) {
        if let Some(code) = crl_reason_from_optional(extra) {
            s.push_str(&format!(
                "; reason: {} ({})",
                crl_reason_name(code),
                code
            ));
        } else if let BerObjectContent::Enum(n) = &extra.content {
            s.push_str(&format!(
                "; reason: {} ({n})",
                crl_reason_name(*n)
            ));
        }
    }
    s
}

fn describe_cert_status(cs: &BerObject<'_>) -> String {
    match &cs.content {
        BerObjectContent::Tagged(cls, tag, inner) if *cls == Class::ContextSpecific => {
            match tag.0 {
                0 if matches!(inner.content, BerObjectContent::Null) => "good".into(),
                1 => describe_revoked(inner.as_ref()),
                2 => "unknown".into(),
                _ => format!("unexpected tag {}", tag.0),
            }
        }
        _ => "(unexpected certStatus encoding)".into(),
    }
}

fn next_update_str(o: &BerObject<'_>) -> Option<String> {
    match &o.content {
        BerObjectContent::Tagged(cls, tag, inner) if *cls == Class::ContextSpecific && tag.0 == 0 => {
            generalized_time_str(inner.as_ref())
        }
        BerObjectContent::GeneralizedTime(gt) => Some(format!("{gt}")),
        _ => None,
    }
}

fn emit_single_response(idx: usize, sr: &BerObject<'_>, out: &mut String) {
    let seq = match &sr.content {
        BerObjectContent::Sequence(s) => s,
        _ => return,
    };
    if seq.len() < 3 {
        return;
    }
    let cert_id = match &seq[0].content {
        BerObjectContent::Sequence(parts) if looks_like_cert_id(parts) => parts,
        _ => return,
    };

    let hash_alg = algorithm_identifier_oid(&cert_id[0]).unwrap_or_else(|| "?".into());
    let issuer_name_hash = octet_string_hex(&cert_id[1]).unwrap_or_else(|| "?".into());
    let issuer_key_hash = octet_string_hex(&cert_id[2]).unwrap_or_else(|| "?".into());
    let serial = integer_hex(&cert_id[3]).unwrap_or_else(|| "?".into());

    out.push_str(&format!("  SingleResponse[{idx}]:\r\n"));
    out.push_str(&format!("    certID.hashAlgorithm: {hash_alg}\r\n"));
    out.push_str(&format!("    certID.issuerNameHash: {issuer_name_hash}\r\n"));
    out.push_str(&format!("    certID.issuerKeyHash: {issuer_key_hash}\r\n"));
    out.push_str(&format!("    certID.serialNumber: {serial}\r\n"));

    let status_line = describe_cert_status(&seq[1]);
    out.push_str(&format!("    certStatus: {status_line}\r\n"));

    if let Some(tu) = generalized_time_str(&seq[2]) {
        out.push_str(&format!("    thisUpdate: {tu}\r\n"));
    }

    let mut idx_extra = 3;
    if idx_extra < seq.len() {
        if let Some(nu) = next_update_str(&seq[idx_extra]) {
            out.push_str(&format!("    nextUpdate: {nu}\r\n"));
            idx_extra += 1;
        }
    }
    let _ = idx_extra;
}

fn find_produced_at_and_responses<'a>(
    rd: &'a BerObject<'a>,
) -> (Option<String>, Option<&'a Vec<BerObject<'a>>>) {
    let children = match &rd.content {
        BerObjectContent::Sequence(c) => c,
        _ => return (None, None),
    };

    let mut produced: Option<String> = None;
    for c in children {
        if let BerObjectContent::GeneralizedTime(gt) = &c.content {
            if produced.is_none() {
                produced = Some(format!("{gt}"));
            }
        }
    }

    for c in children {
        if let BerObjectContent::Sequence(inner) = &c.content {
            if inner.is_empty() {
                continue;
            }
            if let BerObjectContent::Sequence(cid) = &inner[0].content {
                if looks_like_cert_id(cid.as_slice()) {
                    return (produced, Some(inner));
                }
            }
        }
    }
    (produced, None)
}

/// Summarize OCSP `responseStatus` and (when possible) `BasicOCSPResponse` / `ResponseData` (RFC 6960).
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

    let (_, basic) = match parse_der(inner) {
        Ok(x) => x,
        Err(_) => {
            out.push_str("  BasicOCSPResponse: (inner ASN.1 parse failed)\r\n");
            return out;
        }
    };

    let parts = match &basic.content {
        BerObjectContent::Sequence(parts) => parts,
        _ => {
            out.push_str("  BasicOCSPResponse: (not SEQUENCE)\r\n");
            return out;
        }
    };

    let tbs = match parts.first() {
        Some(o) => o,
        None => return out,
    };

    let (produced_at, responses_opt) = find_produced_at_and_responses(tbs);
    if let Some(pa) = produced_at {
        out.push_str(&format!("  producedAt: {pa}\r\n"));
    }

    let Some(list) = responses_opt else {
        out.push_str("  responses: (SEQUENCE OF SingleResponse not found)\r\n");
        return out;
    };

    let n = list.len().min(MAX_SINGLE_RESPONSES);
    out.push_str(&format!(
        "  responses: {} SingleResponse item(s){}\r\n",
        list.len(),
        if list.len() > MAX_SINGLE_RESPONSES {
            format!(" (showing first {MAX_SINGLE_RESPONSES})")
        } else {
            String::new()
        }
    ));

    for i in 0..n {
        emit_single_response(i, &list[i], &mut out);
    }

    out
}
