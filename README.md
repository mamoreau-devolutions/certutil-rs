# certutil-rs

Windows-only Rust tooling inspired by **`certutil.exe`**, focused on **read-only** certificate diagnostics (chains, CRL/CDP/OCSP-related troubleshooting). It deliberately **does not** implement commands that modify certificate stores or system state.

## Prerequisites

- Windows (MSVC toolchain).
- Rust stable.

## Build

```powershell
cargo build --release
```

## Tests

Default `cargo test` stays offline. To run the live **devolutions.net** check (TLS fetch + `CertGetCertificateChain` / policy validation):

```powershell
cargo test -- --ignored --nocapture devolutions_net_https_leaf_validates
```

**Parity with `certutil.exe -verify`** (prefetches the leaf via **`tls fetch`**, then runs both tools on the same `.cer`):

```powershell
cargo test --test parity_certutil_verify -- --ignored --nocapture
```

Requires **`certutil.exe`** on `PATH` (typically `%SystemRoot%\System32`).

## Usage

```text
certutil-rs -dump <INFILE>
certutil-rs -verify [--urlfetch] [-t MS] [--ssl-dns-name DNS] [--ssl-client-dns-name DNS]
    [--policy-authenticode] [--policy-authenticode-ts] [--policy-basic-constraints] [--policy-nt-auth]
    [--probe-urls] [--probe-revocation] <CRTBLOB>
certutil-rs -encode <INFILE> <OUTFILE> [--fmt hex|base64-pem|base64-raw] [--hex-spaced]
certutil-rs -decode <INFILE> <OUTFILE>
certutil-rs -hashfile <INFILE> <MD5|SHA1|SHA256|SHA384>
certutil-rs -store <STORE> [--location current-user|local-machine] [--filter SUBSTR]
certutil-rs -URL <InFile | URL> [-t MS]
certutil-rs tls fetch <HOST> -o <PATH> [--port PORT] [--server-name NAME] [--insecure] [--verbose] [--format pem|der]
```

`-dump` accepts PEM (`-----BEGIN CERTIFICATE-----`) or DER for certificates, CRLs, CSRs, and PKCS#7. Certificate dumps include **Key Usage**, **Basic Constraints**, **Enhanced Key Usage**, **Certificate Policies** (policy identifiers plus CPS / notice qualifiers when present), **SAN**, **AIA**, and **CDP** where decodable.

`-verify` loads the encoded cert, calls **`CertGetCertificateChain`** (with revocation checking on the chain, excluding the root) and **`CertVerifyCertificateChainPolicy`** with **`CERT_CHAIN_POLICY_BASE`**, then prints trust status and chain elements. Options **`--urlfetch`** and **`-t`** mirror `certutil` URL retrieval behavior for chain building. **`--ssl-dns-name`** runs **`CERT_CHAIN_POLICY_SSL`** (server profile); **`--ssl-client-dns-name`** runs the SSL policy with the **client** authentication type. Additional optional passes match extended `certutil`-style checks: **`--policy-authenticode`**, **`--policy-authenticode-ts`**, **`--policy-basic-constraints`**, **`--policy-nt-auth`**.

**`--probe-urls`** (optional) performs live **`CryptRetrieveObjectByUrl`** attempts for every AIA and CDP URL gathered from the built chain (HTTP(S), LDAP(S), FTP), with PKIX OCSP vs CA Issuers OID hints where appropriate, and prints Win32/CryptNet-style outcomes. For **AIA OCSP** URLs, successful raw-DER responses print **total byte length**, a **hex prefix** (first 32 octets), and an **RFC 6960-oriented ASN.1 summary** when parsing succeeds: **`responseStatus`**, **`producedAt`**, each **`SingleResponse`** with **`certID`** (hash algorithm, issuer name/key hashes, serial), **`certStatus`** (including **`revocationTime`** / **CRLReason** when revoked), and **`thisUpdate`** / **`nextUpdate`**. Raw DER that is neither a certificate nor a CRL is reported as **opaque DER** when OCSP parsing does not apply. **`--probe-revocation`** (optional) calls **`CertVerifyRevocation`** for each chain certificate paired with its parent issuer and prints **`CERT_REVOCATION_STATUS`**. Both flags use **`-t`** milliseconds when set; otherwise a default timeout applies (see the printed “Verify options” section). These probes issue **real outbound network traffic** (and may hit caches); use only in environments where that is acceptable.

`-URL` uses **`CryptRetrieveObjectByUrl`** for certificate/CRL retrieval diagnostics. When the target is a certificate file, URLs are taken from **AIA** (OCSP, CA issuers) and **CDP** extensions (not only AIA HTTP URLs).

### TLS fetch (certutil-rs extension)

Use **`tls fetch`** to perform a client TLS handshake and write the **peer leaf certificate** to disk (PEM or DER), without scripting OpenSSL or PowerShell first. Output format follows the file extension (`.pem`/`.crt` vs `.der`/`.cer`) unless **`--format`** is set. **`--server-name`** sets SNI and TLS hostname verification (defaults to the host part of **`HOST`**). **`--insecure`** disables certificate validation (diagnostics only). **`--verbose`** adds TCP endpoints, ALPN, session resumption, peer chain store size, and **Schannel** **`SecPkgContext_ConnectionInfo`**: raw **`dwProtocol`** / **`aiCipher`** plus short **human-readable** labels (TLS version from `SP_PROT_*`, cipher from common **`CALG_*`** bulk IDs), cipher strength in bits, and a link to Microsoft’s struct documentation.

Parity check with **`certutil.exe`** on the saved file:

```powershell
certutil-rs tls fetch example.com -o leaf.pem
certutil.exe -verify leaf.pem
```

For IPv6 or non-default ports, use bracket form or **`--port`** (see **`certutil-rs tls fetch --help`**).

### Other utilities

- **`-encode` / `-decode`**: hex (optional space-separated pairs), PEM-style base64, or raw base64 output for encode.
- **`-hashfile`**: **`MD5`**, **`SHA1`**, **`SHA256`**, or **`SHA384`** (aligned with common `certutil -hashfile` algorithms).
- **`-store`**: read-only listing for **`CertOpenStore`** system stores; **`--location`** selects **current user** vs **local machine** (`CERT_SYSTEM_STORE_CURRENT_USER` / `CERT_SYSTEM_STORE_LOCAL_MACHINE`). Columns include subject, issuer, serial, not-after, SHA-256 fingerprint, and EKU summary where available.

## Reversing artifacts

See [`reversing/README.md`](reversing/README.md): local copies of `certutil.exe` / `certcli.dll` for IDA (not committed).

## Docs

- [`docs/ida-api-map.md`](docs/ida-api-map.md) — verb ↔ Win32 API notes from reversing.

## License

MIT OR Apache-2.0 — **your choice**.
