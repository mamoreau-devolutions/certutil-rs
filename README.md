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

## Usage

```text
certutil-rs -dump <INFILE>
certutil-rs -verify <CRTBLOB>
```

`-dump` accepts PEM (`-----BEGIN CERTIFICATE-----`) or DER.

`-verify` loads the encoded cert, calls **`CertGetCertificateChain`** (with revocation checking on the chain, excluding the root) and **`CertVerifyCertificateChainPolicy`** with **`CERT_CHAIN_POLICY_BASE`**, then prints trust status and chain elements. This is a diagnostic baseline, not a byte-for-byte match to every `certutil -verify` flag yet.

## Reversing artifacts

See [`reversing/README.md`](reversing/README.md): local copies of `certutil.exe` / `certcli.dll` for IDA (not committed).

## Docs

- [`docs/ida-api-map.md`](docs/ida-api-map.md) — verb ↔ Win32 API notes from reversing.

## License

MIT OR Apache-2.0 — **your choice**.
