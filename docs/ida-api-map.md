# IDA → Win32 API map

Fill this in while analyzing `reversing/certutil.exe` and `reversing/certcli.dll` with the **user-ida** MCP (`open_idb`, `imports`, `decompile`, xrefs).

## Native binary reference

- **certutil.exe** FileVersion: see `reversing/README.md` (pinned per machine).
- **Prioritized verbs (read-only diagnostics)**  
  `-dump`, `-verify`, URL/cache-related verbs used for CRL/CDP/OCSP troubleshooting.

## Import clusters (certutil.exe — initial PE parse)

See `reversing/README.md` for the full DLL list. Heavy lifters expected for our Rust clone:

- **`crypt32.dll`** — `CertCreateCertificateContext`, `CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`, `CertVerifyRevocation`, `CryptRetrieveObjectByUrl`, etc. (confirm names via IDA `imports`.)
- **`certcli.dll`** — Internal helpers behind many certutil verbs (trace xrefs from dispatcher).

## Verb → API notes

- **`-dump`** — Suspected: `CryptStringToBinaryW`, `CertCreateCertificateContext`, `CertGetNameStringW`, `CertGetCertificateContextProperty`. **Status:** prototype in [`src/win/dump.rs`](../src/win/dump.rs).
- **`-verify`** — Suspected: `CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`, revocation helpers. **Status:** first cut in [`src/win/verify.rs`](../src/win/verify.rs): builds with `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, runs **`CERT_CHAIN_POLICY_BASE`**, prints chain trust flags + elements (not yet matched flag-for-flag to native `certutil -verify`). Optional **`--ssl-dns-name`** runs **`CERT_CHAIN_POLICY_SSL`** with [`HTTPSPolicyCallbackData`](https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-httpspolicycallbackdata) (`AUTHTYPE_SERVER`) — certutil-rs extension, not stock `certutil -verify`.

- **`tls fetch`** — Not in **`certutil.exe`**. Implemented via **`native-tls`** (Schannel on Windows): TCP connect + TLS handshake, leaf cert from `peer_certificate()`, PEM/DER export in [`src/win/tls_fetch.rs`](../src/win/tls_fetch.rs). Used for workflows such as saving a leaf PEM then running **`certutil.exe -verify`** on that file.

(Add entries as you decompile the dispatcher and leaf functions.)

## Pseudocode hotspots

*(Paste IDA pseudocode addresses / function names here.)*
