# Agent guidance — certutil-rs

This document tells automated coding agents how to work on **certutil-rs** without drifting from project intent.

## Mission

Build a **Windows-only** Rust tool that tracks **`certutil.exe`** behavior as closely as practical for **certificate validation diagnostics**: incomplete chains, revocation (CRL/OCSP/CDP), policy errors, and readable inspection of cert material. Prefer the **same Win32 CryptoAPI / certificate chain APIs** that `certutil.exe` uses internally (discovered via imports and reversing notes), exposed through the **`windows`** crate—not cross-platform crypto stacks for core validation logic.

The user goal is **support-style diagnosis** on customer machines (trust stores, revocation fetch failures, chain policy), with a binary they can **build from source** and extend.

## Platform

- **Target:** Windows only. Use **`windows-msvc`** and the **`windows`** / **`windows-core`** crates for FFI.
- Do **not** add Linux/macOS code paths, portable TLS stacks for chain verification, or `#[cfg(unix)]` shims in the core validation paths. Test helpers may use dev-dependencies (for example **`native-tls`** only to **fetch** a leaf cert in integration tests); **trust and policy evaluation** stay on **CryptoAPI/Schannel-related Win32 APIs**.

If a contributor needs non-Windows CI, keep it limited to **metadata /fmt / no-compile** checks—do not pretend to validate Windows trust off-platform.

## Behavioral alignment with certutil.exe

- Treat **`certutil.exe`** (and related binaries such as **`certcli.dll`**) as the reference. Prefer **golden comparisons** against native `certutil` on real `.cer` / PEM inputs when changing output or flags.
- Extend [`docs/ida-api-map.md`](docs/ida-api-map.md) when mapping new verbs or APIs so the Rust tool stays traceable to observed dispatcher and import surfaces.
- Parity is **aspirational and phased**: document gaps (“not yet matched to certutil flag X”) rather than silently diverging.

## Scope boundaries

- **In scope:** Read-only diagnostics—**`-dump`**, **`-verify`**, URL/cache-style flows used for **CRL/CDP/OCSP** troubleshooting, and read-only store **view/list** modes if they match certutil’s non-mutating behavior.
- **Out of scope unless explicitly requested:** Commands that **install/remove/repair** certs or stores, publish to AD, or otherwise **mutate** machine crypto state. Do not add hidden flags that write to stores.

## Code organization (current)

- **[`src/lib.rs`](src/lib.rs)** — Library surface (CLI also links here); keeps integration tests able to call **`win`** modules.
- **[`src/cli.rs`](src/cli.rs)** — Clap CLI; mirror certutil-style **`-verb`** names where possible.
- **[`src/win/`](src/win/)** — Thin **`unsafe` wrappers** around Win32 (e.g. chain, dump, encoding helpers). New behavior should land here or in small sibling modules, not in duplicated FFI blocks.

## Reversing artifacts

- Local copies of Microsoft binaries live under **`reversing/`** (ignored by git—see **`.gitignore`**). Do not commit **`certutil.exe`** / **`certcli.dll`**.
- Use **[`reversing/README.md`](reversing/README.md)** for provenance and PE import lists.

## Testing

- Default **`cargo test`** must remain usable **offline**; network-dependent tests stay **`#[ignore]`** with a clear reason string.
- Document how to run ignored tests in **[`README.md`](README.md)** when adding new live checks.

## Style and constraints

- Match existing naming, error handling (**`anyhow`**), and thin FFI layering.
- Avoid drive-by refactors unrelated to the task; keep diffs focused.
- Do not add unsolicited markdown files beyond what the user asked for; **`AGENTS.md`** is an exception as project agent policy.

## Summary for triage

- **Crypto/trust APIs:** Win32 **`crypt32`** and related chain APIs via the **`windows`** crate.
- **Cross-platform validation:** No; Windows only.
- **Reference:** **`certutil.exe`** / **`certcli.dll`**, plus **[`docs/ida-api-map.md`](docs/ida-api-map.md)**.
- **Mutating store commands:** Out of scope unless explicitly requested.

---

When unsure whether an API or flag belongs in scope, prefer **documenting the gap** and **matching certutil’s diagnostics story** over inventing new semantics.
