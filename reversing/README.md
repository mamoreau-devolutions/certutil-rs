# Reversing artifacts (local only)

Do **not** commit Microsoft PE files; they stay on your machine and are listed in [`.gitignore`](../.gitignore).

## Provenance

- **`certutil.exe`** — copied from `%SystemRoot%\System32\certutil.exe`.
- **`certcli.dll`** — copied from `%SystemRoot%\System32\certcli.dll` (import dependency; most verb logic is expected here).

On the machine used to seed this repo, `certutil.exe` reported **FileVersion 10.0.26100.8115**. Re-pin when you change reference machines.

## Import table (`certutil.exe`) — from PE

`advapi32.dll`, `kernel32.dll`, `msvcrt.dll`, **`certcli.dll`**, `crypt32.dll`, `cabinet.dll`, `comctl32.dll`, `cryptui.dll`, `gdi32.dll`, `ncrypt.dll`, `netapi32.dll`, `normaliz.dll`, `ntdll.dll`, `ntdsapi.dll`, `setupapi.dll`, `shell32.dll`, `version.dll`, `wldap32.dll`, `ole32.dll`, `oleaut32.dll`, `rpcrt4.dll`, `secur32.dll`, `user32.dll`, `shlwapi.dll`, `cryptsp.dll`, `api-ms-win-security-lsapolicy-l1-1-0.dll`

Regenerate (Python + pefile):

```powershell
py -3 -m pip install pefile
py -3 -c "import pefile; pe=pefile.PE('certutil.exe'); print([e.dll.decode() for e in pe.DIRECTORY_ENTRY_IMPORT])"
```

## IDA

Open `certutil.exe` (and/or `certcli.dll`) with IDA; use the **user-ida** MCP `open_idb` with this path. See [`docs/ida-api-map.md`](../docs/ida-api-map.md) for the living API/verb map.
