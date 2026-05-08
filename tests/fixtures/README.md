# Test fixtures

Do not commit customer or internal certificates. Add locally:

```powershell
New-Item -ItemType Directory -Force -Path tests/fixtures | Out-Null
Get-ChildItem cert:\LocalMachine\Root | Select-Object -First 1 | ForEach-Object {
  Export-Certificate -Cert $_ -FilePath tests/fixtures/smoke.cer -Force
}
```

Then compare:

```powershell
certutil -dump tests/fixtures/smoke.cer
cargo run -- -dump tests/fixtures/smoke.cer
```
