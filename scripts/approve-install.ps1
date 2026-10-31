#Requires -Version 5.1
<#
  approve-install.ps1 -- owner-side release valve for the install gate.

  alpha-guard blocks package installs and downloads by default. When the owner
  actually wants to install something, they run this once: it writes a
  short-lived approval stamp. alpha-guard then allows ONE install within the
  next 2 minutes and consumes the stamp.

  The stamp is just a JSON file with a unix timestamp. It grants nothing on its
  own -- it is only honoured by alpha-guard running on this machine, and only
  once. There is no network call, no credential, and nothing is uploaded.

  Why a separate script: the model is not allowed to touch the approval
  mechanism (that would defeat the whole point). Only the owner, sitting at the
  keyboard, can run this.
#>
$dir = Join-Path (Join-Path $env:USERPROFILE '.dsh') 'alpha-guard'
if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$p = Join-Path $dir 'install-approval.json'
@{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); note = 'owner-approved-one-install' } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $p -Encoding UTF8
Write-Host 'OK: the next install is allowed for 2 minutes (single use).'
Write-Host ("Stamp written to: " + $p)
