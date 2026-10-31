#Requires -Version 5.1
<#
  guard-pause.ps1 -- temporarily disable alpha-guard for N minutes, then re-enable.

  Why not kill a process: alpha-guard is a DSH plugin that runs INSIDE the DSH
  process. There is no separate process to kill. Its real switch is the
  top-level "enabled" key in config.json.

  config.json contains several "enabled" keys (top level plus one per
  submodule). This script uses IndexOf to take the FIRST occurrence and
  additionally checks that it appears within the first 400 characters, so the
  submodule switches are never touched. If the position looks wrong it refuses
  to modify anything.

  Safety measures:
    1. backs up config.json to config.json.bak-before-pause-<timestamp>
    2. changes exactly one true -> false (file grows by 1 byte) and verifies
       the delta is exactly 1, rolling back otherwise
    3. the resume process is a detached hidden process, so closing the window
       does not cancel the re-enable
    4. if a previous run left the guard disabled, the next run restores first
    5. after the countdown it polls for the resume process to land, so a
       timing race cannot produce a false alarm
#>
param(
    [int]$Minutes = 2
)

$ErrorActionPreference = 'Stop'

# Everything is derived from the current user's home, so this works for any
# username and any install location.
$cfgDir = Join-Path (Join-Path $env:USERPROFILE '.dsh') 'alpha-guard'
$cfg    = Join-Path $cfgDir 'config.json'
$state  = Join-Path $cfgDir 'pause-state.json'
$resume = Join-Path $PSScriptRoot 'guard-resume.ps1'

$ENC = New-Object System.Text.UTF8Encoding $false
$TXT_ON  = '"enabled": true'
$TXT_OFF = '"enabled": false'

function Write-Ok   ($m) { Write-Host $m -ForegroundColor Green }
function Write-Warn ($m) { Write-Host $m -ForegroundColor Yellow }
function Write-Bad  ($m) { Write-Host $m -ForegroundColor Red }

if (-not (Test-Path $cfg))    { Write-Bad "Config not found: $cfg"; exit 1 }
if (-not (Test-Path $resume)) { Write-Bad "Resume script not found: $resume"; exit 1 }

$raw = [System.IO.File]::ReadAllText($cfg)

# ---- already disabled? ----
if ($raw.IndexOf($TXT_OFF) -ge 0) {
    if (Test-Path $state) {
        try {
            $s    = Get-Content $state -Raw -Encoding UTF8 | ConvertFrom-Json
            $left = [math]::Ceiling(([datetime]$s.until - (Get-Date)).TotalSeconds)
            if ($left -gt 0) {
                Write-Warn "The guard is already disabled; $left seconds left before auto-resume."
                Write-Warn 'Not re-running, to avoid pushing the resume time further out.'
                exit 0
            }
        } catch { }
    }
    Write-Warn 'Found a leftover disabled state (a previous run probably died). Restoring first...'
    $i0 = $raw.IndexOf($TXT_OFF)
    $raw = $raw.Substring(0, $i0) + $TXT_ON + $raw.Substring($i0 + $TXT_OFF.Length)
    [System.IO.File]::WriteAllText($cfg, $raw, $ENC)
    if (Test-Path $state) { Remove-Item $state -Force -ErrorAction SilentlyContinue }
    Write-Ok 'Restored.'
}

# ---- locate the top-level switch ----
$i = $raw.IndexOf($TXT_ON)
if ($i -lt 0) {
    Write-Bad 'No enabled:true entry found in config.json; the format may have changed.'
    Write-Bad 'Open config.json and check by hand. This script changed nothing.'
    exit 1
}
if ($i -gt 400) {
    Write-Bad "The first enabled key is at character $i, which is unexpected. Changed nothing."
    exit 1
}

# ---- backup ----
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bak   = Join-Path $cfgDir "config.json.bak-before-pause-$stamp"
[System.IO.File]::WriteAllText($bak, $raw, $ENC)

# ---- disable ----
$off = $raw.Substring(0, $i) + $TXT_OFF + $raw.Substring($i + $TXT_ON.Length)
[System.IO.File]::WriteAllText($cfg, $off, $ENC)

$delta = ([System.IO.File]::ReadAllText($cfg)).Length - $raw.Length
if ($delta -ne 1) {
    Write-Bad "Unexpected size change ($delta, expected 1). Rolling back now."
    [System.IO.File]::WriteAllText($cfg, $raw, $ENC)
    exit 1
}

$until = (Get-Date).AddMinutes($Minutes)
@{ started = (Get-Date).ToString('o'); until = $until.ToString('o'); backup = $bak; minutes = $Minutes } |
    ConvertTo-Json | Set-Content -Path $state -Encoding UTF8

# ---- start the detached resume process ----
$argList = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', ('"' + $resume + '"'),
    '-Until', ('"' + $until.ToString('o') + '"'),
    '-Config', ('"' + $cfg + '"'),
    '-State', ('"' + $state + '"')
)
Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -WindowStyle Hidden | Out-Null

# ---- report ----
Write-Host ''
Write-Ok '  alpha-guard is now temporarily disabled'
Write-Host "  Resumes at: $($until.ToString('HH:mm:ss')) ($Minutes minutes from now)"
Write-Host "  Backup:     config.json.bak-before-pause-$stamp"
Write-Host ''
Write-Warn '  While disabled, these checks are OFF:'
Write-Warn '    read whitelist, sensitive-path deny list, dangerous-command blocking,'
Write-Warn '    install approval, malware static audit.'
Write-Warn '  It re-enables automatically. You may close this window.'
Write-Host ''
Write-Host '  Countdown (Ctrl+C only stops the display; the resume process is unaffected):'
Write-Host ''

for ($n = $Minutes * 60; $n -gt 0; $n--) {
    $t = [TimeSpan]::FromSeconds($n)
    Write-Host ("`r  remaining " + $t.ToString('mm\:ss') + " ...") -NoNewline -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}
Write-Host ("`r  time is up, waiting for the resume process...        ") -ForegroundColor Green

# ---- poll for the restore (up to 15s, avoids a timing race) ----
$restored = $false
for ($w = 0; $w -lt 30; $w++) {
    Start-Sleep -Milliseconds 500
    $now = [System.IO.File]::ReadAllText($cfg)
    if ($now.IndexOf($TXT_OFF) -lt 0) { $restored = $true; break }
}

Write-Host ''
if ($restored) {
    Write-Ok "  Confirmed restored: enabled is true again (waited $([math]::Round($w * 0.5, 1))s)"
} else {
    Write-Bad '  Still disabled after 15s; the resume process may have been killed.'
    Write-Bad '  Fix: run this script again (it restores first), or set enabled back to true by hand.'
    $lg = Join-Path $cfgDir 'pause.log'
    if (Test-Path $lg) { Write-Host '  Last 3 lines of the resume log:'; Get-Content $lg -Tail 3 -Encoding UTF8 | ForEach-Object { "    $_" } }
}
Write-Host ''
Read-Host 'Press Enter to close'
