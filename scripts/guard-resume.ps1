#Requires -Version 5.1
<#
  guard-resume.ps1 -- launched by guard-pause.ps1. Sleeps until the target time
  and then re-enables alpha-guard. Runs detached and hidden, so closing the
  console window does not stop it.
#>
param(
    [Parameter(Mandatory)][string]$Until,
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$State
)

$ErrorActionPreference = 'Stop'

$ENC = New-Object System.Text.UTF8Encoding $false
$TXT_ON  = '"enabled": true'
$TXT_OFF = '"enabled": false'
$log     = Join-Path (Split-Path $Config -Parent) 'pause.log'

function Log($m) {
    $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + "  " + $m
    Add-Content -Path $log -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
}

try {
    $target = [datetime]::Parse($Until)
    $wait   = ($target - (Get-Date)).TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Seconds ([int][math]::Ceiling($wait)) }

    if (-not (Test-Path $Config)) { Log 'config.json missing, giving up'; exit 1 }

    $raw = [System.IO.File]::ReadAllText($Config)
    $i = $raw.IndexOf($TXT_OFF)
    if ($i -lt 0) {
        Log 'already enabled, nothing to do'
        if (Test-Path $State) { Remove-Item $State -Force -ErrorAction SilentlyContinue }
        exit 0
    }

    $on = $raw.Substring(0, $i) + $TXT_ON + $raw.Substring($i + $TXT_OFF.Length)
    [System.IO.File]::WriteAllText($Config, $on, $ENC)

    if (Test-Path $State) { Remove-Item $State -Force -ErrorAction SilentlyContinue }
    Log 'restored enabled: true'
}
catch {
    Log ("restore failed: " + $_.Exception.Message)
    exit 1
}
