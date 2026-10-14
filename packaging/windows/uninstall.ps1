#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstall kw-agent v0.1: stop/remove the tasks, delete binaries and data.
.DESCRIPTION
  Removes identity.json too — use only on disposable guests or when a fresh
  enrollment is intended. Product Reset semantics are owned by the platform,
  not this script. Removes both the SYSTEM daemon task and the interactive
  logon serve task (see install.ps1), plus the HKCU Run fallback written by
  Register-ServeTask.ps1.
#>
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
    [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
    [string]$ServeUser = 'workspace'
)
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName 'workspace-agent'
Unregister-ScheduledTask -TaskName 'workspace-agent' -Confirm:$false
Stop-ScheduledTask -TaskName 'kw-agent-serve'
Unregister-ScheduledTask -TaskName 'kw-agent-serve' -Confirm:$false
try {
    $sid = (Get-LocalUser $ServeUser -ErrorAction Stop).SID.Value
    $loaded = Test-Path -LiteralPath "Registry::HKEY_USERS\$sid"
    $mounted = $false
    if (-not $loaded) {
        $prof = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction Stop |
          Where-Object { $_.LocalPath } | Select-Object -First 1
        if ($null -ne $prof) {
            & reg.exe load "HKU\$sid" (Join-Path $prof.LocalPath 'NTUSER.DAT') | Out-Null
            if ($LASTEXITCODE -eq 0) { $mounted = $true }
        }
    }
    Remove-ItemProperty -Path "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name 'kw-agent-serve' -ErrorAction Stop
    Write-Output 'Run fallback removed'
} catch {
    Write-Warning "Run fallback not removed: $($_.Exception.Message)"
} finally {
    if ($mounted) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$sid" | Out-Null
    }
}
Remove-Item -LiteralPath $BinDir -Recurse -Force
Remove-Item -LiteralPath $DataDir -Recurse -Force
Write-Output 'workspace-agent removed'
