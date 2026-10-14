<#
.SYNOPSIS
  Registers the per-logon kw-agent serve task (interactive console session).

.DESCRIPTION
  The SYSTEM service/daemon (install.ps1) cannot serve the interactive
  desktop (Session 0 isolation), so video/audio/input need serve running in
  the logged-on console session. This registers a logon-triggered scheduled
  task for that user with an InteractiveToken principal: no password is
  stored, and a 30 s delay plus restart-on-failure covers display drivers
  that are not ready in the first seconds after logon.

  Survives stop/start and reboot (UID+generation are stable). Re-run with new
  values after a workspace Reset, which rotates the binding.

  As a fallback the script also writes an HKCU Run value for the same user:
  Explorer launches it in-session at every logon with no scheduler
  involvement, which survives hardened-image Task Scheduler launch denials
  (observed 0x80070005). If both fire, the loser exits on bind failure
  (serve exits 1), so a double start is safe. Uninstall removes the Run
  value (see uninstall.ps1).

.PARAMETER WorkspaceUid
  Workspace UID the serve session binds to.

.PARAMETER WorkspaceGeneration
  Workspace generation the serve session binds to.

.PARAMETER User
  Interactive account name (default workspace).

.PARAMETER UserSid
  That account's SID (no password needed for InteractiveToken tasks).

.PARAMETER ExtraServeArgs
  Extra serve flags (default full premium set).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Register-ServeTask.ps1 `
    -WorkspaceUid <uid> -WorkspaceGeneration <gen>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$WorkspaceUid,
  [Parameter(Mandatory = $true)][string]$WorkspaceGeneration,
  [string]$User = 'workspace',
  [string]$UserSid = '',
  [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
  [string]$ExtraServeArgs = '--capture-video --capture-audio --clipboard --input --resize'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($UserSid)) {
  $UserSid = (Get-LocalUser $User).SID.Value
}
$exe = Join-Path $BinDir 'kw-agent.exe'
if (-not (Test-Path $exe -PathType Leaf)) {
  throw "Agent binary missing: $exe (install the MSI first)"
}
$args = "serve --workspace-uid `"$WorkspaceUid`" --workspace-generation `"$WorkspaceGeneration`" --bind 0.0.0.0 --port 44787 $ExtraServeArgs"
$action = New-ScheduledTaskAction -Execute $exe -Argument $args
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$trigger.Delay = 'PT30S'
$principal = New-ScheduledTaskPrincipal -UserId $UserSid -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 1) `
  -AllowStartIfOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName 'kw-agent-serve' -Action $action `
  -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "logon task 'kw-agent-serve' registered for $User"

function Set-ServeRunKey {
  # HKCU Run fallback for $User: Explorer starts serve in-session at logon
  # without Task Scheduler. Resolves the user's profile hive (loaded when
  # logged on, else mounted from NTUSER.DAT) and writes the Run value there.
  # Non-fatal by design: the logon task above stays the primary mechanism.
  param([string]$Exe, [string]$ServeArgs, [string]$UserSid)
  $runName = 'kw-agent-serve'
  $runValue = "`"$Exe`" $ServeArgs"
  $mounted = $false
  try {
    $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$UserSid'" -ErrorAction Stop |
      Where-Object { $_.LocalPath -and (Test-Path (Join-Path $_.LocalPath 'NTUSER.DAT') -PathType Leaf) } |
      Select-Object -First 1
    if ($null -eq $profile) { throw "no local profile for SID $UserSid yet; Run key skipped" }
    if (-not (Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid")) {
      & reg.exe load "HKU\$UserSid" (Join-Path $profile.LocalPath 'NTUSER.DAT') | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "reg load of $($profile.LocalPath) failed ($LASTEXITCODE)" }
      $mounted = $true
    }
    $runKey = "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $runKey -Force | Out-Null
    New-ItemProperty -Path $runKey -Name $runName -Value $runValue -PropertyType String -Force | Out-Null
    Write-Output "Run fallback '$runName' registered for $User"
  } catch {
    Write-Warning "Run fallback not registered: $($_.Exception.Message)"
  } finally {
    if ($mounted) {
      [GC]::Collect()
      [GC]::WaitForPendingFinalizers()
      & reg.exe unload "HKU\$UserSid" | Out-Null
    }
  }
}

Set-ServeRunKey -Exe $exe -ServeArgs $args -UserSid $UserSid
