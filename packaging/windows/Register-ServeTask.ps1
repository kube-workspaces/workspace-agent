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
