#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install kw-agent v0.1 on Windows: files, machine-protected data dir,
  one-use enrollment token, SYSTEM scheduled task at startup.
.DESCRIPTION
  Proof installer for disposable guests. Not an MSI, not signed, no driver
  handling. The task runs `kw-agent daemon` as SYSTEM at startup; the agent
  itself performs no capture, networking, input or display changes in v0.1.
.PARAMETER WorkspaceUid
  Workspace UID the enrollment token is bound to (generation-bound below).
.PARAMETER WorkspaceGeneration
  Workspace generation the enrollment token is bound to.
.PARAMETER TokenHours
  Enrollment token validity in hours (default 2). Keep short: the token is
  consumed on first boot and never reused.
.PARAMETER DataDir
  Defaults to $env:ProgramData\workspace-agent.
.PARAMETER BinDir
  Defaults to $env:ProgramFiles\workspace-agent. kw-agent.exe must sit next
  to this script or be given via -InstallerPath.
#>
param(
    [Parameter(Mandatory=$true)][string]$WorkspaceUid,
    [Parameter(Mandatory=$true)][string]$WorkspaceGeneration,
    [int]$TokenHours = 2,
    [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
    [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent')
)
$ErrorActionPreference = 'Stop'

$exe = Join-Path $PSScriptRoot 'kw-agent.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "kw-agent.exe not found next to install.ps1" }
New-Item -ItemType Directory -Force -Path $BinDir, $DataDir | Out-Null
Copy-Item -LiteralPath $exe -Destination (Join-Path $BinDir 'kw-agent.exe') -Force

# Machine-protected data dir: SYSTEM + Administrators only, no inheritance.
$acl = Get-Acl -LiteralPath $DataDir
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
foreach ($account in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    [void]$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $DataDir -AclObject $acl

# One-use enrollment token, consumed on first daemon start. Written BOM-less:
# PowerShell 5.1 `Set-Content -Encoding UTF8` emits a BOM (the agent tolerates
# one, but do not rely on it).
$bytes = New-Object byte[] 32
[void][Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$token = [ordered]@{
    token = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLower()
    workspaceUid = $WorkspaceUid
    workspaceGeneration = $WorkspaceGeneration
    expiresAt = [int64](Get-Date -UFormat %s) + $TokenHours * 3600
}
[System.IO.File]::WriteAllText(
    (Join-Path $DataDir 'enrollment-token.json'),
    ($token | ConvertTo-Json),
    (New-Object System.Text.UTF8Encoding $false))

$action = New-ScheduledTaskAction -Execute (Join-Path $BinDir 'kw-agent.exe') `
    -Argument "daemon --workspace-uid `"$WorkspaceUid`" --workspace-generation `"$WorkspaceGeneration`" --data-dir `"$DataDir`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'workspace-agent' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'workspace-agent'
Start-Sleep -Seconds 5
$state = (Get-ScheduledTask -TaskName 'workspace-agent').State
$status = if (Test-Path (Join-Path $DataDir 'status.json')) { Get-Content (Join-Path $DataDir 'status.json') -Raw } else { '(no status yet)' }
Write-Output "task state: $state"
Write-Output "status: $status"
