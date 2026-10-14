#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install kw-agent v0.1 on Windows: files, machine-protected data dir,
  one-use enrollment token, SYSTEM scheduled task at startup.
.DESCRIPTION
  Proof installer for disposable guests. Not an MSI, not signed, no driver
  handling. The task runs `kw-agent daemon` as SYSTEM at startup; the agent
  itself performs no capture, networking, input or display changes in v0.1.
  Capture needs serve in the interactive console session (Session 0
  isolation), so install also registers the per-logon `kw-agent-serve` task
  via Register-ServeTask.ps1 unless -NoServeTask is given.
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
.PARAMETER ServeUser
  Interactive account the serve task runs as (default workspace). Must exist
  at install time; otherwise the serve task is skipped with a warning and
  can be registered later by re-running install or Register-ServeTask.ps1.
.PARAMETER ExtraServeArgs
  Extra serve flags for the logon task (default full premium set).
.PARAMETER NoServeTask
  Skip the interactive logon serve task (control plane only).
#>
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$WorkspaceUid,
    [Parameter(Mandatory=$true)][ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) -and $_ -eq $_.Trim() -and $_ -notmatch '[\x00-\x1f\x7f]' })][string]$WorkspaceGeneration,
    [int]$TokenHours = 2,
    [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
    [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
    [string]$ServeUser = 'workspace',
    [string]$ExtraServeArgs = '--capture-video --capture-audio --clipboard --input --resize',
    [switch]$NoServeTask
)
$ErrorActionPreference = 'Stop'

$exe = Join-Path $PSScriptRoot 'kw-agent.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "kw-agent.exe not found next to install.ps1" }
if ($WorkspaceGeneration.Contains('"') -or $DataDir.Contains('"')) { throw 'Generation and DataDir cannot contain double quotes' }
if (Test-Path -LiteralPath (Join-Path $DataDir 'identity.json')) {
    # Never silently reconfigure an enrolled machine for a mistyped binding.
    & $exe identity-check --data-dir $DataDir --workspace-uid $WorkspaceUid --workspace-generation $WorkspaceGeneration | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Enrolled identity mismatch; installation was not changed' }
}

# Idempotent reinstall: stop a running previous version first (the task holds
# the binary open while the daemon runs).
if (Get-ScheduledTask -TaskName 'workspace-agent' -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName 'workspace-agent' -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-ScheduledTask -TaskName 'workspace-agent').State -ne 'Ready' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
    }
}
New-Item -ItemType Directory -Force -Path $BinDir, $DataDir | Out-Null
$destination = Join-Path $BinDir 'kw-agent.exe'
if ([IO.Path]::GetFullPath($exe) -ne [IO.Path]::GetFullPath($destination)) {
    Copy-Item -LiteralPath $exe -Destination $destination -Force
}

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

# Interactive serve task: capture/video/audio/input need the logged-on
# console session, which the SYSTEM task above cannot see (Session 0
# isolation). Non-fatal when the account does not exist yet (image
# provisioning order): warn and let a later re-run register it.
if (-not $NoServeTask) {
    $serveScript = Join-Path $PSScriptRoot 'Register-ServeTask.ps1'
    if (-not (Test-Path -LiteralPath $serveScript)) {
        Write-Warning "Register-ServeTask.ps1 not staged next to install.ps1; skipping interactive serve task"
    } else {
        try {
            & $serveScript -WorkspaceUid $WorkspaceUid -WorkspaceGeneration $WorkspaceGeneration `
                -User $ServeUser -BinDir $BinDir -DataDir $DataDir -ExtraServeArgs $ExtraServeArgs
        } catch {
            Write-Warning "interactive serve task not registered: $($_.Exception.Message)"
            Write-Warning "re-run install.ps1 (or Register-ServeTask.ps1) once '$ServeUser' exists"
        }
    }
}
