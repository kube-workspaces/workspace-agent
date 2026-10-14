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

  Loads UID+generation from the daemon's public enrolled binding at startup.
  Optional binding parameters are assertions, never independent task state.

  As a fallback the script also writes an HKCU Run value for the same user:
  Explorer launches it in-session at every logon with no scheduler
  involvement, which survives hardened-image Task Scheduler launch denials
  (observed 0x80070005). A shared per-session launcher mutex prevents double
  starts and competing log writers. Uninstall removes the Run
  value (see uninstall.ps1).

.PARAMETER WorkspaceUid
  Optional expected workspace UID. Must match the enrolled identity.

.PARAMETER WorkspaceGeneration
  Optional expected generation. Must match the enrolled identity.

.PARAMETER DataDir
  Enrollment directory shared with the daemon (default ProgramData\workspace-agent).

.PARAMETER User
  Interactive account name (default workspace).

.PARAMETER UserSid
  That account's SID (no password needed for InteractiveToken tasks).

.PARAMETER ExtraServeArgs
  Extra serve flags (default full premium set).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Register-ServeTask.ps1
#>
[CmdletBinding()]
param(
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$WorkspaceUid,
  [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) -and $_ -eq $_.Trim() -and $_ -notmatch '[\x00-\x1f\x7f]' })][string]$WorkspaceGeneration,
  [string]$User = 'workspace',
  [string]$UserSid = '',
  [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
  [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
  [string]$ExtraServeArgs = '--capture-video --capture-audio --clipboard --input --resize'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Get-Service -Name KubeWorkspacesAgent -ErrorAction SilentlyContinue) {
  throw 'Native agent service is installed; configure it with install.ps1 instead of enabling legacy logon startup'
}

if ([string]::IsNullOrWhiteSpace($UserSid)) {
  $UserSid = (Get-LocalUser $User).SID.Value
}
$exe = Join-Path $BinDir 'kw-agent.exe'
if (-not (Test-Path $exe -PathType Leaf)) {
  throw "Agent binary missing: $exe (install the MSI first)"
}
# Validate before touching either startup mechanism or its permissions.
$checkArgs = @('identity-check', '--data-dir', $DataDir)
if ($WorkspaceUid) { $checkArgs += @('--workspace-uid', $WorkspaceUid) }
if ($WorkspaceGeneration) { $checkArgs += @('--workspace-generation', $WorkspaceGeneration) }
$bindingJson = & $exe @checkArgs
if ($LASTEXITCODE -ne 0) { throw 'Enrolled identity validation failed; startup registration was not changed' }
$binding = ($bindingJson -join "`n") | ConvertFrom-Json
if (-not (Test-Path -LiteralPath (Join-Path $DataDir 'public\binding.json'))) {
  throw 'public/binding.json missing; start the enrolled daemon before registering desktop startup'
}
if ($ExtraServeArgs -match '(?i)--(?:workspace-uid|workspace-generation|data-dir)(?:\s|=|$)') {
  throw 'ExtraServeArgs cannot override the enrolled identity or data directory'
}
if ($DataDir.Contains('"')) { throw 'DataDir cannot contain double quotes' }
$launcher = Join-Path $BinDir 'Start-Serve.ps1'
$sourceLauncher = Join-Path $PSScriptRoot 'Start-Serve.ps1'
if (-not (Test-Path -LiteralPath $sourceLauncher)) { throw "Launcher missing: $sourceLauncher" }
if ([IO.Path]::GetFullPath($sourceLauncher) -ne [IO.Path]::GetFullPath($launcher)) {
  Copy-Item -LiteralPath $sourceLauncher -Destination $launcher -Force
}

# The user may traverse the protected data directory but cannot list/read its
# private files. Only the public subdirectory grants inherited read access.
$acl = Get-Acl -LiteralPath $DataDir
$sid = New-Object Security.Principal.SecurityIdentifier($UserSid)
[void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
  $sid, 'Traverse', 'None', 'None', 'Allow')))
Set-Acl -LiteralPath $DataDir -AclObject $acl
$publicDir = Join-Path $DataDir 'public'
$acl = Get-Acl -LiteralPath $publicDir
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
foreach ($accountSid in @('S-1-5-18', 'S-1-5-32-544')) {
  $account = New-Object Security.Principal.SecurityIdentifier($accountSid)
  [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
  $sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $publicDir -AclObject $acl
[IO.File]::WriteAllText((Join-Path $publicDir 'serve-options.json'),
  (@{ extraServeArgs = $ExtraServeArgs } | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$launchArgs = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$launcher`" -DataDir `"$DataDir`""
$action = New-ScheduledTaskAction -Execute $powershell -Argument $launchArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$trigger.Delay = 'PT30S'
$principal = New-ScheduledTaskPrincipal -UserId $UserSid -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName 'kw-agent-serve' -Action $action `
  -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "logon task 'kw-agent-serve' registered for $User"
Write-Output "desktop binding uses enrolled identity ($($binding.workspaceUid)); logs: %LOCALAPPDATA%\workspace-agent\serve*.log"

function Set-ServeRunKey {
  # HKCU Run fallback for $User: Explorer starts serve in-session at logon
  # without Task Scheduler. Resolves the user's profile hive (loaded when
  # logged on, else mounted from NTUSER.DAT) and writes the Run value there.
  # The launcher hides every window: powershell.exe itself starts hidden and
  # Start-Process hides the console agent (a visible console on every boot
  # is not shippable). Non-fatal by design: the logon task above stays the
  # primary mechanism.
  param([string]$Exe, [string]$ServeArgs, [string]$UserSid)
  $runName = 'kw-agent-serve'
  $runValue = "`"$Exe`" $ServeArgs"
  $mounted = $false
  try {
    if ($runValue.Length -gt 260) { throw 'Run command exceeds the Windows 260-character limit; use shorter BinDir/DataDir paths' }
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

Set-ServeRunKey -Exe $powershell -ServeArgs $launchArgs -UserSid $UserSid
