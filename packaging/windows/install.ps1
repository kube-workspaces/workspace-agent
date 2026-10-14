#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Enroll/configure the native Kube Workspaces Agent Windows service.
.DESCRIPTION
  MSI owns SCM registration; this script also supports installation from the
  archive. Enrollment is per guest and never embedded in the MSI. Retires the
  legacy SYSTEM/logon tasks and Run fallback before starting native supervision.
  Reinstall preserves identity and refuses a mismatched binding before changes.
#>
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$WorkspaceUid,
  [Parameter(Mandatory=$true)][ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) -and $_ -eq $_.Trim() -and $_ -notmatch '[\x00-\x1f\x7f]' })][string]$WorkspaceGeneration,
  [ValidateRange(1,24)][int]$TokenHours = 2,
  [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
  [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
  [string]$ServeUser = 'workspace',
  [string]$ExtraServeArgs = '--capture-video --capture-audio --clipboard --input --resize',
  [string[]]$ServeArgs,
  [Alias('NoServeTask')][switch]$NoDesktopWorker,
  [ValidatePattern('^[A-Za-z0-9-]{1,64}$')][string]$ServiceName = 'KubeWorkspacesAgent'
)
$ErrorActionPreference = 'Stop'
$name = $ServiceName
if ($name -ne 'KubeWorkspacesAgent' -and (-not $PSBoundParameters.ContainsKey('DataDir') -or -not $PSBoundParameters.ContainsKey('BinDir'))) {
  throw 'An isolated service instance requires explicit DataDir and BinDir'
}
$source = Join-Path $PSScriptRoot 'kw-agent.exe'
if (-not (Test-Path -LiteralPath $source)) { throw 'kw-agent.exe must be next to install.ps1' }
$migration = Join-Path $PSScriptRoot 'Migrate-LegacyStartup.ps1'
if (-not (Test-Path -LiteralPath $migration)) { throw 'Migrate-LegacyStartup.ps1 must be staged next to install.ps1' }
$payload = @('kw-agent.exe','install.ps1','uninstall.ps1','Migrate-LegacyStartup.ps1','Register-ServeTask.ps1','Start-Serve.ps1')
foreach ($file in $payload) { if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $file))) { throw "Installer payload missing: $file" } }
$DataDir = [IO.Path]::GetFullPath($DataDir)
$BinDir = [IO.Path]::GetFullPath($BinDir)
if ($DataDir.Contains('"') -or $BinDir.Contains('"')) { throw 'Paths cannot contain double quotes' }
if (Test-Path -LiteralPath (Join-Path $DataDir 'identity.json')) {
  & $source identity-check --data-dir $DataDir --workspace-uid $WorkspaceUid --workspace-generation $WorkspaceGeneration | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Enrolled identity mismatch; installation was not changed' }
}
# Validate typed worker arguments before stopping or changing an installation.
# -ServeArgs supports quoted values as actual argv; legacy ExtraServeArgs is
# whitespace-separated switches/numbers/device names, not a shell command.
if (-not $PSBoundParameters.ContainsKey('ServeArgs')) {
  # Explicit char[] avoids .NET Core's additional string-separator overload
  # treating the whole default flag list as one argument in PowerShell 7.
  $ServeArgs = @($ExtraServeArgs.Split([char[]]@(' ', "`t"), [StringSplitOptions]::RemoveEmptyEntries))
}
$config = @{ workerEnabled = -not $NoDesktopWorker.IsPresent; port = 44787; workerArgs = @($ServeArgs) }
$checkDir = Join-Path $env:TEMP ([guid]::NewGuid().ToString())
try {
  New-Item -ItemType Directory $checkDir | Out-Null
  [IO.File]::WriteAllText((Join-Path $checkDir 'service.json'), ($config | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
  & $source service-config-check --data-dir $checkDir | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Invalid desktop worker configuration; installation was not changed' }
} finally { if (Test-Path $checkDir) { Remove-Item $checkDir -Recurse -Force } }

$service = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($service) {
  Stop-Service $name
  $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  $service.Dispose()
}
if ($name -eq 'KubeWorkspacesAgent') {
  & $migration -BinDir $BinDir
}
$exe = Join-Path $BinDir 'kw-agent.exe'

New-Item -ItemType Directory -Path $BinDir, $DataDir -Force | Out-Null
function Set-InstallDirectoryAcl($Path, [bool]$UsersRead) {
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $principal = New-Object Security.Principal.SecurityIdentifier($sid)
    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  if ($UsersRead) {
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  # Cmdlet works on both Windows PowerShell 5.1 and PowerShell 7; do not rely
  # on .NET Framework-only DirectoryInfo.SetAccessControl instance methods.
  Set-Acl -LiteralPath $Path -AclObject $acl
}
Set-InstallDirectoryAcl $DataDir $false
Set-InstallDirectoryAcl $BinDir $true
foreach ($file in $payload) {
  $src = Join-Path $PSScriptRoot $file
  $dest = Join-Path $BinDir $file
  if ([IO.Path]::GetFullPath($src) -ne [IO.Path]::GetFullPath($dest)) { Copy-Item -LiteralPath $src -Destination $dest -Force }
  # Custom archive paths must be machine-owned too. A LocalSystem service
  # must never execute user-writable binaries or elevation helper scripts.
  $acl = New-Object Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  foreach ($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')) {
    $principal = New-Object Security.Principal.SecurityIdentifier($sid)
    $rights = if ($sid -eq 'S-1-5-32-545') { 'ReadAndExecute' } else { 'FullControl' }
    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal,$rights,'Allow')))
  }
  Set-Acl -LiteralPath $dest -AclObject $acl
}
[IO.File]::WriteAllText((Join-Path $DataDir 'service.json'), ($config | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
if (-not (Test-Path (Join-Path $DataDir 'identity.json'))) {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  $token = @{token=([BitConverter]::ToString($bytes)).Replace('-','').ToLower(); workspaceUid=$WorkspaceUid; workspaceGeneration=$WorkspaceGeneration; expiresAt=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+$TokenHours*3600}
  [IO.File]::WriteAllText((Join-Path $DataDir 'enrollment-token.json'), ($token | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
}
$binaryPath = "`"$exe`" service"
if ($name -eq 'KubeWorkspacesAgent') {
  # Use the service's 64-bit registry view even from a 32-bit provisioning shell.
  $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  try {
    $key = $machine.CreateSubKey('SOFTWARE\KubeWorkspaces\Agent')
    try { $key.SetValue('DataDir',$DataDir,[Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
  } finally { $machine.Dispose() }
} else { $binaryPath += " --service-name $name --data-dir `"$DataDir`"" }
if (-not $service) {
  $displayName = 'Kube Workspaces Agent'
  if ($name -ne 'KubeWorkspacesAgent') { $displayName += " ($name)" }
  New-Service -Name $name -DisplayName $displayName -BinaryPathName $binaryPath -StartupType Automatic -Description 'Kube Workspaces machine agent and interactive desktop worker supervisor' | Out-Null
} else {
  $cim = Get-CimInstance Win32_Service | Where-Object Name -eq $name
  $changed = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{PathName=$binaryPath;StartMode='Automatic';StartName='LocalSystem'}
  if ($changed.ReturnValue -ne 0) { throw "Cannot update SCM registration: WMI error $($changed.ReturnValue)" }
}
& $exe service-configure --service-name $name
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure native SCM recovery' }
Start-Service $name
$started = Get-Service $name
try { $started.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } finally { $started.Dispose() }
Write-Output 'Native Windows service running; enrollment and console-worker readiness are reported in service-status.json'
