#Requires -Version 5.1
#Requires -RunAsAdministrator
# Isolated lifecycle test: unique product UpgradeCode, service, files and data.
# Per-machine service MSI: install, launch, upgrade, downgrade rejection,
# uninstall — and %ProgramData%\workspace-agent must survive (agent identity).
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$StagingDir,
  [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$TestInstance = ([guid]::NewGuid().ToString('N')),
  [string]$FirstMsi,
  [string]$SecondMsi
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($TestInstance -eq 'f72bb43edba84dbba963b201e6c0d885') { throw 'Lifecycle test cannot use the production UpgradeCode' }
$tempRoot = $env:RUNNER_TEMP
if (-not $tempRoot) { $tempRoot = $env:TEMP }
$work = Join-Path $tempRoot "msi-lifecycle-$TestInstance"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$folder = "kw-agent-test-$TestInstance"
$serviceName = "KwAgentMsiTest-$TestInstance"
$upgradeCode = '{' + ([guid]::ParseExact($TestInstance,'N')).ToString().ToUpper() + '}'
$install = Join-Path $env:ProgramFiles $folder
$installer = New-Object -ComObject WindowsInstaller.Installer
function Get-Registration([ValidateSet('user', 'machine')][string]$Scope) {
  # ARP registry hive is not the MSI installation context. In particular,
  # Windows Installer can register a per-user product under HKLM. Ask MSI.
  $products = $installer.GetType().InvokeMember('RelatedProducts', 'GetProperty', $null, $installer,
    @($upgradeCode))
  foreach ($product in $products) {
    $assignment = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($product, 'AssignmentType'))
    if (($Scope -eq 'user' -and $assignment -eq '0') -or ($Scope -eq 'machine' -and $assignment -eq '1')) {
      $version = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($product, 'VersionString'))
      [pscustomobject]@{ ProductCode = $product; DisplayVersion = $version }
    }
  }
}
function Invoke-Msi([string]$Arguments, [string]$Log, [int]$Expected = 0) {
  $p = Start-Process msiexec.exe -ArgumentList "$Arguments /qn /norestart /l*v `"$work\$Log.log`"" -Wait -PassThru
  if ($p.ExitCode -ne $Expected) { throw "msiexec returned $($p.ExitCode), expected $Expected; see $Log.log" }
}
function Assert-Payload([string]$Directory) {
  # Contract: MSI carries the staged exe + enrollment scripts (README/LICENSE
  # stay archive-only).
  foreach ($source in Get-ChildItem $StagingDir -File | Where-Object { $_.Extension -in @('.exe', '.ps1') }) {
    $dest = Join-Path $Directory $source.Name
    if (-not (Test-Path $dest)) { throw "Installed payload missing: $dest" }
    if ((Get-FileHash $source.FullName).Hash -ne (Get-FileHash $dest).Hash) { throw "Installed payload mismatch: $dest" }
  }
}
if ((Test-Path $install) -or (Get-Registration machine)) {
  throw "Runner already contains workspace-agent; refusing to overwrite it."
}
$first = $FirstMsi
$second = $SecondMsi
if (-not $first -or -not $second) {
  $first = Join-Path $work "first.msi"
  $second = Join-Path $work "second.msi"
  & "$PSScriptRoot/build-msi.ps1" -Version v0.0.1 -Arch amd64 -StagingDir $StagingDir -OutFile $first -TestInstance $TestInstance
  & "$PSScriptRoot/build-msi.ps1" -Version v0.0.2 -Arch amd64 -StagingDir $StagingDir -OutFile $second -TestInstance $TestInstance
}
# Agent identity lives in %ProgramData%\workspace-agent and must survive
# upgrade and uninstall (install.ps1 owns real enrollment files there).
$dataDir = Join-Path $env:ProgramData $folder
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$sentinel = Join-Path $dataDir 'msi-test-preserve.txt'
Set-Content $sentinel 'preserve me'
$commonRoot = [Environment]::GetFolderPath('CommonPrograms')
try {
  Invoke-Msi "/i `"$first`"" 'install'
  Assert-Payload $install
  if ((Get-Service $serviceName).Status -ne 'Running') { throw 'MSI did not start the native agent service' }
  if (Test-Path (Join-Path $commonRoot $folder)) {
    throw 'Background agent package must not create Start Menu shortcuts.'
  }
  if (@(Get-Registration user)) { throw 'Machine-scope package registered per-user.' }
  $registered = @(Get-Registration machine)
  if ($registered.Count -ne 1 -or $registered[0].DisplayVersion -ne '0.0.1') {
    throw 'Default install is not registered per-machine.'
  }
  $location = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($registered[0].ProductCode, 'InstallLocation'))
  # Directory properties resolve with a trailing separator; trim for compare.
  if ($location.TrimEnd('\', '/') -ne $install) { throw "InstallLocation is '$location', want '$install'." }
  $run = Start-Process (Join-Path $install 'kw-agent.exe') -ArgumentList '--version' -Wait -PassThru
  if ($run.ExitCode -ne 0) { throw 'Installed agent failed to launch.' }
  & (Join-Path $install 'install.ps1') -WorkspaceUid '00000000-0000-4000-8000-000000000001' -WorkspaceGeneration 'msi-lifecycle-test' -NoServeTask -DataDir $dataDir -BinDir $install -ServiceName $serviceName
  $deadline = (Get-Date).AddSeconds(20)
  while (-not (Test-Path (Join-Path $dataDir 'identity.json')) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
  if (-not (Test-Path (Join-Path $dataDir 'identity.json'))) { throw 'Native provisioning did not enroll the service' }
  $identityHash = (Get-FileHash (Join-Path $dataDir 'identity.json')).Hash
  Invoke-Msi "/i `"$second`"" 'upgrade'
  if ((Get-Service $serviceName).Status -ne 'Running') { throw 'Upgrade did not restart the native service' }
  Assert-Payload $install
  $registered = @(Get-Registration machine)
  if ($registered.Count -ne 1 -or $registered[0].DisplayVersion -ne '0.0.2') { throw 'Major upgrade left wrong registration.' }
  $location = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($registered[0].ProductCode, 'InstallLocation'))
  if ($location.TrimEnd('\', '/') -ne $install) { throw "InstallLocation after upgrade is '$location', want '$install'." }
  Invoke-Msi "/i `"$first`"" 'downgrade' 1603
  Invoke-Msi "/x `"$second`"" 'uninstall'
  if (Get-Service $serviceName -ErrorAction SilentlyContinue) { throw 'MSI uninstall left SCM registration' }
  if ((Test-Path (Join-Path $install 'kw-agent.exe')) -or (Get-Registration machine)) {
    throw 'Uninstall left installed files or registration.'
  }
  if ((Get-Content $sentinel -Raw).Trim() -ne 'preserve me') { throw 'Uninstall changed agent identity data.' }
  if ((Get-FileHash (Join-Path $dataDir 'identity.json')).Hash -ne $identityHash) { throw 'Upgrade/uninstall changed enrolled identity' }
  # Exercise archive creation and removal as well as MSI's existing-service
  # provisioning path. Same isolated namespace; never the machine's real agent.
  & (Join-Path $StagingDir 'install.ps1') -WorkspaceUid '00000000-0000-4000-8000-000000000001' -WorkspaceGeneration 'msi-lifecycle-test' -NoDesktopWorker -DataDir $dataDir -BinDir $install -ServiceName $serviceName
  Assert-Payload $install
  $exeAcl = Get-Acl (Join-Path $install 'kw-agent.exe')
  if ($exeAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Archive service binary is not administrator-owned' }
  foreach ($rule in $exeAcl.Access) {
    if ($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' -and $rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) { throw 'Archive service binary is user-writable' }
  }
  if ((Get-Service $serviceName).Status -ne 'Running') { throw 'Archive install did not start the native service' }
  & (Join-Path $StagingDir 'uninstall.ps1') -DataDir $dataDir -BinDir $install -ServiceName $serviceName
  if (Get-Service $serviceName -ErrorAction SilentlyContinue) { throw 'Archive uninstall left SCM registration' }
  if ((Get-FileHash (Join-Path $dataDir 'identity.json')).Hash -ne $identityHash) { throw 'Archive uninstall changed enrolled identity' }
  Write-Host 'MSI lifecycle passed: install, payload, no shortcut, launch, upgrade, downgrade rejection, uninstall, identity preservation.'
} finally {
  # Clean this uniquely namespaced test even after a failed assertion. Keep MSI
  # logs in $work for diagnosis; never remove another product or service.
  foreach ($registered in @(Get-Registration machine)) {
    $null = Start-Process msiexec.exe -ArgumentList "/x $($registered.ProductCode) /qn /norestart" -Wait -PassThru
  }
  $remaining = Get-Service $serviceName -ErrorAction SilentlyContinue
  if ($remaining) {
    try { Stop-Service $serviceName -ErrorAction SilentlyContinue; $remaining.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) } finally { $remaining.Dispose() }
    & sc.exe delete $serviceName | Out-Null
  }
  if (-not (Get-Registration machine) -and (Test-Path $install)) { Remove-Item $install -Recurse -Force }
  Remove-Item $sentinel -ErrorAction SilentlyContinue
  if (Test-Path $dataDir) { Remove-Item $dataDir -Recurse -Force }
}
