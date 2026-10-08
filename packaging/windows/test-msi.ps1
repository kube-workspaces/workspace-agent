#Requires -Version 5.1
# Destructive lifecycle test for a disposable GitHub-hosted Windows runner.
# Files-only per-machine MSI: install, launch, upgrade, downgrade rejection,
# uninstall — and %ProgramData%\workspace-agent must survive (agent identity).
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$StagingDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true") { throw "Run lifecycle tests only on a disposable GitHub Actions runner." }
$work = Join-Path $env:RUNNER_TEMP "msi-lifecycle"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$install = Join-Path $env:ProgramFiles 'workspace-agent'
$installer = New-Object -ComObject WindowsInstaller.Installer
function Get-Registration([ValidateSet('user', 'machine')][string]$Scope) {
  # ARP registry hive is not the MSI installation context. In particular,
  # Windows Installer can register a per-user product under HKLM. Ask MSI.
  $products = $installer.GetType().InvokeMember('RelatedProducts', 'GetProperty', $null, $installer,
    @('{F72BB43E-DBA8-4DBB-A963-B201E6C0D885}'))
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
$first = Join-Path $work "first.msi"
$second = Join-Path $work "second.msi"
& "$PSScriptRoot/build-msi.ps1" -Version v0.0.1 -Arch amd64 -StagingDir $StagingDir -OutFile $first
& "$PSScriptRoot/build-msi.ps1" -Version v0.0.2 -Arch amd64 -StagingDir $StagingDir -OutFile $second
# Agent identity lives in %ProgramData%\workspace-agent and must survive
# upgrade and uninstall (install.ps1 owns real enrollment files there).
$dataDir = Join-Path $env:ProgramData 'workspace-agent'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$sentinel = Join-Path $dataDir 'msi-test-preserve.txt'
Set-Content $sentinel 'preserve me'
$commonRoot = [Environment]::GetFolderPath('CommonPrograms')
try {
  Invoke-Msi "/i `"$first`"" 'install'
  Assert-Payload $install
  if (Test-Path (Join-Path $commonRoot 'workspace-agent')) {
    throw 'Files-only agent package must not create Start Menu shortcuts.'
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
  Invoke-Msi "/i `"$second`"" 'upgrade'
  Assert-Payload $install
  $registered = @(Get-Registration machine)
  if ($registered.Count -ne 1 -or $registered[0].DisplayVersion -ne '0.0.2') { throw 'Major upgrade left wrong registration.' }
  $location = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($registered[0].ProductCode, 'InstallLocation'))
  if ($location.TrimEnd('\', '/') -ne $install) { throw "InstallLocation after upgrade is '$location', want '$install'." }
  Invoke-Msi "/i `"$first`"" 'downgrade' 1603
  Invoke-Msi "/x `"$second`"" 'uninstall'
  if ((Test-Path (Join-Path $install 'kw-agent.exe')) -or (Get-Registration machine)) {
    throw 'Uninstall left installed files or registration.'
  }
  if ((Get-Content $sentinel -Raw).Trim() -ne 'preserve me') { throw 'Uninstall changed agent identity data.' }
  Write-Host 'MSI lifecycle passed: install, payload, no shortcut, launch, upgrade, downgrade rejection, uninstall, identity preservation.'
} finally {
  Remove-Item $sentinel -ErrorAction SilentlyContinue
}
