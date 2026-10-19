#Requires -Version 5.1
#Requires -RunAsAdministrator
# Disposable Windows CI only: uniquely named MSI family/service/directory, never
# the production agent. Native adapter test code lives only in the Rust test binary.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$StagingDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$instance = [guid]::NewGuid().ToString('N')
if ($instance -eq 'f72bb43edba84dbba963b201e6c0d885') { throw 'Test must use an isolated UpgradeCode' }
$upgrade = '{' + ([guid]::ParseExact($instance, 'N')).ToString().ToUpper() + '}'
$folder = "kw-agent-test-$instance"
$install = Join-Path $env:ProgramFiles $folder
$data = Join-Path $env:ProgramData $folder
$service = "KwAgentMsiTest-$instance"
$work = Join-Path $env:TEMP "updater-msi-$instance"
$installer = New-Object -ComObject WindowsInstaller.Installer
function Get-TestProducts {
  $codes = $installer.GetType().InvokeMember('RelatedProducts', 'GetProperty', $null, $installer, @($upgrade))
  foreach ($code in $codes) {
    $assignment = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($code, 'AssignmentType'))
    if ($assignment -ne '1') { throw 'Isolated updater fixture unexpectedly registered per-user' }
    $code
  }
}
if ((Test-Path $install) -or (Test-Path $data) -or (Get-TestProducts)) { throw 'Isolated test namespace already exists' }
New-Item -ItemType Directory -Path $work, $data | Out-Null
$sentinel = Join-Path $data 'updater-identity-preservation-sentinel'
[IO.File]::WriteAllBytes($sentinel, [Text.Encoding]::UTF8.GetBytes('synthetic identity preservation evidence'))
$hash = (Get-FileHash $sentinel).Hash
$names = @('KW_UPDATER_TEST_FIRST', 'KW_UPDATER_TEST_SECOND', 'KW_UPDATER_TEST_INSTANCE', 'KW_UPDATER_TEST_INSTALL_DIR')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
  $first = Join-Path $work 'first.msi'
  $second = Join-Path $work 'second.msi'
  & "$PSScriptRoot/build-msi.ps1" -Version v0.0.1 -Arch amd64 -StagingDir $StagingDir -OutFile $first -TestInstance $instance
  & "$PSScriptRoot/build-msi.ps1" -Version v0.0.2 -Arch amd64 -StagingDir $StagingDir -OutFile $second -TestInstance $instance
  $env:KW_UPDATER_TEST_FIRST = $first
  $env:KW_UPDATER_TEST_SECOND = $second
  $env:KW_UPDATER_TEST_INSTANCE = $upgrade
  $env:KW_UPDATER_TEST_INSTALL_DIR = $install
  cargo test -p kw-management --locked --lib updates::installer::native::tests::isolated_native_msi_compensation -- --ignored --exact --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Native updater MSI regression failed' }
  if ((Get-FileHash $sentinel).Hash -ne $hash) { throw 'Native MSI compensation changed protected identity data' }
  Write-Host 'Native updater adapter passed: package pinning, MSI metadata, machine inventory, upgrade, downgrade rejection, exact-target removal, predecessor install and ProgramData preservation.'
} finally {
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
  foreach ($code in @(Get-TestProducts)) {
    $p = Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -PassThru -Wait
    if ($p.ExitCode -notin @(0, 3010)) { Write-Warning "Isolated fixture cleanup returned $($p.ExitCode)" }
  }
  $remaining = Get-Service $service -ErrorAction SilentlyContinue
  if ($remaining) {
    try { Stop-Service $service -ErrorAction SilentlyContinue; $remaining.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } finally { $remaining.Dispose() }
    & sc.exe delete $service | Out-Null
  }
  if (-not (Get-TestProducts)) {
    if (Test-Path $install) { Remove-Item $install -Recurse -Force }
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
  }
}
