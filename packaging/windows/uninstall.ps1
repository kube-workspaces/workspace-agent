#Requires -RunAsAdministrator
<# Archive-install removal. MSI installations should use Windows Installer.
   Identity/configuration survive by default, matching MSI upgrade/uninstall.
   -PurgeIdentity is explicit re-enrollment/reset preparation, not an upgrade. #>
param(
  [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
  [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent'),
  [string]$ServeUser = 'workspace',
  [ValidatePattern('^[A-Za-z0-9-]{1,64}$')][string]$ServiceName = 'KubeWorkspacesAgent',
  [switch]$PurgeIdentity
)
$ErrorActionPreference = 'Stop'
if ($ServiceName -ne 'KubeWorkspacesAgent' -and (-not $PSBoundParameters.ContainsKey('DataDir') -or -not $PSBoundParameters.ContainsKey('BinDir'))) {
  throw 'An isolated service instance requires explicit DataDir and BinDir'
}
$service = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($service) {
  try {
    Stop-Service $ServiceName
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  } finally { $service.Dispose() }
  & sc.exe delete $ServiceName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot remove native SCM registration' }
}
if ($ServiceName -eq 'KubeWorkspacesAgent') {
  & (Join-Path $PSScriptRoot 'Migrate-LegacyStartup.ps1') -BinDir $BinDir
}
if (Test-Path -LiteralPath $BinDir) { Remove-Item -LiteralPath $BinDir -Recurse -Force }
if ($PurgeIdentity -and (Test-Path -LiteralPath $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
Write-Output 'Agent service and archive binaries removed; identity is retained unless -PurgeIdentity was specified'
