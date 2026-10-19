#Requires -Version 5.1
#Requires -RunAsAdministrator
# Isolated SCM proof: same service implementation, synthetic off-guest authority,
# unique service/root. The example host is not a shipped updater entry point.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$FixtureHost,
  [Parameter(Mandatory = $true)][string]$StagingDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$hostExe = (Resolve-Path $FixtureHost).Path
$instance = [guid]::NewGuid().ToString('N')
$name = "KwUpdaterTest-$instance"
$work = Join-Path $env:TEMP "updater-scm-$instance"
$root = Join-Path $work "upg_$instance"
$head = Join-Path $work 'fixture-authority.json'
$helper = Join-Path $root 'kw-agent-updater.exe'
$statusPath = Join-Path $root 'updater-status.json'
New-Item -ItemType Directory -Path $work | Out-Null
& $hostExe prepare $root $head
if ($LASTEXITCODE -ne 0) { throw 'Updater fixture preparation failed' }
Copy-Item $hostExe $helper
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
Set-Acl -LiteralPath $helper -AclObject $acl
$checkpointHash = (Get-FileHash (Join-Path $root 'checkpoint.json')).Hash
$imageHash = (Get-FileHash $helper).Hash
$imagePath = '"{0}" service "{1}" "{2}" "{3}"' -f $helper, $name, $root, $head
function Wait-Updater([string]$State, [uint32]$ExcludedProcess = 0) {
  $deadline = (Get-Date).AddSeconds(35)
  while ((Get-Date) -lt $deadline) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($service -and $service.State -eq 'Running' -and $service.ProcessId -ne $ExcludedProcess -and (Test-Path $statusPath)) {
      $status = Get-Content $statusPath -Raw | ConvertFrom-Json
      if ($status.process_id -eq $service.ProcessId -and $status.state -eq $State) {
        if ($service.StartName -ne 'LocalSystem' -or $service.ServiceType -ne 'Own Process') { throw 'Updater is not an independent LocalSystem own-process service' }
        if ($status.effects_enabled) { throw 'Recovery host must not enable installer dispatch' }
        return $status
      }
    }
    Start-Sleep -Milliseconds 200
  }
  throw "Updater did not reach $State"
}
try {
  New-Service -Name $name -BinaryPathName $imagePath -StartupType Manual | Out-Null
  & $hostExe configure $name
  if ($LASTEXITCODE -ne 0) { throw 'Updater SCM recovery configuration failed' }
  Start-Service $name
  $first = Wait-Updater 'checkpoint_verified'
  if ($first.journal_sequence -ne 3 -or $first.journal_phase -ne 'active') { throw 'Updater failed to reopen the existing write-ahead action' }

  # Actual native agent MSI install/upgrade/uninstall/compensation runs while the
  # independent helper remains running, outside the MSI replacement directory.
  & "$PSScriptRoot/test-updater-msi.ps1" -StagingDir $StagingDir
  $after = Wait-Updater 'checkpoint_verified'
  if ($after.process_id -ne $first.process_id) { throw 'Agent replacement disturbed the independent updater process' }
  if ((Get-FileHash $helper).Hash -ne $imageHash) { throw 'Agent MSI replaced the independent helper image' }

  Stop-Process -Id $first.process_id -Force
  $restarted = Wait-Updater 'checkpoint_verified' $first.process_id
  if ($restarted.journal_sequence -ne 3 -or $restarted.journal_phase -ne 'active') { throw 'SCM recovery replayed or lost the active journal action' }
  if ((Get-FileHash (Join-Path $root 'checkpoint.json')).Hash -ne $checkpointHash) { throw 'Read-only SCM recovery changed the checkpoint' }

  Stop-Service $name
  (Get-Service $name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
  Start-Sleep -Seconds 7
  if ((Get-Service $name).Status -ne 'Stopped') { throw 'Clean SCM stop unexpectedly triggered failure recovery' }

  # A protected launch file alone is never authority. Same host, same journal,
  # no authority provider: remain alive and explicitly waiting, with no effects.
  $waitingPath = '"{0}" service-unavailable "{1}" "{2}"' -f $helper, $name, $root
  & sc.exe config $name binPath= $waitingPath | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Fixture service reconfiguration failed' }
  Start-Service $name
  $waiting = Wait-Updater 'waiting_for_authority'
  if ($null -ne $waiting.journal_sequence) { throw 'Unavailable authority adopted a local checkpoint' }
  if ((Get-FileHash (Join-Path $root 'checkpoint.json')).Hash -ne $checkpointHash) { throw 'Authority outage changed the checkpoint' }
  Write-Host 'Updater SCM proof passed: LocalSystem own-process lifetime, agent replacement independence, crash restart from unchanged active journal, clean stop, and fail-closed authority outage.'
} finally {
  $service = Get-Service $name -ErrorAction SilentlyContinue
  if ($service) {
    try {
      if ($service.Status -ne 'Stopped') { Stop-Service $name -ErrorAction SilentlyContinue; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15)) }
    } finally { $service.Dispose() }
    & sc.exe delete $name | Out-Null
  }
  # All paths and service names belong to this unique fixture only.
  if (Test-Path $work) { Remove-Item $work -Recurse -Force }
}
