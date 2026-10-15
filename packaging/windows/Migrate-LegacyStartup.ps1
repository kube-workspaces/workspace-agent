#Requires -RunAsAdministrator
<# Retire legacy startup only. Exact task/value names and installed executable
   path are intentional; never stop unrelated processes by image name. #>
param(
  [Parameter(Mandatory=$true)][string]$BinDir,
  [string[]]$TaskNames = @('workspace-agent','kw-agent-serve'),
  [string]$RunValueName = 'kw-agent-serve',
  [switch]$LoadedHivesOnly
)
$ErrorActionPreference = 'Stop'
foreach ($task in $TaskNames) {
  if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
  }
}
$hives = @(Get-ChildItem Registry::HKEY_USERS | ForEach-Object PSChildName)
function Remove-Fallback($Sid) {
  $key = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $key) { Remove-ItemProperty $key -Name $RunValueName -ErrorAction SilentlyContinue }
}
foreach ($sid in $hives) { Remove-Fallback $sid }
if (-not $LoadedHivesOnly) {
  # Retire startup for formerly configured accounts too, including logged-out
  # profiles. Mount only real user hives, unload everything mounted here.
  foreach ($profile in @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -and $hives -notcontains $_.SID })) {
    $file = Join-Path $profile.LocalPath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $file)) { continue }
    $mounted = $false
    try {
      & reg.exe load "HKU\$($profile.SID)" $file | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Cannot retire legacy startup for profile $($profile.SID)" }
      $mounted = $true
      Remove-Fallback $profile.SID
    } finally {
      if ($mounted) {
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$($profile.SID)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot unload migration profile hive' }
      }
    }
  }
}
$exe = Join-Path ([IO.Path]::GetFullPath($BinDir)) 'kw-agent.exe'
# Superseded launcher scripts are not shipped by the current MSI; remove any
# leftover so only MSI-owned files remain beside the native service binary.
foreach ($orphan in @('launch-serve.ps1')) {
  $path = Join-Path ([IO.Path]::GetFullPath($BinDir)) $orphan
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
Get-CimInstance Win32_Process | Where-Object {
  $_.ExecutablePath -eq $exe -and $_.CommandLine -match '\s(daemon|serve)(\s|$)'
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
