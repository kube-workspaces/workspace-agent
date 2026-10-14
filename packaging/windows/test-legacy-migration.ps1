#Requires -Version 5.1
#Requires -RunAsAdministrator
# Real Task Scheduler/registry migration test, with unique fixture names only.
$ErrorActionPreference = 'Stop'
$name = 'KwAgentMigrationTest-' + [guid]::NewGuid().ToString('N')
$other = $name + '-unrelated'
$key = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run'
$taskCreated = $false
$keyCreated = -not (Test-Path $key)
try {
  if ($keyCreated) { New-Item $key -Force | Out-Null }
  New-ItemProperty $key -Name $name -Value 'legacy test launcher' -PropertyType String | Out-Null
  New-ItemProperty $key -Name $other -Value 'must survive' -PropertyType String | Out-Null
  $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120'
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal | Out-Null
  $taskCreated = $true
  Start-ScheduledTask $name
  & (Join-Path $PSScriptRoot 'Migrate-LegacyStartup.ps1') -BinDir (Join-Path $env:TEMP $name) -TaskNames @($name) -RunValueName $name -LoadedHivesOnly
  if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'Legacy task was not retired' }
  if ((Get-Item $key).GetValueNames() -contains $name) { throw 'Legacy Run value was not retired' }
  if ((Get-ItemPropertyValue $key -Name $other) -ne 'must survive') { throw 'Migration changed an unrelated startup app' }
  Write-Output 'Legacy task/Run migration passed; unrelated startup preserved'
} finally {
  if ($taskCreated -and (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
    Stop-ScheduledTask $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask $name -Confirm:$false
  }
  Remove-ItemProperty $key -Name $name -ErrorAction SilentlyContinue
  Remove-ItemProperty $key -Name $other -ErrorAction SilentlyContinue
  if ($keyCreated -and (Get-Item $key).GetValueNames().Count -eq 0) { Remove-Item $key }
}
