#Requires -Version 5.1
#Requires -RunAsAdministrator
# Native test for `kw-agent retire-legacy-startup`: creates the exact legacy
# artifacts (scheduled tasks, HKCU Run value, leftover launcher), verifies they
# are removed, and proves idempotency. Refuses to run if the legacy names
# already exist so it can never clobber a live installation.
param([Parameter(Mandatory=$true)][string]$AgentPath)
$ErrorActionPreference = 'Stop'
$taskNames = @('kw-agent-serve','workspace-agent')
$runValue = 'kw-agent-serve'
$root = Join-Path $env:TEMP ('kw-retire-' + [guid]::NewGuid().ToString('N'))
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$created = @()
try {
  foreach ($task in $taskNames) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
      throw "Refusing to run: scheduled task '$task' already exists on this machine"
    }
  }
  if (Get-ItemProperty -Path $runKey -Name $runValue -ErrorAction SilentlyContinue) {
    throw "Refusing to run: Run value '$runValue' already exists for this user"
  }

  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $exe = Join-Path $root 'kw-agent.exe'
  Copy-Item -LiteralPath $AgentPath -Destination $exe
  $launcher = Join-Path $root 'launch-serve.ps1'
  [IO.File]::WriteAllText($launcher, "# legacy placeholder`n")

  # Legacy artifacts, matching the shapes superseded releases left behind.
  $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120'
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount
  foreach ($task in $taskNames) {
    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    $created += $task
  }
  New-Item -Path $runKey -Force | Out-Null
  New-ItemProperty -Path $runKey -Name $runValue -Value 'legacy' -PropertyType String -Force | Out-Null

  & $exe retire-legacy-startup
  if ($LASTEXITCODE -ne 0) { throw "retire-legacy-startup failed ($LASTEXITCODE)" }

  foreach ($task in $taskNames) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { throw "Legacy task '$task' survived retirement" }
  }
  if (Get-ItemProperty -Path $runKey -Name $runValue -ErrorAction SilentlyContinue) { throw 'Legacy Run value survived retirement' }
  if (Test-Path -LiteralPath $launcher) { throw 'Leftover launcher survived retirement' }

  # A second run must succeed and report a clean machine.
  $second = & $exe retire-legacy-startup 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "Second retirement run failed ($LASTEXITCODE)" }
  if ($second -notmatch 'nothing to retire') { throw "Second run did not report a clean state: $second" }

  Write-Output 'Legacy startup retirement passed: tasks, Run value and leftover launcher removed; repeat run clean.'
} finally {
  foreach ($task in $created) { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue }
  Remove-ItemProperty -Path $runKey -Name $runValue -ErrorAction SilentlyContinue
  if (Test-Path $root) { Remove-Item $root -Recurse -Force }
}
