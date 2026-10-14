#Requires -Version 5.1
<#
.SYNOPSIS
  Launch the desktop agent from its public enrolled binding, with durable logs.
.DESCRIPTION
  Runs as the interactive user, never as SYSTEM. Only public/binding.json
  and public/serve-options.json are readable by that user; identity.json and
  enrollment tokens remain restricted to SYSTEM and Administrators.
#>
param(
  [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent')
)
$ErrorActionPreference = 'Stop'
# The logon task and Explorer Run fallback can fire together. Hold one
# per-session launcher before opening logs or spawning another agent.
$mutex = New-Object Threading.Mutex($false, 'Local\kw-agent-serve-launcher')
try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
if (-not $held) { $mutex.Dispose(); exit 0 }
$logDir = Join-Path $env:LOCALAPPDATA 'workspace-agent'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$outLog = Join-Path $logDir 'serve.log'
$errLog = Join-Path $logDir 'serve-error.log'
try {
  foreach ($log in @($outLog, $errLog)) {
    if (Test-Path -LiteralPath $log) { Copy-Item -LiteralPath $log -Destination "$log.previous" -Force }
  }
  $options = Get-Content -LiteralPath (Join-Path $DataDir 'public\serve-options.json') -Raw | ConvertFrom-Json
  if ($DataDir.Contains('"')) { throw 'DataDir cannot contain double quotes' }
  # Start-Process redirects native stderr without PowerShell 5.1 converting
  # each log line into a NativeCommandError (or terminating the agent).
  $arguments = "serve --data-dir `"$DataDir`" --bind 0.0.0.0 --port 44787 $($options.extraServeArgs)"
  $process = Start-Process -FilePath (Join-Path $PSScriptRoot 'kw-agent.exe') `
    -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait `
    -RedirectStandardOutput $outLog -RedirectStandardError $errLog
  exit $process.ExitCode
} catch {
  Add-Content -LiteralPath $errLog -Value "Desktop agent launcher: $($_.Exception.Message)"
  exit 1
} finally {
  $mutex.ReleaseMutex()
  $mutex.Dispose()
}
