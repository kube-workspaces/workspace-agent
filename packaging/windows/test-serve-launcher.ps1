#Requires -Version 5.1
# Exercise hidden launch, quoting, native stderr, exit propagation and duplicate
# suppression without starting an agent, opening a port or changing startup.
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$bin = Join-Path $root 'bin with spaces'
$data = Join-Path $root 'data with spaces'
$originalLocalAppData = $env:LOCALAPPDATA
$mutex = $null
try {
  New-Item -ItemType Directory -Path $bin, (Join-Path $data 'public') -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Start-Serve.ps1') -Destination $bin
  Add-Type -TypeDefinition @'
public static class FakeDesktopAgent {
  public static int Main(string[] args) {
    System.Console.WriteLine(string.Join("\n", args));
    System.Console.Error.WriteLine("simulated binding mismatch");
    return 7;
  }
}
'@ -OutputAssembly (Join-Path $bin 'kw-agent.exe') -OutputType ConsoleApplication
  [IO.File]::WriteAllText((Join-Path $data 'public\serve-options.json'),
    (@{extraServeArgs='--capture-output-name "\\.\DISPLAY2"'} | ConvertTo-Json))
  $env:LOCALAPPDATA = Join-Path $root 'local app data'
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $bin 'Start-Serve.ps1')`" -DataDir `"$data`""
  $process = Start-Process $powershell -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -ne 7) { throw "Agent exit code was lost: $($process.ExitCode)" }
  $logDir = Join-Path $env:LOCALAPPDATA 'workspace-agent'
  $out = Get-Content (Join-Path $logDir 'serve.log') -Raw
  $err = Get-Content (Join-Path $logDir 'serve-error.log') -Raw
  if ($out -notlike "*$data*" -or $out -notlike '*DISPLAY2*') { throw 'Arguments with spaces or output names were corrupted' }
  if ($err -notmatch 'simulated binding mismatch' -or $err -match 'NativeCommandError') { throw 'Native stderr was not preserved' }
  $mutex = New-Object Threading.Mutex($true, 'Local\kw-agent-serve-launcher')
  $duplicate = Start-Process $powershell -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  if ($duplicate.ExitCode -ne 0) { throw 'Duplicate launcher did not exit cleanly' }
  if ((Get-Content (Join-Path $logDir 'serve.log') -Raw) -ne $out) { throw 'Duplicate launch changed the active log' }
  $mutex.ReleaseMutex(); $mutex.Dispose(); $mutex = $null
  $again = Start-Process $powershell -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  if ($again.ExitCode -ne 7 -or -not (Test-Path (Join-Path $logDir 'serve-error.log.previous'))) { throw 'Previous launch logs were not retained' }
  Write-Output 'Desktop launcher regression checks passed'
} finally {
  if ($null -ne $mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
  $env:LOCALAPPDATA = $originalLocalAppData
  if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
