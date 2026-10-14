#Requires -Version 5.1
#Requires -RunAsAdministrator
# Isolated SCM/process test: unique service, identity, binary and port. No live
# service/task/Run registration changes. Default tests use no capture/audio;
# optional CaptureProof verifies read-only media, never clipboard/input/resize.
param([Parameter(Mandatory=$true)][string]$AgentPath, [switch]$CaptureProof)
$ErrorActionPreference = 'Stop'
$name = 'KwAgentTest-' + [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData $name
$bin = Join-Path $root 'bin'
$data = Join-Path $root 'data'
$workerPids = @()
$workerArgs = @()
if ($CaptureProof) { $workerArgs = @('--capture-video','--capture-audio') }
function Test-Media($Port) {
  $client = New-Object Net.Sockets.TcpClient
  try {
    $client.Connect('127.0.0.1',$Port)
    $stream = $client.GetStream(); $stream.ReadTimeout = 15000
    function Read-Exactly($Count) {
      $bytes = New-Object byte[] $Count; $offset=0
      while($offset -lt $Count) { $n=$stream.Read($bytes,$offset,$Count-$offset); if($n -le 0) { throw 'Worker closed media connection' }; $offset += $n }
      return ,$bytes
    }
    function Read-Frame {
      $header=Read-Exactly 5
      $length=([long]$header[1]*16777216)+([long]$header[2]*65536)+([long]$header[3]*256)+$header[4]
      if($length -le 0 -or $length -gt 8388613) { throw 'Invalid media frame length' }
      [pscustomobject]@{Tag=$header[0];Body=(Read-Exactly $length)}
    }
    $hello=[Text.Encoding]::UTF8.GetString((Read-Frame).Body) | ConvertFrom-Json
    $ticket=@{workspaceUid='00000000-0000-4000-8000-000000000001';workspaceGeneration='test-generation';sessionId=$hello.sessionId;participant='isolated-service-proof';role='controller';controlEpoch=1;audience='workspace-agent';expiresAtNs=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+60000)*1000000}
    $message=@{protocol='kw-agent-v1';protocolVersion=1;sessionId=$hello.sessionId;generation=1;sequence=2;sentAtNs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()*1000000;channel='control';type='attach';payload=@{ticket=$ticket}}
    $body=[Text.Encoding]::UTF8.GetBytes(($message | ConvertTo-Json -Depth 6 -Compress))
    $header=New-Object byte[] 5; $header[0]=0
    $header[1]=($body.Length -shr 24) -band 255; $header[2]=($body.Length -shr 16) -band 255; $header[3]=($body.Length -shr 8) -band 255; $header[4]=$body.Length -band 255
    $stream.Write($header,0,5); $stream.Write($body,0,$body.Length)
    $result=[Text.Encoding]::UTF8.GetString((Read-Frame).Body) | ConvertFrom-Json
    if(-not $result.payload.admitted) { throw 'Isolated native worker refused its enrolled binding' }
    $video=0; $audio=0; $end=(Get-Date).AddSeconds(5)
    do { $frame=Read-Frame; if($frame.Tag -eq 1) { $video++ }; if($frame.Tag -eq 2) { $audio++ } } while((Get-Date) -lt $end)
    if($video -eq 0) { throw 'Native worker did not deliver desktop video' }
    Write-Output "Native user-token desktop media passed: $video video packets, $audio audio packets, $($hello.payload.capture.width)x$($hello.payload.capture.height)"
  } finally { $client.Dispose() }
}
function Wait-State($Predicate) {
  $end = (Get-Date).AddSeconds(40)
  do {
    try {
      $snapshot = Get-Content (Join-Path $data 'service-status.json') -Raw | ConvertFrom-Json
      if (& $Predicate $snapshot) { return $snapshot }
    } catch { }
    Start-Sleep -Milliseconds 250
  } while ((Get-Date) -lt $end)
  throw "Native service state timed out; logs: $data\logs"
}
try {
  New-Item -ItemType Directory -Path $bin, $data -Force | Out-Null
  # Service binary is machine-owned and readable by the test console user.
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','ReadAndExecute'))) {
    $sid = New-Object Security.Principal.SecurityIdentifier($entry[0])
    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,$entry[1],'ContainerInherit,ObjectInherit','None','Allow')))
  }
  (Get-Item $root).SetAccessControl($acl)
  $exe = Join-Path $bin 'kw-agent.exe'
  Copy-Item -LiteralPath $AgentPath -Destination $exe
  $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
  $listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop()
  [IO.File]::WriteAllText((Join-Path $data 'service.json'), (@{workerEnabled=$false;port=$port;workerArgs=$workerArgs} | ConvertTo-Json))
  New-Service -Name $name -BinaryPathName "`"$exe`" service --service-name $name --data-dir `"$data`"" -StartupType Manual | Out-Null
  & $exe service-configure --service-name $name
  if ($LASTEXITCODE -ne 0) { throw 'Native service recovery setup failed' }
  Start-Service $name
  $snapshot = Wait-State { param($s) $s.state -eq 'awaiting-enrollment' }
  if ($snapshot.workerPid) { throw 'Unconfigured service started a worker' }
  [IO.File]::WriteAllText((Join-Path $data 'identity.json'), (@{agentKeyHex='private-test-key';workspaceUid='00000000-0000-4000-8000-000000000001';workspaceGeneration='test-generation';enrolledAt=1} | ConvertTo-Json))
  $snapshot = Wait-State { param($s) $s.state -eq 'no-console-worker' }
  $keyHash = (Get-FileHash (Join-Path $data 'identity.json')).Hash
  [IO.File]::WriteAllText((Join-Path $data 'service.json'), (@{workerEnabled=$true;port=$port;workerArgs=$workerArgs} | ConvertTo-Json))
  $snapshot = Wait-State { param($s) $s.workerEnabled -eq $true -and ($s.state -eq 'worker-process-running' -or ($s.state -eq 'no-console-worker' -and $null -eq $s.consoleSession)) }
  if ($snapshot.workerPid) {
    $first = [int]$snapshot.workerPid; $workerPids += $first
    # Wait for native log setup and listener rather than trusting process liveness.
    $end = (Get-Date).AddSeconds(15)
    do { $connection = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue; if ($connection) { break }; Start-Sleep -Milliseconds 250 } while ((Get-Date) -lt $end)
    if (-not $connection -or $connection.OwningProcess -ne $first) { throw 'Worker listener did not become available' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$first"
    if ($process.SessionId -eq 0) { throw 'Desktop worker was launched in Session 0' }
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    if ($owner.Sid -eq 'S-1-5-18') { throw 'Desktop worker is running as SYSTEM' }
    if ($CaptureProof) { Test-Media $port }
    if ($snapshot.mediaReady -ne $null) { throw 'Process liveness was mislabeled as media readiness' }
    Stop-Process -Id $first -Force
    $snapshot = Wait-State { param($s) $s.workerPid -and [int]$s.workerPid -ne $first }
    $workerPids += [int]$snapshot.workerPid
    Write-Output 'Console worker launch and crash restart passed'
    $previous = [int]$snapshot.workerPid
    [IO.File]::WriteAllText((Join-Path $data 'service.json'), (@{workerEnabled=$false;port=$port;workerArgs=$workerArgs} | ConvertTo-Json))
    $null = Wait-State { param($s) $s.workerEnabled -eq $false -and -not $s.workerPid }
    if (Get-Process -Id $previous -ErrorAction SilentlyContinue) { throw 'Worker removal left the old session process alive' }
    [IO.File]::WriteAllText((Join-Path $data 'service.json'), (@{workerEnabled=$true;port=$port;workerArgs=$workerArgs} | ConvertTo-Json))
    $snapshot = Wait-State { param($s) $s.workerPid -and [int]$s.workerPid -ne $previous }
    $workerPids += [int]$snapshot.workerPid
  } else {
    if ($CaptureProof) { throw 'CaptureProof requires an unlocked logged-in console' }
    Write-Output 'No eligible logged-in console on this runner; console-worker acceptance not claimed'
  }
  Stop-Service $name
  (Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
  foreach ($pidValue in $workerPids) { if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) { throw 'Service stop left an owned worker alive' } }
  Start-Service $name
  $snapshot = Wait-State { param($s) $s.serviceState -eq 'running' -and ($s.workerPid -or $s.state -eq 'no-console-worker') }
  if ($snapshot.workerPid) { $workerPids += [int]$snapshot.workerPid }
  $oldService = Get-CimInstance Win32_Service | Where-Object Name -eq $name
  $oldServicePid = $oldService.ProcessId
  $oldWorkerPid = $snapshot.workerPid
  Stop-Process -Id $oldServicePid -Force
  $deadline = (Get-Date).AddSeconds(30)
  do {
    Start-Sleep -Milliseconds 250
    $recovered = Get-CimInstance Win32_Service | Where-Object Name -eq $name
  } while (($recovered.State -ne 'Running' -or $recovered.ProcessId -eq $oldServicePid) -and (Get-Date) -lt $deadline)
  if ($recovered.State -ne 'Running' -or $recovered.ProcessId -eq $oldServicePid) { throw 'SCM crash recovery failed' }
  if ($oldWorkerPid) {
    if (Get-Process -Id $oldWorkerPid -ErrorAction SilentlyContinue) { throw 'Service crash left an orphan worker job' }
    $snapshot = Wait-State { param($s) $s.workerPid -and $s.workerPid -ne $oldWorkerPid }
    $workerPids += [int]$snapshot.workerPid
  }
  Stop-Service $name
  (Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
  if ((Get-FileHash (Join-Path $data 'identity.json')).Hash -ne $keyHash) { throw 'Service restart changed identity' }
  foreach ($pidValue in $workerPids) { if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) { throw 'Final stop left a worker alive' } }
  Write-Output 'SCM crash recovery and job-owned orphan cleanup passed'
  Write-Output 'Native SCM start, unconfigured state, stop, restart and identity preservation passed'
} finally {
  $service = Get-Service $name -ErrorAction SilentlyContinue
  if ($service) {
    Stop-Service $name -ErrorAction SilentlyContinue
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    & sc.exe delete $name | Out-Null
    $service.Dispose()
  }
  if (Test-Path $root) { Remove-Item $root -Recurse -Force }
  foreach ($profile in @(Get-CimInstance Win32_UserProfile | Where-Object LocalPath)) {
    $logs = Join-Path $profile.LocalPath 'AppData\Local\workspace-agent'
    if (Test-Path $logs) {
      Get-ChildItem -LiteralPath $logs -Filter "worker-$name.*" -File | Remove-Item -Force
    }
  }
}
