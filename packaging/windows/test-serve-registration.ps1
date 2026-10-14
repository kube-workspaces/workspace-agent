#Requires -Version 5.1
# Isolated registration regression: real agent/ACLs, mocked Task Scheduler and
# profile lookup. Never changes host tasks, Run values or a live enrollment.
param([Parameter(Mandatory=$true)][string]$AgentPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$bin = Join-Path $root 'bin with spaces'
$data = Join-Path $root 'data with spaces'
$uid = '00000000-0000-4000-8000-000000000001'
$generation = 'opaque-generation:v2'
# An ordinary desktop principal, distinct from the elevated test runner.
$sid = 'S-1-5-21-111111111-222222222-333333333-1001'
$global:KwServeTestRegistrations = @()

function New-ScheduledTaskAction { param($Execute, $Argument); [pscustomobject]@{Execute=$Execute;Arguments=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$AtLogOn, $User); [pscustomobject]@{Delay='';User=$User} }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel); [pscustomobject]@{UserId=$UserId} }
function New-ScheduledTaskSettingsSet { param($RestartCount, $RestartInterval, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, $ExecutionTimeLimit, [switch]$StartWhenAvailable, [switch]$Hidden); [pscustomobject]@{Hidden=$Hidden.IsPresent} }
function Get-Service { param($Name, $ErrorAction); return $null }
function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force); $global:KwServeTestRegistrations += $Action }
function Get-CimInstance { param($ClassName, $Filter, $ErrorAction); return $null }
function Get-AccessSnapshot($Path) {
  $acl = Get-Acl -LiteralPath $Path
  # Windows can add the auto-inherited (AI) descriptor flag when a parent's
  # DACL is updated, without changing a single ACE. Compare access semantics,
  # ownership and inheritance protection, not that bookkeeping flag.
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
    ForEach-Object {
      '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights,
        $_.AccessControlType, $_.IsInherited, $_.InheritanceFlags, $_.PropagationFlags
    } | Sort-Object)
  [ordered]@{
    Owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Group = $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    Protected = $acl.AreAccessRulesProtected
    Rules = $rules
  } | ConvertTo-Json -Compress
}
function Assert-Fails($Overrides, $Expected) {
  $before = $global:KwServeTestRegistrations.Count
  $failed = $false
  try {
    & (Join-Path $PSScriptRoot 'Register-ServeTask.ps1') -BinDir $bin -DataDir $data -UserSid $sid @Overrides | Out-Null
  } catch {
    $failed = $true
    if ($_.Exception.Message -notmatch $Expected) { throw "Unexpected error: $_" }
  }
  if (-not $failed) { throw 'Invalid registration was accepted' }
  if ($global:KwServeTestRegistrations.Count -ne $before) { throw 'Invalid input changed startup registration' }
}
try {
  New-Item -ItemType Directory -Path $bin, $data -Force | Out-Null
  # Match install.ps1 rather than inheriting the runner's TEMP permissions.
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($accountSid in @('S-1-5-18', 'S-1-5-32-544')) {
    $account = New-Object Security.Principal.SecurityIdentifier($accountSid)
    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
      $account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  (Get-Item -LiteralPath $data).SetAccessControl($acl)
  Copy-Item -LiteralPath $AgentPath -Destination (Join-Path $bin 'kw-agent.exe')
  $identity = @{agentKeyHex='private-test-key';workspaceUid=$uid;workspaceGeneration=$generation;enrolledAt=1}
  [IO.File]::WriteAllText((Join-Path $data 'identity.json'), ($identity | ConvertTo-Json))
  New-Item -ItemType Directory -Path (Join-Path $data 'public') | Out-Null
  [IO.File]::WriteAllText((Join-Path $data 'public\binding.json'), (@{workspaceUid=$uid;workspaceGeneration=$generation} | ConvertTo-Json))
  $privateAcl = Get-AccessSnapshot (Join-Path $data 'identity.json')
  Assert-Fails @{WorkspaceUid=($uid+'0')} 'validat|pattern'
  Assert-Fails @{WorkspaceUid='00000000-0000-4000-8000-000000000002'} 'UID mismatch|validation failed'
  Assert-Fails @{WorkspaceGeneration='mistyped'} 'generation mismatch|validation failed'
  Assert-Fails @{ExtraServeArgs='--data-dir other'} 'cannot override'
  & (Join-Path $PSScriptRoot 'Register-ServeTask.ps1') -BinDir $bin -DataDir $data -UserSid $sid | Out-Null
  if ($global:KwServeTestRegistrations.Count -ne 1) { throw 'Expected exactly one registration' }
  $action = $global:KwServeTestRegistrations[0]
  if ($action.Arguments -notmatch 'Start-Serve.ps1' -or $action.Arguments -notmatch '-WindowStyle Hidden') { throw 'Hidden launcher missing' }
  if ($action.Arguments -match 'workspace-uid|workspace-generation') { throw 'Registration duplicated identity values' }
  $afterAcl = Get-AccessSnapshot (Join-Path $data 'identity.json')
  if ($afterAcl -ne $privateAcl) { throw "Private identity access changed: before=$privateAcl after=$afterAcl" }
  $publicAcl = Get-Acl (Join-Path $data 'public')
  $userRule = @($publicAcl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid })
  if ($userRule.Count -ne 1 -or $userRule[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) { throw 'Desktop binding must be read-only' }
  Write-Output 'Desktop registration regression checks passed'
} finally {
  Remove-Variable -Name KwServeTestRegistrations -Scope Global
  if (Test-Path -LiteralPath $root) {
    # Owner can reset the public DACL for cleanup even with a limited token.
    $public = Join-Path $data 'public'
    if (Test-Path -LiteralPath $public) {
      $acl = New-Object Security.AccessControl.DirectorySecurity
      $acl.SetAccessRuleProtection($false, $false)
      (Get-Item -LiteralPath $public).SetAccessControl($acl)
    }
    Remove-Item -LiteralPath $root -Recurse -Force
  }
}
