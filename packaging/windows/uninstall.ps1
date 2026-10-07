#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstall kw-agent v0.1: stop/remove the task, delete binaries and data.
.DESCRIPTION
  Removes identity.json too — use only on disposable guests or when a fresh
  enrollment is intended. Product Reset semantics are owned by the platform,
  not this script.
#>
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'workspace-agent'),
    [string]$BinDir = (Join-Path $env:ProgramFiles 'workspace-agent')
)
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName 'workspace-agent'
Unregister-ScheduledTask -TaskName 'workspace-agent' -Confirm:$false
Remove-Item -LiteralPath $BinDir -Recurse -Force
Remove-Item -LiteralPath $DataDir -Recurse -Force
Write-Output 'workspace-agent removed'
