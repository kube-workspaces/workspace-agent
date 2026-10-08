#Requires -Version 5.1
# Read the actual MSI tables (not just the WiX source). COM methods/properties
# use IDispatch explicitly so Windows PowerShell and PowerShell 7 behave alike.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [Parameter(Mandatory = $true)][ValidateSet("amd64", "arm64")][string]$Arch,
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$StagingDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Invoke-Com($Object, [string]$Name, [object[]]$Arguments) {
  $Object.GetType().InvokeMember($Name, "InvokeMethod", $null, $Object, $Arguments)
}
function Get-Com($Object, [string]$Name, [object[]]$Arguments) {
  $Object.GetType().InvokeMember($Name, "GetProperty", $null, $Object, $Arguments)
}
function Read-Rows([string]$Query, [int]$Columns) {
  $view = Invoke-Com $db "OpenView" @($Query)
  try {
    Invoke-Com $view "Execute" @() | Out-Null
    while ($record = Invoke-Com $view "Fetch" @()) {
      try {
        $values = @(for ($i = 1; $i -le $Columns; $i++) { Get-Com $record "StringData" @($i) })
        ,$values
      } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    }
  } finally {
    Invoke-Com $view "Close" @() | Out-Null
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
  }
}
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $null
$summary = $null
try {
  $db = Invoke-Com $installer "OpenDatabase" @((Resolve-Path $Path).Path, 0)
  $properties = @{}
  Read-Rows 'SELECT `Property`, `Value` FROM `Property`' 2 | ForEach-Object { $properties[$_[0]] = $_[1] }
  # Files-only per-machine package: the agent runs machine-wide, so the
  # package must default to ALLUSERS=1 (dual-scope would let a silent
  # per-user install shadow Program Files and break upgrade detection).
  if ($properties.ALLUSERS -ne '1') {
    throw "Agent MSI must default to per-machine (ALLUSERS=1), got '$($properties.ALLUSERS)'."
  }
  if ($properties.ProductVersion -ne $Version) { throw "Incorrect ProductVersion: $($properties.ProductVersion)" }
  if ($properties.UpgradeCode -ne "{F72BB43E-DBA8-4DBB-A963-B201E6C0D885}") { throw "UpgradeCode changed." }
  if ($properties.ContainsKey('ARPINSTALLLOCATION')) { throw "ARPINSTALLLOCATION must not be a Property-table row: such values reach the uninstall key literally." }
  $actions = @(Read-Rows 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4)
  $setLoc = @($actions | Where-Object { $_[0] -eq 'SetARPINSTALLLOCATION' })
  if ($setLoc.Count -ne 1 -or $setLoc[0][1] -ne '51' -or $setLoc[0][2] -ne 'ARPINSTALLLOCATION' -or $setLoc[0][3] -ne '[INSTALLDIR]') {
    throw "ARPINSTALLLOCATION must be assigned from [INSTALLDIR] by a type-51 action, or the uninstall key records the literal text and blinds upgrade detection."
  }
  $seq = @{}
  Read-Rows 'SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`' 2 | ForEach-Object { $seq[$_[0]] = [int]$_[1] }
  if (-not $seq.ContainsKey('SetARPINSTALLLOCATION') -or -not $seq.ContainsKey('CostFinalize') -or $seq['SetARPINSTALLLOCATION'] -le $seq['CostFinalize']) {
    throw "SetARPINSTALLLOCATION must run after CostFinalize so the registry holds the resolved directory."
  }
  $summary = Get-Com $db "SummaryInformation" @(0)
  $template = Get-Com $summary "Property" @(7)
  $expected = @{ amd64 = "x64"; arm64 = "Arm64" }[$Arch]
  if ($template -ne "$expected;1033") { throw "Incorrect MSI architecture: $template" }
  $files = @(Read-Rows 'SELECT `File`, `FileName`, `FileSize` FROM `File`' 3)
  $names = @()
  foreach ($file in $files) {
    $name = ($file[1] -split '\|')[-1]
    $names += $name
    $source = Get-Item -LiteralPath (Join-Path $StagingDir $name)
    if ($source.Length -ne [long]$file[2]) { throw "Payload size mismatch: $name" }
  }
  # Generator contract (build-msi.ps1): the agent exe carries the fixed File
  # Id AgentExe so tooling can address it without parsing the File table.
  $agentFile = @($files | Where-Object { $_[0] -eq 'AgentExe' })
  if ($agentFile.Count -ne 1 -or $agentFile[0][1] -notlike '*kw-agent.exe') {
    throw "Agent exe must be authored with File Id 'AgentExe'."
  }
  $staged = @(Get-ChildItem $StagingDir -File | Where-Object { $_.Extension -in @('.exe', '.ps1') } | ForEach-Object { $_.Name })
  if (Compare-Object $staged $names) { throw "MSI payload differs from the staged archive (exe + enrollment scripts)." }
  $dialogs = @(Read-Rows 'SELECT `Dialog` FROM `Dialog`' 1 | ForEach-Object { $_[0] })
  # WixUI_Minimal: welcome, progress, exit — nothing more (no license or
  # scope dialogs for a files-only agent package).
  foreach ($required in @('WelcomeDlg', 'ProgressDlg', 'ExitDialog')) {
    if ($dialogs -notcontains $required) { throw "Missing installer dialog: $required" }
  }
  Write-Host "Verified MSI: $template, version $Version, per-machine default, $($names.Count) payload files."
} finally {
  foreach ($object in @($summary, $db, $installer)) {
    if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
  }
}
