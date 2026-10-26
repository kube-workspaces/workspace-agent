#Requires -Version 5.1
#Requires -RunAsAdministrator
# Run exactly the privileged Rust script test in an isolated SYSTEM task. No
# installed agent, workspace identity, capture, network or live service is used.
$ErrorActionPreference = 'Stop'
$name = 'KwManagementScriptTest-' + [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData $name
$registered = $false
try {
    $messages = & cargo test -p kw-agent --no-run --locked --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the Windows script test binary' }
    $artifacts = @($messages | ForEach-Object {
        $value = $_ | ConvertFrom-Json
        if ($value.reason -eq 'compiler-artifact' -and $value.target.name -eq 'kw-agent' -and $value.profile.test -and $value.executable) {
            $value.executable
        }
    })
    if ($artifacts.Count -ne 1) { throw 'Expected exactly one kw-agent unit-test executable' }
    $exe = $artifacts[0]
    New-Item -ItemType Directory -Path $root | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $admin = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($admin)
    foreach ($id in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($id)
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    (Get-Item $root).SetAccessControl($acl)
    $runner = Join-Path $root 'run.ps1'
    $script = @'
$ErrorActionPreference = 'Stop'
$root = '__ROOT__'
$env:TEMP = $root
$env:TMP = $root
$env:SystemTemp = $root
$env:RUST_BACKTRACE = '1'
$code = 1
try {
    & '__TEST_EXE__' --exact management_exec::scripts::tests::system_script_acl_file_execution_and_recovery --ignored --nocapture *> (Join-Path $root 'result.log')
    $code = $LASTEXITCODE
} catch {
    $_ | Out-String | Add-Content (Join-Path $root 'result.log')
} finally {
    # A failed assertion can leave SYSTEM-only test directories. Clean them as
    # SYSTEM, while retaining the test log and result for the calling CI user.
    Get-ChildItem -LiteralPath $root -Directory -Filter 'kw-script-test-*' | Remove-Item -Recurse -Force
    [IO.File]::WriteAllText((Join-Path $root 'exit-code'), [string]$code)
}
exit $code
'@
    $script = $script.Replace('__ROOT__', $root.Replace("'", "''")).Replace('__TEST_EXE__', $exe.Replace("'", "''"))
    [IO.File]::WriteAllText($runner, $script, (New-Object Text.UTF8Encoding($true)))
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    Start-ScheduledTask -TaskName $name
    $end = (Get-Date).AddSeconds(120)
    while (-not (Test-Path (Join-Path $root 'exit-code'))) {
        if ((Get-Date) -ge $end) { throw 'SYSTEM script test timed out' }
        Start-Sleep -Milliseconds 250
    }
    $log = Get-Content (Join-Path $root 'result.log') -Raw
    Write-Output $log
    $code = [int](Get-Content (Join-Path $root 'exit-code') -Raw)
    if ($code -ne 0 -or $log -notmatch 'test result: ok\. 1 passed;') { throw 'SYSTEM script test failed or did not execute exactly one test' }
} finally {
    if ($registered) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
