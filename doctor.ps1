#Requires -Version 5.1
<#
.SYNOPSIS
    Check that an installed data guard is still intact and running.

.DESCRIPTION
    Run this after a Python upgrade, after editing the guard, when a project
    starts behaving oddly, or on any day you want to be sure. It reports what
    it finds and changes nothing.

    The most important failure it catches is a stale Python path. The hook
    pins an absolute interpreter path at install time, and if Python moves,
    Claude Code logs an error and carries on. The deny rules would still apply
    but the hook would not, and nothing would announce that.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$claudeDir    = Join-Path $env:USERPROFILE '.claude'
$hooksDir     = Join-Path $claudeDir 'hooks'
$settingsPath = Join-Path $claudeDir 'settings.json'
$guardPath    = Join-Path $hooksDir 'data_guard.py'
$configPath   = Join-Path $hooksDir 'guard_config.json'

$problems = @()
function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '', [string]$Fix = '')
    if ($Ok) {
        Write-Host ("  [ok  ] {0}" -f $Label) -ForegroundColor Green
        if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
    } else {
        Write-Host ("  [FAIL] {0}" -f $Label) -ForegroundColor Red
        if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
        $script:problems += @{ Label = $Label; Fix = $Fix }
    }
}

Write-Host "`nData guard health check`n" -ForegroundColor White

$runnerPath = Join-Path $hooksDir 'run_checked.py'
# Names earlier versions installed under. Either one left behind means a half
# upgraded install, where the guard permits one file and a different one sits
# in the folder.
$staleNames = @('claude-sandbox.cmd', 'run_sandboxed.py')
$stalePaths = @($staleNames | ForEach-Object { Join-Path $hooksDir $_ } |
    Where-Object { Test-Path $_ })

Check 'Guard hook present' (Test-Path $guardPath) $guardPath 'Run install.ps1'
Check 'Guard config present' (Test-Path $configPath) $configPath 'Run install.ps1'
Check 'Runner present' (Test-Path $runnerPath) $runnerPath `
    'Run install.ps1. Without it Claude cannot execute anything, which is safe but unhelpful.'
Check 'No files from an earlier version' ($stalePaths.Count -eq 0) ($stalePaths -join ', ') `
    'Re-run install.ps1, which removes them.'

$folderNames = @()
if (Test-Path $configPath) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        $folderNames = @(@($config.protected_folders) | Where-Object { $_ })
        Check 'Guard config parses' ($folderNames.Count -gt 0) ("data folders: " + ($folderNames -join ', ')) 'Fix guard_config.json by hand'

        $runnerPython = $config.runner_python
        $runnerScript = $config.runner_script
        Check 'Runner paths pinned' ($runnerPython -and $runnerScript) `
            "$runnerPython $runnerScript" `
            'Run install.ps1. Without these the guard permits no execution at all.'
        if ($runnerPython) {
            Check 'Pinned runner interpreter exists' (Test-Path $runnerPython) $runnerPython `
                'Python moved. Re-run install.ps1 to repoint it.'
        }
    } catch {
        Check 'Guard config parses' $false $_.Exception.Message 'Fix guard_config.json by hand'
    }
}

$settings = $null
if (Test-Path $settingsPath) {
    try { $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json; Check 'Settings parse' $true $settingsPath }
    catch { Check 'Settings parse' $false $_.Exception.Message 'Fix the JSON by hand, or restore a .backup- copy' }
} else {
    Check 'Settings present' $false $settingsPath 'Run install.ps1'
}

$hookCommand = $null
if ($settings -and $settings.hooks -and $settings.hooks.PreToolUse) {
    foreach ($entry in @($settings.hooks.PreToolUse)) {
        foreach ($h in @($entry.hooks)) {
            if ($h.command -like '*data_guard.py*') { $hookCommand = $h.command }
        }
    }
}
Check 'Hook registered' ($null -ne $hookCommand) $hookCommand 'Run install.ps1'

# The stale interpreter check, which is the whole reason this script exists.
$pythonPath = $null
if ($hookCommand -match '^"([^"]+)"') { $pythonPath = $Matches[1] }
if ($pythonPath) {
    Check 'Hook interpreter exists' (Test-Path $pythonPath) $pythonPath `
        'Python moved or was upgraded. Re-run install.ps1 to repoint the hook.'

    # Existing is not the same as working. py.exe can be present and still fail
    # to find a Python, and a pinned python.exe can be present and broken. The
    # only honest check is to run the guard the way Claude Code runs it and
    # require the answer we depend on.
    if ((Test-Path $pythonPath) -and (Test-Path $guardPath) -and $folderNames.Count -gt 0) {
        $payload = '{"tool_name":"Read","tool_input":{"file_path":"./' +
                   $folderNames[0] + '/__probe__.csv"}}'
        $answer = ''
        try { $answer = "$($payload | & $pythonPath $guardPath 2>&1)" } catch { $answer = "$_" }
        $refused = $answer -match '"permissionDecision":\s*"deny"'
        Check 'Hook interpreter actually runs the guard' $refused `
            $(if ($refused) { 'a protected path was refused' }
              else { "no refusal came back: $($answer.Trim())" }) `
            'The interpreter cannot start the guard. Re-run install.ps1.'
    }
}

# Every rule install.ps1 recorded must still be in settings.json. A count
# threshold said nothing useful once most of the list became generated: it
# passed while the rule that mattered was missing.
$currentDeny = @()
if ($settings -and $settings.permissions -and $settings.permissions.deny) {
    $currentDeny = @($settings.permissions.deny)
}
# Filtered: @($null).Count is 1 in PowerShell, so a config written before
# installed_deny_rules existed would look like a one-rule list of nothing.
$expectedDeny = @()
if ($config) { $expectedDeny = @(@($config.installed_deny_rules) | Where-Object { $_ }) }

if ($expectedDeny.Count -gt 0) {
    $missing = @($expectedDeny | Where-Object { $currentDeny -notcontains $_ })
    $detail = if ($missing.Count -gt 0) { "missing: " + ($missing -join ', ') }
              else { "$($expectedDeny.Count) rules, all present" }
    Check 'Deny rules intact' ($missing.Count -eq 0) $detail 'Run install.ps1'
} else {
    Check 'Deny rules recorded' $false "$($currentDeny.Count) rules in settings, none recorded in the config" `
        'Run install.ps1, which records what it installs so this can be checked.'
}

$terminalDenied = $false
if ($settings -and $settings.permissions -and $settings.permissions.deny) {
    $terminalDenied = @($settings.permissions.deny) -contains 'mcp__terminal__read_terminal'
}
# LAB_DATA_ROOT belonged to an earlier design where data lived outside the
# project. It means nothing now, and a stale one pointing at a folder that is
# no longer special is worth flagging rather than ignoring.
$stale = [Environment]::GetEnvironmentVariable('LAB_DATA_ROOT', 'User')
Check 'No stale LAB_DATA_ROOT' (-not $stale) $stale `
    'Left over from an older version. Re-run install.ps1, which clears it.'

Check 'Terminal read channel closed' $terminalDenied `
    'Without this, anything printed in the Claude Code terminal panel is readable.' `
    'Run install.ps1'

if ((Test-Path $guardPath) -and $pythonPath -and (Test-Path $pythonPath)) {
    Write-Host "`nRunning the guard test suite`n" -ForegroundColor White
    & $pythonPath (Join-Path $PSScriptRoot 'guard\test_guard.py') $guardPath
    if ($LASTEXITCODE -ne 0) { $problems += @{ Label = 'Guard tests'; Fix = 'See the failures above' } }

    if (Test-Path $runnerPath) {
        Write-Host "`nRunning the runner test suite`n" -ForegroundColor White
        & $pythonPath (Join-Path $PSScriptRoot 'guard\test_runner.py') $runnerPath
        if ($LASTEXITCODE -ne 0) { $problems += @{ Label = 'Runner tests'; Fix = 'See the failures above' } }
    }
}

Write-Host ''
if ($problems.Count -eq 0) {
    Write-Host 'No problems found.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'This still does not prove Claude Code is calling the hook. Open a'
    Write-Host 'session and paste this in:'
    Write-Host ''
    if ($folderNames.Count -gt 0) {
        Write-Host ("    read ./" + $folderNames[0] + "/__probe__.csv") -ForegroundColor Cyan
    }
    Write-Host ''
    Write-Host 'It must refuse. That file does not exist, so being told it is missing'
    Write-Host 'means the hook is not running.'
    exit 0
}

Write-Host "$($problems.Count) problem(s):" -ForegroundColor Red
foreach ($p in $problems) { Write-Host ("  - {0}: {1}" -f $p.Label, $p.Fix) -ForegroundColor Red }
exit 1
