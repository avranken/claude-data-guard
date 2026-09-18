#Requires -Version 5.1
<#
.SYNOPSIS
    Remove the Claude Code data guard for the current user.

.DESCRIPTION
    Removes only what install.ps1 added: the guard hook registration and the
    deny rules listed in settings\guard_rules.json. Every other setting is
    left untouched, and the file is backed up first.

    This removes protection. Claude Code will be able to read research data in
    any project afterwards. You are asked to confirm.

.PARAMETER KeepFiles
    Leave the guard script and its config in ~\.claude\hooks\.

.PARAMETER Force
    Skip the confirmation prompt.
#>
[CmdletBinding()]
param(
    [switch]$KeepFiles,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$claudeDir    = Join-Path $env:USERPROFILE '.claude'
$hooksDir     = Join-Path $claudeDir 'hooks'
$settingsPath = Join-Path $claudeDir 'settings.json'
$guardPath    = Join-Path $hooksDir 'data_guard.py'
$configPath   = Join-Path $hooksDir 'guard_config.json'

function Get-BytesHash {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
}

function Write-JsonFile {
    param([string]$Path, $Object)
    $json = $Object | ConvertTo-Json -Depth 100
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host "`nThis removes the data guard." -ForegroundColor Yellow
Write-Host "Afterwards Claude Code can read research data in any project." -ForegroundColor Yellow
Write-Host "Your data folders stay exactly where they are. They simply stop" -ForegroundColor Yellow
Write-Host "being refused." -ForegroundColor Yellow

if (-not $Force) {
    $answer = Read-Host "`nType 'remove' to continue"
    if ($answer -ne 'remove') { Write-Host 'Cancelled. Nothing changed.'; exit 0 }
}

if (-not (Test-Path $settingsPath)) {
    Write-Host "No settings file at $settingsPath. Nothing to remove."
} else {
    $backup = "$settingsPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $settingsPath $backup -Force
    Write-Host "Backup: $backup" -ForegroundColor Green

    # Read the bytes once and hash exactly what is parsed. Claude Code writes to
    # this file during a session, so a whole file write-back from a stale
    # snapshot would silently revert whatever it changed in between.
    $originalBytes = [System.IO.File]::ReadAllBytes($settingsPath)
    $settingsHashAtRead = Get-BytesHash $originalBytes
    $raw = [System.Text.Encoding]::UTF8.GetString($originalBytes)
    if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }

    try { $settings = $raw | ConvertFrom-Json }
    catch { Write-Host "settings.json is not valid JSON, so nothing was changed." -ForegroundColor Red; exit 1 }

    # Deny rules. install.ps1 records exactly what it merged, in
    # installed_deny_rules, so this removes exactly that. Reconstructing the
    # list from its parts is what once left rules behind, and most of it is now
    # generated rather than listed anywhere.
    $rulesFile = Join-Path $PSScriptRoot 'settings\guard_rules.json'
    $rules = Get-Content $rulesFile -Raw | ConvertFrom-Json
    $ours = @(@($rules.retired) | Where-Object { $_ })

    $config = $null
    if (Test-Path $configPath) {
        try { $config = Get-Content $configPath -Raw | ConvertFrom-Json } catch { $config = $null }
    }

    # Filter out empties. @($null).Count is 1 in PowerShell, so an array built
    # from a property that does not exist looks populated while containing
    # nothing. That is not hypothetical: it shipped, and it made this script
    # take the 'exact record' branch against a config written before
    # installed_deny_rules existed, removing no deny rules at all while still
    # deleting the guard's files. A half removed install is the worst outcome
    # here, so every list below is filtered.
    $recorded = @()
    if ($config) { $recorded = @(@($config.installed_deny_rules) | Where-Object { $_ }) }

    if ($recorded.Count -gt 0) {
        $ours += $recorded
    } else {
        # No record: a config from before installed_deny_rules existed, or one
        # that cannot be read. Rebuild what can be rebuilt, and say what cannot.
        $ours += @(@($rules.deny) | Where-Object { $_ })

        $folders = @()
        if ($config) { $folders = @(@($config.protected_folders) | Where-Object { $_ }) }
        foreach ($name in $folders) {
            $ours += "Read(./$name/**)"
            $ours += "Read(./**/$name/**)"
        }

        # The interpreter rules too, from the same source install.ps1 generates
        # them from. This runs before any file is deleted, so the guard is still
        # on disk to be read. Without this the fallback leaves sixty rules
        # behind, which is a half removed install by any other name.
        $rebuilt = @()
        $interpreter = $null
        if ($config -and $config.runner_python -and (Test-Path $config.runner_python)) {
            $interpreter = $config.runner_python
        } else {
            $found = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($found) { $interpreter = $found.Source }
        }
        if ($interpreter -and (Test-Path $guardPath)) {
            $reader = "import sys, json; sys.path.insert(0, r'$hooksDir'); import data_guard; print(json.dumps(data_guard.BLOCKED_PROGRAMS))"
            try {
                $rebuilt = @((& $interpreter -c $reader | ConvertFrom-Json) | Where-Object { $_ })
            } catch {
                $rebuilt = @()
            }
        }
        foreach ($program in $rebuilt) {
            $ours += "Bash($program`:*)"
            $capital = $program.Substring(0, 1).ToUpper() + $program.Substring(1)
            if ($capital -cne $program) { $ours += "Bash($capital`:*)" }
        }

        Write-Host "guard_config.json does not record what was installed, so the" -ForegroundColor Yellow
        Write-Host "rules were rebuilt from its folder names and the guard itself." -ForegroundColor Yellow
        if ($folders.Count -eq 0) {
            Write-Host "It lists no folder names, so per folder rules could not be" -ForegroundColor Yellow
            Write-Host "rebuilt. Check permissions.deny for leftover Read(./<folder>/**)." -ForegroundColor Yellow
        }
        if ($rebuilt.Count -eq 0) {
            Write-Host "The blocked program list could not be read, so check" -ForegroundColor Yellow
            Write-Host "permissions.deny for leftover Bash(<program>:*) rules." -ForegroundColor Yellow
        }
    }

    if ($settings.permissions -and $settings.permissions.deny) {
        $before = @($settings.permissions.deny)
        # Exact comparison, not -like. Nearly every rule here contains a '*',
        # and several contain brackets, so wildcard matching would let one rule
        # remove others that merely resemble it.
        $kept = @($before | Where-Object { $ours -notcontains $_ })
        $settings.permissions.deny = $kept
        Write-Host "Deny rules: $($before.Count) before, $($kept.Count) after" -ForegroundColor Green
    }

    # Hooks: remove any PreToolUse entry pointing at the guard.
    if ($settings.hooks -and $settings.hooks.PreToolUse) {
        $before = @($settings.hooks.PreToolUse)
        $kept = @($before | Where-Object {
            $entry = $_
            -not (@($entry.hooks) | Where-Object { $_.command -like '*data_guard.py*' })
        })
        $settings.hooks.PreToolUse = $kept
        Write-Host "Hook entries: $($before.Count) before, $($kept.Count) after" -ForegroundColor Green
    }

    # Staleness check, immediately before the write. A mismatch means the file
    # moved on since it was read, and this copy would revert it. Refuse rather
    # than guess: nothing here can merge two concurrent edits.
    $hashNow = Get-BytesHash ([System.IO.File]::ReadAllBytes($settingsPath))
    if ($hashNow -ne $settingsHashAtRead) {
        Write-Host ""
        Write-Host "$settingsPath changed while this was running." -ForegroundColor Red
        Write-Host "Nothing was written. Your settings are untouched, and the backup is at:"
        Write-Host "  $backup"
        Write-Host ""
        Write-Host "Claude Code writes to this file during a session, so the usual cause is"
        Write-Host "having one open. Close any running session and try again."
        Write-Host ""
        Write-Host "The guard has NOT been removed." -ForegroundColor Yellow
        exit 1
    }

    Write-JsonFile $settingsPath $settings
    Write-Host "Updated: $settingsPath" -ForegroundColor Green
}

if ($KeepFiles) {
    Write-Host "Left in place: $guardPath"
} else {
    # Every file install.ps1 puts here, including the names earlier versions
    # used: claude-sandbox.cmd from the shim, and run_sandboxed.py from before
    # the runner was renamed. Leaving one behind is how someone ends up with a
    # half removed install and no way to tell which half.
    $installed = @(
        $guardPath,
        $configPath,
        (Join-Path $hooksDir 'run_checked.py'),
        (Join-Path $hooksDir 'run_sandboxed.py'),
        (Join-Path $hooksDir 'claude-sandbox.cmd')
    )
    foreach ($path in $installed) {
        if (Test-Path $path) { Remove-Item $path -Force; Write-Host "Removed: $path" -ForegroundColor Green }
    }
    $cache = Join-Path $hooksDir '__pycache__'
    if (Test-Path $cache) { Remove-Item $cache -Recurse -Force; Write-Host "Removed: $cache" -ForegroundColor Green }
}

if ([Environment]::GetEnvironmentVariable('LAB_DATA_ROOT', 'User')) {
    [Environment]::SetEnvironmentVariable('LAB_DATA_ROOT', $null, 'User')
    Write-Host "Removed: LAB_DATA_ROOT, left over from an older version" -ForegroundColor Green
}

Write-Host "`nDone. Your research data is no longer protected from Claude Code." -ForegroundColor Yellow
Write-Host "Project level settings files, if any, are untouched."
