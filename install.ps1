#Requires -Version 5.1
<#
.SYNOPSIS
    Install the Claude Code data guard for the current Windows user.

.DESCRIPTION
    Copies the guard hook into ~\.claude\hooks\, writes its machine specific
    config, and merges the deny rules into ~\.claude\settings.json. After this
    the guard applies to every project, with nothing to remember per project.

    This script edits a file you may already depend on. It backs up first,
    merges rather than overwrites, and refuses to continue rather than guess.

.PARAMETER DataFolder
    Extra folder names that hold data, on top of the built in ones. Supplying
    this skips the interactive question, for a scripted install.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -DataFolder Datasets,SPSS
#>
[CmdletBinding()]
param(
    [string[]]$DataFolder
)

$ErrorActionPreference = 'Stop'

# One line per thing that was done, in a fixed column. Everything worth
# reading afterwards is in that column, and everything else stays quiet.
# A long installer gets skimmed, and the one line that matters here is the
# list of protected names at the end.
function Write-Row   { param($k, $v) Write-Host ("  {0,-8} {1}" -f $k, $v) -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  $m" -ForegroundColor Yellow }
function Fail        { param($m) Write-Host "`nABORTED: $m" -ForegroundColor Red; exit 1 }

function Set-Prop {
    param($Object, [string]$Name, $Value)
    if ($Object.PSObject.Properties[$Name]) { $Object.$Name = $Value }
    else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}

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
    # UTF8 without a byte order mark. A BOM breaks some JSON parsers.
    $json = $Object | ConvertTo-Json -Depth 100
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

$repo       = $PSScriptRoot
$claudeDir  = Join-Path $env:USERPROFILE '.claude'
$hooksDir   = Join-Path $claudeDir 'hooks'
$settingsPath = Join-Path $claudeDir 'settings.json'
$guardTarget  = Join-Path $hooksDir 'data_guard.py'
$configTarget = Join-Path $hooksDir 'guard_config.json'

Write-Host "`nClaude Code data guard" -ForegroundColor White

# ---------------------------------------------------------------------------
# Python. Refuse rather than install a guard that can never run. A guard that
# silently does nothing is worse than no guard, because it is trusted.
# ---------------------------------------------------------------------------

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $python) {
    Fail @"
Python was not found on PATH.

The guard hook is a Python script. Without it, only the deny rules would be
installed, which is a real but partial protection, and you would have no way
of knowing which one you had.

Install Python from https://www.python.org/downloads/windows/ or ask IT, then
run this again. Nothing has been changed.
"@
}

$pythonPath = $python.Source
if (-not (Test-Path $pythonPath)) { Fail "Python resolved to '$pythonPath', which does not exist." }

$pythonVersion = (& $pythonPath --version 2>&1) -join ' '

# Prefer the Windows Python launcher to a specific interpreter. A pinned
# python.exe dies the day Python is upgraded or that version is removed, and
# the hook then fails to start. Claude Code logs that and carries on, so the
# protection disappears without announcing itself. py.exe lives in the Windows
# folder, is not tied to a version, and finds whatever Python is installed.
#
# Chosen by test rather than by assumption. On at least one machine here,
# py.exe reports "No installed Python found!" for 'py -0' and yet runs a script
# with a shebang perfectly well, because it resolves '#!/usr/bin/env python'
# through PATH. So the probe is a real script file, which is how the hook is
# actually invoked, and the launcher is used only if the probe works.
function Resolve-HookInterpreter {
    param([string]$Fallback)

    $launcher = Join-Path $env:SystemRoot 'py.exe'
    if (-not (Test-Path $launcher)) { return $Fallback }

    $probe = Join-Path ([System.IO.Path]::GetTempPath()) `
        ("guard-launcher-probe-" + [guid]::NewGuid().ToString('N') + ".py")
    try {
        # The same shebang the guard carries, so this tests the real mechanism.
        Set-Content -Path $probe -Value "#!/usr/bin/env python`nprint('ok')" -Encoding ASCII
        $output = & $launcher $probe 2>&1
        if ($LASTEXITCODE -eq 0 -and "$output".Trim() -eq 'ok') { return $launcher }
    } catch {
        # Any failure at all means fall back. This must never abort the install.
    } finally {
        if (Test-Path $probe) { Remove-Item $probe -Force -ErrorAction SilentlyContinue }
    }
    return $Fallback
}

$hookPython = Resolve-HookInterpreter -Fallback $pythonPath

# ---------------------------------------------------------------------------
# The one question. Researchers keep data in a subfolder of the project, so a
# folder NAME is the whole rule. One answer covers every project, including
# ones that do not exist yet, and nobody has to maintain a list of locations
# that goes stale.
#
# The cost, stated rather than hidden: a data folder called something not on
# the list has no protection at all.
# ---------------------------------------------------------------------------

$defaults = @('data', 'raw', 'staging', 'patients', 'subjects')

$extraFolders = @()
if ($DataFolder) {
    $extraFolders = @($DataFolder)
} elseif (-not $PSBoundParameters.ContainsKey('DataFolder')) {
    Write-Host ''
    Write-Host '  Always treated as data: ' -NoNewline
    Write-Host ($defaults -join ', ') -ForegroundColor Cyan
    Write-Host '  What else do you call folders that hold data? One per line, blank to'
    Write-Host '  finish. A folder named anything else is not protected.'
    while ($true) {
        $answer = Read-Host '  name'
        if ([string]::IsNullOrWhiteSpace($answer)) { break }
        $extraFolders += $answer.Trim()
    }
}

$folderNames = @()
foreach ($name in @($defaults + $extraFolders)) {
    $clean = $name.Trim().Trim('"').Trim('/').Trim('\').ToLower()
    if (-not $clean) { continue }
    if ($clean -match '[\\/:*?"<>|]') {
        Fail "'$clean' must be a plain folder name, not a path."
    }
    if ($folderNames -notcontains $clean) { $folderNames += $clean }
}

Write-Host ''
Write-Row 'Python' "$pythonVersion at $pythonPath"
if ($hookPython -ne $pythonPath) {
    Write-Row 'Launcher' "$hookPython, so the hook survives a Python upgrade"
} else {
    Write-Warn "No usable py.exe, so the hook is pinned to the path above."
    Write-Warn "If Python moves or is upgraded, run doctor.ps1."
}

New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null

# An earlier version kept data outside the project and pointed at it with
# LAB_DATA_ROOT. Data now lives in a subfolder of the project, reached by an
# ordinary relative path, so the variable means nothing. Clear a stale one
# rather than leave it pointing somewhere that is no longer special.
if ([Environment]::GetEnvironmentVariable('LAB_DATA_ROOT', 'User')) {
    [Environment]::SetEnvironmentVariable('LAB_DATA_ROOT', $null, 'User')
    Write-Row 'Cleared' 'LAB_DATA_ROOT, left over from an older version'
}

Copy-Item (Join-Path $repo 'guard\data_guard.py') $guardTarget -Force
Write-Row 'Hook' $guardTarget

# The runner. It lives here rather than in the project so that Claude cannot
# edit it, which is what lets it be trusted to check what it runs even when the
# hook itself is not working.
$runnerTarget = Join-Path $hooksDir 'run_checked.py'
Copy-Item (Join-Path $repo 'guard\run_checked.py') $runnerTarget -Force
Write-Row 'Runner' $runnerTarget

# Names earlier versions used. claude-sandbox.cmd was a shim, abandoned because
# group policy on a managed machine refuses to execute a .cmd outside an
# approved folder. run_sandboxed.py was the runner under a name that claimed
# more than it does: nothing here confines a running script, so 'sandbox' told
# the reader the opposite of the truth. Remove both, so nobody is left with a
# file the guard no longer recognises.
foreach ($stale in @('claude-sandbox.cmd', 'run_sandboxed.py')) {
    $stalePath = Join-Path $hooksDir $stale
    if (Test-Path $stalePath) {
        Remove-Item $stalePath -Force
        Write-Row 'Removed' "$stale, from an earlier version"
    }
}

# Keep any names a previous install recorded, so a reinstall does not quietly
# drop a folder name somebody added by hand.
if (Test-Path $configTarget) {
    try {
        $old = Get-Content $configTarget -Raw | ConvertFrom-Json
        foreach ($name in @($old.protected_folders)) {
            $clean = "$name".Trim().ToLower()
            if ($clean -and ($folderNames -notcontains $clean)) { $folderNames += $clean }
        }
    } catch {
        Write-Warn 'Existing guard_config.json could not be read, replacing it.'
    }
}

# ---------------------------------------------------------------------------
# The deny rules. Built here, before the config is written, so the exact list
# that gets installed can be recorded in it. That record is what uninstall.ps1
# removes: reconstructing the list from its parts was a source of rules left
# behind, and generation now covers interpreters as well as folder names.
# ---------------------------------------------------------------------------

$rulesFile = Join-Path $repo 'settings\guard_rules.json'
$rules = Get-Content $rulesFile -Raw | ConvertFrom-Json
$newDeny = @($rules.deny)

# One pair per configured folder name.
foreach ($name in $folderNames) {
    $newDeny += "Read(./$name/**)"
    $newDeny += "Read(./**/$name/**)"
}

# One per blocked interpreter, read from the guard itself rather than kept in a
# second hand written list. The two had drifted: the hook blocked 26 programs
# and the rule file listed 11, so the floor was lower than the ceiling for
# exactly the programs the floor exists to catch.
#
# Importing data_guard runs nothing, because its entry point is guarded by
# __name__ == "__main__".
$reader = "import sys, json; sys.path.insert(0, r'$hooksDir'); import data_guard; print(json.dumps(data_guard.BLOCKED_PROGRAMS))"
$blocked = @()
try {
    # Filtered, because @($null).Count is 1 in PowerShell: an empty or absent
    # result would otherwise look populated and generate 'Bash(:*)'.
    # Deliberately the direct interpreter, not the launcher. This is a '-c'
    # invocation with no script file and therefore no shebang, which is exactly
    # the case where py.exe can fail to find a Python at all.
    $blocked = @((& $pythonPath -c $reader | ConvertFrom-Json) | Where-Object { $_ })
} catch {
    Fail @"
Could not read BLOCKED_PROGRAMS from $guardTarget.

The deny rules for interpreters are generated from that list, so without it the
floor beneath the hook would be missing. Your settings.json has not been
touched.

Python said: $($_.Exception.Message)
"@
}
if ($blocked.Count -eq 0) { Fail "BLOCKED_PROGRAMS in $guardTarget is empty." }

# Claude Code matches these by prefix, case sensitively, so 'rscript' alone
# would miss 'Rscript model.R'. Add the capitalised spelling too. All caps is
# deliberately not generated: it would triple the list to catch spellings the
# hook already handles case insensitively.
foreach ($program in $blocked) {
    $newDeny += "Bash($program`:*)"
    $capital = $program.Substring(0, 1).ToUpper() + $program.Substring(1)
    if ($capital -cne $program) { $newDeny += "Bash($capital`:*)" }
}

$newDeny = @($newDeny | Select-Object -Unique)

Write-JsonFile $configTarget ([PSCustomObject]@{
    _comment          = 'Machine specific config for data_guard.py. protected_folders are folder names, refused wherever they appear. Claude Code cannot edit this file.'
    protected_folders = $folderNames
    # The only interpreter and the only script Claude may execute, both pinned
    # to absolute paths. The guard compares against these exactly.
    runner_python     = $hookPython
    runner_script     = $runnerTarget
    # Exactly what was merged into settings.json, so uninstall.ps1 removes
    # exactly that and nothing else.
    installed_deny_rules = $newDeny
})
Write-Row 'Config' $configTarget

# ---------------------------------------------------------------------------
# Verify before activating. Deliberately before the settings merge: if the
# guard is broken you end up with your settings untouched rather than with a
# live guard that fails.
#
# Only the essential cases run here. The full suites exercise logic that is
# identical on every machine, which is a development concern: a failure there
# is a bug to find before shipping, not on a researcher's laptop. What is NOT
# identical is the config just written from the answer to the one question, so
# the essential set checks every folder name that was typed, plus enough ALLOW
# cases to tell a working guard from a bricked one.
#
# doctor.ps1 runs everything.
# ---------------------------------------------------------------------------

$summary = @()
foreach ($suite in @(
    @{ Name = 'guard';  Script = 'guard\test_guard.py';  Target = $guardTarget },
    @{ Name = 'runner'; Script = 'guard\test_runner.py'; Target = $runnerTarget }
)) {
    # Run the suites under the interpreter the hook will actually use, so a
    # launcher that cannot start the guard fails here rather than in a session.
    $output = & $hookPython (Join-Path $repo $suite.Script) '--essential' $suite.Target 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { Write-Host $_ }
        Fail @"
The guard failed its own tests, so it has NOT been activated.

Your settings.json has not been touched. The guard script and its config were
copied to $hooksDir but nothing references them, so they have no effect.

Read the failures above. If every ALLOW case failed, the guard is erroring on
every call and the message names the exception.
"@
    }
    $count = @($output | Where-Object { $_ -match '^\[pass\]' }).Count
    $summary += "$count $($suite.Name)"
}
Write-Row 'Checked' (($summary -join ', ') + ' cases passed, against your own folder names')

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

$settings = $null
$settingsHashAtRead = $null
if (Test-Path $settingsPath) {
    $backup = "$settingsPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $settingsPath $backup -Force
    Write-Row 'Backup' $backup

    # Read the bytes once and hash exactly what we parsed. Claude Code writes to
    # this file while a session is running, so a whole file write-back from a
    # stale snapshot would silently discard whatever it changed in between.
    $originalBytes = [System.IO.File]::ReadAllBytes($settingsPath)
    $settingsHashAtRead = Get-BytesHash $originalBytes

    $raw = [System.Text.Encoding]::UTF8.GetString($originalBytes)
    if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        $settings = [PSCustomObject]@{}
    } else {
        try { $settings = $raw | ConvertFrom-Json }
        catch {
            Fail @"
$settingsPath is not valid JSON, so it cannot be merged into safely.

Nothing has been changed. Fix the file by hand, or move it aside and run this
again to start from a clean one.

Parser said: $($_.Exception.Message)
"@
        }
    }
} else {
    $settings = [PSCustomObject]@{}
}

# Permissions: union the deny list, preserve everything else untouched.
if (-not $settings.PSObject.Properties['permissions']) {
    Set-Prop $settings 'permissions' ([PSCustomObject]@{})
}
$existingDeny = @()
if ($settings.permissions.PSObject.Properties['deny']) { $existingDeny = @($settings.permissions.deny) }
$mergedDeny = @($existingDeny + $newDeny | Select-Object -Unique)

# Rules earlier versions installed and this one does not. Without this, a
# machine that already has them keeps them forever: they are nobody's to
# maintain, and the user never agreed to them under this version.
$retired = @(@($rules.retired) | Where-Object { $_ })
if ($retired.Count -gt 0) {
    $dropped = @($mergedDeny | Where-Object { $retired -contains $_ })
    if ($dropped.Count -gt 0) {
        $mergedDeny = @($mergedDeny | Where-Object { $retired -notcontains $_ })
        Write-Row 'Dropped' "$($dropped.Count) rule(s) from an earlier version"
    }
}
Set-Prop $settings.permissions 'deny' $mergedDeny

# Hooks: drop any previous guard entry, then add the current one. This makes
# re-running the installer idempotent and repoints a stale Python path.
$hookCommand = '"{0}" "{1}"' -f $hookPython, ($guardTarget -replace '\\', '/')
$newEntry = [PSCustomObject]@{
    matcher = '*'
    hooks   = @([PSCustomObject]@{ type = 'command'; command = $hookCommand; timeout = 15 })
}

if (-not $settings.PSObject.Properties['hooks']) {
    Set-Prop $settings 'hooks' ([PSCustomObject]@{})
}
$preToolUse = @()
if ($settings.hooks.PSObject.Properties['PreToolUse']) {
    $preToolUse = @($settings.hooks.PreToolUse) | Where-Object {
        $entry = $_
        -not (@($entry.hooks) | Where-Object { $_.command -like '*data_guard.py*' })
    }
}
Set-Prop $settings.hooks 'PreToolUse' @(@($preToolUse) + $newEntry)

# Staleness check, immediately before the write and after all the work above.
# If the file changed since it was read, the in memory copy is out of date and
# writing it would revert whatever changed. Refuse rather than guess: nothing
# here can merge two concurrent edits.
if ($settingsHashAtRead) {
    $hashNow = Get-BytesHash ([System.IO.File]::ReadAllBytes($settingsPath))
    if ($hashNow -ne $settingsHashAtRead) {
        Fail @"
$settingsPath changed while this installer was running.

Nothing has been written. Your settings are untouched, and the backup taken at
the start is at:
  $backup

Claude Code writes to this file during a session, so the usual cause is having
a session open right now. Close any running Claude Code session and run this
again.
"@
    }
}

Write-JsonFile $settingsPath $settings
Write-Row 'Settings' "$settingsPath ($($mergedDeny.Count) deny rules)"

$firstName = $folderNames[0]

# The full list, always, even on a reinstall that changed nothing. A name
# missing from it is a folder with no protection, and that should be read
# rather than assumed.
Write-Host ''
Write-Host '  Protected folder names, every project, every permission mode:' -ForegroundColor Cyan
Write-Host ("    " + ($folderNames -join ', ')) -ForegroundColor Cyan
Write-Host '  A data folder called anything else is not protected. Re-run to add one.' -ForegroundColor Cyan

Write-Host @"

Now verify it, because this is the one thing the installer cannot check: that
Claude Code is really calling the hook. Open Claude Code in any folder, paste
this in, and watch it refuse.

    read ./$firstName/__probe__.csv

That file does not exist, so being told it is missing means the hook is not
running. If that happens, run doctor.ps1.
"@ -ForegroundColor White
