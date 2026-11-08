<#
.SYNOPSIS
Install vahta (and its short name vh) and vahta-hook from this checkout, for
daily use on this machine. Windows PowerShell 5.1 and PowerShell 7.

.DESCRIPTION
This is not a release: nothing is published anywhere. It builds the Rust
binaries and copies them into a directory you own (default
$HOME\.local\bin), then points the harnesses that already run vahta-hook at the
installed copy. The Windows counterpart of scripts/install-local.sh.

vh.exe is a copy of vahta.exe, not a link (symlinks need privileges on Windows).

A running `vahta daemon run` keeps its file open, and Windows will not let a
file in use be replaced. So the script stops the daemon of the installed vahta
first (open sessions end) and starts it again afterwards if it had been
running. A file that is still locked (a hook that is mid-call, say) is renamed to
NAME.old and the new one put in its place; the .old files are removed on the
next run.

The prefix is added to your user PATH if it is not there yet, and the script
says so when it does.

.PARAMETER Prefix
Directory to install into. Created if missing.

.PARAMETER NoSetup
Do not run `vahta setup --refresh` or print the setup table.

.EXAMPLE
scripts\install-local.ps1
.EXAMPLE
scripts\install-local.ps1 -Prefix D:\tools\bin -NoSetup
#>
[CmdletBinding()]
param(
    [string]$Prefix = (Join-Path $HOME '.local\bin'),
    [switch]$NoSetup
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("install-local: error: $Message")
    exit 1
}

if (-not $Prefix) { Fail 'no prefix: pass -Prefix DIR, or set HOME' }
$Prefix = [System.IO.Path]::GetFullPath($Prefix).TrimEnd('\')

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Fail 'cargo not found; install a Rust toolchain first'
}

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    # Files left over from an earlier run that could not be replaced in place.
    if (Test-Path -LiteralPath $Prefix) {
        Get-ChildItem -LiteralPath $Prefix -Filter '*.old' -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $file = $_.FullName
                try { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }
                catch { Write-Host "warning: $file is still in use; it stays for the next run" }
            }
    }

    Write-Host 'building vahta, vh and vahta-hook (release)...'
    & cargo build --release --locked -p vahta-cli -p vahta-hook
    if ($LASTEXITCODE -ne 0) { Fail 'cargo build failed' }

    $targetDir = $null
    try {
        $meta = (& cargo metadata --format-version 1 --no-deps --locked 2>$null) -join "`n" |
            ConvertFrom-Json
        $targetDir = $meta.target_directory
    } catch { $targetDir = $null }
    if (-not $targetDir) { $targetDir = Join-Path $repo 'target' }
    $built = Join-Path $targetDir 'release'
    foreach ($name in 'vahta', 'vh', 'vahta-hook') {
        if (-not (Test-Path -LiteralPath (Join-Path $built "$name.exe"))) {
            Fail "build did not produce $built\$name.exe"
        }
    }

    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

    # Stop the daemon of the vahta that is installed now, if there is one. A
    # daemon of another build is not ours to find; its file stays locked and the
    # rename below deals with that.
    $installed = Join-Path $Prefix 'vahta.exe'
    $daemonWasRunning = $false
    if (Test-Path -LiteralPath $installed) {
        # Windows PowerShell 5.1 turns native stderr under 2>&1 into errors.
        $ErrorActionPreference = 'Continue'
        $status = (& $installed daemon status 2>&1 | ForEach-Object { "$_" }) -join ' '
        $ErrorActionPreference = 'Stop'
        if ($LASTEXITCODE -eq 0 -and $status -notmatch '^not running') {
            $daemonWasRunning = $true
            Write-Host 'stopping the running daemon (open sessions end)...'
            & $installed daemon stop
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'warning: the daemon did not stop; its file may stay locked'
            }
        }
    }

    # Copy next to the target, then move over it. If the target is locked, move
    # it aside as NAME.old (a running program can be renamed, not replaced).
    function Install-One([string]$Source, [string]$Name) {
        $dest = Join-Path $Prefix $Name
        $tmp = Join-Path $Prefix ".$Name.new"
        Copy-Item -LiteralPath $Source -Destination $tmp -Force
        try {
            Move-Item -LiteralPath $tmp -Destination $dest -Force -ErrorAction Stop
        } catch {
            $old = "$dest.old"
            try {
                if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force -ErrorAction Stop }
                Move-Item -LiteralPath $dest -Destination $old -Force -ErrorAction Stop
                Move-Item -LiteralPath $tmp -Destination $dest -Force -ErrorAction Stop
                Write-Host "note: $Name was in use; the old one is $Name.old and goes on the next run"
            } catch {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Fail "cannot replace $dest (in use?): $($_.Exception.Message)"
            }
        }
        Write-Host "installed $dest"
    }

    # The hook first: a vahta that is newer than its hook is the worse way round.
    Install-One (Join-Path $built 'vahta-hook.exe') 'vahta-hook.exe'
    Install-One (Join-Path $built 'vahta.exe') 'vahta.exe'
    Install-One (Join-Path $built 'vahta.exe') 'vh.exe'

    Write-Host ''
    Write-Host 'smoke checks...'
    & (Join-Path $Prefix 'vahta.exe') --version
    if ($LASTEXITCODE -ne 0) { Fail "$Prefix\vahta.exe --version failed" }
    & (Join-Path $Prefix 'vh.exe') --version | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "$Prefix\vh.exe --version failed" }
    $hookOut = '{}' | & (Join-Path $Prefix 'vahta-hook.exe') --harness claude --event before_tool
    if ($LASTEXITCODE -ne 0) { Fail 'vahta-hook exited non-zero on an empty event' }
    if ($hookOut) { Fail "vahta-hook printed something on an empty event: $hookOut" }
    Write-Host 'vahta-hook: ok (exit 0, empty stdout)'

    # The user PATH, only if the prefix is not on it yet.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) {
        $entries = $userPath.Split(';') | Where-Object { $_ } | ForEach-Object {
            [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\')
        }
    }
    if (@($entries | Where-Object { $_ -ieq $Prefix }).Count -eq 0) {
        $new = $Prefix
        if ($userPath) { $new = $userPath.TrimEnd(';') + ';' + $Prefix }
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        Write-Host ''
        Write-Host "added $Prefix to your user PATH; open a new terminal for it to take effect"
    }

    if (-not $NoSetup) {
        Write-Host ''
        & (Join-Path $Prefix 'vahta.exe') setup --refresh
        Write-Host ''
        & (Join-Path $Prefix 'vahta.exe') setup
    } else {
        Write-Host ''
        Write-Host "skipped setup (-NoSetup). Run `"$Prefix\vahta.exe setup --refresh`" to repoint existing harnesses."
    }

    if ($daemonWasRunning) {
        Write-Host ''
        Write-Host 'starting the daemon on the new binary...'
        & (Join-Path $Prefix 'vahta.exe') daemon restart
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'warning: the daemon did not start; run `vahta daemon restart`'
        }
    }
} finally {
    Pop-Location
}
