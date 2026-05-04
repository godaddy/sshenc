# Lint-Powershell.ps1
#
# Pre-flight check for `.ps1` files in this repo: pure-ASCII +
# parse-clean. PowerShell 5.1 reads BOM-less .ps1 files using the
# OEM/ANSI code page; UTF-8 multi-byte sequences for em-dash, en-dash,
# curly quotes etc. corrupt parser state and produce wildly misleading
# errors hundreds of lines from the offending byte. Catching this in
# CI before the script runs avoids debugging spurious cascades.
#
# Tokenize-only checks (Tokenize / PSParser) are NOT sufficient -- they
# return "no errors" on a file with em-dashes. The full grammar parser
# (`Parser::ParseFile`) is what catches them. Use that.
#
# Usage: .\scripts\Lint-Powershell.ps1
#
# Exit code: 0 if every .ps1 in scripts/ passes both checks; 1
# otherwise. CI maps non-zero to a failed job.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptsDir = Join-Path $repoRoot 'scripts'

$failures = 0
$files = Get-ChildItem -Path $scriptsDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue
if (-not $files) {
    Write-Host "No .ps1 files under $scriptsDir; nothing to lint." -ForegroundColor DarkGray
    exit 0
}

foreach ($f in $files) {
    Write-Host "Checking $($f.Name)..." -ForegroundColor DarkGray

    # ASCII byte check. Build-bots run en-US; the failure mode of
    # silent re-decoding only manifests under that locale, but the
    # check works under any locale because we just count bytes > 127.
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $nonAscii = ($bytes | Where-Object { $_ -gt 127 }).Count
    if ($nonAscii -gt 0) {
        Write-Host "  FAIL: $nonAscii non-ASCII byte(s) -- use '--' for em-dash and ASCII quotes" -ForegroundColor Red
        $failures++
        continue
    }

    # Full grammar parse. ParseFile returns a list of ParseError
    # entries for every malformed expression / statement. Any
    # non-empty list means the file would have failed at runtime;
    # catching it here is cheap and avoids the late-bound surprise.
    $errs = $null
    $tokens = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $f.FullName,
        [ref]$tokens,
        [ref]$errs
    ) | Out-Null
    if ($errs -and $errs.Count -gt 0) {
        Write-Host "  FAIL: $($errs.Count) parse error(s):" -ForegroundColor Red
        foreach ($e in $errs) {
            Write-Host "    line $($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor DarkRed
        }
        $failures++
        continue
    }

    Write-Host "  OK" -ForegroundColor Green
}

if ($failures -gt 0) {
    Write-Host "`n$failures script(s) failed lint. See output above." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll $($files.Count) script(s) pass lint." -ForegroundColor Green
exit 0
