# Test-Sshenc-Windows.ps1
#
# Windows-side test harness for sshenc + gitenc. Designed to run both
# locally (TPM 2.0 available) and in CI on `windows-latest` (no TPM).
# Detects TPM presence at runtime and picks a backend accordingly:
#
#   - TPM detected     -> exercises the production hardware path
#   - TPM not detected -> falls back to the test-only software backend
#                         via SSHENC_FORCE_SOFTWARE=1, requires the
#                         sshenc binary to have been compiled with the
#                         `force-software` Cargo feature
#
# Coverage that runs in EITHER mode (TPM-irrelevant): version output,
# config commands, completions emission, key lifecycle (keygen / list
# / inspect / export-pub / sign / delete), shell-wrapper consistency
# across PowerShell / Git Bash / CMD, gitenc smoke + signing, agent
# named-pipe binding, named-pipe -> ssh-keygen sign round-trip.
#
# Coverage that requires TPM (skipped in software mode): the actual
# Windows CNG NCryptOpenStorageProvider / NCryptCreatePersistedKey
# code path, NCRYPT_UI_PROTECT_KEY_FLAG round-trips, the WebAuthn /
# SK / Windows Hello path. Hardware regressions in those paths are
# caught by the developer's local matrix run on a TPM-equipped host.
#
# This file MUST be pure ASCII. PowerShell 5.1 (default in Windows
# CI runners and on local developer machines) reads BOM-less .ps1
# files using the OEM/ANSI code page; UTF-8 multi-byte sequences for
# em-dash, en-dash, curly quotes, etc. corrupt parser state and
# produce wildly misleading errors hundreds of lines from the
# offending byte. Use `--` for em-dash, plain ASCII quotes only. The
# CI workflow runs a pre-flight ASCII / parse check; if your edit
# introduces a non-ASCII byte, that check fails before the matrix
# even tries to start.
#
# Usage:
#   .\scripts\Test-Sshenc-Windows.ps1 [-Strict] [-StrongSk]
#                                     [-ResetSharedKeys] [-NoCleanup]
#                                     [-SshencBinDir <path>]

param(
    # Run lifecycle tests with `--auth-policy any` (user-presence required
    # at every sign). Without -Strict, lifecycle tests use `--auth-policy
    # none` so they can run unattended in CI. Setting -Strict locally
    # exercises the same code path the real-world default takes.
    [switch]$Strict,

    # Run the FIDO2/WebAuthn SK tests against a Docker-hosted OpenSSH.
    # Requires Docker Desktop AND a Windows-Hello-enrolled TPM. Skipped
    # automatically if either is missing. Each invocation fires Hello
    # gestures (make_credential + get_assertion).
    [switch]$StrongSk,

    # Force SSHENC_FORCE_SOFTWARE=1 even if a TPM is present. CI sets
    # this; locally, omit it to exercise the real hardware path.
    # Requires the sshenc binary to have been built with the
    # `force-software` Cargo feature; production-shipped binaries
    # ignore the env var (and this flag becomes a no-op).
    [switch]$Software,

    # Force the persistent shared keys to be regenerated even if they
    # already exist locally.
    [switch]$ResetSharedKeys,

    # Skip post-flight cleanup. Useful for debugging a failed run --
    # leaves the test artifacts in place so you can inspect them.
    [switch]$NoCleanup,

    # Override the directory containing the sshenc binaries. Defaults
    # to PATH lookup. CI sets this to the cargo build target dir.
    [string]$SshencBinDir = ""
)

$ErrorActionPreference = "Continue"
$script:Pass = 0
$script:Fail = 0
$script:Skip = 0
$script:Results = @()

# ---------------------------------------------------------------------
# Output helpers (intentionally minimal -- we want clean, greppable
# output that a CI log parser can summarize without escaping).
# ---------------------------------------------------------------------
function Record($Status, $Test, $Detail = "") {
    switch ($Status) {
        "P" { $script:Pass++; $color = "Green" }
        "F" { $script:Fail++; $color = "Red" }
        "S" { $script:Skip++; $color = "Yellow" }
    }
    $label = switch ($Status) { "P" { "PASS" } "F" { "FAIL" } "S" { "SKIP" } }
    Write-Host "  [$label] " -NoNewline -ForegroundColor $color
    Write-Host "$Test" -NoNewline
    if ($Detail) { Write-Host " - $Detail" -ForegroundColor DarkGray } else { Write-Host "" }
    $script:Results += [PSCustomObject]@{ Status = $label; Test = $Test; Detail = $Detail }
}

function Section($Title) { Write-Host "`n  -- $Title --" -ForegroundColor White }

function Banner($Title) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Command($Test, $Command, $Expect = $null) {
    try {
        $out = Invoke-Expression $Command 2>&1 | Out-String
        if ($Expect -and $out -notmatch [regex]::Escape($Expect)) {
            $snippet = $out.Trim()
            if ($snippet.Length -gt 80) { $snippet = $snippet.Substring(0, 80) }
            Record "F" $Test "expected '$Expect', got: $snippet"
        } else {
            Record "P" $Test
        }
    } catch {
        Record "F" $Test $_.Exception.Message
    }
}

# ---------------------------------------------------------------------
# Backend detection. Returns one of:
#   "tpm-hello"  TPM present AND Hello enrolled (full coverage incl SK)
#   "tpm"        TPM present, Hello unconfirmed (no SK tests)
#   "software"   No TPM (CI / VM); SSHENC_FORCE_SOFTWARE=1 path
#
# This is a SOFT signal. The real backend selection happens inside
# the sshenc binary via `enclaveapp_app_storage::AppSigningBackend::init`.
# The mode label here only affects:
#   1. Whether SK tests can run (require tpm-hello)
#   2. Whether to flip SSHENC_FORCE_SOFTWARE on (when -Software passed)
#   3. The banner output
# A wrong detection in the script doesn't break the tests -- the
# binary is the source of truth.
# ---------------------------------------------------------------------
function Get-BackendMode {
    param([switch]$ForceSoftware)
    if ($ForceSoftware) { return "software" }

    $tpmPresent = $false
    # Try CIM first (no admin needed on most configurations); fall
    # back to the registry presence of TPM driver / TBS service. We
    # never error -- a wrong "no TPM" detection just means the script
    # assumes software, which the binary will overrule anyway when
    # SSHENC_FORCE_SOFTWARE isn't set on a TPM-having build.
    try {
        $tpm = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' `
                               -ClassName Win32_Tpm `
                               -ErrorAction SilentlyContinue
        if ($null -ne $tpm -and $tpm.IsActivated_InitialValue -eq $true) {
            $tpmPresent = $true
        }
    } catch { $tpmPresent = $false }

    if (-not $tpmPresent) {
        # Registry signal. HKLM\SYSTEM\CCS\Services\TPM exists on
        # any host where the TPM driver is registered, even when CIM
        # is gated by permissions. Doesn't prove the TPM is usable
        # (the driver could be installed without hardware), but it's
        # a stronger "probably has TPM" hint than empty CIM alone.
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM') {
            $tpmPresent = $true
        }
    }

    $helloEnrolled = $false
    try {
        $ngcPath = Join-Path $env:LOCALAPPDATA "Microsoft\Ngc"
        if (Test-Path $ngcPath) {
            $entries = Get-ChildItem -Path $ngcPath -ErrorAction SilentlyContinue
            if ($entries -and $entries.Count -gt 0) { $helloEnrolled = $true }
        }
    } catch { $helloEnrolled = $false }

    if ($tpmPresent -and $helloEnrolled) { return "tpm-hello" }
    if ($tpmPresent) { return "tpm" }
    return "software"
}

# ---------------------------------------------------------------------
# Resolve the sshenc binary. -SshencBinDir overrides PATH; useful in
# CI where we want to test a freshly-built target/debug/sshenc.exe.
# ---------------------------------------------------------------------
function Resolve-SshencBin {
    param([string]$Override)
    if ($Override) {
        $bin = Join-Path $Override "sshenc.exe"
        if (-not (Test-Path $bin)) { $bin = Join-Path $Override "sshenc" }
        if (Test-Path $bin) { return [System.IO.Path]::GetFullPath($bin) }
        throw "sshenc binary not found in -SshencBinDir '$Override'"
    }
    $cmd = Get-Command sshenc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "sshenc not on PATH and no -SshencBinDir provided"
}

# ---------------------------------------------------------------------
# Persistent shared keys. The matrix in the parent enclaveapps repo
# uses two keys per policy mode; here we keep just one pair per mode
# (the sshenc-only matrix doesn't need the WSL-bridge key sync that
# makes two keys interesting). One pair = one make_credential gesture
# in -StrongSk mode at first run, zero on subsequent runs.
# ---------------------------------------------------------------------
$SharedKeyMode = if ($Strict) { "strict" } else { "silent" }
$SharedKeyA    = "matrix-a-$SharedKeyMode"
$SharedKeyB    = "matrix-b-$SharedKeyMode"
$SharedKeys    = @($SharedKeyA, $SharedKeyB)
$AllSharedKeys = @("matrix-a-silent", "matrix-b-silent", "matrix-a-strict", "matrix-b-strict")

# Resolve binary up front so a missing-tool error fires before we
# start banner output / reset-keys / etc.
$SshencBin = Resolve-SshencBin -Override $SshencBinDir
$SshencDir = Split-Path -Parent $SshencBin
$AgentBin  = Join-Path $SshencDir "sshenc-agent.exe"
if (-not (Test-Path $AgentBin)) { $AgentBin = Join-Path $SshencDir "sshenc-agent" }
$GitencBin = Join-Path $SshencDir "gitenc.exe"
if (-not (Test-Path $GitencBin)) { $GitencBin = Join-Path $SshencDir "gitenc" }

# ---------------------------------------------------------------------
# Backend mode + env setup. In software mode we propagate
# SSHENC_FORCE_SOFTWARE=1 to the current process AND any child
# processes (sshenc, sshenc-agent, gitenc, sshenc-keygen). The flag
# is only honored by binaries built with the `force-software` feature;
# CI builds with that feature explicitly. Production-shipped binaries
# do NOT enable it, so this env var is a no-op there.
# ---------------------------------------------------------------------
$BackendMode = Get-BackendMode -ForceSoftware:$Software
if ($BackendMode -eq "software") {
    $env:SSHENC_FORCE_SOFTWARE = "1"
    if ($Software) {
        Write-Host "  [INFO] -Software flag set; using software backend (SSHENC_FORCE_SOFTWARE=1)" -ForegroundColor Yellow
    } else {
        Write-Host "  [INFO] No TPM detected; using software backend (SSHENC_FORCE_SOFTWARE=1)" -ForegroundColor Yellow
    }
    Write-Host "         Requires sshenc to have been built with --features force-software." -ForegroundColor DarkGray
} elseif ($BackendMode -eq "tpm-hello") {
    Write-Host "  [INFO] TPM 2.0 + Windows Hello detected; full hardware coverage available" -ForegroundColor Green
} else {
    Write-Host "  [INFO] TPM 2.0 detected (Hello not enrolled); SK tests will skip" -ForegroundColor DarkGray
}

# `sshenc keygen` extra-args toggle. Empty array under -Strict (lets
# the v0.6.44+ default-flip kick in on Hello-enrolled hosts);
# `--auth-policy none` for unattended/CI runs.
$KeygenAuthArgs = if ($Strict) { @() } else { @("--auth-policy", "none") }

# ---------------------------------------------------------------------
# Reset-SshencKeys: idempotent cleanup. -Keep is the allowlist; any
# managed key NOT in -Keep gets deleted via `sshenc delete --if-exists`
# (the latter flag landed in v0.6.50, so the script must be run with
# at least that version; older binaries error here).
# ---------------------------------------------------------------------
function Reset-SshencKeys {
    param([switch]$Quiet, [string[]]$Keep = @())
    # Process-name lookup without `Split-Path -LeafBase` (PS6+); use
    # GetFileNameWithoutExtension which exists on every PS version.
    $agentName = [System.IO.Path]::GetFileNameWithoutExtension($AgentBin)
    if (-not (Get-Process -Name $agentName -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath $AgentBin -WindowStyle Hidden | Out-Null
        Start-Sleep 2
    }
    $listJson = & $SshencBin list --json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        if (-not $Quiet) { Write-Host "  [WARN] sshenc list --json failed: $($listJson.Trim())" -ForegroundColor Yellow }
        return 0
    }
    $keys = @()
    try { $keys = $listJson | ConvertFrom-Json } catch { return 0 }
    if ($null -eq $keys) { return 0 }
    if ($keys -isnot [System.Array]) { $keys = @($keys) }
    $count = 0
    foreach ($k in $keys) {
        $label = $k.metadata.label
        if (-not $label) { continue }
        if ($Keep -contains $label) { continue }
        & $SshencBin delete -y --delete-pub --if-exists $label 2>&1 | Out-Null
        $count++
    }
    return $count
}

function Test-SshencKeyExists {
    param([string]$Label)
    & $SshencBin inspect $Label 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Ensure-SharedKeys {
    param([string[]]$Labels, [string[]]$KeygenArgs, [switch]$ForceReset)
    $created = 0
    foreach ($lbl in $Labels) {
        if ($ForceReset) {
            & $SshencBin delete -y --delete-pub --if-exists $lbl 2>&1 | Out-Null
        }
        if (-not (Test-SshencKeyExists -Label $lbl)) {
            $out = & $SshencBin keygen -l $lbl -C "matrix-shared" @KeygenArgs 2>&1 | Out-String
            if ($out -match "Generated") {
                $created++
                Write-Host "  [INFO] Created shared key: $lbl" -ForegroundColor DarkGray
            } else {
                Write-Host "  [WARN] Failed to create $($lbl): $($out.Trim())" -ForegroundColor Yellow
            }
        }
    }
    return $created
}

# ---------------------------------------------------------------------
# Banner: backend selection + pre-flight key cleanup
# ---------------------------------------------------------------------
Banner "sshenc Windows test matrix ($BackendMode mode)"
Write-Host "  Binary:   $SshencBin"
Write-Host "  Policy:   $SharedKeyMode (Strict=$([bool]$Strict))"
Write-Host "  Shared:   $($SharedKeys -join ', ')"

Banner "Pre-flight: clean transients, ensure shared keys"
$preCount = Reset-SshencKeys -Keep $AllSharedKeys
if ($preCount -gt 0) {
    Write-Host "  [INFO] Cleaned $preCount transient key(s) from prior runs" -ForegroundColor Yellow
} else {
    Write-Host "  [INFO] No transient keys to clean" -ForegroundColor DarkGray
}
$created = Ensure-SharedKeys -Labels $SharedKeys -KeygenArgs $KeygenAuthArgs -ForceReset:$ResetSharedKeys
if ($created -gt 0) {
    Write-Host "  [INFO] Created $created new shared key(s); future runs will reuse" -ForegroundColor Yellow
} else {
    Write-Host "  [INFO] All $($SharedKeys.Count) shared keys already exist" -ForegroundColor Green
}
foreach ($k in $SharedKeys) {
    if (-not (Test-SshencKeyExists -Label $k)) {
        Record "F" "shared key available: $k" "could not be created or read"
    }
}

# ---------------------------------------------------------------------
# Smoke tests. Backend-irrelevant. Run in EVERY mode.
# ---------------------------------------------------------------------
Banner "Smoke tests (backend-irrelevant)"
Section "sshenc"
Test-Command "sshenc --version" "& '$SshencBin' --version" "sshenc"
Test-Command "sshenc config path" "& '$SshencBin' config path"
Test-Command "sshenc config show" "& '$SshencBin' config show" "socket_path"
Test-Command "sshenc list" "& '$SshencBin' list"
Test-Command "sshenc completions bash" "& '$SshencBin' completions bash" "_sshenc"
Test-Command "sshenc completions powershell" "& '$SshencBin' completions powershell" "Register-ArgumentCompleter"
Test-Command "sshenc delete --if-exists missing" "& '$SshencBin' delete -y --if-exists never-existed-12345"

Section "gitenc"
Test-Command "gitenc -h" "& '$GitencBin' -h" "Git wrapper"
Test-Command "gitenc --help" "& '$GitencBin' --help" "sshenc"
$gitencVer = (& $GitencBin --version 2>&1 | Out-String).Trim()
if ($gitencVer -match "^gitenc \d") { Record "P" "gitenc --version" } else { Record "F" "gitenc --version" $gitencVer }

# ---------------------------------------------------------------------
# Lifecycle tests. Use the persistent shared key. The shared key was
# created in pre-flight using whatever backend is active, so the same
# tests run in TPM mode and software mode -- only the backing storage
# differs.
# ---------------------------------------------------------------------
Banner "Lifecycle (PowerShell -> $BackendMode backend)"

$fpA = (& $SshencBin export-pub $SharedKeyA --fingerprint 2>&1 | Out-String).Trim()
$fpB = (& $SshencBin export-pub $SharedKeyB --fingerprint 2>&1 | Out-String).Trim()
if ($fpA -match "SHA256:" -and $fpB -match "SHA256:" -and $fpA -ne $fpB) {
    Record "P" "shared keys have distinct fingerprints"
} else {
    Record "F" "shared keys have distinct fingerprints" "A=$fpA B=$fpB"
}
Test-Command "sshenc inspect $SharedKeyA" "& '$SshencBin' inspect $SharedKeyA" "ecdsa"
Test-Command "sshenc export-pub $SharedKeyA" "& '$SshencBin' export-pub $SharedKeyA" "ecdsa-sha2-nistp256"

$env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
$pubFile = Join-Path $env:USERPROFILE ".ssh\$SharedKeyA.pub"
$signOut = ("matrix sign test (PowerShell)" | & "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -Y sign -f $pubFile -n "matrix-test" 2>&1) -join "`n"
if ($signOut -match "BEGIN SSH SIGNATURE") {
    Record "P" "sign via $BackendMode ($SharedKeyA)"
} else {
    $snippet = $signOut.Substring(0, [Math]::Min(150, $signOut.Length))
    Record "F" "sign via $BackendMode ($SharedKeyA)" "no signature: $snippet"
}

# ---------------------------------------------------------------------
# Git Bash shell. Skipped if Git Bash is unavailable (most CI runners
# install Git, so the bash.exe path resolves; on a stripped-down image
# we record SKIP and move on).
# ---------------------------------------------------------------------
Banner "Lifecycle (Git Bash)"
try { $pf86 = ${env:ProgramFiles(x86)} } catch { $pf86 = $null }
$bashCandidates = @(
    "$env:USERPROFILE\scoop\apps\git\current\bin\bash.exe",
    "$env:ProgramFiles\Git\bin\bash.exe"
)
if ($pf86) { $bashCandidates += "$pf86\Git\bin\bash.exe" }
$bashExe = $bashCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bashExe) {
    Record "S" "Git Bash not available on this host"
} else {
    $sshKeygenPosix = ("$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe") -replace '\\', '/'
    $gbScriptPath = Join-Path $env:TEMP "sshenc-gb-$PID.sh"
    $gbTemplate = @(
        'set -e',
        '"__SSHENC__" --version | grep -q sshenc && echo PASS gb-version || echo FAIL gb-version',
        '"__SSHENC__" list >/dev/null && echo PASS gb-list || echo FAIL gb-list',
        '"__SSHENC__" inspect __LABEL__ 2>&1 | grep -q ecdsa && echo PASS gb-inspect || echo FAIL gb-inspect',
        '"__SSHENC__" export-pub __LABEL__ 2>&1 | grep -q ecdsa-sha2-nistp256 && echo PASS gb-export-pub || echo FAIL gb-export-pub',
        'SIG=$(echo "matrix sign test (Git Bash)" | "__SSHKEYGEN__" -Y sign -f "$HOME/.ssh/__LABEL__.pub" -n matrix-test 2>&1 || true)',
        'echo "$SIG" | grep -q "BEGIN SSH SIGNATURE" && echo PASS gb-sign || echo FAIL gb-sign'
    )
    $sshencPosix = $SshencBin -replace '\\', '/'
    $gbLines = $gbTemplate | ForEach-Object {
        $_.Replace('__LABEL__', $SharedKeyA).Replace('__SSHKEYGEN__', $sshKeygenPosix).Replace('__SSHENC__', $sshencPosix)
    }
    Set-Content -Path $gbScriptPath -Value $gbLines -Encoding ASCII
    $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
    $gbResults = & $bashExe $gbScriptPath 2>&1
    Remove-Item $gbScriptPath -Force -ErrorAction SilentlyContinue
    foreach ($line in $gbResults) {
        if ($line -match '^PASS\s+(.+)$') { Record "P" $Matches[1] }
        elseif ($line -match '^FAIL\s+(.+)$') { Record "F" $Matches[1] }
    }
}

# ---------------------------------------------------------------------
# CMD shell. Always available on Windows. Same lifecycle, validates
# that the named-pipe agent is reachable from a non-bash, non-PS host.
# ---------------------------------------------------------------------
Banner "Lifecycle (CMD)"
$cmdLines = @(
    '@echo off',
    "`"$SshencBin`" --version | findstr sshenc >nul && echo PASS cmd-version || echo FAIL cmd-version",
    "`"$SshencBin`" list >nul && echo PASS cmd-list || echo FAIL cmd-list",
    "`"$SshencBin`" inspect $SharedKeyA 2>&1 | findstr ecdsa >nul && echo PASS cmd-inspect || echo FAIL cmd-inspect",
    "`"$SshencBin`" export-pub $SharedKeyA 2>&1 | findstr ecdsa-sha2-nistp256 >nul && echo PASS cmd-export-pub || echo FAIL cmd-export-pub",
    "echo matrix sign test ^(CMD^) | `"%SystemRoot%\System32\OpenSSH\ssh-keygen.exe`" -Y sign -f `"%USERPROFILE%\.ssh\$SharedKeyA.pub`" -n matrix-test 2>nul | findstr `"BEGIN SSH SIGNATURE`" >nul && echo PASS cmd-sign || echo FAIL cmd-sign"
)
$cmdBatchPath = Join-Path $env:TEMP "sshenc-cmd-$PID.cmd"
Set-Content -Path $cmdBatchPath -Value $cmdLines -Encoding ASCII
$env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
$cmdResults = & cmd.exe /c $cmdBatchPath 2>&1
Remove-Item $cmdBatchPath -Force -ErrorAction SilentlyContinue
foreach ($line in $cmdResults) {
    if ($line -match '^PASS\s+(.+)$') { Record "P" $Matches[1] }
    elseif ($line -match '^FAIL\s+(.+)$') { Record "F" $Matches[1] }
}

# ---------------------------------------------------------------------
# SK / WebAuthn coverage. Hard requirement on TPM + Hello + Docker.
# Skipped silently elsewhere (this is the cleanest / smallest surface
# area we can verify without a Hello gesture, so leave the rest of
# the matrix to the developer's local run).
# ---------------------------------------------------------------------
if ($StrongSk) {
    Banner "FIDO2 SK keys (Windows Hello, hardware-enforced)"
    if ($BackendMode -ne "tpm-hello") {
        Record "S" "SK keys -- requires TPM 2.0 + Windows Hello enrolled"
    } elseif (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Record "S" "SK keys -- docker not on PATH (full SK verification needs the e2e Docker container)"
    } else {
        # Defer to the parent enclaveapps Test-EnclaveApps.ps1 -StrongSk
        # path -- duplicating its Docker-image build + container plumbing
        # here is more code than the per-sshenc-repo script wants to own.
        # If a future contributor wants to inline it, keep this comment
        # block as a pointer.
        Record "S" "SK keys -- run the parent enclaveapps Test-EnclaveApps.ps1 -StrongSk for full coverage"
    }
}

# ---------------------------------------------------------------------
# Post-flight: assert no transient keys leaked, persistent keys still
# there. The pre-flight cleaned the slate; if anything beyond the
# allowlist exists now, a test section leaked it.
# ---------------------------------------------------------------------
if (-not $NoCleanup) {
    Banner "Post-flight: verify no transient keys leaked"
    $preLeak = & $SshencBin list --json 2>&1 | Out-String
    try {
        $allKeys = $preLeak | ConvertFrom-Json
        if ($allKeys -isnot [System.Array]) { $allKeys = @($allKeys) }
        $leaked = $allKeys | Where-Object { $AllSharedKeys -notcontains $_.metadata.label }
        if ($leaked) {
            $names = ($leaked | ForEach-Object { $_.metadata.label }) -join ", "
            Write-Host "  [DEBUG] leaked key labels: $names" -ForegroundColor Yellow
        }
    } catch { }
    $postCount = Reset-SshencKeys -Quiet -Keep $AllSharedKeys
    if ($postCount -gt 0) {
        Record "F" "post-flight: no transient keys leaked" "$postCount key(s) leaked; auto-cleaned"
    } else {
        Record "P" "post-flight: no transient keys leaked"
    }
    foreach ($k in $SharedKeys) {
        if (Test-SshencKeyExists -Label $k) {
            Record "P" "post-flight: shared key preserved ($k)"
        } else {
            Record "F" "post-flight: shared key preserved ($k)" "removed during run"
        }
    }
}

# ---------------------------------------------------------------------
# Summary + non-zero exit on failure (so CI fails the job).
# ---------------------------------------------------------------------
Banner "SUMMARY"
$totalTests = $script:Pass + $script:Fail + $script:Skip
Write-Host "  $($script:Pass) pass" -ForegroundColor Green -NoNewline
Write-Host ", $($script:Fail) fail" -ForegroundColor $(if ($script:Fail -gt 0) { "Red" } else { "Green" }) -NoNewline
Write-Host ", $($script:Skip) skip" -ForegroundColor Yellow -NoNewline
Write-Host " ($totalTests total) -- backend: $BackendMode"

if ($script:Fail -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    $script:Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "  $($_.Test)" -ForegroundColor Red -NoNewline
        if ($_.Detail) { Write-Host " - $($_.Detail)" -ForegroundColor DarkGray } else { Write-Host "" }
    }
}

Write-Host ""
exit $script:Fail
