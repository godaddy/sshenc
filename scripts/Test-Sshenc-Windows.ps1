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
    [string]$SshencBinDir = "",

    # Skip the WSL distro lifecycle tests. Useful in CI (no WSL
    # available) and locally when iterating on Windows-side fixes.
    [switch]$SkipWSL,

    # Distros to exercise via the WSL bridge -> Windows TPM path. Each
    # gets its own clean WSL VM start (`wsl --shutdown` + WSLInterop
    # probe). Reset to a smaller list for faster iteration, or to a
    # different set for CI parity.
    [string[]]$Distros = @("Ubuntu", "Debian", "FedoraLinux-43", "AlmaLinux-9"),

    # Per-distro timeout (seconds) for the WSL bash matrix script.
    # Hot machines complete in ~30s; cold WSL VM + cold Windows TPM
    # bridge can take 90+. 180s is a comfortable upper bound.
    [int]$WslTimeout = 180
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

    # Hello enrollment detection. Several signals exist; we OR them
    # because each is partial. The %LOCALAPPDATA%\Microsoft\Ngc
    # directory is system-protected on locked-down hosts (returns
    # "exists=False" even when Hello is enrolled), so we also check
    # `dsregcmd /status` (NgcSet line, present when the user has
    # gestured Hello into existence) and the per-user PassportForWork
    # registry entries that Windows writes during enrollment. Any
    # positive signal -> "tpm-hello".
    $helloEnrolled = $false
    try {
        $ngcPath = Join-Path $env:LOCALAPPDATA "Microsoft\Ngc"
        if (Test-Path $ngcPath) {
            $entries = Get-ChildItem -Path $ngcPath -ErrorAction SilentlyContinue
            if ($entries -and $entries.Count -gt 0) { $helloEnrolled = $true }
        }
    } catch { $helloEnrolled = $false }
    if (-not $helloEnrolled) {
        try {
            $dsr = & dsregcmd /status 2>&1 | Out-String
            if ($dsr -match 'NgcSet\s*:\s*YES') { $helloEnrolled = $true }
        } catch { }
    }
    if (-not $helloEnrolled) {
        # PassportForWork tenant subkeys appear once a user has
        # enrolled Hello against AAD; if any tenant subkey exists the
        # signal is good even when other heuristics fail.
        $pfw = 'HKCU:\SOFTWARE\Microsoft\PassportForWork'
        if (Test-Path $pfw) {
            $tenants = Get-ChildItem $pfw -ErrorAction SilentlyContinue
            if ($tenants -and $tenants.Count -gt 0) { $helloEnrolled = $true }
        }
    }

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
# WSL helpers: convert paths, mirror Windows-side keys to each distro,
# probe WSLInterop, and reset WSL state with a 3-tier auto-heal that
# only escalates to terminating Docker Desktop's helper distro when
# the gentler retries fail. See the long comment blocks on
# Initialize-WslDistroForTest for the rationale.
# ---------------------------------------------------------------------
function ConvertTo-WslPath {
    param([string]$WinPath)
    $resolved = (Resolve-Path $WinPath).Path
    $drive    = $resolved.Substring(0,1).ToLower()
    return "/mnt/$drive" + ($resolved.Substring(2) -replace '\\', '/')
}

# Mirror the Windows-side shared keys into each WSL distro. The TPM /
# webauthn credential lives on Windows; the metadata + .pub files
# live per-user on each platform, so WSL has no record of a key
# created on the Windows side. This function copies:
#   `%APPDATA%\sshenc\keys\<label>.meta` -> `/root/.sshenc/keys/<label>.meta`
#   `%USERPROFILE%\.ssh\<label>.pub`     -> `/root/.ssh/<label>.pub`
# and rewrites the `pub_file_path` in the .meta to the WSL path so
# `sshenc inspect` / `export-pub` / sign all resolve cleanly.
# Also mirrors the SEC1 raw-bytes cache (`<label>.pub` in keys_dir)
# for non-SK keys -- SK keys carry their pubkey embedded in the .meta
# and never write a SEC1 cache, so that copy is conditional.
function Sync-SharedKeysToWsl {
    param([string[]]$Labels, [string[]]$Distros)
    $appdata = "$env:APPDATA\sshenc\keys"
    $sshDir  = "$env:USERPROFILE\.ssh"
    foreach ($lbl in $Labels) {
        $metaPath = Join-Path $appdata "$lbl.meta"
        $pubPath  = Join-Path $sshDir  "$lbl.pub"
        if (-not (Test-Path $metaPath)) {
            Write-Host "  [WARN] no Windows metadata for shared key $($lbl): $metaPath" -ForegroundColor Yellow
            continue
        }
        if (-not (Test-Path $pubPath)) {
            Write-Host "  [WARN] no Windows .pub for shared key $($lbl): $pubPath" -ForegroundColor Yellow
            continue
        }
        $metaJson  = Get-Content $metaPath -Raw
        $wslPub    = "/root/.ssh/$lbl.pub"
        $rewritten = $metaJson -replace '("pub_file_path"\s*:\s*")[^"]*(")', "`$1$wslPub`$2"
        $stagedMeta = "$env:TEMP\sshenc-sync-$lbl-$PID.meta"
        [System.IO.File]::WriteAllBytes(
            $stagedMeta,
            [System.Text.UTF8Encoding]::new($false).GetBytes($rewritten)
        )
        $metaWslSrc = ConvertTo-WslPath $stagedMeta
        $pubWslSrc  = ConvertTo-WslPath $pubPath
        $sec1Path = Join-Path $appdata "$lbl.pub"
        $sec1Cmds = @()
        if (Test-Path $sec1Path) {
            $sec1WslSrc = ConvertTo-WslPath $sec1Path
            $sec1Cmds = @(
                "cp '$sec1WslSrc' /root/.sshenc/keys/$lbl.pub",
                "chmod 0644 /root/.sshenc/keys/$lbl.pub"
            )
        }
        $cmdLines = @(
            "set -e",
            "mkdir -p /root/.sshenc/keys /root/.ssh",
            "cp '$metaWslSrc' /root/.sshenc/keys/$lbl.meta",
            "cp '$pubWslSrc' /root/.ssh/$lbl.pub",
            "chmod 0600 /root/.sshenc/keys/$lbl.meta",
            "chmod 0644 /root/.ssh/$lbl.pub"
        ) + $sec1Cmds
        $cmdText  = ($cmdLines -join "`n") + "`n"
        $stagedSh = "$env:TEMP\sshenc-sync-$lbl-$PID.sh"
        [System.IO.File]::WriteAllBytes(
            $stagedSh,
            [System.Text.UTF8Encoding]::new($false).GetBytes($cmdText)
        )
        $shWslPath = ConvertTo-WslPath $stagedSh
        foreach ($d in $Distros) {
            $syncOut = & wsl -d $d -- bash $shWslPath 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0 -or $syncOut.Trim()) {
                Write-Host "  [DEBUG] sync $lbl -> $($d): exit=$LASTEXITCODE out=$($syncOut.Trim())" -ForegroundColor Yellow
            }
        }
    }
}

# Probe WSLInterop in the named distro by trying to exec `whoami.exe`
# with a 5-second timeout. Returns $true if the probe succeeds and
# whoami exits 0; $false on ENOEXEC, binfmt corruption, hang, or
# timeout (any of which indicate the binfmt_misc handler that lets
# Linux exec a Windows .exe is not correctly registered for this
# distro). Docker Desktop's `docker-desktop` helper distro hooks into
# the WSL2 VM boot path and can race the WSLInterop registration of
# a freshly-cold-booted test distro (AlmaLinux is observed to be the
# most fragile). When that happens, sshenc-agent's bridge_spawn
# returns ENOEXEC and the agent never starts.
function Test-WslInteropWorking {
    param([string]$Distro)
    $probe = @'
timeout 5 /mnt/c/Windows/System32/whoami.exe >/dev/null 2>&1
echo "exit=$?"
'@
    $probePath = "$env:TEMP\sshenc-wslinterop-probe-$PID.sh"
    [System.IO.File]::WriteAllBytes(
        $probePath,
        [System.Text.UTF8Encoding]::new($false).GetBytes($probe)
    )
    $wslProbe = ConvertTo-WslPath $probePath
    $out = (& wsl.exe -d $Distro -- bash $wslProbe 2>&1 | Out-String)
    Remove-Item $probePath -ErrorAction SilentlyContinue
    return ($out -match 'exit=0\b')
}

# Reset WSL state in front of the next test distro. Three escalating
# tiers, each gated on the previous one having failed -- so the
# common case is silent (tier 1 always works on a healthy host), and
# the destructive option only fires when we're actually stuck:
#   Tier 1: `wsl --shutdown` + 2.5s settle + probe.
#   Tier 2: another `wsl --shutdown` + 5s settle + probe.
#   Tier 3: `wsl --terminate docker-desktop` + `wsl --shutdown` + 4s.
# Returns $true if the distro is ready, $false if WSLInterop is still
# broken after tier 3. Caller logs and proceeds; the actual test will
# fail loudly if the probe was right.
function Initialize-WslDistroForTest {
    param([string]$Distro)
    & wsl.exe --shutdown 2>&1 | Out-Null
    Start-Sleep -Milliseconds 2500
    if (Test-WslInteropWorking -Distro $Distro) { return $true }

    Write-Host "  [WARN] $Distro WSLInterop probe failed; retrying with longer settle" -ForegroundColor Yellow
    & wsl.exe --shutdown 2>&1 | Out-Null
    Start-Sleep -Milliseconds 5000
    if (Test-WslInteropWorking -Distro $Distro) { return $true }

    Write-Host "  [WARN] $Distro WSLInterop still broken after retry; escalating to" -ForegroundColor Red
    Write-Host "         'wsl --terminate docker-desktop'. This will stop any running" -ForegroundColor Red
    Write-Host "         Docker containers; restart Docker Desktop after the matrix" -ForegroundColor Red
    Write-Host "         finishes if you need them back." -ForegroundColor Red
    & wsl.exe --terminate docker-desktop 2>&1 | Out-Null
    & wsl.exe --shutdown 2>&1 | Out-Null
    Start-Sleep -Milliseconds 4000
    if (Test-WslInteropWorking -Distro $Distro) { return $true }

    Write-Host "  [WARN] $Distro WSLInterop still broken after terminate+shutdown." -ForegroundColor Red
    return $false
}

# Locate Docker Desktop CLI even when it isn't on PATH. Returns the
# string "docker" if the binary is reachable or $null on any failure
# (no install, no docker-engine running, wedged 500-error engine).
function Resolve-DockerOrSkip {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        $dockerExe = "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path $dockerExe) {
            $env:Path = "$env:Path;$([System.IO.Path]::GetDirectoryName($dockerExe))"
        } else {
            return $null
        }
    }
    $null = docker ps 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    return "docker"
}

# Build the e2e Docker image if it isn't already present. The
# Dockerfile context is sshenc/crates/sshenc-e2e/docker, resolved
# relative to this script (not cwd) so the matrix can be launched
# from anywhere. Returns $null on success or a skip-reason string.
function Ensure-E2eDockerImage {
    param([string]$Image)
    $imageExists = (docker images -q $Image 2>$null | Measure-Object -Line).Lines -gt 0
    if ($imageExists) { return $null }
    $dockerCtx = Join-Path $PSScriptRoot "..\crates\sshenc-e2e\docker"
    $dockerCtx = [System.IO.Path]::GetFullPath($dockerCtx)
    if (-not (Test-Path $dockerCtx)) { return "e2e Dockerfile not found at $dockerCtx" }
    docker build -t $Image $dockerCtx 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return "image build failed" }
    return $null
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

# Mirror Windows-side keys into each WSL distro so the WSL-bridge
# section can `sshenc inspect` / sign against them. The TPM credential
# itself stays on Windows; we just copy the metadata + .pub so each
# distro's sshenc CLI can talk about the same key. No-op if -SkipWSL
# or no `wsl.exe` on PATH.
if (-not $SkipWSL -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Sync-SharedKeysToWsl -Labels $SharedKeys -Distros $Distros
    Write-Host "  [INFO] Mirrored shared keys to $($Distros.Count) WSL distros" -ForegroundColor DarkGray
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
# Trust anchor (.meta integrity). Asserts the windows-tpm-trust-anchor
# end-to-end on real Windows TPM + Credential Manager. Skipped in
# software mode: the trust anchor is layered on top of the platform
# meta-HMAC blob, which the software backend doesn't write. Each
# scenario uses --auth-policy none so no UI / fingerprint / password
# prompt fires; the trust anchor is orthogonal to AccessPolicy.
#
# Scenarios:
#   T1 fresh-keygen sign succeeds (re-stamp ran)
#   T2 .meta.hmac sidecar deleted -> sign still OK (Cred Mgr is the
#      authority, not the sidecar; deletion primitive is closed)
#   T3 .meta tampered -> sign refused (Tamper outcome)
#   T4 .meta restored -> sign succeeds again
#   T5 per-key Cred-Mgr entry deleted -> sign refused (Legacy outcome)
#   migrate-meta --yes round-trip stamps tag and sets marker
#   T6 post-migrate sign succeeds
#   marker present in Credential Manager
#   T8 tamper + delete tag with marker set -> sign refused
#      (strong-tamper variant)
# ---------------------------------------------------------------------
Banner "Trust anchor (.meta integrity)"
if ($BackendMode -eq "software") {
    Record "S" "trust anchor: skipped (software backend has no platform meta-tag)"
} else {
    $taLabel  = "trust-anchor-$PID"
    $taDir    = Join-Path $env:APPDATA "sshenc\keys"
    $taPub    = Join-Path $env:USERPROFILE ".ssh\$taLabel.pub"
    $taData   = Join-Path $env:TEMP "$taLabel.data"
    $taTarget = "com.godaddy.sshenc.meta-tag.$taLabel"
    $taMarker = "com.godaddy.sshenc.migrate-marker"
    $sshKeygenExe = "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe"
    "trust-anchor matrix probe" | Out-File -Encoding ascii -NoNewline $taData
    & $SshencBin delete -y --delete-pub $taLabel 2>&1 | Out-Null
    & cmdkey /delete:$taTarget 2>&1 | Out-Null
    # Clear the migration marker too -- the test exercises the
    # gentle-cutover migrate-meta path (T5 -> migrate -> T6), and a
    # prior matrix run may have already set the marker, in which
    # case migrate-meta refuses with "already completed". Clearing
    # here makes the test deterministic across repeated runs.
    & cmdkey /delete:$taMarker 2>&1 | Out-Null

    function Test-TaSign {
        param([string]$tag, [bool]$ExpectOk)
        Remove-Item "$taData.sig" -ErrorAction SilentlyContinue
        & $sshKeygenExe -Y sign -n test -f $taPub $taData 2>&1 | Out-Null
        $signed = Test-Path "$taData.sig"
        Remove-Item "$taData.sig" -ErrorAction SilentlyContinue
        if ($signed -eq $ExpectOk) {
            Record "P" "trust anchor: $tag"
        } else {
            $expected = if ($ExpectOk) { "SIGN OK" } else { "SIGN REFUSED" }
            $actual   = if ($signed)   { "SIGN OK" } else { "SIGN REFUSED" }
            Record "F" "trust anchor: $tag" "expected $expected, got $actual"
        }
    }

    $taKg = & $SshencBin keygen -l $taLabel --auth-policy none -C "trust-anchor" 2>&1 | Out-String
    if ($taKg -match "Generated") {
        Record "P" "trust anchor: keygen"

        Test-TaSign "T1 fresh key signs" $true

        $sidecarPath = Join-Path $taDir "$taLabel.meta.hmac"
        if (Test-Path $sidecarPath) { Remove-Item $sidecarPath -Force }
        Test-TaSign "T2 sidecar deleted -> still signs" $true

        $taMetaPath = Join-Path $taDir "$taLabel.meta"
        $taOrig = Get-Content $taMetaPath -Raw
        Set-Content $taMetaPath -Value ($taOrig -replace 'trust-anchor','tampered') -NoNewline
        Test-TaSign "T3 .meta tampered -> refuses" $false
        Set-Content $taMetaPath -Value $taOrig -NoNewline
        Test-TaSign "T4 .meta restored -> signs" $true

        & cmdkey /delete:$taTarget 2>&1 | Out-Null
        Test-TaSign "T5 cred-mgr tag deleted -> refuses (Legacy)" $false

        # `--yes` instead of piping "yes\n" because PowerShell's object
        # pipeline does NOT deliver byte stdin to native exes (the same
        # gotcha that bit `sshenc delete` in matrix v0.6.33 -- Issue 4).
        $taMig = & $SshencBin migrate-meta --yes 2>&1 | Out-String
        if ($taMig -match "Migrated") {
            Record "P" "trust anchor: migrate-meta succeeds"
        } else {
            $snippet = $taMig.Trim().Substring(0, [Math]::Min(120, $taMig.Trim().Length))
            Record "F" "trust anchor: migrate-meta succeeds" $snippet
        }
        Test-TaSign "T6 post-migrate -> signs" $true

        $markerOut = (& cmdkey /list:$taMarker 2>&1 | Out-String)
        if ($markerOut -match [regex]::Escape($taMarker)) {
            Record "P" "trust anchor: marker present after migrate"
        } else {
            Record "F" "trust anchor: marker present after migrate" "cmdkey /list shows no entry"
        }

        Set-Content $taMetaPath -Value ($taOrig -replace 'trust-anchor','tampered') -NoNewline
        & cmdkey /delete:$taTarget 2>&1 | Out-Null
        Test-TaSign "T8 strong-tamper-after-marker -> refuses" $false
        Set-Content $taMetaPath -Value $taOrig -NoNewline
    } else {
        $kgSnip = $taKg.Trim().Substring(0, [Math]::Min(120, $taKg.Trim().Length))
        Record "F" "trust anchor: keygen" $kgSnip
    }

    # Cleanup transient state. Marker stays set across runs (intentional --
    # real users only run migrate-meta once per install, so subsequent
    # matrix runs find the marker already present).
    & $SshencBin delete -y --delete-pub $taLabel 2>&1 | Out-Null
    & cmdkey /delete:$taTarget 2>&1 | Out-Null
    Remove-Item $taData -ErrorAction SilentlyContinue
    Remove-Item "$taData.sig" -ErrorAction SilentlyContinue
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
# Agent + SSH + gitenc signing against a throwaway OpenSSH+git Docker
# container. Exercises the full named-pipe -> ssh -> remote-host path
# end-to-end without depending on a GitHub-registered key being
# present in the agent. Uses the SILENT shared key for git signing
# regardless of the matrix's policy mode -- `sshenc -Y sign` (the
# program gitenc wires up as gpg.ssh.program) doesn't yet support
# sk-ecdsa keys, and the silent key is regular ECDSA-P256 either way.
# Skipped if Docker isn't available; reports the exact reason.
# ---------------------------------------------------------------------
Banner "Agent + git over SSH (container)"
$dockerCmd = Resolve-DockerOrSkip
$extSkipReason = $null
if (-not $dockerCmd) { $extSkipReason = "docker not reachable" }

# Sign with whichever key the current matrix mode uses -- regular
# ECDSA under no -Strict, sk-ecdsa under -Strict. `sshenc -Y sign`
# is agent-routed and the agent dispatches to webauthn.dll for SK
# (so SK signing fires one Hello gesture per signed commit, same as
# any other SK use). No band-aid silent-key fallback any more.
$signKey = $SharedKeyA
$extPubPath = Join-Path $env:USERPROFILE ".ssh\$signKey.pub"
if (-not $extSkipReason -and -not (Test-Path $extPubPath)) {
    $extSkipReason = "shared key pub file missing: $extPubPath"
}

$extImage = "sshenc-e2e-sshd:latest"
$extContainer = "sshenc-ext-matrix-$PID"
$extPort = 13000 + ($PID % 1000)
$extAuthPath = "$env:TEMP\ext-matrix-authorized_keys-$PID"

if (-not $extSkipReason) {
    $reason = Ensure-E2eDockerImage -Image $extImage
    if ($reason) { $extSkipReason = $reason }
}

if (-not $extSkipReason) {
    Set-Content -Path $extAuthPath -Value (Get-Content $extPubPath -Raw).TrimEnd() -Encoding ASCII -NoNewline
    docker rm -f $extContainer 2>&1 | Out-Null
    docker run -d --name $extContainer -p ${extPort}:22 -v "${extAuthPath}:/authorized_keys:ro" $extImage 2>&1 | Out-Null
    Start-Sleep 2
    $running = (docker ps --filter "name=$extContainer" --format "{{.Names}}" 2>$null) -eq $extContainer
    if (-not $running) { $extSkipReason = "container did not stay running" }
}

if (-not $extSkipReason) {
    docker exec --user sshtest $extContainer sh -c "cd /home/sshtest && git init --bare test-repo.git >/dev/null && git -C test-repo.git symbolic-ref HEAD refs/heads/main" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $extSkipReason = "container repo init failed" }
}

# Make sure sshenc-agent is up so the SSH round-trip below has
# identities. Reset-SshencKeys started it for pre-flight; in case it
# died between then and now, restart.
$agentName = [System.IO.Path]::GetFileNameWithoutExtension($AgentBin)
if (-not (Get-Process -Name $agentName -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $AgentBin -WindowStyle Hidden | Out-Null
    Start-Sleep 2
}
$env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"

if ($extSkipReason) {
    Record "S" "SSH via agent to local container" $extSkipReason
} else {
    $sshOut = & "$env:SystemRoot\System32\OpenSSH\ssh.exe" -p $extPort `
        -o StrictHostKeyChecking=no `
        -o UserKnownHostsFile=NUL `
        -o PreferredAuthentications=publickey `
        -o ConnectTimeout=30 `
        sshtest@127.0.0.1 'echo AGENT_E2E_OK && hostname' 2>&1 | Out-String
    if ($sshOut -match 'AGENT_E2E_OK') {
        Record "P" "SSH via agent to local container"
    } else {
        Record "F" "SSH via agent to local container" ($sshOut.Trim() -split "`n" | Select-Object -Last 3 | Out-String).Trim()
    }
}

if ($extSkipReason) {
    Record "S" "git clone via SSH from local container" $extSkipReason
} else {
    $testDir = "$env:TEMP\gitenc-ps-test-$PID"
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    # MSYS2 sh (which git invokes for GIT_SSH_COMMAND) eats backslashes
    # in unquoted strings (C:\W -> C:W). Forward slashes survive.
    $sshExe = ("$env:SystemRoot\System32\OpenSSH\ssh.exe") -replace '\\','/'
    $env:GIT_SSH_COMMAND = "$sshExe -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=publickey"
    $cloneUrl = "ssh://sshtest@127.0.0.1:$extPort/home/sshtest/test-repo.git"
    $cloneOut = git clone $cloneUrl $testDir 2>&1 | Out-String
    if (Test-Path "$testDir\.git") { Record "P" "git clone via SSH from local container" } else { Record "F" "git clone via SSH from local container" $cloneOut.Trim() }
}

if (-not $extSkipReason -and (Test-Path "$testDir\.git")) {
    Push-Location $testDir
    git config user.email "matrix@sshenc-e2e.local" | Out-Null
    git config user.name "sshenc matrix" | Out-Null
    & $GitencBin --config -l $signKey 2>&1 | Out-Null

    $branch = "test/ps-matrix-$(Get-Date -Format 'yyyyMMddHHmmss')"
    git checkout -b $branch 2>&1 | Out-Null
    "# matrix sign probe $(Get-Date -Format o)" | Out-File -Append TESTING.md
    git add TESTING.md 2>&1 | Out-Null
    # commit.gpgsign is set by `gitenc --config`. The commit-output
    # regex match is unreliable (the message itself contains "signed");
    # check HEAD directly.
    $commitOut = git commit -m "Test: matrix signed commit probe" 2>&1 | Out-String
    $headSha = (git rev-parse --verify HEAD 2>&1 | Out-String).Trim()
    $commitOk = ($headSha -match '^[0-9a-f]{40}$')
    if ($commitOk) {
        Record "P" "signed commit"
    } else {
        Record "F" "signed commit" ($commitOut.Trim() -split "`n" | Select-Object -Last 5 | Out-String).Trim()
    }

    if ($commitOk) {
        $sigOut = git log --show-signature -1 2>&1 | Out-String
        if ($sigOut -match "Good.*signature") { Record "P" "local signature verification" } else { Record "F" "local signature verification" $sigOut.Trim() }

        $pushOut = git push origin $branch 2>&1 | Out-String
        $remoteSha = (docker exec --user sshtest $extContainer git -C /home/sshtest/test-repo.git rev-parse "refs/heads/$branch" 2>&1 | Out-String).Trim()
        $localSha = (git rev-parse $branch 2>&1 | Out-String).Trim()
        if ($remoteSha -and $remoteSha -eq $localSha) {
            Record "P" "git push to local container"
        } else {
            Record "F" "git push to local container" "remote=$remoteSha local=$localSha push=$($pushOut.Trim())"
        }
    } else {
        Record "S" "local signature verification" "signed commit failed"
        Record "S" "git push to local container" "signed commit failed"
    }

    Pop-Location
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Tear down container + authorized_keys mount.
if (-not $extSkipReason) {
    docker rm -f $extContainer 2>&1 | Out-Null
}
Remove-Item $extAuthPath -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------
# FIDO2 SK / WebAuthn coverage. Spins up the same e2e Docker image,
# generates a fresh `--strong` SK key (Hello make-credential gesture),
# authorizes its pub in the container, and ssh-es in (Hello sign
# gesture; sshd verifies the SK signature). Two Hello prompts per
# run. Cleans up the SK key (which removes the platform passkey
# entry from Windows' passkey list -- avoids accumulating one
# orphan passkey per matrix run).
# ---------------------------------------------------------------------
if ($StrongSk) {
    Banner "FIDO2 SK keys (Windows Hello, hardware-enforced)"
    $skSkipReason = $null
    if ($BackendMode -ne "tpm-hello") {
        $skSkipReason = "requires TPM 2.0 + Windows Hello enrolled"
    } elseif (-not (Resolve-DockerOrSkip)) {
        $skSkipReason = "docker not reachable"
    } else {
        $helpOut = & $SshencBin keygen --help 2>&1 | Out-String
        if ($helpOut -notmatch '--strong') {
            $skSkipReason = "sshenc was built without the webauthn-sk feature"
        }
    }

    if ($skSkipReason) {
        Record "S" "SK keys -- $skSkipReason"
    } else {
        $reason = Ensure-E2eDockerImage -Image $extImage
        if ($reason) {
            Record "S" "SK keys -- $reason"
        } else {
            $skLabel = "ps-sk-test-$PID"
            $skPubPath = "$env:USERPROFILE\.ssh\$skLabel.pub"
            $skContainer = "sshenc-sk-matrix-$PID"
            $skPort = 12000 + ($PID % 1000)

            $kgOut = & $SshencBin keygen --strong -l $skLabel 2>&1 | Out-String
            if ($kgOut -match 'sk-ecdsa-p256') {
                Record "P" "SK keygen --strong (Hello make prompt fired)"
            } else {
                Record "F" "SK keygen --strong" $kgOut.Trim()
                $skSkipReason = "keygen-failed"
            }

            if (-not $skSkipReason -and (Test-Path $skPubPath)) {
                $skKg = & "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -l -f $skPubPath 2>&1 | Out-String
                if ($skKg -match 'ECDSA-SK') {
                    Record "P" "ssh-keygen accepts SK pub format"
                } else {
                    Record "F" "ssh-keygen accepts SK pub" $skKg.Trim()
                }

                $skAuthPath = "$env:TEMP\sk-matrix-authorized_keys-$PID"
                Set-Content -Path $skAuthPath -Value (Get-Content $skPubPath -Raw).TrimEnd() -Encoding ASCII -NoNewline
                docker rm -f $skContainer 2>&1 | Out-Null
                docker run -d --name $skContainer -p ${skPort}:22 -v "${skAuthPath}:/authorized_keys:ro" $extImage 2>&1 | Out-Null
                Start-Sleep 2
                $running = (docker ps --filter "name=$skContainer" --format "{{.Names}}" 2>$null) -eq $skContainer
                if ($running) {
                    Record "P" "SK e2e container running"
                } else {
                    Record "F" "SK e2e container start" "container did not stay running"
                    $skSkipReason = "container-failed"
                }

                if (-not $skSkipReason) {
                    $sshOut = & "$env:SystemRoot\System32\OpenSSH\ssh.exe" -p $skPort `
                        -o StrictHostKeyChecking=no `
                        -o UserKnownHostsFile=NUL `
                        -o IdentitiesOnly=yes `
                        -i $skPubPath `
                        -o PreferredAuthentications=publickey `
                        -o ConnectTimeout=120 `
                        sshtest@127.0.0.1 'echo SK_E2E_OK && hostname' 2>&1 | Out-String
                    if ($sshOut -match 'SK_E2E_OK') {
                        Record "P" "SK ssh-via-container (Hello sign prompt fired, sig verified by sshd)"
                    } else {
                        Record "F" "SK ssh-via-container" ($sshOut.Trim() -split "`n" | Select-Object -Last 3 | Out-String).Trim()
                    }
                }

                docker rm -f $skContainer 2>&1 | Out-Null
                Remove-Item $skAuthPath -ErrorAction SilentlyContinue
                $delOut = & $SshencBin delete -y --delete-pub $skLabel 2>&1 | Out-String
                if ($delOut -match 'Deleted key') {
                    Record "P" "SK key cleanup via sshenc delete"
                } else {
                    Record "F" "SK key cleanup" $delOut.Trim()
                }
            }
        }
    }
}

# ---------------------------------------------------------------------
# install / uninstall: round-trip the IdentityAgent stanza in
# ~/.ssh/config. Backs up the file first; restores on the way out.
# ---------------------------------------------------------------------
Banner "install / uninstall"
$sshConfigPath = "$env:USERPROFILE\.ssh\config"
$configBackup = Get-Content $sshConfigPath -Raw -ErrorAction SilentlyContinue

& $SshencBin uninstall 2>&1 | Out-Null
$afterUninstall = Get-Content $sshConfigPath -Raw -ErrorAction SilentlyContinue
if (-not $afterUninstall -or $afterUninstall -notmatch "sshenc") {
    Record "P" "sshenc uninstall removes config"
} else {
    Record "F" "sshenc uninstall removes config"
}

& $SshencBin install 2>&1 | Out-Null
Start-Sleep 3
$afterInstall = Get-Content $sshConfigPath -Raw -ErrorAction SilentlyContinue
if ($afterInstall -match "IdentityAgent") {
    Record "P" "sshenc install writes config"
} else {
    Record "F" "sshenc install writes config"
}

if ($configBackup) { Set-Content $sshConfigPath -Value $configBackup -NoNewline }

# ---------------------------------------------------------------------
# WSL distros. Mirrors the Windows-side shared keys (already done in
# pre-flight), then runs the same lifecycle on each distro. Each
# distro signs through the JSON-RPC bridge to the Windows TPM.
# Under -Strict the SK key fires a Hello prompt per distro -- watch
# for it. Skipped under -SkipWSL or when wsl.exe isn't on PATH.
# ---------------------------------------------------------------------
if (-not $SkipWSL -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    $bashTests = @'
#!/usr/bin/env bash
# Reproduce what an interactive shell does: prefer the native
# sshenc-agent over a stale socat+npiperelay shim; pre-warm the
# Windows-side bridge BEFORE starting the agent so its one-shot
# bridge_list_keys doesn't race a cold TPM and cache empty for the
# rest of its life.
export SSH_AUTH_SOCK="$HOME/.sshenc/agent.sock"
mkdir -p "$HOME/.sshenc"
__BRIDGE="/mnt/c/Users/JeremiahGowdy/scoop/apps/sshenc/current/sshenc-tpm-bridge.exe"
if [ -x "$__BRIDGE" ]; then
    export SSHENC_BRIDGE_PATH="$__BRIDGE"
fi
if command -v sshenc-agent >/dev/null 2>&1; then
    if pgrep -f 'socat.*npiperelay' >/dev/null 2>&1; then
        pkill -f 'socat.*npiperelay' 2>/dev/null
        rm -f "$SSH_AUTH_SOCK"
        sleep 1
    fi
    sshenc list >/dev/null 2>&1 || true
    pkill -f "sshenc-agent .*$SSH_AUTH_SOCK" 2>/dev/null || true
    rm -f "$SSH_AUTH_SOCK"
    sleep 1
    sshenc-agent --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
    sleep 1
elif command -v socat >/dev/null 2>&1 && command -v npiperelay.exe >/dev/null 2>&1; then
    if [ ! -S "$SSH_AUTH_SOCK" ] || ! pgrep -f "socat.*npiperelay" >/dev/null 2>&1; then
        rm -f "$SSH_AUTH_SOCK"
        socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork \
            EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent" >/dev/null 2>&1 &
        disown 2>/dev/null
        sleep 1
    fi
fi
set -uo pipefail
PASS=0; FAIL=0; SKIP=0
record() { local s=$1 t=$2; case $s in P) ((PASS++)); l=PASS;; F) ((FAIL++)); l=FAIL;; S) ((SKIP++)); l=SKIP;; esac; printf "  [%s] %s\n" "$l" "$t"; }

if pgrep -af 'socat.*npiperelay' >/dev/null 2>&1; then
    echo "  [INFO] agent transport: socat+npiperelay (legacy; racy on keygen)"
elif pgrep -af 'sshenc-agent' >/dev/null 2>&1; then
    echo "  [INFO] agent transport: native sshenc-agent (preferred)"
else
    echo "  [INFO] agent transport: not running yet (first sshenc command will start it)"
fi

sshenc --version 2>&1 | grep -q "sshenc" && record P "sshenc --version" || record F "sshenc --version"
gitenc --version 2>&1 | grep -q "gitenc" && record P "gitenc --version" || record F "gitenc --version"
sshenc config show 2>&1 | grep -q "socket_path\|prompt_policy" && record P "sshenc config show" || record F "sshenc config show"
gitenc -h 2>&1 | grep -q "Git wrapper" && record P "gitenc -h" || record F "gitenc -h"
sshenc completions bash 2>&1 | grep -q "_sshenc" && record P "sshenc completions bash" || record F "sshenc completions bash"

SHARED_A="__SHARED_A__"
SHARED_B="__SHARED_B__"
FP_A=$(sshenc export-pub "$SHARED_A" --fingerprint 2>&1)
FP_B=$(sshenc export-pub "$SHARED_B" --fingerprint 2>&1)
if [[ "$FP_A" == SHA256:* ]] && [[ "$FP_B" == SHA256:* ]] && [[ "$FP_A" != "$FP_B" ]]; then
    record P "shared keys have distinct fingerprints"
else
    record F "shared keys have distinct fingerprints (A=$FP_A B=$FP_B)"
fi
sshenc inspect "$SHARED_A" 2>&1 | grep -q "ecdsa" && record P "sshenc inspect" || record F "sshenc inspect"
sshenc export-pub "$SHARED_A" 2>&1 | grep -q "ecdsa-sha2-nistp256" && record P "sshenc export-pub" || record F "sshenc export-pub"

PUB_PATH="$HOME/.ssh/$SHARED_A.pub"
EXPECTED_PUB=""
if [ -r "$PUB_PATH" ]; then
    read -r _pub_algo EXPECTED_PUB _pub_comment < "$PUB_PATH" || true
fi
poll_for_key() {
    local timeout_secs=$1
    local start=$(date +%s)
    while [ $(( $(date +%s) - start )) -lt "$timeout_secs" ]; do
        local agent_keys
        agent_keys=$(ssh-add -L 2>/dev/null || true)
        if [ -n "$EXPECTED_PUB" ] && echo "$agent_keys" | grep -qF "$EXPECTED_PUB"; then
            return 0
        fi
        sleep 1
    done
    return 1
}
WARM_OK=0
WARM_START=$(date +%s)
if poll_for_key 60; then
    WARM_OK=1
else
    echo "  [INFO] agent cache empty after 60s; restarting agent (likely cold-bridge race)"
    pkill -f "sshenc-agent .*$SSH_AUTH_SOCK" 2>/dev/null || true
    rm -f "$SSH_AUTH_SOCK"
    sleep 1
    sshenc-agent --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
    sleep 1
    if poll_for_key 60; then
        WARM_OK=1
    fi
fi
WARM_ELAPSED=$(( $(date +%s) - WARM_START ))
if [ "$WARM_OK" != "1" ]; then
    echo "  [WARN] agent identity cache did not populate the shared key within ${WARM_ELAPSED}s (incl. one restart)"
elif [ "$WARM_ELAPSED" -gt 5 ]; then
    echo "  [INFO] agent cache populated after ${WARM_ELAPSED}s"
fi

SIG_OUT=$(echo "matrix sign test (WSL)" | timeout 120 ssh-keygen -Y sign -f "$HOME/.ssh/$SHARED_A.pub" -n "matrix-test" 2>&1)
if echo "$SIG_OUT" | grep -q "BEGIN SSH SIGNATURE"; then
    record P "sign via WSL bridge -> Windows TPM"
else
    record F "sign via WSL bridge -> Windows TPM ($(echo "$SIG_OUT" | head -3 | tr -d '\n'))"
fi

echo "  TOTAL: $PASS pass, $FAIL fail, $SKIP skip"
exit $FAIL
'@

    foreach ($distro in $Distros) {
        Banner "WSL2 $distro (bridge, no keyring)"
        $null = Initialize-WslDistroForTest -Distro $distro
        if ($Strict) {
            Write-Host "  [INFO] $distro sign -- watch for Windows Hello prompt..." -ForegroundColor Cyan
        }
        $scriptText = $bashTests.Replace('__SHARED_A__', $SharedKeyA).Replace('__SHARED_B__', $SharedKeyB) -replace "`r`n", "`n" -replace "`r", "`n"
        $stagedPath = "$env:TEMP\sshenc-wsl-matrix-$distro-$PID.sh"
        [System.IO.File]::WriteAllBytes($stagedPath, [System.Text.UTF8Encoding]::new($false).GetBytes($scriptText))
        $resolvedPath = (Resolve-Path $stagedPath).Path
        $drive = $resolvedPath.Substring(0,1).ToLower()
        $wslPath = "/mnt/$drive" + ($resolvedPath.Substring(2) -replace '\\', '/')

        $wslJob = Start-Job -ScriptBlock {
            param($d, $p)
            $result = & wsl -d $d -- bash $p 2>&1
            $result -join "`n"
        } -ArgumentList $distro, $wslPath

        $completed = Wait-Job $wslJob -Timeout $WslTimeout
        if ($completed) {
            $output = Receive-Job $wslJob
            $lines = ($output -split "`n")
            foreach ($line in $lines) {
                Write-Host $line
                if ($line -match '^\s*\[PASS\]\s+(.+?)\s*$') {
                    $script:Pass++
                    $script:Results += [PSCustomObject]@{ Status = "PASS"; Test = "WSL/$distro $($Matches[1])"; Detail = "" }
                } elseif ($line -match '^\s*\[FAIL\]\s+(.+?)\s*$') {
                    $script:Fail++
                    $script:Results += [PSCustomObject]@{ Status = "FAIL"; Test = "WSL/$distro $($Matches[1])"; Detail = "" }
                } elseif ($line -match '^\s*\[SKIP\]\s+(.+?)\s*$') {
                    $script:Skip++
                    $script:Results += [PSCustomObject]@{ Status = "SKIP"; Test = "WSL/$distro $($Matches[1])"; Detail = "" }
                }
            }
        } else {
            Write-Host "  [TIMEOUT] WSL test timed out after ${WslTimeout}s" -ForegroundColor Yellow
            $script:Fail++
            $script:Results += [PSCustomObject]@{ Status = "FAIL"; Test = "WSL/$distro timeout"; Detail = "${WslTimeout}s" }
            Stop-Job $wslJob
        }
        Remove-Job $wslJob -Force
        Remove-Item $stagedPath -Force -ErrorAction SilentlyContinue
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
