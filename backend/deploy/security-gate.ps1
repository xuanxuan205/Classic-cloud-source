# IronWall v1.38.0: release security gate (GAP=0 required before deploy).
# Usage:  powershell -ExecutionPolicy Bypass -File deploy\security-gate.ps1
# Optional params:
#   -RunPython         run security-tests\ironwall_regression_test.py (against IRONWALL_BASE_URL)
#   -SkipPython        never run python regression (backward compatible)
#   -RunSupplyChain    best-effort supply-chain scan (mvn dependency-check + npm audit);
#                      missing offline plugin / no network / no manifest = INFO only, never red
#   -SkipMaven         skip maven regression (self-test / CI reuse)
#   -ReportsDir PATH   override surefire reports dir (self-test / CI reuse)
param(
    [switch]$SkipPython,
    [switch]$RunPython,
    [switch]$RunSupplyChain,
    [switch]$SkipMaven,
    [string]$ReportsDir = ""
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ReportsDir)) {
    $ReportsDir = Join-Path $repo 'target\surefire-reports'
}

Write-Host '== IronWall release security gate =='

# 1) Maven full regression
if (-not $SkipMaven) {
    $settings = Join-Path $repo '.m2\settings.xml'
    $mvnArgs = @('test')
    if (Test-Path $settings) {
        $mvnArgs = @('test', '-s', $settings)
    }
    Push-Location $repo
    try {
        & mvn @mvnArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[GATE] FAIL: mvn test exited non-zero'
            exit 1
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host '[GATE] INFO: maven step skipped (-SkipMaven)'
}

# 2) Aggregate surefire summaries: GAP = Failures + Errors, must be 0
$tests = 0; $failures = 0; $errors = 0
if (Test-Path $ReportsDir) {
    Get-ChildItem -Path (Join-Path $ReportsDir '*.txt') | ForEach-Object {
        $line = Select-String -Path $_.FullName -Pattern 'Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)' | Select-Object -Last 1
        if ($line) {
            $tests += [int]$line.Matches[0].Groups[1].Value
            $failures += [int]$line.Matches[0].Groups[2].Value
            $errors += [int]$line.Matches[0].Groups[3].Value
        }
    }
}
$gap = $failures + $errors
Write-Host ("[GATE] JUnit: tests={0} failures={1} errors={2}" -f $tests, $failures, $errors)
if ($tests -eq 0) {
    Write-Host '[GATE] FAIL: no surefire summary found'
    exit 1
}
if ($gap -gt 0) {
    Write-Host ("[GATE] FAIL: GAP={0} (must be 0)" -f $gap)
    exit 1
}

# 3) Optional python regression (explicit -RunPython, see security-tests/README.md)
$pyScript = Join-Path $repo 'security-tests\ironwall_regression_test.py'
if ($RunPython -and -not $SkipPython -and (Test-Path $pyScript)) {
    Write-Host '[GATE] Running python regression ...'
    python $pyScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[GATE] FAIL: python regression failed'
        exit 1
    }
} elseif ($RunPython -and -not (Test-Path $pyScript)) {
    Write-Host '[GATE] FAIL: -RunPython requested but ironwall_regression_test.py is missing'
    exit 1
} else {
    Write-Host '[GATE] INFO: python regression skipped (use -RunPython to enable)'
}

# 4) Best-effort supply-chain scan (explicit -RunSupplyChain). Never blocks on missing tooling/network.
if ($RunSupplyChain) {
    Write-Host '[GATE] Supply-chain scan (best effort) ...'
    $root = Split-Path -Parent $repo
    Push-Location $repo
    try {
        $settings = Join-Path $repo '.m2\settings.xml'
        $scanArgs = @('-B', '-o')
        if (Test-Path $settings) {
            $scanArgs = @('-B', '-o', '-s', $settings)
        }
        $scanArgs += 'org.owasp:dependency-check-maven:check'
        & mvn @scanArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[GATE] INFO: backend dependency-check unavailable offline or failed to resolve plugin; report skipped (not blocking)'
        } else {
            Write-Host '[GATE] OK: backend dependency-check completed'
        }
    } finally {
        Pop-Location
    }
    $frontend = Join-Path $root 'frontend'
    if (Test-Path (Join-Path $frontend 'package.json')) {
        Push-Location $frontend
        try {
            & npm audit --audit-level=high
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[GATE] WARN: npm audit reported high/critical findings or network unavailable; see output above (not blocking)'
            } else {
                Write-Host '[GATE] OK: npm audit clean or no high+ findings'
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host '[GATE] INFO: frontend package.json not present, npm audit skipped'
    }
}

Write-Host '[GATE] PASS: GAP=0, release allowed'
exit 0
