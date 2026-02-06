# Quick Test Runner for GitHub Actions
# Simplified test suite for CI/CD validation

param(
    [switch]$SkipDocker
)

Write-Host "=== Quick Test Suite ===" -ForegroundColor Cyan

# Test 1: Basic Prerequisites
Write-Host "[1/5] Checking Prerequisites" -ForegroundColor Cyan
try {
    docker --version | Out-Null
    Write-Host "✅ Docker available" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker not found" -ForegroundColor Red
    exit 1
}

try {
    docker-compose --version | Out-Null
    Write-Host "✅ Docker Compose available" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Compose not found" -ForegroundColor Red
    exit 1
}

# Test 2: Script Syntax
Write-Host "[2/5] Validating Script Syntax" -ForegroundColor Cyan
$syntaxErrors = 0

Get-ChildItem *.ps1 | ForEach-Object {
    try {
        $null = [scriptblock]::Create((Get-Content $_.FullName -Raw))
        Write-Host "✅ $($_.Name) syntax valid" -ForegroundColor Green
    } catch {
        Write-Host "❌ $($_.Name) syntax error" -ForegroundColor Red
        $syntaxErrors++
    }
}

if ($syntaxErrors -gt 0) {
    Write-Host "Found $syntaxErrors syntax errors" -ForegroundColor Red
    exit 1
}

# Test 3: Configuration
Write-Host "[3/5] Testing Configuration" -ForegroundColor Cyan
if (Test-Path "config.ps1") {
    try {
        & .\config.ps1 -Action validate | Out-Null
        Write-Host "✅ Configuration validation passed" -ForegroundColor Green
    } catch {
        Write-Host "❌ Configuration validation failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "❌ config.ps1 not found" -ForegroundColor Red
    exit 1
}

# Test 4: Setup Process
Write-Host "[4/5] Testing Setup Process" -ForegroundColor Cyan
if (Test-Path "setup.ps1") {
    try {
        if ($SkipDocker) {
            & .\setup.ps1 -SkipDockerPull | Out-Null
        } else {
            & .\setup.ps1 | Out-Null
        }
        Write-Host "✅ Setup process completed" -ForegroundColor Green
    } catch {
        Write-Host "❌ Setup process failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "❌ setup.ps1 not found" -ForegroundColor Red
    exit 1
}

# Test 5: File Structure
Write-Host "[5/5] Validating File Structure" -ForegroundColor Cyan
$requiredFiles = @("docker-compose.yml", ".env.example", "README.md")
$missingFiles = 0

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✅ $file exists" -ForegroundColor Green
    } else {
        Write-Host "❌ Missing: $file" -ForegroundColor Red
        $missingFiles++
    }
}

if ($missingFiles -gt 0) {
    Write-Host "Missing $missingFiles required files" -ForegroundColor Red
    exit 1
}

Write-Host "`n🎉 All quick tests passed!" -ForegroundColor Green
Write-Host "Platform is ready for GitHub Actions testing" -ForegroundColor Cyan
