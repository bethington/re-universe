# Ghidra RE Platform - Initial Setup Script
# Creates necessary directories and validates environment

param(
    [switch]$SkipDockerPull
)

Write-Host "=== Ghidra RE Platform Setup ===" -ForegroundColor Cyan

# Check for required tools
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check Docker
try {
    docker --version | Out-Null
    Write-Host "✓ Docker is available" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Docker is required but not installed" -ForegroundColor Red
    Write-Host "Please install Docker Desktop and try again" -ForegroundColor Yellow
    exit 1
}

# Check Docker Compose
try {
    docker-compose --version | Out-Null
    Write-Host "✓ Docker Compose is available" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Docker Compose is required but not installed" -ForegroundColor Red
    exit 1
}

# Create environment file if it doesn't exist
if (!(Test-Path ".env")) {
    Write-Host "Creating .env file from template..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "✓ Created .env file" -ForegroundColor Green
} else {
    Write-Host "✓ .env file already exists" -ForegroundColor Green
}

# Create necessary directories
Write-Host "Creating directory structure..." -ForegroundColor Yellow
$directories = @("repo-data", "sync-logs", "backups")

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Create .gitkeep files to ensure directories are tracked
"# Ghidra repository data directory" | Out-File -FilePath "repo-data\.gitkeep" -Encoding UTF8
"# ret-sync logs directory" | Out-File -FilePath "sync-logs\.gitkeep" -Encoding UTF8
"# Backup storage directory" | Out-File -FilePath "backups\.gitkeep" -Encoding UTF8

Write-Host "✓ Directory structure created" -ForegroundColor Green

# Pull Docker images (unless skipped)
if (!$SkipDockerPull) {
    Write-Host "Pulling Docker images..." -ForegroundColor Yellow
    try {
        docker-compose pull
        Write-Host "✓ Docker images updated" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not pull Docker images. You may need to run this manually." -ForegroundColor Yellow
    }
}

# Test configuration
Write-Host "Validating configuration..." -ForegroundColor Yellow
if (Test-Path ".\test-connectivity.ps1") {
    Write-Host "✓ All scripts are present" -ForegroundColor Green
} else {
    Write-Host "WARNING: Some scripts may be missing" -ForegroundColor Yellow
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review .env configuration if needed" -ForegroundColor White
Write-Host "2. Run .\start.ps1 to start the platform" -ForegroundColor White
Write-Host "3. Run .\test-connectivity.ps1 to verify setup" -ForegroundColor White
