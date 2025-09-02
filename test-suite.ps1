# Automated Test Suite for Ghidra RE Platform
# This script runs comprehensive tests that can b    # Test bash scripts (if bash is available and not in CI on Windows)
    if ((Get-Command bash -ErrorAction SilentlyContinue) -and !($CI -and $IsWindows)) {
        Get-ChildItem *.sh | ForEach-Object {
            try {
                $result = & bash -n $_.FullName 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Test-Pass "Bash syntax valid: $($_.Name)"
                } else {
                    Test-Fail "Bash syntax error: $($_.Name)"
                }
            } catch {
                Test-Fail "Bash syntax check failed: $($_.Name)"
            }
        }
    } else {
        if ($CI) {
            Write-Host "⚠️ Skipping Bash syntax tests (CI mode)" -ForegroundColor Yellow
        } else {
            Write-Host "⚠️ Bash not available, skipping .sh syntax tests" -ForegroundColor Yellow
        }
    }CD

param(
    [switch]$CI,
    [switch]$SkipDocker
)

# Test counters
$script:TestsRun = 0
$script:TestsPassed = 0
$script:TestsFailed = 0

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Test result functions
function Start-Test {
    param([string]$TestName)
    $script:TestsRun++
    Write-Host "`n[TEST $script:TestsRun] $TestName" -ForegroundColor Cyan
}

function Test-Pass {
    param([string]$Message)
    $script:TestsPassed++
    Write-Host "✅ PASS: $Message" -ForegroundColor Green
}

function Test-Fail {
    param([string]$Message)
    $script:TestsFailed++
    Write-Host "❌ FAIL: $Message" -ForegroundColor Red
    if (!$CI) {
        Write-Host "Continuing with remaining tests..." -ForegroundColor Yellow
    }
}

# Test 1: Prerequisites Check
function Test-Prerequisites {
    Start-Test "Prerequisites Check"
    
    # Docker
    try {
        docker --version | Out-Null
        Test-Pass "Docker is installed"
    } catch {
        Test-Fail "Docker is not installed"
        return
    }
    
    # Docker Compose
    try {
        # Try docker-compose first (v1)
        docker-compose --version | Out-Null
        Test-Pass "Docker Compose is installed"
    } catch {
        try {
            # Try docker compose (v2)
            docker compose version | Out-Null
            Test-Pass "Docker Compose is installed"
        } catch {
            Test-Fail "Docker Compose is not installed"
            return
        }
    }
    
    # Check if scripts exist
    $scripts = @("start.ps1", "stop.ps1", "config.ps1", "backup.ps1", "restore.ps1", "cleanup.ps1", "test-connectivity.ps1")
    foreach ($script in $scripts) {
        if (Test-Path $script) {
            Test-Pass "Script exists: $script"
        } else {
            Test-Fail "Missing script: $script"
        }
    }
}

# Test 2: Script Syntax Validation
function Test-ScriptSyntax {
    Start-Test "Script Syntax Validation"
    
    # Test PowerShell scripts
    Get-ChildItem *.ps1 | ForEach-Object {
        try {
            $null = [scriptblock]::Create((Get-Content $_.FullName -Raw))
            Test-Pass "PowerShell syntax valid: $($_.Name)"
        } catch {
            Test-Fail "PowerShell syntax error: $($_.Name) - $($_.Exception.Message)"
        }
    }
    
    # Test bash scripts (if bash is available)
    if (Get-Command bash -ErrorAction SilentlyContinue) {
        Get-ChildItem *.sh | ForEach-Object {
            try {
                $result = & bash -n $_.FullName 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Test-Pass "Bash syntax valid: $($_.Name)"
                } else {
                    Test-Fail "Bash syntax error: $($_.Name)"
                }
            } catch {
                Test-Fail "Bash syntax check failed: $($_.Name)"
            }
        }
    } else {
        Write-Host "⚠️  Bash not available, skipping .sh syntax tests" -ForegroundColor Yellow
    }
}

# Test 3: Configuration Management
function Test-Configuration {
    Start-Test "Configuration Management"
    
    # Backup existing .env if it exists
    $envBackup = $null
    if (Test-Path ".env") {
        $envBackup = ".env.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item ".env" $envBackup
    }
    
    try {
        # Test config script functionality
        if (Test-Path "config.ps1") {
            # Test show functionality
            try {
                & .\config.ps1 | Out-Null
                Test-Pass "Config show functionality works"
            } catch {
                Test-Fail "Config show functionality failed"
            }
            
            # Test validation
            try {
                & .\config.ps1 -Action validate | Out-Null
                Test-Pass "Config validation works"
            } catch {
                Test-Fail "Config validation failed"
            }
            
            # Test set functionality
            try {
                & .\config.ps1 -Action set -Key TEST_KEY -Value test_value | Out-Null
                if (Select-String -Path ".env" -Pattern "TEST_KEY=test_value" -Quiet) {
                    Test-Pass "Config set functionality works"
                    # Clean up test key
                    (Get-Content ".env") | Where-Object { $_ -notmatch "^TEST_KEY=" } | Set-Content ".env"
                } else {
                    Test-Fail "Config set functionality failed - value not found"
                }
            } catch {
                Test-Fail "Config set functionality failed - command error"
            }
            
            # Test reset functionality
            try {
                & .\config.ps1 -Action reset | Out-Null
                Test-Pass "Config reset functionality works"
            } catch {
                Test-Fail "Config reset functionality failed"
            }
        } else {
            Test-Fail "config.ps1 script not found"
        }
    } finally {
        # Restore backup if it exists
        if ($envBackup -and (Test-Path $envBackup)) {
            Move-Item $envBackup ".env" -Force
        }
    }
}

# Test 4: Directory Structure
function Test-DirectoryStructure {
    Start-Test "Directory Structure Validation"
    
    $requiredDirs = @("repo-data", "sync-logs", "backups", ".vscode")
    foreach ($dir in $requiredDirs) {
        if (Test-Path $dir -PathType Container) {
            Test-Pass "Directory exists: $dir"
        } else {
            Test-Fail "Missing directory: $dir"
        }
    }
    
    # Check for important files
    $requiredFiles = @("docker-compose.yml", ".env.example", "README.md")
    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            Test-Pass "Required file exists: $file"
        } else {
            Test-Fail "Missing required file: $file"
        }
    }
}

# Test 5: Docker Configuration
function Test-DockerConfig {
    Start-Test "Docker Configuration Validation"
    
    if (!$SkipDocker) {
        # Test docker-compose file syntax
        try {
            docker-compose config | Out-Null
            Test-Pass "docker-compose.yml syntax is valid"
        } catch {
            Test-Fail "docker-compose.yml has syntax errors"
        }
        
        # Test that required services are defined
        try {
            $config = docker-compose config 2>$null
            if ($config -match "ghidra-server") {
                Test-Pass "ghidra-server service is defined"
            } else {
                Test-Fail "ghidra-server service not found in docker-compose.yml"
            }
        } catch {
            Test-Fail "Could not parse docker-compose configuration"
        }
    } else {
        Write-Host "⚠️  Skipping Docker tests (SkipDocker flag set)" -ForegroundColor Yellow
    }
}

# Test 6: Backup System
function Test-BackupSystem {
    Start-Test "Backup System Validation"
    
    # Test backup script exists and is valid PowerShell
    if (Test-Path "backup.ps1") {
        try {
            # Just validate the script syntax without running it
            [scriptblock]::Create((Get-Content "backup.ps1" -Raw)) | Out-Null
            Test-Pass "Backup script syntax is valid"
        } catch {
            Test-Fail "Backup script has syntax errors"
        }
    } else {
        Test-Fail "backup.ps1 script not found"
    }
    
    # Test restore script syntax  
    if (Test-Path "restore.ps1") {
        try {
            [scriptblock]::Create((Get-Content "restore.ps1" -Raw)) | Out-Null
            Test-Pass "Restore script syntax is valid"
        } catch {
            Test-Fail "Restore script has syntax errors"
        }
    } else {
        Test-Fail "restore.ps1 script not found"
    }
}

# Test 7: VS Code Integration
function Test-VSCodeIntegration {
    Start-Test "VS Code Integration"
    
    # Check tasks.json
    if (Test-Path ".vscode\tasks.json") {
        try {
            $tasks = Get-Content ".vscode\tasks.json" | ConvertFrom-Json
            Test-Pass "tasks.json syntax is valid"
            
            # Check for essential tasks
            $taskLabels = $tasks.tasks | ForEach-Object { $_.label }
            if ($taskLabels -contains "🚀 Start Ghidra Server") {
                Test-Pass "Start Ghidra Server task exists"
            } else {
                Test-Fail "Start Ghidra Server task missing"
            }
        } catch {
            Test-Fail "tasks.json has syntax errors"
        }
    } else {
        Test-Fail ".vscode\tasks.json not found"
    }
    
    # Check extensions.json
    if (Test-Path ".vscode\extensions.json") {
        try {
            $extensions = Get-Content ".vscode\extensions.json" | ConvertFrom-Json
            Test-Pass "extensions.json syntax is valid"
            
            # Check for essential extensions
            if ($extensions.recommendations -contains "ms-vscode.powershell") {
                Test-Pass "PowerShell extension recommended"
            } else {
                Test-Fail "PowerShell extension not in recommendations"
            }
        } catch {
            Test-Fail "extensions.json has syntax errors"
        }
    } else {
        Test-Fail ".vscode\extensions.json not found"
    }
}

# Test 8: Documentation Quality
function Test-Documentation {
    Start-Test "Documentation Quality Check"
    
    $docs = @("README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md")
    foreach ($doc in $docs) {
        if (Test-Path $doc) {
            # Check if file has content (more than just a title)
            $lineCount = (Get-Content $doc).Count
            if ($lineCount -gt 5) {
                Test-Pass "Documentation exists and has content: $doc"
            } else {
                Test-Fail "Documentation too short or empty: $doc"
            }
        } else {
            Test-Fail "Missing documentation: $doc"
        }
    }
    
    # Check for license
    if (Test-Path "LICENSE") {
        Test-Pass "LICENSE file exists"
    } else {
        Test-Fail "LICENSE file missing"
    }
}

# Main execution
Write-Log "=== Ghidra RE Platform - Automated Test Suite ==="
Write-Log "Running comprehensive validation tests..."

# Run all test suites
Test-Prerequisites
Test-ScriptSyntax
Test-Configuration
Test-DirectoryStructure
Test-DockerConfig
Test-BackupSystem
Test-VSCodeIntegration
Test-Documentation

# Test summary
Write-Host "`n=== Test Results Summary ===" -ForegroundColor Cyan
Write-Host "Tests Run: $script:TestsRun" -ForegroundColor White
Write-Host "Passed: $script:TestsPassed" -ForegroundColor Green
Write-Host "Failed: $script:TestsFailed" -ForegroundColor Red

if ($script:TestsFailed -gt 0) {
    Write-Host "`n❌ Some tests failed. Please review the output above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n✅ All tests passed! Project is ready for production." -ForegroundColor Green
    exit 0
}
