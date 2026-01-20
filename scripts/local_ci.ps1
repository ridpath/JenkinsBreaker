# Local CI Pipeline for JenkinsBreaker (PowerShell version for Windows)
# Validates code quality and functionality against local jenkins-lab before committing

param(
    [switch]$SkipDocker = $false,
    [switch]$SkipIntegration = $false,
    [switch]$KeepRunning = $false
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$JenkinsLabDir = Join-Path $ProjectRoot "jenkins-lab"
$JenkinsUrl = "http://localhost:8080"
$JenkinsUser = "admin"
$JenkinsPass = "admin"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-Requirements {
    Write-Info "Checking requirements..."
    
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error-Custom "Docker not found. Install Docker to run local CI."
        exit 1
    }
    
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error-Custom "Python not found."
        exit 1
    }
    
    Write-Success "Requirements check passed"
}

function Start-JenkinsLab {
    if ($SkipDocker) {
        Write-Warning "Skipping Docker startup (--SkipDocker)"
        return
    }
    
    Write-Info "Starting jenkins-lab environment..."
    
    Push-Location $JenkinsLabDir
    
    $running = docker-compose ps | Select-String "jenkins-lab.*Up"
    if ($running) {
        Write-Warning "jenkins-lab already running"
    } else {
        docker-compose up -d
        Write-Info "Waiting for Jenkins to be ready..."
        
        $maxAttempts = 60
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            try {
                $response = Invoke-WebRequest -Uri $JenkinsUrl -UseBasicParsing -Credential (New-Object PSCredential($JenkinsUser, (ConvertTo-SecureString $JenkinsPass -AsPlainText -Force))) -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    Write-Success "jenkins-lab is ready"
                    break
                }
            } catch {
                # Continue waiting
            }
            Start-Sleep -Seconds 2
            $attempt++
        }
        
        if ($attempt -eq $maxAttempts) {
            Write-Error-Custom "jenkins-lab failed to start within timeout"
            Pop-Location
            exit 1
        }
    }
    
    Pop-Location
}

function Invoke-Linting {
    Write-Info "Running linting checks..."
    
    $config = Join-Path $ProjectRoot "pyproject.toml"
    
    try {
        ruff check src/ tests/ --config $config
        ruff format --check src/ tests/ --config $config
        Write-Success "Linting passed"
        return $true
    } catch {
        Write-Error-Custom "Linting failed"
        return $false
    }
}

function Invoke-TypeChecking {
    Write-Info "Running type checking..."
    
    $config = Join-Path $ProjectRoot "pyproject.toml"
    
    try {
        mypy src/jenkins_breaker/ --config-file $config
        Write-Success "Type checking passed"
        return $true
    } catch {
        Write-Error-Custom "Type checking failed"
        return $false
    }
}

function Invoke-UnitTests {
    Write-Info "Running unit tests..."
    
    try {
        pytest tests/unit/ -v --tb=short
        Write-Success "Unit tests passed"
        return $true
    } catch {
        Write-Error-Custom "Unit tests failed"
        return $false
    }
}

function Invoke-IntegrationTests {
    if ($SkipIntegration) {
        Write-Warning "Skipping integration tests (--SkipIntegration)"
        return $true
    }
    
    Write-Info "Running integration tests against jenkins-lab..."
    
    $env:JENKINS_URL = $JenkinsUrl
    $env:JENKINS_USER = $JenkinsUser
    $env:JENKINS_PASS = $JenkinsPass
    
    try {
        pytest tests/integration/ -v --tb=short -m integration
        Write-Success "Integration tests passed"
        return $true
    } catch {
        Write-Error-Custom "Integration tests failed"
        return $false
    }
}

function Test-Secrets {
    Write-Info "Scanning for accidentally committed secrets..."
    
    if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
        try {
            gitleaks detect --source $ProjectRoot --no-git --verbose
            Write-Success "No secrets detected"
            return $true
        } catch {
            Write-Error-Custom "Potential secrets detected!"
            return $false
        }
    } else {
        Write-Warning "gitleaks not installed, skipping secret scanning"
        return $true
    }
}

function New-Report {
    param(
        [hashtable]$Results
    )
    
    Write-Info "Generating CI report..."
    
    $reportFile = Join-Path $ProjectRoot "ci_report.txt"
    
    $pythonVersion = python --version
    $dockerVersion = docker --version
    
    $report = @"
JenkinsBreaker Local CI Report
Generated: $(Get-Date)

Environment:
- Jenkins Lab: $JenkinsUrl
- Python: $pythonVersion
- Docker: $dockerVersion

Test Results:
- Linting: $(if ($Results.Linting) { "PASSED" } else { "FAILED" })
- Type Checking: $(if ($Results.TypeCheck) { "PASSED" } else { "FAILED" })
- Unit Tests: $(if ($Results.UnitTests) { "PASSED" } else { "FAILED" })
- Integration Tests: $(if ($Results.Integration) { "PASSED" } else { "FAILED" })
- Secret Scanning: $(if ($Results.Secrets) { "PASSED" } else { "FAILED" })
"@
    
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host $report
    Write-Info "Full report saved to: $reportFile"
}

function Stop-JenkinsLab {
    if ($KeepRunning) {
        Write-Info "Leaving jenkins-lab running (--KeepRunning)"
        return
    }
    
    if ($SkipDocker) {
        return
    }
    
    Write-Info "Cleaning up..."
    Push-Location $JenkinsLabDir
    docker-compose down
    Pop-Location
    Write-Info "jenkins-lab stopped"
}

# Main execution
Write-Info "Starting JenkinsBreaker Local CI Pipeline"
Write-Host "==========================================" -ForegroundColor Cyan

Set-Location $ProjectRoot

Test-Requirements
Start-JenkinsLab

$results = @{
    Linting = $false
    TypeCheck = $false
    UnitTests = $false
    Integration = $false
    Secrets = $false
}

$results.Linting = Invoke-Linting
$results.TypeCheck = Invoke-TypeChecking
$results.UnitTests = Invoke-UnitTests
$results.Integration = Invoke-IntegrationTests
$results.Secrets = Test-Secrets

Write-Host ""
Write-Info "CI Pipeline Summary:"
Write-Host "==========================================" -ForegroundColor Cyan

New-Report -Results $results

Stop-JenkinsLab

$totalFailures = ($results.Values | Where-Object { $_ -eq $false }).Count

if ($totalFailures -eq 0) {
    Write-Success "All checks passed! Ready to commit."
    exit 0
} else {
    Write-Error-Custom "CI pipeline failed with $totalFailures error(s)"
    exit 1
}
