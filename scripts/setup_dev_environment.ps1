# Development Environment Setup for JenkinsBreaker (PowerShell)
# Installs pre-commit hooks and validates local CI pipeline

param(
    [switch]$SkipJenkinsLab = $false
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

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

function Test-Python {
    Write-Info "Checking Python version..."
    
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error-Custom "Python not found. Install Python 3.9+ first."
        exit 1
    }
    
    $pythonVersion = python --version
    Write-Success "$pythonVersion detected"
}

function Test-Docker {
    Write-Info "Checking Docker..."
    
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Warning "Docker not found. jenkins-lab will not work."
        Write-Warning "Install Docker: https://docs.docker.com/get-docker/"
    } else {
        $dockerVersion = docker --version
        Write-Success "$dockerVersion detected"
    }
}

function Install-Package {
    Write-Info "Installing JenkinsBreaker package..."
    
    Set-Location $ProjectRoot
    
    if (-not (Test-Path ".venv")) {
        Write-Info "Creating virtual environment..."
        python -m venv .venv
    }
    
    & .\.venv\Scripts\Activate.ps1
    
    Write-Info "Installing development dependencies..."
    pip install -e ".[dev]" --quiet
    
    Write-Success "Package installed"
}

function Install-PreCommit {
    Write-Info "Installing pre-commit hooks..."
    
    Set-Location $ProjectRoot
    & .\.venv\Scripts\Activate.ps1
    
    if (-not (Get-Command pre-commit -ErrorAction SilentlyContinue)) {
        Write-Info "Installing pre-commit..."
        pip install pre-commit --quiet
    }
    
    pre-commit install
    
    Write-Success "Pre-commit hooks installed"
}

function Test-PreCommit {
    Write-Info "Verifying pre-commit configuration..."
    
    Set-Location $ProjectRoot
    & .\.venv\Scripts\Activate.ps1
    
    try {
        pre-commit run --all-files --show-diff-on-failure
        Write-Success "Pre-commit hooks verified"
    } catch {
        Write-Warning "Some pre-commit hooks failed. Review output above."
    }
}

function Test-GitLeaks {
    Write-Info "Checking for gitleaks..."
    
    if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
        $gitleaksVersion = gitleaks version
        Write-Success "gitleaks already installed: $gitleaksVersion"
        return
    }
    
    Write-Warning "gitleaks not found. Secret scanning will be limited."
    Write-Info "Install from: https://github.com/gitleaks/gitleaks"
    Write-Info "Windows: Download binary from releases page"
}

function Test-JenkinsLab {
    if ($SkipJenkinsLab) {
        Write-Info "Skipping jenkins-lab setup (--SkipJenkinsLab)"
        return
    }
    
    Write-Info "Testing jenkins-lab..."
    
    Push-Location (Join-Path $ProjectRoot "jenkins-lab")
    
    $running = docker-compose ps | Select-String "jenkins-lab"
    if (-not $running) {
        Write-Info "Starting jenkins-lab..."
        docker-compose up -d
        
        Write-Info "Waiting for Jenkins to be ready..."
        $maxAttempts = 60
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:8080" -UseBasicParsing -Credential (New-Object PSCredential("admin", (ConvertTo-SecureString "admin" -AsPlainText -Force))) -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    Write-Success "jenkins-lab is accessible at http://localhost:8080"
                    Write-Info "Credentials: admin/admin"
                    break
                }
            } catch {
                # Continue waiting
            }
            Start-Sleep -Seconds 2
            $attempt++
        }
        
        if ($attempt -eq $maxAttempts) {
            Write-Error-Custom "jenkins-lab failed to start"
            Pop-Location
            return
        }
    } else {
        Write-Success "jenkins-lab already running"
    }
    
    Pop-Location
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Info "JenkinsBreaker Development Setup"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Test-Python
Test-Docker
Install-Package
Install-PreCommit
Test-GitLeaks

Write-Host ""
Write-Info "Running initial pre-commit validation..."
Test-PreCommit

Write-Host ""
Write-Info "Testing jenkins-lab environment..."
Test-JenkinsLab

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Success "Development environment ready!"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Next steps:"
Write-Host "  1. Activate virtual environment: .\.venv\Scripts\Activate.ps1"
Write-Host "  2. Run local CI: .\scripts\local_ci.ps1"
Write-Host "  3. Start development: Review DEVELOPMENT.md"
Write-Host ""
Write-Info "jenkins-lab: http://localhost:8080 (admin/admin)"
