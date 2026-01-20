# Multi-Lab Environment Setup Script (PowerShell)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Setting Up Multi-Lab Environment" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Copy shared files to jenkins-mid
Write-Host "[1/4] Setting up jenkins-mid..." -ForegroundColor Yellow
Copy-Item -Path "jenkins\secrets" -Destination "jenkins-mid\" -Recurse -Force
Copy-Item -Path "jenkins\init.groovy.d" -Destination "jenkins-mid\" -Recurse -Force
Copy-Item -Path "jenkins\jobs" -Destination "jenkins-mid\" -Recurse -Force
Write-Host "    checkmark Copied secrets, init.groovy.d, and jobs" -ForegroundColor Green

# Copy shared files to jenkins-new
Write-Host "[2/4] Setting up jenkins-new..." -ForegroundColor Yellow
Copy-Item -Path "jenkins\secrets" -Destination "jenkins-new\" -Recurse -Force
Copy-Item -Path "jenkins\init.groovy.d" -Destination "jenkins-new\" -Recurse -Force
Copy-Item -Path "jenkins\jobs" -Destination "jenkins-new\" -Recurse -Force
Write-Host "    checkmark Copied secrets, init.groovy.d, and jobs" -ForegroundColor Green

# Fix Dockerfiles to use local paths
Write-Host "[3/4] Fixing Dockerfiles..." -ForegroundColor Yellow

$midDockerfile = Get-Content "jenkins-mid\Dockerfile" -Raw
$midDockerfile = $midDockerfile -replace '\.\./jenkins/secrets/', 'secrets/'
$midDockerfile = $midDockerfile -replace '\.\./jenkins/init\.groovy\.d/', 'init.groovy.d/'
$midDockerfile = $midDockerfile -replace '\.\./jenkins/jobs/', 'jobs/'
Set-Content -Path "jenkins-mid\Dockerfile" -Value $midDockerfile

$newDockerfile = Get-Content "jenkins-new\Dockerfile" -Raw
$newDockerfile = $newDockerfile -replace '\.\./jenkins/secrets/', 'secrets/'
$newDockerfile = $newDockerfile -replace '\.\./jenkins/init\.groovy\.d/', 'init.groovy.d/'
$newDockerfile = $newDockerfile -replace '\.\./jenkins/jobs/', 'jobs/'
Set-Content -Path "jenkins-new\Dockerfile" -Value $newDockerfile

Write-Host "    checkmark Fixed Dockerfiles" -ForegroundColor Green

# Build all images
Write-Host "[4/4] Building Docker images..." -ForegroundColor Yellow
docker compose -f docker-compose-multi.yml build

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start all labs:" -ForegroundColor Yellow
Write-Host "  docker compose -f docker-compose-multi.yml up -d" -ForegroundColor White
Write-Host ""
Write-Host "Or use the startup script:" -ForegroundColor Yellow
Write-Host "  powershell .\start_all_labs.ps1" -ForegroundColor White
Write-Host ""
