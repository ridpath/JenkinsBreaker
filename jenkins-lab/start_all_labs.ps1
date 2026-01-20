# JenkinsBreaker Multi-Lab Startup Script (PowerShell)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Starting JenkinsBreaker Multi-Lab Environment" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Starting 3 Jenkins instances..." -ForegroundColor Yellow
Write-Host "    - OLD (2.138.3) on port 8080"
Write-Host "    - MID (2.275) on port 8081"
Write-Host "    - NEW (2.442) on port 8082"
Write-Host ""

docker-compose -f docker-compose-multi.yml up -d

Write-Host ""
Write-Host "[*] Waiting for Jenkins instances to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Jenkins Labs Status" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

docker-compose -f docker-compose-multi.yml ps

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Access Points" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "OLD Lab: http://localhost:8080 (admin/admin)" -ForegroundColor Green
Write-Host "MID Lab: http://localhost:8081 (admin/admin)" -ForegroundColor Green
Write-Host "NEW Lab: http://localhost:8082 (admin/admin)" -ForegroundColor Green
Write-Host ""
Write-Host "Total Exploitable CVEs: 25+" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
