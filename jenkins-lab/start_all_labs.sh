#!/bin/bash

echo "========================================="
echo "Starting JenkinsBreaker Multi-Lab Environment"
echo "========================================="
echo ""

echo "[*] Starting 3 Jenkins instances..."
echo "    - OLD (2.138.3) on port 8080"
echo "    - MID (2.275) on port 8081"
echo "    - NEW (2.442) on port 8082"
echo ""

docker-compose -f docker-compose-multi.yml up -d

echo ""
echo "[*] Waiting for Jenkins instances to start..."
sleep 30

echo ""
echo "========================================="
echo "Jenkins Labs Status"
echo "========================================="

docker-compose -f docker-compose-multi.yml ps

echo ""
echo "========================================="
echo "Access Points"
echo "========================================="
echo "OLD Lab: http://localhost:8080 (admin/admin)"
echo "MID Lab: http://localhost:8081 (admin/admin)"
echo "NEW Lab: http://localhost:8082 (admin/admin)"
echo ""
echo "Total Exploitable CVEs: 25+"
echo "========================================="
