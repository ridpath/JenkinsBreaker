#!/bin/bash
#
# Jenkins Lab Reset Script
# Resets jenkins-lab container to clean state for test isolation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_COMPOSE_FILE="$SCRIPT_DIR/../../../jenkins-lab/docker-compose.yml"
CONTAINER_NAME="jenkins-lab"

echo "[*] Jenkins Lab Reset Script"
echo "[*] This will stop, remove, and recreate the Jenkins lab container"
echo ""

if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    echo "[!] Error: docker-compose.yml not found at $DOCKER_COMPOSE_FILE"
    exit 1
fi

cd "$(dirname "$DOCKER_COMPOSE_FILE")"

echo "[*] Stopping Jenkins lab container..."
docker-compose down

echo "[*] Removing volumes to ensure clean state..."
docker-compose down -v

echo "[*] Starting Jenkins lab container..."
docker-compose up -d

echo "[*] Waiting for Jenkins to initialize..."
max_wait=120
elapsed=0

while [ $elapsed -lt $max_wait ]; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/json 2>/dev/null | grep -q "200\|403"; then
        echo "[+] Jenkins is ready!"
        break
    fi
    
    sleep 2
    elapsed=$((elapsed + 2))
    echo "    Waiting... ($elapsed seconds)"
done

if [ $elapsed -ge $max_wait ]; then
    echo "[!] Warning: Jenkins may not be fully initialized"
    echo "[!] Check container logs: docker logs $CONTAINER_NAME"
fi

echo "[+] Jenkins lab reset complete"
echo "[+] Access at: http://localhost:8080"
echo "[+] Credentials: admin/admin"
