#!/bin/bash

echo "========================================="
echo "Setting Up Multi-Lab Environment"
echo "========================================="
echo ""

# Copy shared files to jenkins-mid
echo "[1/4] Setting up jenkins-mid..."
cp -r jenkins/secrets jenkins-mid/
cp -r jenkins/init.groovy.d jenkins-mid/
cp -r jenkins/jobs jenkins-mid/
echo "    ✓ Copied secrets, init.groovy.d, and jobs"

# Copy shared files to jenkins-new
echo "[2/4] Setting up jenkins-new..."
cp -r jenkins/secrets jenkins-new/
cp -r jenkins/init.groovy.d jenkins-new/
cp -r jenkins/jobs jenkins-new/
echo "    ✓ Copied secrets, init.groovy.d, and jobs"

# Fix Dockerfiles to use local paths instead of ../jenkins/
echo "[3/4] Fixing Dockerfiles..."
cd jenkins-mid
sed -i 's|../jenkins/secrets/|secrets/|g' Dockerfile
sed -i 's|../jenkins/init.groovy.d/|init.groovy.d/|g' Dockerfile
sed -i 's|../jenkins/jobs/|jobs/|g' Dockerfile
cd ..

cd jenkins-new
sed -i 's|../jenkins/secrets/|secrets/|g' Dockerfile
sed -i 's|../jenkins/init.groovy.d/|init.groovy.d/|g' Dockerfile
sed -i 's|../jenkins/jobs/|jobs/|g' Dockerfile
cd ..

echo "    ✓ Fixed Dockerfiles"

# Build all images
echo "[4/4] Building Docker images..."
docker-compose -f docker-compose-multi.yml build

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "To start all labs:"
echo "  docker-compose -f docker-compose-multi.yml up -d"
echo ""
echo "Or use the startup script:"
echo "  bash start_all_labs.sh"
echo ""
