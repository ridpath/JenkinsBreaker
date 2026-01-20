#!/bin/bash

export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

BACKUP_DIR="/var/jenkins_home/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="jenkins_backup_${TIMESTAMP}.tar.gz"

echo "Starting Jenkins backup at $(date)"

if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
fi

tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" \
    /var/jenkins_home/jobs \
    /var/jenkins_home/users \
    /var/jenkins_home/config.xml \
    2>/dev/null

if [ -f "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
    echo "Backup created: ${BACKUP_FILE}"
    
    find "$BACKUP_DIR" -name "jenkins_backup_*.tar.gz" -mtime +7 -delete
    echo "Cleaned up old backups"
else
    echo "Backup failed!"
    exit 1
fi

echo "Backup completed at $(date)"
