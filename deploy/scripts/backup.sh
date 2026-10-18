#!/usr/bin/env bash
# Ethio-Cyber-Shield (ECS) — Automated Backup Script
# Creates a timestamped, SHA-256 sealed backup archive of PostgreSQL and Redis data.

set -euo pipefail

BACKUP_DIR="${ECS_BACKUP_DIR:-/var/backups/ecs}"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
ARCHIVE_NAME="ecs_backup_${TIMESTAMP}"
DEST_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"

mkdir -p "${DEST_PATH}"

echo "==> [1/3] Dumping PostgreSQL database..."
docker exec -t ecs-postgres pg_dump -U "${POSTGRES_USER:-ecs_admin}" "${POSTGRES_DB:-ecs_db}" > "${DEST_PATH}/postgres_dump.sql"

echo "==> [2/3] Triggering Redis snapshot..."
docker exec -t ecs-redis redis-cli -a "${REDIS_PASSWORD:-RedisSecurePass2026!}" bgsave || true
sleep 2
docker cp ecs-redis:/data/dump.rdb "${DEST_PATH}/redis_dump.rdb" || true

echo "==> [3/3] Compressing and generating SHA-256 seal..."
tar -czf "${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz" -C "${BACKUP_DIR}" "${ARCHIVE_NAME}"
rm -rf "${DEST_PATH}"

sha256sum "${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz" > "${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz.sha256"

echo "Backup complete: ${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz"
cat "${BACKUP_DIR}/${ARCHIVE_NAME}.tar.gz.sha256"
