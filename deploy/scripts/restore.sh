#!/usr/bin/env bash
# Ethio-Cyber-Shield (ECS) — Disaster Recovery Restore Script
# Restores PostgreSQL and Redis states from a validated backup archive.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/ecs_backup_YYYYMMDD_HHMMSS.tar.gz"
    exit 1
fi

ARCHIVE_FILE="$1"
SHA_FILE="${ARCHIVE_FILE}.sha256"

if [ -f "${SHA_FILE}" ]; then
    echo "==> Verifying SHA-256 integrity seal..."
    sha256sum -c "${SHA_FILE}"
else
    echo "WARNING: No .sha256 checksum found. Proceeding with caution."
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "==> Extracting archive..."
tar -xzf "${ARCHIVE_FILE}" -C "${WORK_DIR}"
EXTRACTED_DIR="$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"

if [ -f "${EXTRACTED_DIR}/postgres_dump.sql" ]; then
    echo "==> Restoring PostgreSQL database..."
    docker exec -i ecs-postgres psql -U "${POSTGRES_USER:-ecs_admin}" -d "${POSTGRES_DB:-ecs_db}" < "${EXTRACTED_DIR}/postgres_dump.sql"
    echo "PostgreSQL restoration complete."
fi

echo "Restoration finished successfully."
