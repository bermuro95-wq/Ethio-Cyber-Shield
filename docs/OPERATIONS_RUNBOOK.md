# Ethio-Cyber-Shield (ECS) — Operations & Security Hardening Runbook

> **Version**: 3.0 Production Operations  
> **Target Environment**: Self-hosted Docker Compose / Kubernetes in Ethiopian Data Centers (e.g., Ethio Telecom Cloud, Raxio Data Centre, National Data Center).

---

## 1. Architectural Overview

ECS runs as a decoupled, multi-tenant microservices topology:
- **`ecs-core`**: Flask API handling authentication, detection engine, cases, and reporting.
- **`ecs-worker`**: Background poller executing connector schedules and Redis Stream ingestion.
- **`postgres`**: Relational store partitioned strictly by `organization_id UUID`.
- **`redis`**: Durable event streams, action cooldowns, and deduplication cache.
- **`nginx`**: TLS termination, rate limiting, and reverse proxy.

```mermaid
flowchart TD
    Client["Client / SDK / Bank Core"] --> Nginx["Nginx Reverse Proxy\n(TLS 1.3, Rate Limits)"]
    Nginx --> Core["ECS Core API (Flask)\n(:5000)"]
    Core --> Redis["Redis 7\n(Durable Streams)"]
    Core --> PG["PostgreSQL 15+\n(Tenancy Partitioned)"]
    Worker["ECS Background Worker"] --> Redis
    Worker --> Core
    Worker --> Connectors["External Connectors\n(EthSwitch, Core Banking)"]
```

---

## 2. Quickstart Deployment (Docker Compose)

### 2.1 Environment Setup
Create a secure `.env` file on the target host:
```bash
# General
NODE_ENV=production
FLASK_ENV=production
DEFAULT_ORGANIZATION_ID=00000000-0000-0000-0000-000000000001
TIMEZONE=Africa/Addis_Ababa

# Security & Secrets (Must be 32-byte hex or base64)
JWT_SECRET=generate_with_openssl_rand_hex_32
ENCRYPTION_MASTER_KEY=generate_with_openssl_rand_hex_32
HUB_PEPPER=generate_with_openssl_rand_hex_32

# Storage
DATABASE_URL=postgresql://ecs_admin:StrongPassword123@postgres:5432/ecs_db
REDIS_URL=redis://redis:6379/0
```

### 2.2 Launch Services
```bash
docker compose -f docker-compose.yml up -d
```

### 2.3 Verify Health
```bash
# Check platform health
curl -f http://localhost:5000/health

# Check executive operational status (compact mode)
curl -H "Authorization: Bearer <TOKEN>" \
  http://localhost:5000/api/dashboard/executive?low_bandwidth=true
```

---

## 3. Backup & Disaster Recovery Procedures

### 3.1 Automated PostgreSQL Database Snapshot
Execute daily database dumps with strict timestamping:
```bash
BACKUP_DIR="/var/backups/ecs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "${BACKUP_DIR}"

docker exec -t ecs_postgres pg_dump -U ecs_admin -d ecs_db -F c \
  -f "/tmp/ecs_backup_${TIMESTAMP}.dump"

docker cp "ecs_postgres:/tmp/ecs_backup_${TIMESTAMP}.dump" "${BACKUP_DIR}/"
sha256sum "${BACKUP_DIR}/ecs_backup_${TIMESTAMP}.dump" > "${BACKUP_DIR}/ecs_backup_${TIMESTAMP}.dump.sha256"
```

### 3.2 Evidence Vault Cold Storage Sync
The Evidence Vault contains cryptographically sealed incident records and audit bundles. Sync encrypted manifests to cold offsite storage:
```bash
# Export evidence packages and verify SHA-256 seal integrity
curl -X GET -H "Authorization: Bearer <ADMIN_TOKEN>" \
  "http://localhost:5000/api/readiness/audit-pack/export" > "/var/backups/ecs/evidence_vault_${TIMESTAMP}.json"

sha256sum "/var/backups/ecs/evidence_vault_${TIMESTAMP}.json"
```

### 3.3 Database Restoration
```bash
# Restore from backup snapshot
docker exec -i ecs_postgres pg_restore -U ecs_admin -d ecs_db --clean --if-exists < "${BACKUP_DIR}/ecs_backup_${TIMESTAMP}.dump"
```

---

## 4. Emergency Kill Switch Runbook

If automated response actions trigger unforeseen operational friction or cascading false-positive blocks:

### Step 1: Engage Emergency Kill Switch
Immediately halt all automated mitigations platform-wide or per-tenant:
```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Immediate core banking maintenance drill", "engaged_by": "lead_soc_analyst"}' \
  http://localhost:5000/api/response/kill-switch/engage
```

### Step 2: Confirm Kill Switch Status
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  http://localhost:5000/api/response/kill-switch/status
```
Expected output:
```json
{
  "engaged": true,
  "reason": "Immediate core banking maintenance drill",
  "engaged_by": "lead_soc_analyst",
  "engaged_at": "2026-10-21T19:30:00Z"
}
```

### Step 3: Disengage When Deemed Safe
```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"disengaged_by": "ciso_approver", "reason": "Verification complete; systems nominal"}' \
  http://localhost:5000/api/response/kill-switch/disengage
```

---

## 5. Security Hardening Checklist

1. **Non-Root Execution**: Docker containers must run under an unprivileged user (UID 1000).
2. **Envelope Encryption**: Ensure `ENCRYPTION_MASTER_KEY` is loaded strictly from environment secrets or HashiCorp Vault. Never commit to repository files.
3. **Strict Tenancy Partitioning**: Ensure every custom SQL migration maintains `organization_id UUID NOT NULL` and indexed foreign keys.
4. **Quiet Hours Configuration**: Ensure default notification dispatchers enforce Addis Ababa quiet hours (22:00 – 06:00 UTC+3) for non-critical alerts.
5. **Low-Bandwidth Deployment**: Configure regional bank branch web clients to query `?low_bandwidth=true` to conserve bandwidth over VSAT and 2G/3G links.
