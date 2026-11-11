# Ethio-Cyber-Shield (ECS) v3.0 — Sovereign Deployment & Operations Guide

> **Institutional Submission**: Official Deployment Guide submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Platform**: Ethio-Cyber-Shield (ECS) v3.0  
> **Target Architecture**: Self-Hostable, Sovereign On-Premise or Private Cloud (Docker Compose)  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)

---

## 1. System Requirements

### Hardware Sizing
| Deployment Tier | Workload | vCPU | RAM | Storage |
| :--- | :--- | :--- | :--- | :--- |
| **Lab / Pilot** | Up to 200 events/sec, single institution | 2 vCPU | 4 GB | 40 GB SSD |
| **Production Core** | Up to 2,000 events/sec, multi-tenant bank/PSO | 4 vCPU | 8 GB | 150 GB NVMe |
| **National / Sector Hub** | Aggregated telemetry & signal exchange | 8 vCPU | 16 GB | 500 GB NVMe RAID |

### Software Prerequisites
- Linux OS (Ubuntu 22.04 LTS / 24.04 LTS, RHEL 9+, Debian 12)
- Docker Engine $\ge 24.0$
- Docker Compose $\ge 1.29$ (or `docker compose` plugin $\ge 2.20$)
- Ports required:
  - `5000`: ECS Core REST & Ingestion API
  - `5500`: ECS Analyst Management UI
  - `5432`: PostgreSQL 16 (internal Docker bridge)
  - `6379`: Redis 7 Streams (internal Docker bridge)

---

## 2. Quickstart Deployment (One Command)

```bash
# 1. Clone the repository
git clone https://github.com/ethiocybershield/Ethio-Cyber-Shield.git
cd Ethio-Cyber-Shield

# 2. Configure environment
cp deploy/.env.example deploy/.env
# Edit deploy/.env and generate cryptographically secure keys:
# JWT_SECRET=$(openssl rand -hex 32)
# ECS_MASTER_ENCRYPTION_KEY=$(openssl rand -hex 32)
# POSTGRES_PASSWORD=$(openssl rand -base64 24)
# REDIS_PASSWORD=$(openssl rand -base64 24)

# 3. Start the entire independent stack
cd deploy
docker-compose up -d

# 4. Verify deployment health
curl -f http://localhost:5000/api/health
```

Expected health output:
```json
{
  "status": "ok",
  "service": "Ethio-Cyber-Shield (ECS)",
  "version": "3.0.0",
  "components": {
    "database": {
      "status": "healthy",
      "driver": "psycopg2-postgres",
      "latency_ms": 3
    },
    "stream_engine": {
      "backend": "redis",
      "stream_depth": 0,
      "dlq_depth": 0
    }
  }
}
```

---

## 3. Environment Variables Reference

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `POSTGRES_DB` | Yes | `ecs_db` | PostgreSQL database name |
| `POSTGRES_USER` | Yes | `ecs_admin` | PostgreSQL service superuser |
| `POSTGRES_PASSWORD` | Yes | - | PostgreSQL master password |
| `DATABASE_URL` | Yes | `postgresql://...` | Connection string for core API |
| `REDIS_PASSWORD` | Yes | - | Redis authentication password |
| `REDIS_URL` | Yes | `redis://...` | Redis Streams broker connection |
| `JWT_SECRET` | Yes | - | 256-bit secret for signing analyst sessions and seals |
| `ECS_MASTER_ENCRYPTION_KEY` | Yes | - | 256-bit hex key (64 hex chars) for AES-256-GCM envelope encryption |
| `ALLOWED_ORIGINS` | No | `*` | Allowed CORS origins (e.g. `https://soc.bank.et`) |

---

## 4. Database Architecture & Multi-Tenancy

PostgreSQL 16 initializes automatically via `deploy/postgres/init.sql`:
1. **Schema & Tables**: `organizations`, `users`, `api_tokens`, `target_systems`, `security_events`, `transactions`, `alerts`, `incidents`, `indicators`, `audit_logs`.
2. **Mandatory Tenancy**: Every table enforces `organization_id UUID NOT NULL` with foreign keys to `organizations(id)`.
3. **Row-Level Security (RLS)**: Enforces `current_setting('app.current_organization_id', true)::uuid = organization_id`.

---

## 5. Backup & Disaster Recovery

### Automated Timestamped Backup
Run the backup script (can be scheduled via cron):
```bash
bash deploy/scripts/backup.sh
```
This performs:
1. Online `pg_dump` of PostgreSQL database.
2. Redis snapshot extraction (`dump.rdb`).
3. Gzip compression into `/var/backups/ecs/ecs_backup_YYYYMMDD_HHMMSS.tar.gz`.
4. SHA-256 cryptographic checksum seal (`.tar.gz.sha256`).

### Full Disaster Recovery Restore
```bash
bash deploy/scripts/restore.sh /var/backups/ecs/ecs_backup_20261017_120000.tar.gz
```
The restore script:
1. Validates the SHA-256 checksum seal.
2. Stops conflicting write processes.
3. Restores database tables and schema.
4. Resets Redis stream state.

---

## 6. Hardened Production Checklist

- [ ] Place ECS behind an enterprise reverse proxy (Nginx / HAProxy / F5) with TLS 1.3 certificates.
- [ ] Bind PostgreSQL and Redis ports only to internal Docker bridge or private VPC subnets.
- [ ] Enforce TOTP MFA for all analyst and administrator accounts (`POST /api/auth/mfa/enable`).
- [ ] Issue scoped API tokens (`ecs_pat_...`) for automated connectors; do not use admin JWTs in automation.
- [ ] Configure off-site replication of `/var/backups/ecs` tarballs.
