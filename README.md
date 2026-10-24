# Ethio-Cyber-Shield (ECS) v3.0

> **Independent Threat-Detection, Explainable Risk Scoring & Incident-Readiness Platform**  
> Built for Ethiopian critical infrastructure and digital finance operators.  
> **Live Cloud Production Console**: [https://ethio-cyber-shield.onrender.com](https://ethio-cyber-shield.onrender.com)  
> **Connected Banking Target**: [https://honorpay-banking.vercel.app](https://honorpay-banking.vercel.app)

---

## 1. Executive Summary

**Ethio-Cyber-Shield (ECS)** is an independent, multi-tenant cybersecurity detection, threat intelligence, and incident-readiness platform. Built to support compliance with **INSA Critical Infrastructure Proclamation No. 1426/2026** and **National Bank of Ethiopia (NBE)** risk directives, ECS correlates real-time security events, detects complex multi-stage attack chains, calculates explainable risk scores (0–100), and executes safe, closed-loop mitigations with full rollback capabilities.

---

## 2. Core Architectural Principles

1. **Explainable by Default**:
   Every alert displays exact deterministic rules triggered, condition evaluations, feature weights, and raw event evidence. Deterministic evaluation drives all decisions; ML/LLM is strictly advisory/explanatory.
2. **Safe & Reversible Automation**:
   Mitigations follow progressive risk postures: `observe` (shadow) → `recommend` → `approve` (human-in-the-loop) → `auto`. Actions support blast-radius limits, cooldowns, and idempotent rollbacks (`revert`).
3. **Evidence First & Hash-Sealed**:
   All incident telemetry, detection evaluations, and containment actions are hash-sealed using SHA-256 in an append-only audit trail and exportable in regulatory 48-hour incident packages.
4. **Self-Hostable & Vendor Independent**:
   Zero proprietary cloud lock-in. Operates anywhere via standard Docker Compose, PostgreSQL 18, and Redis 8.
5. **Strict Multi-Tenancy**:
   Every database entity scopes by `organization_id UUID NOT NULL` with Row-Level Security (RLS) enforcement.
6. **Privacy-Preserving Threat Exchange**:
   Cross-tenant community threat indicators exchange only keyed hashes, confidence scores, and TLP markings—never raw PII or banking transaction details.
7. **Ethiopian Operational Context**:
   Native Ethiopian Birr (ETB) currency formatting, Addis Ababa local timezone (`Africa/Addis_Ababa`, UTC+3), local payment rails (P2P, USSD, mobile money, EthSwitch), and multilingual localization.

---

## 3. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│             CONNECTED DIGITAL BANKING TARGET (e.g., HonorPay)          │
│   • Customer Portal   • Mobile Rails   • Transactional Security Outbox │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HMAC-SHA256 Signed Telemetry (JSON)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        ETHIO-CYBER-SHIELD (ECS)                        │
├────────────────────────────────────────────────────────────────────────┤
│  1. Ingest Gateway       Bounded Redis Streams / Transactional Outbox  │
│  2. Detection Engine     Declarative Rules (L1 Schema → L2 Velocity    │
│                          → L3 Cross-Source → L4 Stateful Correlation)  │
│  3. Risk Scoring (0-100) Multi-factor, 100% Explainable Score Breakdown│
│  4. Containment Dispatch Reversible Mitigation Connectors (HMAC-SHA256)│
│  5. Immutable Audit Log  SHA-256 Hash-Sealed Cryptographic Audit Trail │
│  6. Regulatory Packages  INSA / NBE 48-Hour Incident Dossier Generator │
├────────────────────────────────────────────────────────────────────────┤
│  7. SOC Web Console      Minimalist Institutional UI + Web Audio Siren │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Multi-Layer Detection Hierarchy

ECS evaluates inbound security events through a four-tier declarative detection hierarchy:

| Tier | Name | Target Latency | Detection Scope |
| :--- | :--- | :--- | :--- |
| **L1** | **Deterministic / Schema** | < 5 ms | Known bad signatures, SQLi/XSS injection payloads, malformed headers |
| **L2** | **Statistical & Velocity** | < 25 ms | Rapid credential brute-force, high-velocity fund transfers, burst thresholds |
| **L3** | **Cross-Source Correlation** | < 100 ms | Multiple accounts sharing single device fingerprint, IP watchlist cross-match |
| **L4** | **Stateful Attack Chains** | < 250 ms | Multi-step Account Takeover (Password reset + Device switch + Instant max-limit drain) |

---

## 5. Technology Stack

- **Backend**: Python 3.12, Flask, Gunicorn
- **Datastores**: PostgreSQL 18 (Relational & RLS), Redis 8 (Streams & Velocity Caching)
- **Frontend Console**: Vanilla ES6+, HTML5, CSS3, Bootstrap 5 (High-contrast Institutional SOC theme)
- **Audio Engine**: Web Audio API synthesized alert sirens (Critical, High, Medium)
- **Deployment**: Render Web Service + Managed PostgreSQL + Managed Redis

---

## 6. Quick Start (Local Development)

### Prerequisites
- Python 3.11+
- PostgreSQL 16+ or Docker Compose
- Redis 7+

### 1. Environment Setup
```bash
cd core
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp ../.env.example .env
# Configure DATABASE_URL, REDIS_URL, and JWT_SECRET
```

### 3. Initialize Database
```bash
psql -d ecs_db -f ../deploy/postgres/init.sql
```

### 4. Run Services
```bash
# Terminal 1: Backend API (Port 5000)
cd backend && python run.py

# Terminal 2: SOC Web Console (Port 5500)
cd ui && python3 -m http.server 5500
```

Access the SOC Console at `http://localhost:5500`.

---

## 7. Cloud Production Deployment (Render)

ECS is deployed in cloud production on **Render**:
- **Console & API**: [https://ethio-cyber-shield.onrender.com](https://ethio-cyber-shield.onrender.com)
- **Database**: Managed PostgreSQL 18 (`ecs-postgres`)
- **Streams**: Managed Redis Key-Value (`ecs-redis`)
- **Health Check**: `GET /api/health`

### Production Operator Credentials
- **Username**: `admin@shieldbank.test` *(or `admin@ethiocybershield.et` / `admin@honorpay.et`)*
- **Password**: `Testbed#2026`

---

## 8. Verification & Test Suites

ECS includes comprehensive automated test suites covering unit, integration, and security multi-tenancy isolation:

```bash
cd core
source venv/bin/activate

# Run backend unit & integration tests
pytest tests/ -v

# Run multi-tenancy isolation tests
pytest tests/test_multi_tenancy.py -v
```

For complete attack scenario simulation (28 attack scenarios including Burp Suite scripts), see [`ATTACK_TESTING_GUIDE.md`](ATTACK_TESTING_GUIDE.md).

---

## 9. Regulatory Compliance Mapping

| Directive / Proclamation | ECS Capability |
| :--- | :--- |
| **INSA Proclamation No. 1426/2026 (§16)** | Mandatory 48-hour incident reporting package generator with SHA-256 evidence sealing |
| **NBE Cyber Risk Guideline (§5.2)** | Real-time transaction fraud monitoring, velocity throttling & step-up authentication |
| **Ethiopian PDPP (Data Protection)** | Strict tenant isolation, privacy-preserving threat intelligence exchange (TLP:AMBER / TLP:GREEN) |
