# Threat Model — Ethio-Cyber-Shield (ECS) v3.0

> **System**: Ethio-Cyber-Shield (ECS) Sovereign Detection & Incident-Readiness Platform  
> **Institutional Submission**: Official Threat Model submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Methodology**: STRIDE Threat Modeling & Banking CNI Attack Surface Analysis  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)

---

## 1. System Overview & Trust Boundaries

ECS is deployed as an on-premise or sovereign VPC cybersecurity detection, investigation, and incident-readiness platform for Ethiopian commercial banks, MFIs, PSOs, and national infrastructure.

### Trust Zones & Boundaries
```
┌────────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED / EXTERNAL NETWORK                                           │
│  - Public Internet / Attacker IPs                                     │
│  - Rogue Webhook senders                                              │
└─────────────────────────────────┬──────────────────────────────────────┘
                                  │ (Boundary 1: TLS + HMAC-SHA256)
┌─────────────────────────────────▼──────────────────────────────────────┐
│ OPERATOR PERIMETER / CONNECTORS (DMZ)                                  │
│  - Target Banking Core, Mobile App APIs, USSD Gateways                 │
│  - Lightweight ECS Log Agents & SDK Middleware                         │
└─────────────────────────────────┬──────────────────────────────────────┘
                                  │ (Boundary 2: mTLS / Scoped Bearer Token)
┌─────────────────────────────────▼──────────────────────────────────────┐
│ ECS PLATFORM CORE (PROTECTED ENCLAVE)                                  │
│  - Telemetry Ingest & Stream Engine (Redis Streams)                    │
│  - Detection Engine (Deterministic Layers L1-L4)                       │
│  - Controlled Response Orchestrator                                    │
│  - Incident Readiness 48h Clock Engine                                 │
└──────────────────┬───────────────────────────────┬─────────────────────┘
                   │ (Boundary 3: RLS / Encrypted) │ (Boundary 4: HMAC)
┌──────────────────▼──────────────────┐   ┌────────▼─────────────────────┐
│ DATABASE & VAULT (PostgreSQL 16)    │   │ REGULATORY EXPORT HUB        │
│  - Multi-tenant tables (RLS)        │   │  - EthioCERT / INSA format   │
│  - AES-256-GCM encrypted secrets    │   │  - Hash-sealed 48h packages  │
│  - SHA-256 hash-chained audit logs  │   │  - Anonymized indicator feeds│
└─────────────────────────────────────┘   └──────────────────────────────┘
```

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (Identity & Telemetry)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **SPOOF-01** | Attacker transmits synthetic events pretending to be a bank core system | **High** | False positives, alert fatigue, illegitimate automated containment | HMAC-SHA256 signature verification over event payload timestamped with $\le 300\text{s}$ tolerance skew; scoped API tokens (`ecs_pat_`). |
| **SPOOF-02** | Rogue insider impersonates another operator analyst | **High** | Unauthorized case closures or containment approvals | Mandatory TOTP MFA (RFC 6238); session tokens tied to cryptographically signed JWT with revocation blacklist (`auth_service.py`). |
| **SPOOF-03** | Adversary injects spoofed threat indicators into community exchange | **Medium** | Legitimate IP or account flagged as malicious across institutions | Community threat signal sharing exchanges only keyed SHA-256 hashes with minimum cross-institution confirmation thresholds. |

---

### 2.2 Tampering (Data & Code Integrity)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **TAMP-01** | Compromised administrator alters historical audit records to hide fraud | **Critical** | Evidence destruction, regulatory non-compliance | Sequential SHA-256 hash chaining across `audit_logs` where each row stores `prev_hash`; automated `verify_audit_chain()` and signed anchor exports (`ADR-015`). |
| **TAMP-02** | Attacker modifies detection rules to blind detection of specific accounts | **Critical** | Undetected large-scale account takeover or fund draining | Rules-as-data schema versioning; rules stored in database require dual-approver role (`admin`); rule edits generate immutable audit log entries. |
| **TAMP-03** | Telemetry events modified in-transit | **High** | Corrupted fraud correlation | Mandatory TLS 1.3 encryption on ingest endpoints; HMAC payload digest verification. |

---

### 2.3 Repudiation (Accountability)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **REPU-01** | Responder approves an account freeze, then denies taking the action | **High** | Dispute over wrongful account freeze; liability exposure | Controlled response actions enforce mandatory user attribution, hash-sealed evidence payload, and immutable audit logging. |
| **REPU-02** | Operator claims an incident was reported to INSA within 48h without proof | **High** | Regulatory fines under Proclamation 1426/2026 | Hash-sealed statutory incident package generates SHA-256 manifest and digital timestamp anchor at moment of generation (`ADR-003`). |

---

### 2.4 Information Disclosure (Privacy & Cross-Tenancy)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **INFO-01** | Multi-tenant leak: Bank A accesses Bank B's incident or transaction data | **Critical** | Banking confidentiality violation, P0 compliance breach | Strict multi-tenancy enforcement: `organization_id UUID NOT NULL` on all tables, Postgres RLS, and automated cross-tenant isolation test suite (`ADR-011`). |
| **INFO-02** | Connector secret keys or database credentials exposed in logs or dumps | **Critical** | Unauthorized access to target core banking APIs | AES-256-GCM envelope encryption at rest (`crypto_service.py`); zero secrets logged in application output (`ADR-012`). |
| **INFO-03** | Threat intelligence sharing exposes unmasked customer PII | **High** | Violation of Ethiopian Data Protection Proclamation 1321/2024 | Signal exchange strictly hashes identifiers with per-tenant or community keyed salts before transmission; raw PII never leaves tenant enclave. |

---

### 2.5 Denial of Service (Availability)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **DOS-01** | Attacker floods telemetry endpoint with millions of bogus events | **High** | Worker CPU exhaustion, delayed detection of real fraud | Rate-limiting per API token; bounded Redis Streams (`maxlen=50,000`); sliding-window lookups optimized via Redis sorted sets ($O(\log N)$). |
| **DOS-02** | Poison pill event crashes detection worker process | **High** | Detection pipeline stoppage | Stream worker catches per-event exceptions; max 3 retries before routing to Dead-Letter Queue (`ecs:dlq:{org_id}`); main stream continues processing (`ADR-013`). |

---

### 2.6 Elevation of Privilege (Authorization)

| Threat ID | Threat Description | Severity | Impact | ECS v3.0 Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **ELEV-01** | Read-only viewer escalates to execute containment or modify users | **High** | Unauthorized account blocking, platform takeover | Strict RBAC enforcement via `@role_required` with 5 distinct tiers (`admin`, `analyst`, `responder`, `viewer`, `auditor`); tokens evaluated on every request. |
| **ELEV-02** | Connector API token used to access management UI endpoints | **High** | Unauthorized operational configuration | Scoped API tokens restricted to granted permissions (e.g. `ingest:events`); machine tokens cannot authenticate to interactive user routes. |

---

## 3. Defense-in-Depth Hardening Checklist

- [x] Envelope encryption implemented for all target system credentials (`crypto_service.py`).
- [x] Multi-tenancy isolation tested with automated read/write denial tests (`test_part7_multi_tenancy_isolation.py`).
- [x] Redis Streams queue bounded and equipped with dead-letter queue (`stream_service.py`).
- [x] SHA-256 hash chaining active on `audit_logs` (`audit_service.py`).
- [x] TOTP MFA supported for analyst and administrator personas (`auth_service.py`).
- [x] Scoped API tokens enforce least-privilege for automated connectors (`auth.py`).
- [x] PostgreSQL database initialization script defines RLS policies (`deploy/postgres/init.sql`).
