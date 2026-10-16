# Ethio-Cyber-Shield (ECS) v3.0 — Architecture Decision Records (ADRs) & Scope Freeze

> **Document Type**: Architecture Decision Records & MVP Scope Definition  
> **Status**: Frozen / Approved for Implementation  
> **Date**: October 2026  

---

## ADR-001: Strategic Wedge Selection

* **Context**: ECS cannot compete effectively as a generic SIEM/WAF/EDR against entrenched global vendors (Wazuh, Splunk, Elastic) or regulator-developed perimeter utilities (INSA Gasha WAF/VPN). It must address severe, unmet Ethiopian market needs with high regulatory leverage.
* **Decision**: Select the combination of **G2 (48-Hour Incident Readiness Engine)** + **G3 (Transaction-Aware Fraud & ATO Detection)** + **G1 (Opt-in Federated Signal Exchange)** as the core product wedge.
* **Rationale**:
  1. *Regulatory urgency*: Proclamation 1426/2026 legally mandates 48-hour reporting to the National CERT with up to ETB 2M fines. No accessible tool currently produces sealed, audit-ready packages for Ethiopian operators.
  2. *Domain specialization*: Generic SIEMs do not understand banking transaction velocity, account takeover sequences (`ATO-001`), or mobile money mule chains.
  3. *Network effect moat*: Federated signal exchange creates long-term defense value that static point tools cannot replicate.

---

## ADR-002: Scope Freeze for v3.0 MVP

### In-Scope for v3.0 MVP
1. **Core Platform Independence**:
   - Decouple from ShieldBank. Target systems connect via published OpenAPI/JSON Schema.
   - Run on-premise on standard Linux VPS via Docker Compose (`PostgreSQL` + `Redis`).
   - Remove all hard runtime dependencies on Supabase Cloud.
2. **Strict Multi-Tenancy**:
   - Add `organization_id UUID NOT NULL` to every database table.
   - Enforce PostgreSQL Row-Level Security (RLS) and tenant-scoped API authentication.
3. **Durable Event Stream Ingestion**:
   - Replace the in-memory 5,000-event ring buffer with durable streaming (Redis Streams or bounded transactional outbox table).
   - Implement consumer groups, backpressure handling, and dead-letter queues.
4. **Canonical Event Contract v1.1 & Integration SDKs**:
   - Generic channel and rail support (`channel`, `payment_rail`, `counterparty_ref_hash`, `device_fingerprint`, `msisdn_hash`).
   - Lightweight Python and Node.js SDKs with built-in retry and outbox logic.
   - Lightweight log agent collector for Nginx/Apache logs.
5. **Detection Engine v2 (Rules-as-Data)**:
   - Declarative rule definitions in YAML/JSON (Sigma-inspired) with versioning.
   - Rule lifecycle states: `draft` → `backtest` → `shadow` → `live`.
   - Core packs: Fraud & Payments Pack, Web/API Pack, and Insider/Admin Pack.
6. **Safe Controlled Response & Case Management**:
   - Multi-mode response: `observe` (shadow) → `recommend` → `approve` → `auto`.
   - Guardrails: allowlists, cooldown timers, max actions per hour, and mandatory rollback (`revert`).
   - Incident assignment, analyst notes, and entity timeline graph.
7. **Incident Readiness Engine**:
   - Explicit "Time of Detection" logging and live 48-hour countdown clock with 24h/36h/44h alert thresholds.
   - SHA-256 hash-sealed evidence package generator.
   - Bilingual incident report generator (Amharic & English) producing EthioCERT-compatible submission artifacts.

### Explicit Non-Goals (Out of Scope for v3.0 MVP)
- Building custom WAF or DDoS mitigation layers (integrate via log agent instead).
- Building custom endpoint detection agents / EDR (ingest Sysmon/OS logs via connector instead).
- Autonomous AI/LLM decision-making for containment (LLMs may only generate natural language summaries of deterministic evidence).
- Mandatory 24/7 human SOC services.

---

## ADR-003: Architecture Transformation — Self-Hosted PostgreSQL & Redis

* **Context**: ECS v2.0 uses `supabase-py` HTTP client talking to a remote Supabase cloud project (`ibxbsaeeouctuzvpbghl.supabase.co`). This violates Ethiopian financial data sovereignty requirements (PDPP 1321/2024), introduces network latency on event ingestion, and causes schema cache inconsistencies.
* **Decision**:
  - Replace the Supabase HTTP client with a standard direct PostgreSQL driver (`psycopg2` / `asyncpg` with connection pooling) and standard Redis queue.
  - Package the entire infrastructure as an isolated, one-command deployment (`docker-compose.yml`) containing PostgreSQL 16, Redis 7, ECS API Engine (Flask/Gunicorn), and the Web Console.
  - Retain full database migration scripts (`sql/`) runnable against any standard PostgreSQL instance.

---

## ADR-004: Multi-Tenancy & Data Isolation Model

* **Context**: Commercial banks, MFIs, and client agencies require mathematical isolation between tenant datasets.
* **Decision**:
  - Adopt **Row-Level Shared Database Multi-Tenancy**: Every table contains `organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`.
  - Database connections execute within tenant context (Postgres RLS `USING (organization_id = current_setting('app.current_org_id')::uuid)`).
  - Cross-tenant test suite must be integrated into CI/CD, verifying that Tenant A cannot read, insert, update, or delete Tenant B records.

---

## ADR-005: Secrets Protection & Encryption at Rest

* **Context**: ECS v2.0 stores `target_systems.secret_key` in plaintext. If the database is compromised, all connected banking control endpoints become vulnerable.
* **Decision**:
  - Implement envelope encryption for target credentials using AES-256-GCM.
  - Master key is supplied via environment variable (`ECS_MASTER_ENCRYPTION_KEY`) or mounted secret file.
  - Ingestion keys and control secrets are never returned in cleartext via API or logged.

---

## ADR-006: Detection Rules as Data

* **Context**: Hardcoded Python rules require codebase changes, rebuilds, and restarts to adjust thresholds or add detections.
* **Decision**:
  - Express all detection rules as declarative YAML/JSON specifications containing:
    `id`, `name`, `layer` (L1–L4), `category`, `severity`, `weight`, `window_seconds`, `conditions`, `thresholds`, `remediation_hints`, and ATT&CK mappings.
  - Rules support tenant-level parameter overrides (e.g., Bank A sets high-value threshold to ETB 200,000, while MFI B sets it to ETB 30,000).
  - Analyst feedback (True/False Positive tags) automatically tracks precision statistics per rule.

---

## ADR-007: Safe Response Modes & Blast-Radius Guardrails

* **Context**: Automated account locking or transaction freezing can disrupt legitimate commerce and create legal liability.
* **Decision**:
  - Every tenant and action type defaults to `observe` (shadow) mode upon onboarding for a minimum of 14 days.
  - Irreversible actions (`lock_account`) require explicit two-person authorization (`approve` mode).
  - System enforces hard blast-radius limits: maximum of 10 automated containment actions per hour per tenant, protected VIP/system allowlists, and a global "kill switch" that instantly switches all actions to `observe`.
  - Every containment action must implement a documented, tested rollback connector (`revert`).

---

## ADR-008: Success Metrics & Target Thresholds

| Category | Metric | Phase Gate Target | Long-Term Production Target |
| :--- | :--- | :--- | :--- |
| **Detection Quality** | Recall on seeded attack corpus | $\ge 90\%$ (Gate 3) | $\ge 95\%$ |
| **Detection Quality** | False-positive rate after tuning | $\le 10\%$ in shadow mode | $\le 2\%$ |
| **Response Latency** | Median Time to Detect (MTTD) | $\le 30\text{ seconds}$ | $\le 5\text{ seconds}$ |
| **Response Latency** | Median Time to Contain (MTTR) | $\le 60\text{ seconds}$ (auto mode) | $\le 10\text{ seconds}$ |
| **Incident Readiness** | Time to complete 48h report package | $\le 2\text{ hours}$ in tabletop | $\le 30\text{ minutes}$ |
| **Incident Readiness** | 48-Hour statutory clock breaches | 0 breaches | 0 breaches |
| **Platform Safety** | Unintended / uncontained blocks | 0 in pilots | 0 in production |
| **Developer Onboarding** | Time-to-first-event for new target | $\le 1\text{ day}$ with SDK | $\le 2\text{ hours}$ |
| **Platform Scalability** | Throughput on 2 vCPU / 4GB VPS | $\ge 500\text{ events/sec}$ | $\ge 2,000\text{ events/sec}$ |

---

## ADR-009: Compliance & Regulatory Wording Policy

* **Context**: Overclaiming compliance with INSA or NBE directives exposes ECS and its customers to regulatory reprimand and legal liability.
* **Decision**:
  - ECS documentation, UI badges, and sales materials must strictly use the terms:
    - *"Incident Readiness Platform"*
    - *"Supports evidence collection for Proclamation 1426/2026"*
    - *"Assists in statutory 48-hour reporting"*
  - The words *"Guarantees compliance"*, *"Certified by INSA"*, or *"Officially endorsed"* are strictly prohibited.

---

## ADR-010: Product Naming, IP & Neutrality Position

* **Context**: The product must establish a clear identity as an independent, operator-owned platform.
* **Decision**:
  - The canonical product name is **Ethio-Cyber-Shield (ECS)**.
  - Positioning: *"An independent, explainable, self-hostable cybersecurity detection and incident-readiness platform for Ethiopian critical infrastructure and digital finance."*
  - Complete neutrality: No proprietary ties to any single regulator or vendor. Export adapters support EthioCERT formats and open security standards (STIX/TAXII, CEF, Syslog).

---

## ADR-011: Multi-Tenancy Boundary Isolation and Tenant Context Resolution

* **Context**: ECS must support multi-tenant deployments without cross-tenant data leaks.
* **Decision**:
  - Every table must maintain `organization_id UUID NOT NULL` with foreign key to `organizations(id)`.
  - All database queries, route handlers, and stream consumers must scope queries by `organization_id`.
  - Tenant context resolution evaluates in priority order:
    1. Explicit `X-ECS-Tenant` HTTP header (UUID).
    2. Authenticated user's `organization_id` embedded in JWT claims.
    3. Target system registered `organization_id` associated with API key ID (`X-ECS-Key-Id`).
    4. Safe fallback to default organization in single-tenant / legacy environments.
  - Cross-tenant read/write isolation is verified by automated integration test suites (`test_part7_multi_tenancy_isolation.py`).

---

## ADR-012: Envelope Encryption for Connector Secrets at Rest

* **Context**: Storing plaintext target system secrets, API keys, or webhooks in the database violates hard engineering rules and banking compliance.
* **Decision**:
  - Implement envelope encryption via `app.services.crypto_service` using AES-256-GCM.
  - Secret fields (`shared_secret`, `auth_token`, `credentials`) are serialized with random 96-bit IV, ciphertext, and 128-bit authentication tag prefixed as `enc:v1:<base64>`.
  - Master key (`ECS_MASTER_ENCRYPTION_KEY`) is injected via environment variables and never logged or serialized to database tables.

---

## ADR-013: Durable Telemetry Streaming with Redis Streams and Resilient Fallback

* **Context**: ECS v2.0 relied on an in-memory 5,000-event ring buffer (`deque`). A process restart or container termination caused catastrophic event loss, corrupting sliding windows and multi-stage correlation chains (e.g., ATO sequences).
* **Decision**:
  - Implement `app.services.stream_service.StreamService` utilizing Redis Streams (`XADD`, `XREADGROUP`, `XACK`) with consumer group `ecs_workers`.
  - Maintain sliding-window state in Redis Sorted Sets (`ZADD`, `ZRANGEBYSCORE`) indexed by entity tuples (`{org_id}:account:{id}`, `{org_id}:ip:{ip}`, `{org_id}:device:{id}`) with automatic TTL expiry, providing $O(\log N)$ correlation lookups.
  - Route messages that exceed retry limits (`max_retries=3`) to dead-letter queues (`ecs:dlq:{org_id}`).
  - Maintain automatic fallback to thread-safe bounded in-memory sliding structures when Redis is temporarily offline or in single-process test runs, preventing application crashes.


