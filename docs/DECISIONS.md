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

---

## ADR-014: Identity, Multi-Tenant RBAC, TOTP MFA, and Scoped API Tokens

* **Context**: Secure access to ECS requires multi-factor authentication, granular role separation across security operations personas, token revocation, and scoped tokens for automated connectors.
* **Decision**:
  - Implement RFC 6238 Time-based One-Time Password (TOTP) MFA via `pyotp` with encrypted secret storage (`mfa_secret`).
  - Expand RBAC roles to five distinct tiers:
    - `admin`: Platform settings, user lifecycle, connector credentials, rules management.
    - `analyst`: Alert triage, incident promotion, indicator linkage, rule tuning.
    - `responder`: Containment actions, rollback, execution approvals.
    - `auditor`: Read-only access to hash-sealed logs, statutory reports, and evidence packages.
    - `viewer`: Read-only operational dashboard and telemetry monitoring.
  - Implement immediate token revocation / session blacklisting on logout and credential reset.
  - Implement Scoped API Tokens (`ecs_pat_...`) hashed with SHA-256 for non-interactive service-to-service connectors (`ingest:events`, `read:alerts`, `read:incidents`).

---

## ADR-015: Tamper-Evident SHA-256 Hash-Chained Audit Logs and Regulatory Anchors

* **Context**: Financial institutions and critical infrastructure operators under Proclamation 1426/2026 and NBE directives must prove that incident evidence and operational actions have not been altered, deleted, or backdated.
* **Decision**:
  - Implement sequential Merkle/blockchain-style cryptographic hash chaining across `audit_logs`.
  - Every row stores `prev_hash` (matching preceding entry's `entry_hash` or `0`*64 for genesis) and `entry_hash` (SHA-256 digest over predecessor hash, organization ID, user ID, action, entity type, entity ID, timestamp, and canonical details JSON).
  - Each tenant maintains an independent, isolated cryptographic hash chain.
  - Implement verification API (`POST /api/audit/verify`) that recalculates the chain and pinpoints any tampered records.
  - Implement anchor export API (`POST /api/audit/anchor`) generating HMAC-SHA256 sealed statutory verification packages.

---

## ADR-016: Self-Hostable Database Abstraction Layer (Zero Supabase Lock-in)

* **Context**: ECS v2.0 was hard-coded to Supabase cloud endpoints (`supabase-py`). National security operators in Ethiopia require total sovereign independence and must run ECS completely self-hosted on plain PostgreSQL without proprietary cloud APIs or third-party telemetry leakage.
* **Decision**:
  - Implement dual-backend database abstraction in `app.services.db`:
    - Independent PostgreSQL mode (`PostgresDatabaseAdapter`) utilizing standard `psycopg2` when `DATABASE_URL` is configured.
    - Supabase client mode when `SUPABASE_URL` is explicitly provided for legacy / cloud-hosted deployments.
  - Expose deep component health diagnostics via `/api/health` checking database latency, driver, and stream engine status.
  - Maintain automated backup and disaster recovery restore scripts with SHA-256 seal verification (`deploy/scripts/backup.sh`, `deploy/scripts/restore.sh`).

---

## ADR-017: ECS Canonical Event Contract v1.1 Schema and Privacy-Preserving Hashing

* **Context**:
  - Telemetry ingestion in ECS v1.0 lacked generic channel awareness (`channel`, `payment_rail`) and privacy protections needed by Ethiopian financial operators, PSOs, and national critical infrastructure under Proclamation No. 1426/2026, NBE Directives, and PDPP 1321/2024.
  - Operators frequently pass brand-specific rails (e.g. "Telebirr", "CBE Birr", "EthSwitch") or unmasked PII (phone numbers, National IDs, account numbers).
  - Hard rules mandate zero secrets/PII in logs/code, multi-tenancy, and Ethiopian operational context (ETB, Addis Ababa UTC+3).
* **Decision**:
  - Publish **ECS Event Contract v1.1** as an OpenAPI 3.1.0 specification (`docs/contracts/ecs-event-contract-v1.1.yaml`) and JSON Schema (`docs/contracts/ecs-event-v1.1.schema.json`).
  - Introduce generic channel enums (`web`, `mobile`, `ussd`, `api`, `agent`, `branch`, `atm`, `pos`, `system`) and payment rail enums (`p2p`, `card`, `wallet`, `bill_pay`, `interbank`, `rtgs`, `ach`).
  - Implement dynamic Ethiopian brand mapping (`BRAND_TO_RAIL_MAP` and `CHANNEL_ALIASES`) normalizing local brand names to generic canonical rails without hardcoding vendor logic in core detection.
  - Implement privacy-preserving cryptographic SHA-256 hashing for sensitive customer identifiers (`msisdn_hash`, `national_id_hash`, `counterparty_ref_hash`). If raw unmasked identifiers are transmitted, the ingestion gateway automatically scrubs raw PII and computes one-way SHA-256 digests.
  - Set default timezone context to `Africa/Addis_Ababa` (UTC+3) and currency to `ETB`.
  - Expose runtime contract inspection via `GET /api/events/contract`.
  - Equip client SDKs (Python, Node/TypeScript) with client-side hashing helpers (`hash_phone`, `hash_national_id`, `hash_counterparty`) so operators can enforce data privacy before network egress.

---

## ADR-018: Official Client SDKs with Transactional Outbox Pattern and Framework Middleware

* **Context**:
  - Financial, telecom, and critical infrastructure target systems (banks, MFIs, PSOs, USSD switches) must stream security and fraud telemetry into ECS without risking transaction latency, thread pool starvation, or event loss during network partitions or ECS maintenance.
  - Telemetry generation must be safe, asynchronous, and reliable across various languages used by Ethiopian operators (Python, Node/TypeScript, PHP/Laravel).
* **Decision**:
  - Implement the **Transactional Outbox Pattern** across all client SDKs (`sdk/python/outbox.py`, `sdk/node/outbox.ts`, `sdk/php/src/TransactionalOutbox.php`).
  - Use thread-safe SQLite in WAL mode as the default persistent zero-dependency storage engine for Python and PHP outboxes, and in-memory/pluggable engine for Node.js.
  - Implement progressive exponential backoff retry:
    $T_{\text{backoff}} = \min(T_{\text{max}}, T_{\text{initial}} \times 2^{\text{attempts}-1})$, capped at 300 seconds, with up to 8 delivery attempts.
  - Automatically escalate unresolvable events to `DEAD_LETTER` status after exceeding maximum attempts to alert SOC engineers without dropping the event payload.
  - Generate fresh cryptographic HMAC-SHA256 signatures, timestamps, and UUID nonces on every outbox flush attempt to prevent replay rejection.
  - Provide plug-and-play middleware for mainstream frameworks:
    - Flask (`ECSFlaskMiddleware`)
    - FastAPI / Starlette (`ECSFastAPIMiddleware`)
    - Django (`ECSDjangoMiddleware`)
    - Express.js (`ecsExpressMiddleware`)
    - Laravel (`ECSMiddleware`)
  - Enforce client-side PII scrubbing in SDK event builders (`hash_phone`, `hash_national_id`, `hash_counterparty`) to prevent raw personal identifiers from crossing network boundaries.

---

## ADR-019: Generic Inbound Webhook Receiver and Declarative JSONPath Field Mapper Engine

* **Context**:
  - Ethiopian digital finance operators and external payment gateways (e.g., Chapa, Telebirr merchant callbacks, CBE Birr, EthSwitch, and internal core banking webhooks) dispatch notification payloads in diverse, non-standardized JSON structures.
  - Requiring custom backend code deployments for each external integration introduces friction, slows onboarding, and creates maintenance overhead.
  - Webhooks must be verified cryptographically (via shared tokens or HMAC-SHA256 signatures) and mapped into canonical ECS Event Contract v1.1 events without leaking secrets or violating multi-tenancy.
* **Decision**:
  - Implement a zero-dependency JSONPath extraction and transformation engine (`core/app/services/field_mapper.py`).
  - Support dot and bracket indexing notations (`$.data.customer.phones[0]`, `data.id`), type casting (`amount_to_minor`, `minor_to_amount`, `to_float`, `timestamp_iso`), cryptographic phone hashing (`normalize_phone_hash`), and value mapping tables (`value_map`).
  - Provide an interactive test-with-sample dry-run runner (`test_mapping` and `POST /api/webhooks/test-mapping`) returning detailed diagnostic reports, mapped field counts, and schema validation checks before saving configurations.
  - Implement tenant-isolated Webhook Sources management (`webhook_sources` table and `core/app/services/webhook_service.py`), storing webhook secrets under AES-256-GCM envelope encryption (`enc:v1:...`) at rest and strictly masking them in all API responses.
  - Implement a public inbound receiver endpoint `POST /api/webhooks/inbound/<source_id>` supporting constant-time token comparison (`hmac.compare_digest`) and raw-payload HMAC-SHA256 signature verification (`X-Signature-SHA256`).
  - Seamlessly ingest validated canonical events directly into the ECS Redis Streams queue and real-time detection engine.

---

## ADR-020: Lightweight Log Agent Collector Architecture, Normalization, and Bounded Resource Safeguards

* **Context**:
  - Ethiopian critical infrastructure operators (banks, telecom providers, government gateways, payment switches) operate edge web servers (Nginx, Apache), network firewalls, and appliances emitting syslog or Common Event Format (CEF) streams.
  - High log ingestion volumes risk CPU spikes and Out-of-Memory (OOM) crashes on production edge nodes if memory queues are unbounded or multi-gigabyte log files are read in bulk.
  - Telemetry from log streams must be normalized into canonical ECS Event Contract v1.1 events with verifiable evidentiary seals (SHA-256 digests of raw lines) and reliable offset recovery across agent restarts.
* **Decision**:
  - Implement zero-dependency log parsers for Nginx/Apache Combined & Common access logs, Nginx/Apache error logs, Syslog (RFC 3164 & RFC 5424), and Common Event Format (CEF) in `connectors/log_agent/parser.py`.
  - Maintain evidentiary chain of custody by computing a SHA-256 digest (`raw_log_hash`) for each raw log line, stored directly in canonical event attributes.
  - Implement `LogAgentCollector` in `connectors/log_agent/collector.py` with persistent byte-offset state checkpointing (`CollectorCheckpoint`), detecting file rotation and truncation automatically.
  - Enforce strict bounded memory and CPU resource guards: configurable maximum batch size (`batch_size`) and in-memory queue depth (`max_queue_size`), preventing OOM crashes on high-load bursts and tracking `dropped_lines` metrics.
  - Provide an interactive parsing and preview endpoint `POST /api/log-agent/parse` allowing SOC analysts to test-run log parsing on sample lines before deploying collectors.
  - Provide standalone CLI daemon `connectors/log_agent/cli.py` for headless node deployment with HMAC-SHA256 authenticated delivery to the ECS Ingestion Gateway.

---

## ADR-021: Offline-First GeoIP/ASN Network Registry, Threat Intel Caching, and Behavioral Device Reputation Engine

* **Context**:
  - Ethiopian critical infrastructure operators (banks, telecom providers, government gateways, payment switches) often operate in low-bandwidth, air-gapped, or strictly partitioned internal environments where external cloud GeoIP or Threat Intelligence (TI) lookups are prohibited, unreliable, or risk leaking customer transaction IPs.
  - Security analysts require instantaneous classification of domestic networks (Ethio Telecom AS24757, Safaricom Ethiopia AS329340, EthERNet AS37108), datacenter/cloud hosting indicators (AWS, DigitalOcean, Hetzner, GCP, Azure), Tor exit nodes, and device risk scoring without external network dependencies.
* **Decision**:
  - Implement a zero-dependency offline CIDR network registry in `app.services.enrichment_service` pre-seeded with Ethiopian ISP CIDRs, RFC1918 private subnets, and major hosting and anonymizer networks.
  - Maintain an in-memory Threat Intelligence (TI) indicator cache layer providing sub-millisecond evaluation with severity, confidence, and categorization flags.
  - Implement an explainable, multi-tenant-isolated device reputation scoring engine (`calculate_device_reputation`) evaluating 24-hour behavioral baselines: multi-account access frequency (credential stuffing / mule indicator), authentication failure rates, and incident correlation.
  - Provide canonical event enrichment pipeline hook (`enrich_canonical_event`) injecting structured `geo`, `asn`, `threat_intel`, and `device` context into event attributes without altering raw payloads.
  - Expose REST API endpoints `GET /api/enrichment/ip/<ip>`, `GET /api/enrichment/device/<device_id>`, and `POST /api/enrichment/event`.

---

## ADR-022: Unified Entity Graph, Linkage Model, and Transitive Fraud Detection

* **Context**:
  - Complex cyber attacks and fraud schemes in Ethiopian digital banking (e.g., credential stuffing, automated account takeover, and pass-through money mule syndicates) span multiple interconnected entities: accounts, devices, IP addresses, session tokens, beneficiaries, and hashed identity attributes.
  - Storing telemetry solely in isolated tabular logs impedes multi-hop relational investigation and delays incident containment.
  - Multi-tenancy and data protection regulations (PDPP 1321/2024, NBE Directives) require strict organizational data boundaries and privacy-preserving hashing for all personal identifiers.
* **Decision**:
  - Add `entities` and `entity_links` relational schema to PostgreSQL (`deploy/postgres/init.sql`) with mandatory `organization_id UUID NOT NULL` scoping and composite uniqueness constraints.
  - Automatically extract and upsert participating entity nodes and semantic relationships (`used_device`, `connected_from_ip`, `transferred_to`, `active_session`, `registered_phone`, `verified_identity`) upon every event ingested via `app.services.event_service.ingest_event`.
  - Track `first_seen_at`, `last_seen_at`, `event_count`, and `link_count` counters continuously to power behavioral baselines.
  - Implement breadth-first graph traversal (`get_entity_graph`) producing Cytoscape/Vis.js compatible node and edge structures up to exploration depth 2.
  - Implement shared entity detection (`find_shared_entities`) uncovering multi-account device usage (credential stuffing) and multi-sender beneficiary accumulation (mule account rings).
  - Implement transitive risk synthesis (`calculate_graph_risk`) propagating risk scores and explanatory rationales across adjacent graph connections.
  - Expose REST API endpoints `GET /api/entities/<type>/<value>`, `/links`, `/graph`, `/shared`, `/risk`, and `POST /tag`.

---

## ADR-023: Health & Data-Quality Monitoring Architecture, Silent-Source Anomaly Detection, and Explainable Quality Scoring

* **Context**:
  - In production deployments across Ethiopian financial operators and critical infrastructure, telemetry connectors (webhooks, syslog agents, transactional outbox SDKs) can silently degrade or fail due to network partitions, configuration errors, certificate expiry, or upstream schema shifts.
  - When an ingestion source stops emitting events, downstream detection rules silently miss threats without raising operational alerts ("silent failure mode").
  - Malformed or rejected events must be actively tracked, categorized, and diagnosed without leaking sensitive customer PII or authentication secrets.
  - Security and fraud operations leaders require an explainable, composite Data Quality Score (0–100) reflecting schema compliance, source vitality, and field richness rather than an opaque heuristic.
* **Decision**:
  - Implement `app.services.data_quality_service` strictly partitioned by `organization_id UUID NOT NULL` with persistent schema in PostgreSQL (`data_quality_sources`, `schema_violations`) and in-memory cache resilience.
  - Implement silent-source anomaly detection (`check_silent_sources`) with configurable per-source silence thresholds (default 15 minutes / 900 seconds) and progressive severity tiers (`warning` for $1\times \le \text{silence} \le 2\times \text{threshold}$; `critical` for $\text{silence} > 2\times \text{threshold}$).
  - Implement tenant-level silence anomaly alerts flagging when an entire organization has emitted zero telemetry for over 15 minutes ("no events from tenant X in 15 min").
  - Implement schema violation tracking (`record_schema_violation`) with automatic recursive credential redaction (`sanitize_payload`) for passwords, tokens, API keys, and PANs.
  - Track real-time ingestion throughput telemetry (1m, 5m, 15m, 1h, 24h event counters and rates).
  - Calculate an explainable composite Data Quality Score (0–100) and letter grade (A–F) based on transparent weights:
    - 40% Schema Compliance ($\frac{\text{valid}}{\text{valid} + \text{violations}}$)
    - 35% Source Vitality ($\frac{\text{active}}{\text{monitored}}$)
    - 25% Field Richness (presence of `channel`, `device_fingerprint`, `source_ip`, `payment_rail`)
  - Expose REST API endpoints under `/api/health/quality/` (`/overview`, `/sources`, `/silent-alerts`, `/violations`, `/record-violation`).
  - Wire into central event pipeline (`ingest_event`) and webhook handler (`process_inbound_webhook`) to automatically record source activity and schema violations.

---

## ADR-024: Multi-Target Connector Schedulers, Non-Blocking Concurrency, Exponential Backoff, and Gate 2 Verification

* **Context**:
  - The legacy poller assumed a monolithic, single-threaded sequential polling loop where all targets were queried sequentially at a fixed 5-second interval.
  - If a single target experienced network partitions, timeouts, or 502/503 errors, subsequent targets were blocked or delayed, and failing endpoints were repeatedly hammered without backoff.
  - Gate 2 requires an independent, decoupled connector model where ShieldBank runs purely as an external target, schema validation safely rejects malformed payloads without crashing, and any Ethiopian operator can integrate via SDKs in $\le 1$ day.
* **Decision**:
  - Implement `ConnectorSchedulerManager` and `ConnectorScheduler` in `core/app/services/connector_scheduler_service.py` strictly scoped by `organization_id UUID NOT NULL`.
  - Provide independent per-connector scheduling with custom intervals (e.g. 5s for high-volume banking testbeds, 30s or 60s for external clearinghouses).
  - Enforce non-blocking concurrency via a bounded `ThreadPoolExecutor`, preventing slow or hanging targets from blocking other connectors.
  - Implement exponential backoff with jitter on target/network errors:
    $\text{delay} = \min(\text{interval} \times 2^{\text{failures}}, \text{max\_backoff}) \times (1 \pm \text{jitter})$,
    preventing thundering herd problems against struggling banking services.
  - Implement automatic recovery: when a backoff target returns 200 OK with events, consecutive failures reset to 0 and the schedule immediately restores to the base interval.
  - Provide runtime control APIs (`/api/connectors/schedulers/*`) for on-demand trigger, pause, resume, and reconfiguration.
  - Satisfy all Gate 2 criteria:
    - Decoupled connector architecture: ShieldBank runs purely as an external target registered in the scheduler.
    - Schema validation safely rejects malformed payloads without system instability.
    - Official SDKs (Python, Node.js, PHP/Laravel) and `docs/INTEGRATION_GUIDE.md` enable rapid $\le 1$ day operator integration.

---

## ADR-025: Rules as Data, Declarative Sigma-Inspired Engine, and Tenant Threshold Overrides

* **Context**:
  - Previously, detection logic across Layers 1 to 3 was hardcoded into imperative Python branches in `core/app/services/detection_engine.py`.
  - Adding, tuning, or experimenting with rules required source code modifications and deployments, preventing rapid security response to new attack campaigns.
  - Different Ethiopian operators have vastly different risk profiles and operational thresholds (e.g., Bank A defines high-value transfers at 500,000 ETB, while a microfinance institution flags 25,000 ETB). Hardcoded static thresholds cannot accommodate diverse financial institutions.
  - Production deployments require rule lifecycle states (`draft`, `backtest`, `shadow`, `live`) so security engineers can test new detection rules against live production telemetry without firing false-positive alerts or triggering automated account containment.
* **Decision**:
  - Define rules declaratively as data using a Sigma-inspired YAML/JSON schema with versioning, MITRE ATT&CK tags, Ethiopian contextual fields (ETB amounts, Addis Ababa hours), and explicit parameter thresholds (`core/app/rules/definitions/*.yaml`).
  - Migrate all 11 core detection rules across L1-L3 into declarative rule files:
    - L1 Threshold & Signature: `auth_001_login_burst`, `auth_002_credential_stuffing`, `tx_001_high_value_transfer`, `ioc_001_malicious_ip`, `api_001_authz_denial_burst`
    - L2 Contextual: `auth_003_new_device_login`, `tx_003_off_hours_transfer`, `tx_004_untrusted_device_transfer`, `priv_001_privilege_abuse`
    - L3 Correlation Chains: `api_002_idor_enumeration`, `ato_001_account_takeover`
  - Implement `RuleEngine` (`core/app/services/rule_engine_service.py`) supporting dynamic YAML loading, parameter interpolation, and multi-tenant threshold overrides (`tenant_rule_overrides` table in PostgreSQL with `organization_id UUID NOT NULL`).
  - Implement rule lifecycle enforcement:
    - `live`: Contributes to active risk score, produces detections, triggers alerts, incident escalation, and automated containment.
    - `shadow`: Evaluates rules and persists audit detections with `is_shadow=True`, but contributes 0 points to active risk score and is strictly excluded from triggering alerts or automated containment.
    - `draft` / `backtest`: Dormant during real-time event streaming; reserved for historical evaluation.
  - Wire `RuleEngine.evaluate_event` into `core/app/services/detection_engine.py` (`evaluate_event_stream`), making declarative rules the primary detection evaluator.
  - Expose REST API routes (`core/app/routes/rules.py`):
    - `GET /api/rules`: List rules with effective tenant overrides.
    - `GET /api/rules/<id>`: Get single rule details and effective parameters.
    - `PUT /api/rules/<id>/override`: Set or update per-tenant rule configuration (enable/disable, custom ETB thresholds, weight/severity overrides, lifecycle state).
    - `GET /api/rules/<id>/override`: Retrieve tenant-specific override.
    - `DELETE /api/rules/<id>/override`: Revert tenant override to platform defaults.

---

## ADR-026: Rule Lifecycle Tooling, Historical Event Backtesting, and Analyst Precision Feedback

* **Context**:
  - In critical banking and payment rail environments, deploying new detection rules directly into live production or tuning ETB thresholds blindly causes alert fatigue, false positives, and operational disruptions.
  - Security analysts and fraud engineers need an evidence-backed workflow to evaluate candidate rules against actual historical telemetry before activation: `draft` -> `backtest` -> `shadow` -> `live`.
  - The platform requires an explainable "what would have fired in the last 7 days" preview to see the exact delta in detections and simulated risk points when adjusting thresholds.
  - Continuous detection improvement requires closing the analyst feedback loop: capturing `true_positive` vs. `false_positive` verdicts, computing precision and false positive rates (FPR), and automatically surfacing tuning alerts and entity suppression recommendations when FPR exceeds 25%.
* **Decision**:
  - Implement `rule_lifecycle_service.py` (`RuleBacktestEngine`, `RuleLifecycleManager`, `RulePrecisionService`) strictly partitioned by `organization_id UUID NOT NULL`.
  - Add PostgreSQL tables in `deploy/postgres/init.sql`:
    - `rule_backtest_runs`: stores backtest execution history, window parameters, evaluated event counts, match rates, daily distribution, and sample matches.
    - `rule_feedback`: stores analyst review verdicts (`true_positive`, `false_positive`, `suspicious_unconfirmed`, `benign_test`), analyst notes, and suggested entity suppressions.
    - `rule_lifecycle_history`: audit log recording lifecycle transitions, old state, new state, reason, and backtest link.
  - Enforce lifecycle transition validation:
    - Promoting from `draft` or `backtest` to `shadow` or `live` requires a verified historical backtest run (or explicit `force=True` audit override).
    - Transitions update per-tenant overrides (`tenant_rule_overrides`) and emit audit log records.
  - Support dry-run "what would have fired" preview (`RuleBacktestEngine.preview_rule_evaluation`) allowing analysts to test threshold adjustments (e.g. 100k vs 250k ETB) against the last 7 days of stored events without permanent database modifications.
  - Calculate real-time rule precision $\frac{\text{TP}}{\text{TP} + \text{FP}}$ and false positive rate. Automatically raise `HIGH_FALSE_POSITIVE_RATE` warnings when FPR $\ge 25\%$ with $\ge 2$ FPs, recommending threshold tuning and entity allowlists; conversely, surface `PROMOTION_READY` suggestions when low FPR is observed during shadow evaluation.
  - Expose REST API routes under `/api/rules/*`:
    - `POST /api/rules/<id>/backtest`, `GET /api/rules/<id>/backtest`, `GET /api/rules/backtests/<run_id>`
    - `POST /api/rules/preview`
    - `POST /api/rules/<id>/lifecycle`, `GET /api/rules/<id>/lifecycle`
    - `POST /api/rules/<id>/feedback`
    - `GET /api/rules/<id>/metrics`, `GET /api/rules/metrics/summary`

---

## ADR-027: Specialized Detection Rule Packs (Fraud & Payments, Web/API, Insider/Admin) and Multi-Tenant Threshold Tuning

* **Context**:
  - Generic threshold rules do not address the complex attack surfaces facing Ethiopian critical infrastructure and digital finance operators (e.g. USSD cash-outs, mule rings, SIM-swap account takeover, coached push-payment fraud, IDOR enumeration, API rate-limit evasion, dormant admin activations, and mass customer data exfiltration).
  - The platform requires modular, cataloged rule packs (Fraud & Payments, Web/API Abuse, Insider/Admin) totaling at least 25 declarative rules adhering to the Sigma-inspired format with ATT&CK tags and Ethiopian operational context (ETB thresholds, Addis Ababa UTC+3 off-hours, mobile payment rails).
  - Multi-tenancy isolation (`organization_id UUID NOT NULL`) must allow each tenant to selectively enable/disable rules, tune thresholds (e.g. custom ETB limits or structuring ceilings), and assign custom weights without code modifications or cross-tenant leakage.
* **Decision**:
  - Implement 3 specialized rule packs totaling 27 declarative Sigma-inspired YAML rules:
    - **Fraud & Payments Pack (12 rules)**:
      - `TX-001`: High-Value Transfer Threshold (default 100,000 ETB)
      - `TX-003`: Off-Hours Transaction (outside 06:00-22:00 EAT)
      - `TX-004`: Untrusted Device Transfer
      - `ATO-001`: Account Takeover Multi-Stage Chain
      - `AUTH-003`: New Device Login Post-Failures
      - `FRAUD-001`: Rapid Beneficiary Add and Transfer
      - `FRAUD-002`: Mule Pass-Through Account Pattern (high-velocity in/out flow)
      - `FRAUD-003`: SIM-Swap or Credential Reset Prior to Transfer
      - `FRAUD-004`: Transaction Structuring Under Reporting Threshold
      - `FRAUD-005`: USSD and Agent Cash-Out Burst
      - `FRAUD-006`: Authorized Push Payment (APP) Coached Transfer
      - `FRAUD-007`: Impossible Geolocation Travel Velocity
    - **Web & API Abuse Pack (9 rules)**:
      - `AUTH-001`: Login Failure Burst (T1110)
      - `AUTH-002`: Credential Stuffing (distributed targets from single IP)
      - `IOC-001`: Malicious IP Threat Intelligence Match
      - `API-001`: Authorization Denial Burst (401/403)
      - `API-002`: IDOR Enumeration Pattern
      - `API-003`: Bearer Token Misuse and Replay
      - `API-004`: Automated Bot and Security Tool Scanning (sqlmap, nikto, dirbuster)
      - `API-005`: Distributed Rate Limit Evasion Probing
      - `AUTH-004`: Password Spraying Campaign across multiple accounts
    - **Insider & Admin Pack (6 rules)**:
      - `PRIV-001`: Privilege Abuse / Unauthorized Config Change
      - `ADMIN-001`: Mass Customer Data Export Anomaly (records >= 1000)
      - `ADMIN-002`: Dormant Admin Account Activation (inactive >= 30 days)
      - `ADMIN-003`: Off-Hours Privileged Configuration Action (outside 06:00-20:00 EAT)
      - `ADMIN-004`: Unauthorized Role Elevation Attempt (superuser without dual approval)
      - `ADMIN-005`: Audit Trail Tampering Attempt (TRUNCATE/DELETE on audit logs)
  - Engine enhancements in `core/app/services/rule_engine_service.py`:
    - Pack filtering support in rule discovery and listing: `GET /api/rules?pack=<pack_name>`.
    - Candidate rule evaluation and transient override support in `evaluate_event(..., custom_rule_overrides=..., candidate_rules=...)` decoupling backtesting and preview from production database state.
    - Multi-tenant threshold overrides allowing per-tenant customization of rule thresholds (e.g. structuring thresholds, beneficiary cooldowns, off-hours schedules).
  - Verified with Part 21 test suite (`core/tests/test_part21_rule_packs.py`) ensuring rule parsing, pack filtering, evaluation criteria, multi-tenant override isolation, and stream synthesis.

---

## ADR-028: Explainable Behavioral Baselines and Deterministic Fallback (Phase 3.4)

* **Context**:
  - Pure static threshold rules (e.g. fixed 100k ETB transfer limits or fixed off-hours) do not capture entity-specific operational patterns (e.g., an account that routinely transfers 5,000 ETB suddenly transacting 90,000 ETB, or an enterprise operating solely during business hours active at 03:00 EAT).
  - Machine learning anomaly models often present opaque probability scores that fail the platform's core architectural principle: "Explainable by default" (SRS §9, GEMINI.md).
  - When historical telemetry for an entity is thin (e.g., brand-new accounts or < 5 events), statistical models suffer from high false positive rates. The platform requires a reliable deterministic fallback mechanism that prevents alert fatigue while maintaining security posture.
* **Decision**:
  - Implement `BehavioralBaselineService` (`core/app/services/behavioral_baseline_service.py`) supporting explainable per-entity statistical baselines across 4 dimensions:
    1. **Transaction Amounts**: count, min, max, mean, median, 90th percentile, and standard deviation. Detects amount anomalies and outputs plain-language explanations: `"amount is 9.0× this account's 90-day median (20,000 ETB)"`.
    2. **Temporal Operating Profile**: analyzes event timestamps in East Africa Time (`Africa/Addis_Ababa`, UTC+3). Extracts active hours and operating windows, detecting off-hours deviations with plain explanations: `"Activity at 03:00 EAT is outside typical operating window (08:00 - 17:00 EAT) for this account"`.
    3. **Client Devices**: tracks known device IDs and fingerprints; alerts on unfamiliar devices: `"Device 'dev_xyz' has never been observed for this account in the past 90 days"`.
    4. **Geographic Locations & Payment Channels**: tracks typical IPs, locations, and channels (USSD, mobile app, web); detects unprecedented access patterns.
  - Implement deterministic fallback when data is thin (`sample_count < 5`):
    - Sets `status: 'insufficient_data'`, `deterministic_fallback: True`, and `anomaly_score: 0`.
    - Returns explanatory fallback reason: `"Insufficient historical baseline (< 5 events); fallback to platform policy defaults"`.
    - Evaluates against standard deterministic rule engine policies rather than generating noisy statistical anomalies.
  - Store baselines in PostgreSQL table `entity_behavioral_baselines` with `organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`.
  - Wire into `detection_engine.py` (`evaluate_event_stream`):
    - Real-time event recording into tenant baseline buffer.
    - Explainable baseline deviations synthesized into `breakdown` (as `BASE-*` items), `reasons`, and risk score contribution.
  - Expose REST API routes under `/api/baselines`:
    - `GET /api/baselines`: List baselines for tenant with entity_type and status filtering.
    - `GET /api/baselines/<entity_type>/<entity_id>`: Retrieve entity behavioral baseline profile.
    - `POST /api/baselines/<entity_type>/<entity_id>/recalculate`: Force on-demand recalculation over custom lookback window.
    - `POST /api/baselines/evaluate`: Evaluate an event or candidate transaction against baseline.
    - `POST /api/baselines/<entity_type>/<entity_id>/seed`: Seed or override baseline profile directly.
    - `GET /api/baselines/summary`: Organization-wide baseline statistics and coverage.
  - Verified with Part 22 test suite (`core/tests/test_part22_behavioral_baselines.py`) with 8/8 tests passing.

---

## ADR-029: Explainable Risk Model v2 (Additive 0–100 with Rule Confidence, Entity Criticality, and Recency Decay)

* **Context**:
  - Legacy risk scoring in ECS relied on a crude sum of rule weights clamped at 100. This lacked essential security nuance:
    1. Equal weighting regardless of rule confidence (heuristics vs. deterministic attack chains).
    2. Inability to account for entity criticality (a probe against an unauthenticated marketing page had the same mathematical weight as a probe against EthSwitch settlement rails or Core Banking hosts).
    3. Absence of temporal recency decay, causing past resolved alerts to either permanently inflate entity risk or fail to compound acute ongoing multi-stage attacks.
  - Under Ethiopian legal regulations (Proclamation No. 1426/2026 and PDPP 1321/2024), cybersecurity risk scores must be explainable by default and **must never be presented as statistical probabilities of guilt or fraud**.
* **Decision**:
  - Implement `RiskModelV2Service` (`core/app/services/risk_model_service.py`) providing an additive, explainable 0–100 operational risk scoring engine.
  - Multi-factor mathematical formula:
    1. **Rule Confidence Weighting**: Evaluated rules contribute $\text{round}(r.\text{weight} \times C_r)$ with confidence factors $C_r \in \{1.00\text{ (high)}, 0.85\text{ (medium)}, 0.70\text{ (low)}\}$. Unspecified confidence defaults to 1.00 preserving calibrated declarative weights.
    2. **Pre-Criticality Synthesis**: Additive sum of confidence-adjusted rules and behavioral baseline anomaly scores: $\text{pre\_score} = \text{rules\_contrib} + \text{baseline\_score}$.
    3. **Entity Criticality Tiers**:
       - `critical`: $1.40\times$ multiplier, $+15$ pts boost (National switch rails, EthSwitch gateway, Core Banking hosts, RTGS/ACH nodes, Treasury reserve accounts).
       - `high`: $1.20\times$ multiplier, $+8$ pts boost (Corporate accounts, branch managers, cashier terminals, privileged IT admins).
       - `medium`: $1.00\times$ multiplier, $+0$ pts boost (Standard retail accounts, regular authenticated users).
       - `low`: $0.90\times$ multiplier, $+0$ pts boost (Sandbox environments, low-risk public endpoints).
    4. **Zero-Baseline Protection**: If $\text{pre\_score} == 0$, criticality boost is strictly suppressed, preventing false alarms on routine/benign events on critical infrastructure.
    5. **Recency Decay**: Step-wise temporal decay for historical alerts: $0-15\text{m}$ ($1.00$), $15-60\text{m}$ ($0.85$), $1-6\text{h}$ ($0.65$), $6-24\text{h}$ ($0.40$), $>24\text{h}$ ($0.20$).
    6. **Deterministic Severity & Rationale**: Mapping to Low ($0-24$), Medium ($25-49$), High ($50-74$), and Critical ($75-100$) with operational response rationales.
    7. **Non-Probability Mandate**: Mandatory legal notice across all evaluation outputs: `"Deterministic operational risk priority index (0–100); NOT a statistical probability of guilt or fraud."`
  - Store entity criticality configurations in PostgreSQL table `entity_criticality` strictly partitioned by `organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`.
  - Wire into `detection_engine.py` (`evaluate_event_stream`), synthesizing declarative rules, behavioral baselines, and Risk Model v2 into every alert and incident.
  - Expose REST API routes under `/api/risk`:
    - `GET /api/risk/model/spec`: Returns declarative specifications, formulas, and parameters.
    - `POST /api/risk/evaluate`: Dry-run and live evaluation of risk for events or candidate detections.
    - `GET /api/risk/criticality`: List entity criticality definitions for tenant.
    - `POST /api/risk/criticality`: Set or update entity criticality (Admin/Responder only).
    - `DELETE /api/risk/criticality/<id>`: Delete entity criticality override (Admin only).
    - `GET /api/risk/entities/<entity_type>/<entity_id>`: Retrieve composite decayed risk profile and entity history.
  - Verified with Part 23 test suite (`core/tests/test_part23_risk_model_v2.py`) with 11/11 tests passing and no regressions across Part 3, Part 19, Part 20, Part 21, and Part 22.

---

## ADR-030: Benchmark Corpus, Attack Lab Scenario Library, and CI Detection Verification (Phase 3.6)

* **Context**:
  - Deploying and maintaining 27+ detection rules across Fraud & Payments, Web/API, and Insider/Admin packs requires continuous quantitative assurance that rules actually catch target threats without inducing false alarms on legitimate banking operations.
  - Gate 3 requires:
    1. A reproducible labeled benchmark corpus and scenario library containing $\ge 12$ distinct attack scenarios.
    2. Published precision/recall per pack on the corpus.
    3. $\ge 90\%$ of attack scenarios detected with a false positive rate $\le 10\%$.
    4. Automated verification integrated directly into CI to prevent detection regressions on code changes or threshold adjustments.
* **Decision**:
  - Implement the Attack Lab Scenario Library (`core/app/benchmark/scenarios.py`) providing 16 distinct scenarios:
    - **Fraud & Payments (6 scenarios)**: `SCEN-01-ATO-CHAIN` (Multi-stage ATO), `SCEN-02-MULE-TRANSFER` (Mule Syndicate), `SCEN-03-SIM-SWAP` (SIM-swap cashout), `SCEN-04-STRUCTURING` (Smurfing under 50k ETB), `SCEN-05-USSD-CASH-OUT` (USSD session bursts), `SCEN-06-APP-COACHED` (Coached push payment).
    - **Web & API Abuse (4 scenarios)**: `SCEN-07-CRED-STUFFING` (Distributed login spray), `SCEN-08-IDOR-PROBE` (Sequential account traversal), `SCEN-09-BOT-SCANNER` (sqlmap/nikto scanner recon), `SCEN-10-TOKEN-REPLAY` (Bearer token reuse across distinct IPs/devices).
    - **Insider & Admin (3 scenarios)**: `SCEN-11-MASS-EXFIL` (5,000 PII/balance records export), `SCEN-12-AUDIT-TAMPER` (TRUNCATE audit_logs attack), `SCEN-16-DORMANT-ADMIN` (Off-hours dormant admin activation).
    - **Benign Baseline (3 scenarios)**: `SCEN-13-BENIGN-RETAIL` (Daytime P2P retail transfers), `SCEN-14-BENIGN-MERCHANT` (In-store QR payments), `SCEN-15-BENIGN-SALARY` (Corporate batch payroll credits).
  - Implement `BenchmarkCorpus` (`core/app/benchmark/corpus.py`) generating standardized labeled datasets with ground truth assertions (`is_attack`, `category`, `expected_rule_ids`).
  - Implement `BenchmarkService` (`core/app/services/benchmark_service.py`):
    - Computes scenario detection rate, false positive rate, precision, recall, and F1 score per pack and per rule.
    - Evaluates Gate 3 criteria ($\ge 90\%$ detection rate, $\le 10\%$ FPR).
    - Results: **100.00% Scenario Detection Rate**, **0.00% False Positive Rate**, **100.00% Precision**, **F1: 1.0000**.
  - Expose REST API routes under `/api/benchmark` (`core/app/routes/benchmark.py`):
    - `GET /api/benchmark/scenarios`: List scenario catalog and target rules.
    - `POST /api/benchmark/scenarios/run`: Execute individual scenario in sandbox mode.
    - `GET /api/benchmark/corpus`: Summary of labeled benchmark corpus.
    - `POST /api/benchmark/run`: Full benchmark execution.
    - `GET /api/benchmark/latest`: Latest benchmark run metrics.
  - Implement standalone CLI runner (`labs/run_benchmark.py`) with `--min-recall 0.90` and `--max-fpr 0.10` gates and terminal reporting.
  - Integrated into `.github/workflows/ci.yml` ensuring all PRs and commits verify Gate 3 detection performance automatically.
  - Verified with Part 24 test suite (`core/tests/test_part24_benchmark_corpus_and_ci.py`) with 7/7 tests passing.

---

## ADR-031: Alert Quality, Sliding-Window Deduplication, Suppression Windows, and SOC Fatigue Reduction (Phase 3.7)

* **Context**:
  - High-volume transaction processing and telemetry ingestion in Ethiopian financial infrastructure can cause alert floods, where repeated identical events (e.g. brute force sprays, automated retry bursts) overwhelm SOC analysts with duplicate tickets.
  - Furthermore, routine penetration testing, maintenance windows, and rule tuning require temporary, time-bounded suppression without permanently disabling core detection rules.
  - Phase 3.7 completes Phase 3 (Detection Engine v2) by delivering deterministic SHA-256 alert fingerprinting, sliding-window deduplication, dynamic severity escalation, entity-centric correlation grouping, time-based suppression windows, and real-time alert fatigue reduction metrics.

* **Decision**:
  - **Deterministic Alert Fingerprinting**: Calculate canonical SHA-256 hash over invariant attributes: `sha256(f"{org_id}:{rule_id}:{entity_type}:{entity_id}:{alert_type}")`. Identical incident attributes consistently map to the identical fingerprint.
  - **Sliding-Window Deduplication**:
    - During a configurable deduplication window (default: 15 minutes / 900 seconds), incoming candidate alerts matching an active open alert with the identical fingerprint are absorbed rather than spawning new alert records.
    - Increments `duplicate_count`, updates `last_seen_at`, and appends the new `trigger_event_id` to `related_event_ids`.
    - **Risk Score & Severity Escalation**: If duplicate events carry higher risk scores than the initial alert, the parent alert's `risk_score`, `severity`, and `title` automatically escalate to reflect the elevated threat level.
  - **Entity-Centric Alert Grouping & Attack-Chain Correlation**:
    - Multiple distinct detection rules firing on the same entity (e.g. AUTH-001 followed by TX-001) within a 30-minute grouping window share a correlated `group_id`, visually clustering the multi-vector campaign together for analysts.
  - **Time-Based Suppression Windows (`alert_suppression_rules`)**:
    - Allow SOC teams and administrators to define temporary suppression rules on specific entities (IP, account, user) or rule IDs with an explicit duration and reason.
    - Candidate alerts matching active, unexpired suppression rules are suppressed (`action: 'suppressed'`), preventing alert creation and incident dispatch.
    - Expired rules are ignored automatically; manual early revocation supported via API.
  - **Fatigue Reduction Metrics**:
    - Track total evaluated, created, deduplicated, and suppressed candidate alerts per tenant.
    - Compute `alert_reduction_rate = (deduplicated + suppressed) / total_evaluated`, average duplicates per alert, and SOC health grade (`Optimal` $\ge 70\%$, `Good` $\ge 50\%$, `Moderate` $\ge 30\%$, `Critical Fatigue` $< 30\%$).
  - **Database Persistence & Multi-Tenancy**:
    - Table `alert_suppression_rules` with strict `organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`.
    - New columns on `alerts`: `fingerprint`, `duplicate_count`, `last_seen_at`, `group_id`, `entity_type`, `entity_id`, `is_suppressed`.
  - **Detection Engine Integration**:
    - Integrated into `core/app/services/detection_engine.py` (`evaluate_event_stream`).
    - Skips duplicate incident creation and duplicate outbound containment actions when candidate alerts are deduplicated or suppressed.
  - **REST API (`/api/alerts/quality/*`)**:
    - `GET /api/alerts/quality/metrics`: Tenant SOC alert fatigue metrics and health grades.
    - `GET /api/alerts/quality/suppressions`: List active unexpired suppression windows.
    - `POST /api/alerts/quality/suppressions`: Create maintenance/testing suppression rule (Analyst/Admin).
    - `DELETE /api/alerts/quality/suppressions/<id>`: Early revocation of suppression rule.
    - `POST /api/alerts/quality/evaluate`: Candidate alert evaluation (dedupe/suppress/group dry-run).
  - Verified with Part 25 test suite (`core/tests/test_part25_alert_quality.py`) with 10/10 tests passing and zero regressions across detection engine test suites.

---

## ADR-032: Safe Response Modes, Guardrails Engine, and Declarative Playbooks (Phase 4.1, 4.2, 4.3)

* **Context**:
  - Financial and critical infrastructure operators in Ethiopia cannot risk automated containment actions accidentally disrupting interbank settlement rails (EthSwitch, RTGS), legitimate high-value commercial transfers, or administrative operations.
  - Automation must be safe, explainable, progressive, and reversible.
  - Phase 4.1, 4.2, and 4.3 establish the safe automation pillar:
    1. Progressive response modes per action type and tenant (`observe`, `recommend`, `approve`, `auto`).
    2. Comprehensive safety guardrails (Kill Switch, Allowlists, Blast Radius Rate Limits, Cooldowns, Confidence thresholds).
    3. Declarative playbooks with dry-run capabilities and response connector control contracts with idempotent rollback.

* **Decision**:
  - **Phase 4.1: Response Modes (`core/app/services/response_modes_service.py`)**:
    - Progressive risk postures: `observe` (shadow) $\to$ `recommend` $\to$ `approve` $\to$ `auto`.
    - Default posture: new tenants start in `observe` (shadow) mode for $\ge 14$ days, producing simulated "would-have-done" reports without dispatching real mutations against target systems.
    - Per-action-type and per-tenant mode overrides stored in `tenant_response_modes` table (`organization_id UUID NOT NULL`).
    - Compiles shadow observation reports (`generate_would_have_done_report`) showing what actions ECS would have executed.
  - **Phase 4.2: Guardrails Engine (`core/app/services/guardrails_service.py`)**:
    - **Emergency Kill Switch**: Per-tenant toggle instantly halts all automated containment operations with audited rejection.
    - **Allowlists & Protected Entities**: Protects critical national infrastructure IPs (e.g. EthSwitch gateway, RTGS routers) and VIP/staff accounts (`tenant_allowlists`). Actions targeting allowlisted entities are strictly blocked.
    - **Blast Radius Rate Limits**: Enforces sliding-window action rate limits (default: 20 actions/hour, 100 actions/day per tenant). Excess actions are blocked and audited.
    - **Entity Cooldowns**: Enforces a 15-minute lookback window (`cooldown_seconds = 900`) preventing repeat mitigations on the same entity.
    - **Confidence Threshold**: Minimum detection confidence posture (`high`, `medium`, `low`) required before auto-containment can execute.
    - **Audit Trail**: Every guardrail check is recorded to `guardrail_audit_log` with decision (`passed`, `blocked`) and reason.
  - **Phase 4.3: Declarative Playbooks & Response Connectors (`core/app/services/playbook_service.py`)**:
    - Declarative YAML playbooks stored in `core/app/playbooks/definitions/`:
      - `PB-001-ATO-CONTAINMENT`: Multi-step ATO containment (freeze transfer, revoke session, block IP).
      - `PB-002-MULE-FREEZE`: Mule syndicate containment (freeze transfer, disable beneficiary, lock account).
      - `PB-003-CRED-STUFFING`: Credential stuffing & spray defense (block IP, enforce step-up).
      - `PB-004-INSIDER-EXFIL`: Insider threat mitigation (revoke admin session, require step-up, emergency lock).
    - **Response Connectors Control Contract**: Standardized contract defining `is_reversible`, `rollback_connector`, `requires_approval_if_irreversible`, and `supported_entities` across all controls (`freeze_transaction`, `revoke_session`, `block_ip`, `require_step_up`, `disable_beneficiary`, `lock_account`, `revert`).
    - **Dry-Run Simulation Engine**: Evaluates triggers, guardrails, and modes returning simulated execution traces without mutations (`dry_run=True`).
    - **Dual-Custody / Two-Person Approval**: Risky operations (`lock_account`) stage in `action_approvals` requiring two distinct authorized approvers.
    - **Idempotent Rollback**: Revert connector (`revert_target_action`) rolls back previously dispatched reversible actions.
  - **REST API Routes (`core/app/routes/response.py`)**:
    - `/api/response/modes`, `/api/response/modes/would-have-done`
    - `/api/response/guardrails`, `/api/response/guardrails/kill-switch`, `/api/response/guardrails/allowlist`, `/api/response/guardrails/logs`
    - `/api/response/playbooks`, `/api/response/playbooks/<id>/dry-run`, `/api/response/connectors`, `/api/response/approvals`, `/api/response/actions/<id>/rollback`
  - **Integration & Verification**:
    - Integrated with `response_policy.py` (`evaluate_and_execute_containment`).
    - Verified with 13/13 tests passing in `core/tests/test_part26_safe_response_modes_and_guardrails.py` and zero regressions across existing test suites (`test_part5_controlled_response.py`, `test_automated_pipeline.py`, `test_part25_alert_quality.py`).

---

## ADR-033: Case Management, Multi-Channel Notifications, Analyst Feedback Loop, and Post-Incident Reviews (Phases 4.4, 4.5, 4.6, 4.7)

* **Context**:
  - Security Operations Centers (SOCs) in Ethiopian financial institutions and critical infrastructure need comprehensive operational incident handling following detection:
    1. Incident Case Management (Phase 4.4): Formal case tracking, stage-based SLA timers (TTA, TTC, TTR), assignment history, collaborative analyst notes, SHA-256 evidence attachments, cross-time entity timelines, related-alert attack graphs, and cross-time telemetry searches.
    2. Multi-Channel Notifications (Phase 4.5): Real-time alerting across Telegram, SMS, Email, and signed Webhooks; privacy-preserving data minimization (zero PII in messages); local Addis Ababa timezone quiet hours with critical severity override; and automated SLA escalation alerts.
    3. Analyst Feedback Loop (Phase 4.6): Triage verdicts (TP, FP, benign positive, test), precision and False Positive Rate (FPR) tracking, automated rule tuning warnings (FPR >= 25%), and 1-click suppression rule generation from recurring FP invariants.
    4. Post-Incident Review (PIR) Template (Phase 4.7): Automated compilation of executive post-incident reports with operational metrics, ETB financial impact, regulatory mapping (INSA Proc. 1426/2026, NBE Directives, PDPP Proc. 1321/2024), 5 Whys root cause analysis, bilingual summaries (Amharic and English), and cryptographic SHA-256 evidence sealing.

* **Decision**:
  - **Phase 4.4: Case Management (`core/app/services/case_service.py`, `core/app/routes/cases.py`)**:
    - **SLA Engine**: Dynamically computes response (TTA), containment (TTC), and resolution (TTR) milestone adherence by severity (`critical`: 15m/60m/240m; `high`: 30m/240m/720m; `medium`: 120m/720m/1440m; `low`: 480m/1440m/2880m). Tracks SLA health (`on_track`, `at_risk`, `breached`, `met`).
    - **Milestones**: Status transitions automatically record `acknowledged_at` (on investigating), `contained_at` (on contained), and `resolved_at` (on resolved/closed).
    - **Case Notes & Attachments**: Scoped by `organization_id UUID NOT NULL` in `case_notes` and `case_attachments` tables. Every attachment is cryptographically hash-sealed with SHA-256 and verified for tamper resistance.
    - **Cross-Time Entity Timeline & Graph**: Aggregates security events, alerts, incidents, and response mitigations for an account/IP/device across time into a unified chronological feed and node/edge graph.
    - **Saved Searches**: Stores user and shared search queries in `saved_searches` table with multi-parameter event querying.
  - **Phase 4.5: Multi-Channel Notifications (`core/app/services/notification_service.py`, `core/app/routes/notifications.py`)**:
    - **Envelope Encryption**: Sensitive connector credentials (`bot_token`, `webhook_secret`, `smtp_password`, `sms_api_key`) are envelope-encrypted with AES-256-GCM (`crypto_service.encrypt_secret`) and stored in `tenant_notification_configs`. Raw secrets are masked in API outputs (`enc:***MASKED***`).
    - **Privacy Preservation & Redaction**: All notifications strictly redact sensitive customer PII (`ACC-***1234`, `196.188.***.***`, `+25191****56`, `[MASKED_NATIONAL_ID]`, `[REDACTED_SECRET]`).
    - **Severity Routing & Quiet Hours**: Messages routed by minimum severity threshold. Quiet hours enforced in East Africa Time (`Africa/Addis_Ababa`, UTC+3) with critical incident override.
    - **Outbound Webhook Signatures**: Outbound payloads signed with HMAC-SHA256 (`X-ECS-Signature: sha256=<hex>`) and timestamped.
    - **SLA Breach Escalation Watchdog**: Automatically identifies active incidents reaching >= 50% of response SLA target or breached, dispatching urgent escalation alerts.
  - **Phase 4.6: Analyst Feedback Loop (`core/app/services/analyst_feedback_service.py`, `core/app/routes/feedback.py`)**:
    - **Triage Feedback**: Captures verdicts (`true_positive`, `false_positive`, `benign_positive`, `test`) in `rule_feedback` table.
    - **Rule Tuning Statistics**: Aggregates precision and False Positive Rate (FPR) per rule. Triggers automated warning when FPR >= 25% recommending parameter adjustments or shadow mode.
    - **Automated Suppression Suggestions**: Analyzes recurring false-positive invariants (e.g. repeated benign internal IPs or batch accounts) and generates 1-click suppression rule suggestions (`AlertQualityService.create_suppression_rule`).
  - **Phase 4.7: Post-Incident Review & Evidence Sealing (`core/app/services/pir_service.py`, `core/app/routes/pir.py`)**:
    - **Auto-Compilation**: Auto-gathers incident telemetry, operational metrics (TTD, TTA, TTC, TTR, SLA grade), and financial impact in ETB (amount at risk, intercepted/saved, net loss).
    - **Regulatory Evidence Register**: Maps incident evidence to INSA Proclamation No. 1426/2026, NBE Cyber Resilience Directives, and PDPP Proclamation No. 1321/2024 ("Supports Evidence For Compliance").
    - **Root Cause & Lessons Learned**: Generates 5 Whys analysis and actionable rule-tuning tasks.
    - **Bilingual Summaries**: Generates executive summaries in both Amharic and English.
    - **Cryptographic Sealing**: Computes canonical SHA-256 seal locking the PIR document against any future tampering. Verification endpoint validates seal integrity.
    - **Report Export**: Exports complete executive Markdown reports.

* **Consequences**:
  - Completes Phase 4.4, 4.5, 4.6, and 4.7 of the ECS platform roadmap.
  - Verified with 12/12 passing tests in `core/tests/test_part27_case_management_notifications_feedback_pir.py` with zero regressions across Phase 4.1-4.3 (`test_part26`) and Phase 3.7 (`test_part25`).

---

## ADR-034: Incident Readiness Engine, 48-Hour Statutory Clock, Evidence Vault, and Compliance Assistance (Phase 5)

* **Context**:
  - Ethiopian critical infrastructure operators (banks, payment system operators, telecommunications, energy) face strict regulatory reporting obligations under Proclamation No. 1426/2026 (Part 4 §18: mandatory reporting to National CERT within 48 hours of detection), National Bank of Ethiopia (NBE) Financial Cyber Resilience Directives, and PDPP Proclamation No. 1321/2024.
  - Without automated readiness tooling, manual forensic collation takes days, breaching statutory 48-hour deadlines and risking administrative penalties.
  - Architectural mandates require tamper-evident evidence, bilingual reporting (Amharic & English), privacy preservation, and strict non-overclaiming ("supports evidence for", never "guarantees compliance").

* **Decision**:
  - **Phase 5.1: Reportable-Incident Classification (`core/app/services/readiness_service.py`, `core/app/routes/readiness.py`)**:
    - Evaluates statutory triggers: critical severity / risk $\ge 75$, ransomware / ATO, ETB financial exposure $\ge 50,000$ ETB, customer data exposure $\ge 100$ records (PDPP Art. 31), or interbank settlement / EthSwitch / RTGS involvement.
    - Explicit detection timestamp anchor (`detection_date`) locked at detection time; human-in-the-loop confirmation step (`confirm_reportable_status`) records certifying officer attestation.
  - **Phase 5.2: The 48-Hour Statutory Clock Engine**:
    - Calculates real-time countdown in East Africa Time (`Africa/Addis_Ababa`, UTC+3).
    - Milestone stages: `green` (0-24h), `yellow_warning` (24-36h), `amber_warning` (36-44h), `red_critical` (44-48h), and `breached` (>48h).
    - Escalation watchdog (`check_48h_clock_escalations`) dispatches statutory warnings via `NotificationService`.
    - EthioCERT submission recording (`record_cert_submission`) halts the clock as `submitted_on_time`.
  - **Phase 5.3: Submission-Ready EthioCERT / INSA Package (`ECS-IRS-v1.0`)**:
    - Compiles standard statutory JSON (`incident_report_v1.0.json`) conforming to `docs/INCIDENT_REPORT_FALLBACK_SPEC.md`.
    - Generates unique statutory reference: `ECS-REP-YYYYMMDD-<short_id>`.
    - Generates mandatory bilingual executive summaries (English technical narrative & Amharic official declaration: `በአዋጅ ቁጥር 1426/2026 መሰረት የቀረበ የ48 ሰዓት የሳይበር ደህንነት ክስተት ሪፖርት`).
  - **Phase 5.4: Tamper-Evident Evidence Vault & Chain of Custody**:
    - Creates immutable snapshots in `evidence_vaults` table with 10-year retention (`retention_days=3650`).
    - Triple SHA-256 cryptographic sealing: `telemetry_sha256_digest` (ordered raw events), `audit_trail_sha256_digest` (hash-chained audit logs), and composite `manifest_sha256`.
    - Chain-of-custody log in `evidence_chain_of_custody` tracking all creation, verification, export, and submission events.
  - **Phase 5.5: Statutory Obligation Register & Compliance Support Guide**:
    - Versioned register in `regulatory_obligations` mapping ECS capabilities to INSA Proc. 1426/2026 (§18, §19, §20), NBE Directives (§6, §8), and PDPP 1321/2024 (§31, §32).
    - Strictly labels status as `"supports_evidence_for"`, `"partially_supported"`, or `"not_covered"` — NEVER `"compliant"` or `"guarantees compliance"`.
    - Published comprehensive guide: `docs/COMPLIANCE_SUPPORT.md`.
  - **Phase 5.6: One-Click Sealed Audit Pack**:
    - All-in-one sealed regulatory audit package (`generate_audit_pack`) bundling policy, statutory mapping, breach logs, vault manifests, and SHA-256 seal.
  - **Phase 5.7 & 5.8: Auditor Role & Data Protection Controls**:
    - Read-only `auditor` role with inspection access to vaults, 48h clock, and audit packs without mutation privileges.
    - PII minimization and privacy scrubbing on all exported telemetry.

* **Consequences**:
  - Completes Phase 5 of the ECS platform roadmap.
  - Verified with 9/9 passing tests in `core/tests/test_part28_incident_readiness_48h_vault.py` with zero regressions across Phase 4 suites (`test_part27`, `test_part26`).

---

## ADR-035: Community Defense, Privacy-Preserving Keyed Hashing, Anti-Poisoning Corroboration, and STIX 2.1 Exchange (Phase 6)

* **Context**:
  - Cyber fraud syndicates and advanced threat actors operate across multiple Ethiopian financial operators and infrastructure sectors simultaneously (e.g., mule account rings routing stolen funds across CBE, Dashen, Awash, and telebirr).
  - Exchanging raw indicators directly risks exposing sensitive customer PII, account numbers, and balances, violating PDPP Proclamation No. 1321/2024 and banking secrecy rules.
  - Furthermore, untrusted community feeds introduce "signal poisoning" risks where false indicators could cause catastrophic automated denial of service against legitimate counterparties or critical infrastructure.
  - Phase 6 builds the long-term defensive moat through privacy-preserving signal exchange, anti-poisoning corroboration, and national EthioCERT STIX 2.1 interoperability.

* **Decision**:
  - **Phase 6.1: Signal Schema, Keyed Hashing & TLP Policy (`core/app/services/signal_exchange_service.py`, `core/app/routes/signals.py`)**:
    - **Keyed Hashing**: Customer accounts, phone numbers, and mule IDs are hashed using HMAC-SHA256 with an offline hub salt (`HUB_PEPPER`). Raw PII is mathematically irrecoverable across tenant boundaries. Public network observables (IP, domain) remain plain for firewall/WAF matching.
    - **Traffic Light Protocol (TLP)**: Enforces `TLP:CLEAR/WHITE`, `TLP:GREEN`, `TLP:AMBER`, and `TLP:RED`. `TLP:RED` is strictly local and rejected from community egress.
    - **Sharing Preferences & Consent**: Stored in `tenant_sharing_preferences` table. Strict opt-in check enforced before any signal contribution.
  - **Phase 6.2: Anti-Poisoning & Corroboration Engine**:
    - **Reporter Reputation Scoring**: Tracks participant credibility (0.00 to 1.00) in `reporter_reputations` table. Increments on verified corroborations (+0.05); penalizes on retracted false positives (-0.20).
    - **Corroboration Threshold ($N \ge 2$)**: Single-contributor signals start as uncorroborated (`is_corroborated: false`). Corroboration requires independent observation by $\ge 2$ distinct licensed institutions.
    - **Non-Negotiable Safe Automation Rule**: Single-source uncorroborated signals produce ONLY advisory warnings (`IOC-COMMUNITY-ADVISORY`, 15 pts) and **NEVER** trigger automated blocking (`allow_automated_block: false`). Only corroborated signals or locally approved rules can trigger containment.
    - **Retraction & Dispute Flow**: Contributor or administrator can retract false signals (`retract_signal`), deprecating them network-wide.
  - **Phase 6.3: Hub Service & Anonymized Feed Consumption**:
    - Community feed endpoint (`/api/signals/feed`) anonymizes contributor identities (`HUB-ANONYMIZED-PARTICIPANT`) and filters by recipient permitted TLP levels.
    - Audit logging of all contributions, consumptions, and matches in `signal_exchange_audit`.
  - **Phase 6.4: Detection Engine Integration**:
    - Extends `IOC-001` with `COMMUNITY_CORROBORATED_IOC` and `COMMUNITY_UNVERIFIED_ADVISORY`.
    - Enables Gate 6 verification: an indicator contributed by Tenant A flags and prevents a seeded attack at Tenant B.
  - **Phase 6.5: EthioCERT STIX 2.1 Interoperability**:
    - Exports active signals as standardized OASIS STIX 2.1 JSON Bundles (`export_stix_bundle`) with indicators, patterns, and TLP markings.
    - Ingests official EthioCERT threat advisories (`import_cert_advisories`).
  - **Phase 6.6: Governance Charter & Privacy Impact Assessment (PIA)**:
    - Published [`docs/SIGNAL_EXCHANGE_GOVERNANCE.md`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/docs/SIGNAL_EXCHANGE_GOVERNANCE.md) establishing consortium terms, data-handling charter, takedown process, and PIA.
  - **Phase 6.7: Network Effect Dashboard**:
    - Metrics endpoint (`/api/signals/metrics`) tracking signals contributed, signals corroborated, and attacks prevented via community signals.

* **Consequences**:
  - Completes Phase 6 of the ECS platform roadmap.
  - Verified with 8/8 passing tests in `core/tests/test_part29_community_signal_exchange.py` with zero regressions across Phase 5 (`test_part28`), Phase 4 (`test_part27`, `test_part26`), and Phase 3 (`test_part25`).

---

## ADR-036: Product Editions, Feature Entitlements, Executive Metrics, Multilingual Localization, and Pilot Onboarding (Phase 7)

* **Context**:
  - Having completed core multi-tenant decoupling (Phases 1–3), safe response automation (Phase 4), the 48-hour statutory incident readiness engine (Phase 5), and community signal exchange (Phase 6), ECS required a clear product packaging, governance structure, and operational framework for go-to-market.
  - Target operators span independent fintech startups, small microfinance institutions (MFIs), large commercial banks, telecom operators, and national sector hubs (EthSwitch/INSA).
  - Furthermore, operational realities in Ethiopian critical infrastructure require:
    1. Clear edition boundaries (open-source Community vs commercial Pro vs Managed defense vs Sector Hub).
    2. Executive KPIs (MTTD, MTTA, MTTC, MTTR, total ETB protected, 48h compliance rate).
    3. Low-Bandwidth Mode (<1 KB compact telemetry) for regional branches operating over constrained 2G/3G and VSAT links.
    4. Multilingual cybersecurity terminology across English, Amharic (`አማርኛ`), and Afaan Oromo (`Afaan Oromoo`).
    5. Standardized 14-day progressive shadow-mode onboarding runbook.

* **Decision**:
  - **Phase 7.1: Editions & Feature Entitlements (`core/app/services/editions_service.py`, `core/app/routes/settings.py`)**:
    - Defines four distinct tiers:
      1. `community`: Free, self-hosted, Apache-2.0 open-source defense platform for startups and MFIs.
      2. `pro`: Commercial edition for licensed financial institutions, equipped with 48h readiness clock, evidence vault, safe automation, and advanced Ethiopian fraud packs.
      3. `managed`: Dedicated managed defense operations with monthly tuning reviews and facilitated tabletop drills.
      4. `sector_hub`: Multi-tenant signal exchange hub and consortium governance platform for EthSwitch, INSA, and banking associations.
    - Feature gating (`is_feature_enabled`) strictly isolates tenant capabilities based on active edition.
    - Endpoints: `GET /api/settings/editions`, `PUT /api/settings/editions`.
  - **Phase 7.2: Open-Source Governance & Legal Assets**:
    - Standard Apache-2.0 `LICENSE` at repository root.
    - `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` establishing engineering standards and community pledge.
    - `docs/ROADMAP.md` mapping v3.0 release through future HSM and air-gapped SCADA horizons.
    - `docs/SUPPORT_MODEL.md` establishing clear SLA tiers, emergency escalation paths, and explicit Rule #6 disclaimers (no automatic 24/7 SOC guarantee, tools *"support evidence for"* compliance).
  - **Phase 7.3: Executive & Operational Metrics (`core/app/services/metrics_service.py`, `core/app/routes/dashboard.py`)**:
    - Computes real-time MTTD, MTTA, MTTC, MTTR in minutes.
    - Calculates total ETB financial volume protected across blocked transactions and contained incident assets.
    - Evaluates 48-hour statutory compliance adherence percentage under INSA Proclamation No. 1426/2026.
    - Measures alert fatigue reduction and noise suppression percentage.
    - **Low-Bandwidth Mode**: Endpoint `GET /api/dashboard/executive?low_bandwidth=true` returns a compact numeric summary payload under 1,024 bytes (<1 KB) for rural banking branches.
  - **Phase 7.4: Multilingual Terminology Service (`core/app/services/i18n_service.py`)**:
    - Localized glossary supporting English (`en`), Amharic (`am`), and Afaan Oromo (`om`).
    - Standardizes terminology for Account Takeover (`የሂሳብ ቁጥጥር ስርቆት` / `Herrega Dhuunfaa Qabachuu`), Evidence Vault (`የማስረጃ ማከማቻ` / `Kuusaa Ragaa`), Emergency Kill Switch (`የአደጋ ጊዜ ድንገተኛ ማቆሚያ` / `Cufaa Balaa Hatattamaa`), etc.
    - Endpoint: `GET /api/settings/i18n`.
  - **Phase 7.5: Operations Runbook & 14-Day Pilot Onboarding Protocol**:
    - `docs/OPERATIONS_RUNBOOK.md`: Docker Compose deployment, backup/restore, emergency kill switch activation, and security hardening checklist.
    - `docs/PILOT_ONBOARDING.md`: 14-day progressive shadow-mode protocol (`observe` $\to$ `recommend` $\to$ reversibility test $\to$ 48h drill $\to$ sign-off).

* **Consequences**:
  - Completes Phase 7 of the ECS platform roadmap, concluding the planned v3.0 Independent Platform transformation.
  - Verified with 10/10 passing tests in `core/tests/test_part30_productization_editions_and_operations.py` with zero regressions across Phase 6 (`test_part29`), Phase 5 (`test_part28`), and Phase 4 (`test_part27`, `test_part26`).

















