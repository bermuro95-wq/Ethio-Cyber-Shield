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














