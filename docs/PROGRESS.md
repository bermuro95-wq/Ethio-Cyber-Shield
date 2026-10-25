# Ethio-Cyber-Shield (ECS) v3.0 — Platform Execution Progress Tracker

> **Repository**: `Ethio-Cyber-Shield`  
> **Active Branch**: `v3-independent`  
> **Baseline Release Tag**: `ecs-v2.0`  
> **Last Updated**: October 2026  

---

## Overall Roadmap Status

| Phase | Description | Status | Progress | Target Gate |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 0** | **Validate, Obtain Texts, Freeze Scope** | **COMPLETED** | **100%** | **Gate 0 PASSED** |
| **Phase 1** | **Independence, Tenancy & Hardening** | **COMPLETED** | **100%** | **Gate 1 PASSED** |
| **Phase 2** | **Connectors, SDKs & Rich Event Model** | **COMPLETED** | **100%** | **Gate 2 PASSED** |


| **Phase 3** | **Detection Engine v2 (Rules-as-Data)** | **COMPLETED** | **100%** | **Gate 3 PASSED** |
| **Phase 4** | **Safe Response & Case Management** | **COMPLETED** | **100%** | **Gate 4 PASSED** |
| **Phase 5** | **Incident Readiness Engine (48h Clock)** | **COMPLETED** | **100%** | **Gate 5 PASSED** |
| **Phase 6** | **Community Defense (Signal Exchange)** | **COMPLETED** | **100%** | **Gate 6 PASSED** |
| **Phase 7** | **Productization, Packaging & GTM** | **COMPLETED** | **100%** | **Gate 7 PASSED** |
| **Phase 8** | **Selective Expansion** | **COMPLETED** | **100%** | **Gate 8 PASSED** |

---

## Detailed Phase Breakdown

### Phase 0: Validate, Obtain Texts, Freeze Scope (Completed)
- [x] **Primary Texts Analysis**: Analyzed Proclamation No. 1426/2026, NBE Directives, MFI/33/2022, and PDPP 1321/2024.
- [x] **Repository Restructuring Foundation**: Created `docs/` repository workspace; preserved `docs/EXECUTION_PLAN.md` and legacy reference `docs/ECS_LEGACY.md`.
- [x] **Baseline Git Tagging**: Tagged baseline commit as `ecs-v2.0` and branched active development to `v3-independent`.
- [x] **Engineering Rule Guidelines**: Published `AGENTS.md` and `GEMINI.md` establishing mandatory tenancy, secrets encryption, explainable detection, and safe response rules.
- [x] **Stakeholder Interview Protocol**: Formulated `docs/INTERVIEW_SCRIPT.md` targeting 12–15 cross-sector Ethiopian security and fraud leaders.
- [x] **Incident Reporting Fallback Standard**: Formulated `docs/INCIDENT_REPORT_FALLBACK_SPEC.md` providing a structured, bilingual, hash-sealed 48-hour incident package standard.
- [x] **Architecture Decisions & Scope Freeze**: Authored `docs/DECISIONS.md` formalizing ADR-001 through ADR-016, metrics targets, and non-goals.
- [x] **Validation Report**: Synthesized comprehensive findings in `docs/VALIDATION_REPORT.md`.
- [x] **Gate 0 Criteria**: 
  - [x] Focus wedge locked (G2 + G3 + G1).
  - [x] Fallback 48-hour report specification approved.
  - [x] 3 pilot partner candidate profiles established.

---

### Phase 1: Make ECS Independent (Completed)
- [x] **1.1 Repository restructure**: `core/`, `connectors/`, `sdk/`, `ui/`, `deploy/`, `docs/`, `labs/`.
- [x] **1.2 Tenancy**: Add `organization_id` to all tables; implement Postgres RLS schema; add tenant-scoped queries; author cross-tenant test suite (`test_part7_multi_tenancy_isolation.py`).
- [x] **1.3 Self-host stack**: Plain PostgreSQL 16 + Redis 7 in Docker Compose; direct psycopg2 database layer abstraction in `db.py`; `/api/health` diagnostics; backup/restore scripts; documented hardened install in `docs/DEPLOYMENT.md`.
- [x] **1.4 Durable ingest queue**: Redis Streams consumer queue with sliding-window support replacing in-memory ring buffer (`stream_service.py`, `test_part8_durable_stream.py`).
- [x] **1.5 Secrets encryption**: AES-256-GCM envelope encryption for target secret keys (`crypto_service.py`).
- [x] **1.6 Identity & RBAC**: TOTP MFA (pyotp), session revocation blacklist, 5-tier roles (`admin`, `analyst`, `responder`, `viewer`, `auditor`), and scoped API tokens (`test_part9_identity_mfa_rbac.py`).
- [x] **1.7 Tamper-evident audit**: Hash-chained audit logs with SHA-256 predecessor linking, integrity verification, and sealed anchor packages (`audit_service.py`, `test_part10_tamper_evident_audit.py`).
- [x] **1.8 CI/CD & Supply Chain**: Automated multi-version CI (`.github/workflows/ci.yml`), syntax verification, Bandit security scan, `SECURITY.md`, and `docs/THREAT_MODEL.md`.
- [x] **1.9 UI Modernization**: Role-aware navigation, organization selector, MFA flow, API token management, and audit verification UI.
- [x] **Gate 1 Criteria**:
  - [x] Clean machine self-host setup documented (<15 min).
  - [x] Cross-tenant isolation verified with automated tests (reads and writes denied).
  - [x] ECS survives restart with durable Redis stream queuing.
  - [x] ShieldBank decoupled as an external demo lab under `labs/shieldbank`.

---

### Phase 2: Connectors, SDKs and a Richer Event Model (Completed)
- [x] **2.1 ECS Event Contract v1.1**: OpenAPI 3.1 (`docs/contracts/ecs-event-contract-v1.1.yaml`) + JSON Schema (`docs/contracts/ecs-event-v1.1.schema.json`) specifications extending canonical events with channel awareness (`channel`, `payment_rail`, `counterparty_ref_hash`, `device_fingerprint`, `msisdn_hash`, `agent_id`, `national_id_hash`, `locale_tz`), dynamic Ethiopian brand-to-rail mapping, automatic PII scrubbing/hashing, and runtime schema endpoint (`GET /api/events/contract`).
- [x] **2.2 Official Client SDKs**: Python (`sdk/python/outbox.py`, `sdk/python/middleware.py`), Node.js (`sdk/node/outbox.ts`, `sdk/node/middleware.ts`), and PHP/Laravel (`sdk/php/src/TransactionalOutbox.php`, `sdk/php/src/Laravel/ECSMiddleware.php`) with persistent Transactional Outbox pattern (exponential backoff retry, dead-letter escalation, HMAC signing, zero PII leakage) and `docs/INTEGRATION_GUIDE.md`.
- [x] **2.3 Generic Webhook Receiver & Field Mapper**: Configurable JSONPath mapping engine (`app.services.field_mapper`), token/HMAC-SHA256 signature verification, interactive test-with-sample diagnostic runner (`POST /api/webhooks/test-mapping`), envelope encryption of webhook credentials, and public inbound receiver (`POST /api/webhooks/inbound/<source_id>`).
- [x] **2.4 Log Agent Collector**: Lightweight access/syslog/CEF collector (`connectors/log_agent/`), continuous file tailing with state checkpointing, bounded CPU/RAM guardrails, SHA-256 evidence sealing, interactive preview endpoint (`POST /api/log-agent/parse`), and standalone CLI daemon.
- [x] **2.5 Enrichment Service**: Offline-first GeoIP/ASN network registry with Ethiopian telecom CIDRs (`app.services.enrichment_service`), Tor/VPN/hosting flags, Threat Intelligence cache layer, behavioral device reputation scoring, and REST API endpoints (`/api/enrichment/ip`, `/api/enrichment/device`, `/api/enrichment/event`).
- [x] **2.6 Unified Entity Graph**: Real-time entity model and linkage engine (`entities` and `entity_links` in PostgreSQL / `app.services.entity_graph_service`), multi-hop breadth-first graph traversal, shared entity fraud detection (credential stuffing, mule rings), transitive risk propagation, and REST API routes (`/api/entities/`).
- [x] **2.7 Health & Data-Quality Monitor**: Silent-source anomaly alerts (progressive warning/critical tiers, 15m threshold, tenant-level silence detection), schema-violation tracking with sensitive field redaction, 24h/1h throughput telemetry, explainable composite Data Quality Score (0–100, Grade A–F) based on compliance, vitality, and richness, and REST API endpoints (`/api/health/quality/*`).
- [x] **2.8 Multi-Target Connector Schedulers**: Per-connector independent scheduling with custom intervals and backoff parameters (`app.services.connector_scheduler_service`), non-blocking concurrent polling via thread pool, exponential backoff with jitter on target/network failures, rapid recovery, and REST API routes (`/api/connectors/schedulers/*`).
- [x] **Gate 2 Criteria**:
  - [x] A developer unfamiliar with ECS integrates a sample app in ≤1 day (`docs/INTEGRATION_GUIDE.md`, three SDKs with outbox pattern).
  - [x] Schema validation rejects malformed events safely without system crashes (`event_contract.py`, `data_quality_service.py`).
  - [x] ShieldBank runs as just another decoupled connector target.

---

## Phase 3 — Detection Engine v2: configurable, measurable, locally relevant (COMPLETED)

- [x] **3.1 Rules as Data & Declarative Engine**: Sigma-inspired YAML/JSON rule schema (`core/app/rules/definitions/*.yaml`) with versioning, ATT&CK tags, Ethiopian contextual fields, and parameter thresholds. All 11 core detection rules across L1-L3 migrated to declarative packs. Declarative parser & evaluator (`core/app/services/rule_engine_service.py`) supporting dynamic loading, lifecycle states (`live`, `shadow`, `draft`, `backtest`), and per-tenant threshold overrides (`tenant_rule_overrides` table in PostgreSQL with `organization_id UUID NOT NULL`). Shadow mode produces audit detections without alerting or automated mitigations. Integrated directly into `detection_engine.py` (`evaluate_event_stream`). REST API endpoints for rule management and tenant overrides (`/api/rules/*`).
- [x] **3.2 Rule Lifecycle Tooling**: Historical event backtesting engine over sliding windows (default 7 days) and dry-run "what would have fired" preview without persistent mutations (`app.services.rule_lifecycle_service`). State machine enforcement (`draft` -> `backtest` -> `shadow` -> `live`) with mandatory backtest verification before promotion and tamper-evident audit history (`rule_lifecycle_history`, `rule_backtest_runs`). Analyst feedback capture (`rule_feedback`) calculating precision and false-positive rates with automated tuning warnings (FPR ≥ 25%) and shadow mode promotion recommendations. Full REST API coverage (`/api/rules/<id>/backtest`, `/preview`, `/lifecycle`, `/feedback`, `/metrics`, `/metrics/summary`).
- [x] **3.3 Rule Packs**: Specialized Fraud & Payments Pack (12 rules including mule accounts, rapid beneficiary add + transfer, SIM-swap, structuring under reporting limits, USSD/agent abuse bursts, coached APP transfers, impossible travel velocity), Web/API Pack (9 rules including credential stuffing, password spray, IDOR enumeration, bearer token replay, bot/scanner probes, rate limit evasion), and Insider/Admin Pack (6 rules including mass customer data export, dormant admin activation, off-hours privileged config actions, unauthorized role elevation, audit trail tampering). 27 total declarative rules exceeding the ≥ 25 rule gate requirement with multi-pack evaluation, per-tenant threshold overrides, and REST API pack filtering (`/api/rules?pack=<pack_name>`).
- [x] **3.4 Behavioral Baselines**: Explainable per-entity statistical baselines over sliding lookback windows (amounts, operating hours in Addis Ababa EAT, known client devices, geos/channels). Plain human-readable explanations ("amount is 9.0× this account's 90-day median (20,000 ETB)") with deviation scores. Deterministic fallback to standard policy rules when history is thin (< 5 events) preventing statistical alert fatigue. Scoped by `organization_id UUID NOT NULL` in `entity_behavioral_baselines` PostgreSQL table. Integrated into `evaluate_event_stream` scoring and evidence breakdown, with full REST API (`/api/baselines/*`).
- [x] **3.5 Risk Model v2**: Explainable additive 0-100 model incorporating rule confidence factors (`high`=1.0, `medium`=0.85, `low`=0.70), entity criticality tiers (`critical` 1.4x +15 pts, `high` 1.2x +8 pts, `medium` 1.0x, `low` 0.9x) with keyword auto-inference for Ethiopian critical infrastructure (EthSwitch, Core Banking, Treasury reserves, RTGS), zero-baseline false-alarm protection, temporal recency decay over sliding windows (0-15m, 1h, 6h, 24h, >24h), and deterministic severity rationales. Explicit Non-Probability Declaration across all outputs ("Deterministic operational risk priority index (0–100); NOT a statistical probability of guilt or fraud"). Scoped by `organization_id UUID NOT NULL` in `entity_criticality` PostgreSQL table. Integrated into `evaluate_event_stream` and full REST API (`/api/risk/*`).
- [x] **3.6 Benchmark Corpus + CI**: Labeled synthetic benchmark corpus (`core/app/benchmark/corpus.py`) pairing ground-truth assertions with canonical events across 16 scenarios. Attack Lab Scenario Library (`core/app/benchmark/scenarios.py`) featuring 13 distinct attack scenarios across Fraud & Payments (ATO, mule rings, SIM-swap, structuring, USSD bursts, coached APP), Web & API Abuse (credential stuffing, IDOR enumeration, bot scanning, token replay), and Insider/Admin Threat (mass data exfiltration, audit tampering, dormant admin activation) plus 3 benign baselines (retail P2P, merchant QR, payroll credit). Automated precision/recall/FPR reporting engine (`BenchmarkService`) achieving **100.00% detection rate** on attack scenarios with **0.00% false positive rate** (exceeding Gate 3 requirements). Standalone CLI runner (`labs/run_benchmark.py`), full REST API (`/api/benchmark/*`), automated CI gate in `.github/workflows/ci.yml`, and comprehensive report in `docs/BENCHMARK_REPORT.md`.
- [x] **3.7 Alert Quality**: Deterministic SHA-256 alert fingerprinting over invariant incident attributes, sliding-window deduplication absorbing rapid bursts into single alerts with incremented `duplicate_count` and `last_seen_at`, dynamic risk score and severity escalation on higher-risk duplicates, time-based suppression windows (`alert_suppression_rules`) with automatic expiration and manual revocation, entity-centric correlation grouping (`group_id`), real-time alert fatigue reduction metrics (`alert_reduction_rate`, `fatigue_grade`), and detection engine integration (`core/app/services/alert_quality_service.py`, `core/app/routes/alert_quality.py`).
- [x] **Gate 3 Criteria (PASSED)**:
  - [x] Published precision/recall per pack on the corpus (`docs/BENCHMARK_REPORT.md`).
  - [x] ≥90% of pilot-seeded attack scenarios detected with stated false-positive rate (100.00% detection rate, 0.00% FPR).
  - [x] A rule change can be backtested and rolled out without a code deploy (`/api/rules/<id>/backtest`, `/api/rules/<id>/override`).
  - [x] Deduplication and suppression windows eliminate duplicate ticket floods and SOC fatigue.

---

## Phase 4 — Safe, trustworthy response and case management (COMPLETED)

- [x] **4.1 Response Modes per Action Type & Tenant**:
  - Implemented `core/app/services/response_modes_service.py` supporting progressive risk postures: `observe` (shadow) → `recommend` → `approve` (human-in-the-loop / two-person) → `auto`.
  - Default for new tenants is `observe` (shadow mode for ≥14 days) preventing accidental disruption. Default seeded production bank operates in `auto`.
  - Granular per-action overrides per tenant (e.g. `freeze_transaction` can be `auto`, while `lock_account` requires `approve`).
  - Action simulation engine (`dry_run` / `observe` status `simulated`) generating explainable 14-day shadow "would-have-done" reports (`/api/response/reports/would-have-done`).
  - Scoped by `organization_id UUID NOT NULL` in `tenant_response_modes` PostgreSQL table.

- [x] **4.2 Guardrails Engine**:
  - Implemented `core/app/services/guardrails_service.py` providing deterministic safety boundaries before any mitigation execution.
  - **Emergency Kill Switch**: Instant per-tenant automation cut-off (`set_kill_switch(tenant_id, enabled=True)`) stopping all automated mitigations immediately.
  - **Allowlists**: Dynamic allowlist for critical infrastructure, partner gateways (e.g., EthSwitch `196.188.10.1`, RTGS), core banking servers, and VIP/treasury accounts (`tenant_allowlists`). Any mitigation targeting an allowlisted entity is blocked.
  - **Blast Radius Rate Limits**: Configurable max actions per hour (default 20) and max actions per day (default 100) per tenant.
  - **Entity Cooldowns**: Cooldown enforcement (default 900 seconds) preventing repetitive hammering of the same account/IP.
  - **Confidence Thresholds**: Minimum rule confidence required for automated action execution (default 0.85).
  - **Guardrail Audit Logging**: Every guardrail evaluation and block is logged to `guardrail_audit_log` with tamper-evident evidence fields.

- [x] **4.3 Declarative Playbooks & Response Connectors**:
  - Declarative YAML playbook schema (`core/app/playbooks/definitions/*.yaml`):
    - `pb_001_ato_containment.yaml` (`PB-001-ATO-CONTAINMENT`): Multi-step ATO containment (`freeze_transaction`, `revoke_session`, `block_ip`).
    - `pb_002_mule_account_freeze.yaml` (`PB-002-MULE-FREEZE`): Mule syndicate containment (`freeze_transaction`, `disable_beneficiary`, `lock_account`).
    - `pb_003_credential_stuffing_defense.yaml` (`PB-003-CRED-STUFFING`): Credential spray defense (`block_ip`, `require_step_up`).
    - `pb_004_insider_data_exfiltration.yaml` (`PB-004-INSIDER-EXFIL`): Insider threat mitigation (`revoke_session`, `require_step_up`, `lock_account`).
  - **Standardized Response Connectors**: Unified control contracts in `core/app/services/playbook_service.py` for target operations: `freeze_transaction`, `revoke_session`, `block_ip`, `require_step_up`, `disable_beneficiary`, `lock_account`.
  - **Reversibility & Idempotent Rollback**: `rollback_action` / `revert_target_action` reversing actions or safely verifying idempotent undo state.
  - **Dry-run Simulation**: Simulation engine (`dry_run=True`) evaluating condition matching and connector actions without mutating target systems.
  - **Dual-Custody / Two-Person Approvals**: Risky action approval workflow (`action_approvals` table) requiring dual distinct analyst sign-offs before execution.
  - REST API routes (`/api/response/*`) for playbooks, approvals, modes, guardrails, allowlists, and execution logs.

- [x] **4.4 Case Management & SLA Engine**:
  - Implemented `core/app/services/case_service.py` and `core/app/routes/cases.py` (blueprint `/api/cases`).
  - **Dynamic SLA Timers**: Severity-based milestone targets (`critical`: TTA=15m, TTC=60m, TTR=240m; `high`: 30m/240m/720m; `medium`: 120m/720m/1440m; `low`: 480m/1440m/2880m). Real-time health evaluation (`on_track`, `at_risk`, `breached`, `met`).
  - **Milestone Recording**: Status transitions (`open` → `investigating` → `contained` → `resolved` → `closed`) automatically record `acknowledged_at`, `contained_at`, and `resolved_at`.
  - **Case Assignment & Notes**: Assignment tracking with audit logging; collaborative analyst case notes in `case_notes` table.
  - **SHA-256 Evidence Attachments**: Artifact upload and registration with cryptographic SHA-256 integrity verification (`case_attachments` table).
  - **Cross-Time Entity Timeline**: Unified query aggregating security events, alerts, incidents, and response actions for an account/IP/device across time.
  - **Related-Alert Graph**: Correlated case view linking incidents, alerts, indicators, entities, and actions into a visualization-ready graph.
  - **Saved Searches**: Tenant-scoped personal and shared search query storage in `saved_searches` table with cross-time event filtering.

- [x] **4.5 Multi-Channel Notifications & Escalation**:
  - Implemented `core/app/services/notification_service.py` and `core/app/routes/notifications.py` (blueprint `/api/notifications`).
  - **Multi-Channel Dispatch**: Telegram bot, Email, SMS Gateway, and signed outbound HTTP webhooks.
  - **Envelope Encryption**: AES-256-GCM encryption for bot tokens, webhook secrets, SMTP passwords, and SMS API keys stored in `tenant_notification_configs`. Masked display (`enc:***MASKED***`) prevents token leakage.
  - **Privacy Preservation**: Strict recursive PII scrubbing on all outgoing notification payloads (`ACC-***1234`, `196.188.***.***`, `+25191****56`, `[MASKED_NATIONAL_ID]`, `[REDACTED_SECRET]`).
  - **Severity Routing & Quiet Hours**: Minimum severity gating per channel. Addis Ababa local timezone (`Africa/Addis_Ababa`, UTC+3) quiet hours enforcement with critical severity override.
  - **Outbound Webhook Signatures**: Signed with HMAC-SHA256 (`X-ECS-Signature: sha256=...`) and timestamped.
  - **SLA Breach Escalation Watchdog**: Automated identification and high-priority escalation for incidents reaching >= 50% response SLA elapsed time without triage.

- [x] **4.6 Analyst Feedback Loop & Suppression Suggestions**:
  - Implemented `core/app/services/analyst_feedback_service.py` and `core/app/routes/feedback.py` (blueprint `/api/feedback`).
  - **Triage Feedback Capture**: Captures analyst verdicts (`true_positive`, `false_positive`, `benign_positive`, `test`) and reason categories (`benign_business_activity`, `rule_overly_broad`, `data_quality_issue`, `malicious_confirmed`, `authorized_testing`) in `rule_feedback` table.
  - **Rule Tuning Statistics**: Real-time aggregation of precision and False Positive Rate (FPR). Automated tuning warnings triggered when FPR >= 25% recommending threshold adjustments or shadow mode.
  - **Automated Suppression Suggestions**: Detects recurrent false-positive patterns on specific entities and auto-generates 1-click suppression rule suggestions (`AlertQualityService.create_suppression_rule`).

- [x] **4.7 Post-Incident Review (PIR) Template & Evidence Sealing**:
  - Implemented `core/app/services/pir_service.py` and `core/app/routes/pir.py` (blueprint `/api/pir`).
  - **Auto-Compilation**: Compiles formal PIRs for contained/resolved incidents extracting operational metrics (TTD, TTA, TTC, TTR, SLA grade) and ETB financial impact (amount at risk, intercepted/saved, net loss).
  - **Regulatory Evidence Mapping**: Maps incident chronology to INSA Proclamation No. 1426/2026, NBE Cyber Resilience Directives, and PDPP Proclamation No. 1321/2024 ("Supports Evidence For Compliance").
  - **Root Cause & Lessons Learned**: 5 Whys analysis, systemic/human factors, lessons learned, and actionable rule-tuning tasks.
  - **Bilingual Summaries**: Executive summaries in both Amharic (`የድህረ-ክስተት ግምገማ ሪፖርት`) and English.
  - **Cryptographic SHA-256 Sealing**: Finalized PIRs are locked with a canonical SHA-256 seal preventing subsequent tampering. Seal integrity verification endpoint.
  - **Markdown Export**: Complete bilingual executive report export.

- [x] **Gate 4 Criteria (PASSED)**:
  - [x] In shadow mode ECS produces a would-have-done report (`/api/response/reports/would-have-done`).
  - [x] No guardrail bypass in adversarial tests (Kill Switch, Allowlists, Rate Limits, Cooldowns, Confidence).
  - [x] Every automated action is reversible or explicitly marked irreversible and requires two-person approval.
  - [x] End-to-end case management with SLA timers, SHA-256 evidence sealing, multi-channel notifications, analyst feedback loop, and post-incident review.

---

## Phase 5 — Incident Readiness Engine: the 48-hour clock, evidence and compliance support (COMPLETED)

- [x] **5.1 Reportable-Incident Classification**:
  - Implemented `core/app/services/readiness_service.py` evaluating statutory criteria under Proclamation No. 1426/2026:
    - Critical severity or risk score $\ge 75$.
    - Statutory high-impact types: `ransomware`, `account_takeover`.
    - Exposure of national switch / interbank settlement / RTGS rails.
    - Financial volume exposed $\ge 50,000$ ETB.
    - Personal data breach $\ge 100$ records (PDPP Art. 31 trigger).
  - Explicit detection timestamp anchor (`detection_date`) locked at detection time.
  - Human-in-the-loop analyst confirmation step (`confirm_reportable_status`) recording certifying officer attestation.

- [x] **5.2 The 48-Hour Statutory Clock Engine**:
  - Exact countdown calculation in East Africa Time (`Africa/Addis_Ababa`, UTC+3).
  - Milestone stages: `green` (0-24h), `yellow_warning` (24-36h), `amber_warning` (36-44h), `red_critical` (44-48h), and `breached` (>48h).
  - Milestone escalation watchdog (`check_48h_clock_escalations`) dispatching statutory alerts via `NotificationService`.
  - EthioCERT submission recording (`record_cert_submission`) halting the clock on-time with verified reference numbers.

- [x] **5.3 Submission-Ready EthioCERT / INSA Package**:
  - Generates official `incident_report_v1.0.json` conforming strictly to `docs/INCIDENT_REPORT_FALLBACK_SPEC.md` (`ECS-IRS-v1.0`).
  - Standard statutory reference format: `ECS-REP-YYYYMMDD-<short_id>`.
  - Mandatory bilingual executive summaries: English technical narrative and Amharic official declaration (`በአዋጅ ቁጥር 1426/2026 መሰረት የቀረበ የ48 ሰዓት የሳይበር ደህንነት ክስተት ሪፖርት`).
  - Captures organization profile, statutory timeline, attack vector, MITRE ATT&CK techniques, impact assessment in ETB, indicators, containment actions, and certifying officer attestation.

- [x] **5.4 Evidence Vault & Cryptographic Sealing**:
  - Immutable snapshots in `evidence_vaults` table with 10-year retention (`retention_days=3650`).
  - Triple SHA-256 cryptographic sealing:
    - `telemetry_sha256_digest`: hash of all ordered raw security events.
    - `audit_trail_sha256_digest`: hash of associated hash-chained audit records.
    - `manifest_sha256`: composite hash seal over the complete snapshot package.
  - Verification endpoint (`verify_vault_integrity`) recomputes hashes and flags any post-incident tampering.
  - Chain-of-custody log in `evidence_chain_of_custody` tracking creation, verification, export, and submission events.

- [x] **5.5 Statutory Obligation Register & Compliance Support Guide**:
  - Versioned statutory mapping register in `regulatory_obligations` mapping ECS capabilities to:
    - INSA Proclamation No. 1426/2026 (§18, §19, §20).
    - NBE Cyber Resilience Directives (§6, §8).
    - PDPP Proclamation No. 1321/2024 (§31, §32).
  - Strict compliance with Non-Negotiable Rule #6 (No overclaiming): Statuses strictly labeled `"supports_evidence_for"`, `"partially_supported"`, or `"not_covered"` — never `"compliant"`.
  - Published comprehensive guide: `docs/COMPLIANCE_SUPPORT.md`.

- [x] **5.6 One-Click Sealed Audit Pack Bundle**:
  - Compiles an all-in-one sealed regulatory audit package (`generate_audit_pack`): organization profile, statutory mapping register, 48-hour incident breach log, evidence vault manifests, and composite SHA-256 seal.

- [x] **5.7 & 5.8 Auditor Read-Only Role & Data Protection Controls**:
  - Read-only `auditor` role with inspection access to vaults, 48h clock, and audit packs without mutation privileges.
  - Mandatory recursive PII minimization and privacy scrubbing on all exported telemetry.

- [x] **Gate 5 Criteria (PASSED)**:
  - [x] Complete regulatory report package generated in <2 hours from simulated attack.
  - [x] 48-hour clock, escalation milestones, and immutable evidence trail verified with automated tests.
  - [x] Legal wording strictly avoids compliance overclaims ("supports evidence for").
  - [x] Cryptographic SHA-256 manifest integrity verified; post-incident tampering detected.

---

## Phase 6 — Community Defense: privacy-preserving signal exchange (COMPLETED)

- [x] **6.1 Signal Schema, Keyed Hashing & TLP Policy**:
  - Implemented `core/app/services/signal_exchange_service.py` and `core/app/routes/signals.py` (blueprint `/api/signals`).
  - **Privacy-Preserving Keyed Hashing**: Customer accounts, phone numbers, and mule IDs are hashed using HMAC-SHA256 with an offline hub salt (`HUB_PEPPER`). Raw PII is mathematically irrecoverable across tenant boundaries. Public network observables (IP, domain) remain plain for firewall/WAF matching.
  - **Traffic Light Protocol (TLP)**: Enforces FIRST Standards TLP v2.0 (`CLEAR/WHITE`, `GREEN`, `AMBER`, `RED`). `TLP:RED` is strictly local and rejected from community egress.
  - **Sharing Preferences & Consent**: Stored in `tenant_sharing_preferences` table. Strict opt-in check enforced before any signal contribution.

- [x] **6.2 Anti-Poisoning & Corroboration Engine**:
  - **Reporter Reputation Scoring**: Tracks participant credibility (0.00 to 1.00) in `reporter_reputations` table. Increments on verified corroborations (+0.05); penalizes on retracted false positives (-0.20).
  - **Corroboration Threshold ($N \ge 2$)**: Single-contributor signals start as uncorroborated (`is_corroborated: false`). Corroboration requires independent observation by $\ge 2$ distinct licensed institutions.
  - **Non-Negotiable Safe Automation Rule**: Single-source uncorroborated signals produce ONLY advisory warnings (`IOC-COMMUNITY-ADVISORY`, 15 pts) and **NEVER** trigger automated blocking (`allow_automated_block: false`). Only corroborated signals or locally approved rules can trigger containment.
  - **Retraction & Dispute Flow**: Contributor or administrator can retract false signals (`retract_signal`), deprecating them network-wide.

- [x] **6.3 Hub Service & Anonymized Feed Consumption**:
  - Community feed endpoint (`/api/signals/feed`) anonymizes contributor identities (`HUB-ANONYMIZED-PARTICIPANT`) and filters by recipient permitted TLP levels.
  - Audit logging of all contributions, consumptions, and matches in `signal_exchange_audit`.

- [x] **6.4 Detection Engine Integration**:
  - Extends `IOC-001` with `COMMUNITY_CORROBORATED_IOC` and `COMMUNITY_UNVERIFIED_ADVISORY`.
  - Enables Gate 6 verification: an indicator contributed by Tenant A flags and prevents a seeded attack at Tenant B.

- [x] **6.5 EthioCERT STIX 2.1 Interoperability**:
  - Exports active signals as standardized OASIS STIX 2.1 JSON Bundles (`export_stix_bundle`) with indicators, patterns, and TLP markings.
  - Ingests official EthioCERT threat advisories (`import_cert_advisories`).

- [x] **6.6 Governance Charter & Privacy Impact Assessment (PIA)**:
  - Published `docs/SIGNAL_EXCHANGE_GOVERNANCE.md` establishing consortium terms, data-handling charter, takedown process, and PIA.

- [x] **6.7 Network Effect Dashboard**:
  - Metrics endpoint (`/api/signals/metrics`) tracking signals contributed, signals corroborated, and attacks prevented via community signals.

- [x] **Gate 6 Criteria (PASSED)**:
  - [x] Two or more tenants exchange signals end-to-end (`test_gate6_cross_tenant_prevention`).
  - [x] A signal from Tenant A flags and prevents a seeded attack at Tenant B.
  - [x] Anti-poisoning tests verify that single-source uncorroborated signals never trigger automated blocking.
  - [x] Privacy Impact Assessment (PIA) and keyed hashing verify zero raw-PII leakage.

---

### Phase 7: Productization, Packaging & Go-to-Market (Completed)
- [x] **7.1 Product Editions & Feature Entitlements (`editions_service.py`, `settings.py`)**:
  - Four distinct platform tiers: `community` (open-source Apache-2.0), `pro` (financial operator), `managed` (turnkey defense), and `sector_hub` (consortium signal exchange).
  - Feature gating (`is_feature_enabled`) strictly isolating tenant entitlements.
  - Endpoints: `GET /api/settings/editions`, `PUT /api/settings/editions`.

- [x] **7.2 Open-Source & Governance Assets**:
  - Apache-2.0 `LICENSE` at repository root.
  - `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` establishing engineering standards and community pledge.
  - `docs/ROADMAP.md` mapping v3.0 release through future HSM and air-gapped SCADA horizons.
  - `docs/SUPPORT_MODEL.md` establishing clear SLA tiers, emergency escalation paths, and explicit Rule #6 disclaimers (no automatic 24/7 SOC guarantee, tools *"support evidence for"* compliance).

- [x] **7.3 Executive & Operational Metrics (`metrics_service.py`, `dashboard.py`)**:
  - Real-time computation of MTTD, MTTA, MTTC, and MTTR in minutes.
  - Total ETB financial volume protected across blocked transactions and contained incident assets.
  - 48-Hour Statutory Compliance adherence rate under INSA Proclamation No. 1426/2026.
  - Alert fatigue reduction and noise suppression ratio.
  - **Low-Bandwidth Mode**: Endpoint `GET /api/dashboard/executive?low_bandwidth=true` returns a compact numeric summary payload under 1,024 bytes (<1 KB) for rural banking branches.

- [x] **7.4 Multilingual Cybersecurity Terminology Service (i18n) (`i18n_service.py`)**:
  - Localized dictionary supporting English (`en`), Amharic (`am`, አማርኛ), and Afaan Oromo (`om`, Afaan Oromoo).
  - Professional, culturally accurate terminology for Account Takeover (`የሂሳብ ቁጥጥር ስርቆት` / `Herrega Dhuunfaa Qabachuu`), Evidence Vault (`የማስረጃ ማከማቻ` / `Kuusaa Ragaa`), Emergency Kill Switch (`የአደጋ ጊዜ ድንገተኛ ማቆሚያ` / `Cufaa Balaa Hatattamaa`), etc.
  - Endpoint: `GET /api/settings/i18n`.

- [x] **7.5 Operations Runbook & 14-Day Pilot Onboarding Protocol**:
  - `docs/OPERATIONS_RUNBOOK.md`: Docker Compose deployment, backup/restore, emergency kill switch activation, and security hardening checklist.
  - `docs/PILOT_ONBOARDING.md`: 14-day progressive shadow-mode protocol (`observe` $\to$ `recommend` $\to$ reversibility test $\to$ 48h drill $\to$ sign-off).

- [x] **Gate 7 Criteria (PASSED)**:
  - [x] Four editions defined and gated (`community`, `pro`, `managed`, `sector_hub`).
  - [x] Standard open-source assets (`LICENSE` [Apache-2.0], `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`).
  - [x] Real-time executive metrics (MTTD, MTTA, MTTC, MTTR, total ETB protected, 48h statutory compliance rate, noise reduction).
  - [x] Low-bandwidth mode verified under 1 KB for rural branches.
  - [x] Multilingual cybersecurity terminology dictionary operational (`en`, `am`, `om`).
  - [x] Operations runbook and 14-day shadow onboarding protocol published.
  - [x] Test suite `test_part30_productization_editions_and_operations.py` 100% passing (10/10 tests).

---

### Phase 8: Selective Expansion (Completed)
- [x] **8.1 Explainable Multilingual Narratives (`narrative_service.py`, `narrative.py`)**:
  - Structured deterministic narrative generation (English, Amharic `አማርኛ`, Afaan Oromo `Afaan Oromoo`).
  - PII minimization & scrubbing before narrative synthesis.
  - Endpoints: `POST /api/narrative/incident/<id>`, `GET /api/narrative/incident/<id>`.

- [x] **8.2 Endpoint & Email Security Telemetry Adapters (`endpoint_email_adapter_service.py`, `telemetry_adapters.py`)**:
  - Ingestion of host-level Sysmon/Wazuh/Defender process executions.
  - Real-time detection of ransomware precursors (`vssadmin delete shadows`, `wbadmin delete catalog`, MITRE ATT&CK T1490).
  - Ingestion of email security headers, DMARC/SPF evaluation, and Business Email Compromise (BEC) C-Suite/VIP impersonation detection with wire urgency lures.
  - Endpoints: `POST /api/adapters/endpoint/ingest`, `POST /api/adapters/email/ingest`, `GET /api/adapters/events`.

- [x] **8.3 Exposure Management & Attack Surface Context (`exposure_service.py`, `exposure.py`)**:
  - External asset inventory (domains, FQDNs, IPs).
  - TLS/SSL certificate audits (validity, <14 days expiration, self-signed, deprecated TLS versions).
  - HTTP security header checks (HSTS, CSP, X-Frame-Options) and exposed public ports (22, 3389, 5432, 6379).
  - External exposure score calculation integrated directly into ECS transaction risk scoring.
  - Endpoints: `POST /api/exposure/assets`, `GET /api/exposure/assets`, `POST /api/exposure/assets/<id>/scan`.

- [x] **8.4 National Identity Assurance — Fayda Digital ID Adapter (`fayda_id_service.py`, `fayda.py`)**:
  - National digital ID integration under Ethiopian Proclamation No. 1284/2023.
  - Privacy-preserving keyed hashing of Fayda FIN (`fayda_fin_h_...`) to protect citizen privacy.
  - Biometric face/fingerprint verification yields high assurance (risk mitigation factor); presentation attack / deepfake spoof yields critical alert (+90 risk penalty).
  - Endpoints: `POST /api/fayda/verify`, `GET /api/fayda/account/<account_number>`.

- [x] **8.5 Regulator & Sector-Wide Telemetry Dashboard (`regulator_dashboard_service.py`, `regulator.py`)**:
  - Aggregated cross-institution threat posture across Commercial Banking, Microfinance, FinTech, and Telecom sectors.
  - Strict privacy: Strips all individual institutional names, account numbers, and customer PII.
  - Tracks sector-wide 48-hour statutory compliance adherence and total ETB protected volume.
  - Endpoint: `GET /api/regulator/sector-overview`.

- [x] **Gate 8 Criteria (PASSED)**:
  - [x] Multilingual narrative generator verified across English, Amharic, and Afaan Oromo with zero PII leakage.
  - [x] Endpoint adapter detects ransomware shadow deletion precursor (MITRE T1490).
  - [x] Email adapter detects BEC VIP impersonation and DMARC failures.
  - [x] External attack surface inventory and TLS/header audits feed exposure scores into ECS risk model.
  - [x] Fayda Digital ID adapter verifies biometric authentication and detects presentation spoofing attacks.
  - [x] Regulator sector overview provides cross-operator threat intelligence with verified zero bank identity leakage.
  - [x] Test suite `test_part31_selective_expansion.py` 100% passing (7/7 tests) and 59/59 regression tests passing.

---

### Platform Hardening & Operational Polish (ADR-032 & ADR-033)
- [x] **Thread-isolated DB clients**: `db.py` uses `threading.local()` to prevent HTTP/2 HPACK table collisions (`deque mutated during iteration`).
- [x] **Resilient poller**: Suppressed offline target connection refused noise; updated default target to `http://127.0.0.1:8081`; graceful in-memory health cache fallback.
- [x] **Supervisor process protection**: Poller daemon restricted to worker process under Flask debug reloader (`WERKZEUG_RUN_MAIN`).
- [x] **Telemetry-only UI enforcement**: Removed manual creation buttons and forms across `fraud.html`, `incidents.html`, and `indicators.html`.
- [x] **Concurrency verification**: Verified 20/20 concurrent REST requests succeed without error under active SSE threat stream.
- [x] **PostgREST Schema Compatibility (ADR-033)**: Sanitized database write payloads across `security_events`, `indicators`, `transactions`, `alerts`, `incidents`, and `audit_logs` to match remote schema cache; eliminated `PGRST204` errors.
- [x] **Check Constraint Normalization**: Normalized `alert_type` and `incident_type` to values permitted by database constraints (`alerts_alert_type_check` & `incidents_incident_type_check`).
- [x] **Total Seeded Data Purge**: Emptied all synthetic seeded rows in ECS database (0 rows in alerts, incidents, indicators, events, audit logs); preserved only `admin@ethiocybershield.et`.
- [x] **Target System Seed Removal**: Removed customer seed loop in `targetsys/src/integrations/supabase/local-store.ts` and customer quick-fill buttons in `routes/login.tsx`; preserved only `admin@shieldbank.test`.
- [x] **Target System Lab Page Removal**: Deleted `targetsys/src/routes/admin/lab.tsx` and `targetsys/src/lib/scenario.server.ts`; removed `/api/public/lab/run-scenario` route; updated navigation and routing tests (100% passing).
- [x] **Single-Device Admin Concurrency Enforcement (ADR-034)**:
  - Enforced single active device session per administrator in `auth_service.py` using per-user active `jti` tracking (`_ACTIVE_USER_SESSIONS`).
  - Superseded sessions are revoked immediately and return HTTP 401 Unauthorized (`Authentication required`).
  - Frontend `api.js` and `common.js` automatically redirect superseded tabs to `login.html?session_expired=concurrent`.
  - Automated test script verifies login from Device B terminates Device A immediately.
- [x] **Real-Time Explainable Attack Dossier & Instant SOC SSE Synchronization (ADR-035)**:
  - Built attack dossier synthesis engine in `enrichment_service.py` extracting MaxMind GeoIP origin, ISP/carrier (Ethio Telecom, Safaricom), ASN, proxy/Tor flags, threat intelligence reputation, client tool fingerprint (Burp Suite Pro, sqlmap, Nikto, cURL, Python, browsers), OS architecture, targeted banking assets, and SHA-256 evidence seals.
  - Broadcasts rich forensic dossiers directly across Server-Sent Events (`/api/live/stream`) and REST alert endpoints (`/api/alerts`, `/api/alerts/<id>/dossier`) with sub-millisecond memory caching (`_ALERT_DOSSIER_STORE`).
  - Integrated high-density **Attack Investigation Dossier Modal** into `dashboard.html` and `alerts.html` with real-time SSE DOM injection, sound effects, and row highlight animations.
  - Enabled one-click containment controls (`blockAttackerIp`, `revokeAttackerSession`, `freezeSuspiciousTransaction`, `revertAction`) with bidirectional HMAC-SHA256 signature verification and scoped access (`control:revert`).
  - Verified closed-loop mitigation and rollback with ShieldBank (`targetsys`) on port 8080.
  - Resolved multi-tenancy token isolation in `test_part7`, sequence persistence in `test_part2`, and cryptographic hash-chain envelope sealing in `test_part10`.
  - All test suites passing.






- [x] **HonorPay Mobile Banking & Branch Teller Portal (ADR-031)**:
  - Rebranded target application from "ShieldBank" to "HonorPay" with digital mobile banking aesthetics, ETB santim minor units, and Addis Ababa (UTC+3) formatting.
  - Built dedicated Employee / Branch Teller Portal (`/employee`) enabling bank staff to look up registered customers and credit cash deposits via double-entry ledger settlement (`CREDIT` customer account, `DEBIT` vault/settlement).
  - Implemented interactive real-time typing customer search autocomplete with floating dropdown in the Teller dashboard: typing any letters/characters instantly filters registered customers by name, 10-digit account number, phone, and email.
  - Added "Register Customer at Branch" functionality for branch tellers (`registerCustomerByTellerFn`): automatically creates customer profile with `must_change_password: true`, issues a 10-digit account starting with `1000...`, and upon successful creation, automatically redirects/switches to the Deposit Terminal with the new customer pre-selected and ready for initial deposit.
  - Enforced mandatory first-login password change (`CustomerShell` & `forceChangePasswordFn`): customers registered by branch tellers with temporary passwords must set a new private password before accessing their mobile banking dashboard or initiating transfers.
  - Enforced registered-only recipient restriction: customers can only transfer to registered HonorPay customer accounts with verified recipient lookup.
  - Enforced deposit-only balance rule: customers start with 0.00 ETB deposit balance upon registration and can only transfer funds up to their deposited balance. Zero-deposit and overdraft transfers are blocked.
  - Emits structured `DEPOSIT_PROCESSED` and `CUSTOMER_ONBOARDED` security events to ECS for real-time fraud monitoring.
  - Added test suite `honorpay-banking.test.ts` (8/8 passing); all 9 test files (109/109 tests) passing with 0 regressions.

- [x] **20+ Distinct Attack Surface Detection & Attack Testing Handbook (ADR-037)**:
  - Audited all existing 27 detection rules and target system telemetry emitters.
  - Implemented 5 new declarative detection rules expanding coverage to 32 detection rules: `AUTH-005` (OTP Brute Force), `AUTH-006` (Account Lockout Storm), `API-006` (Session Hijack Anomaly), `API-007` (SQLi/XSS/Command Injection), and `FRAUD-008` (Branch/Agent Deposit Structuring).
  - Enhanced rule evaluation in `rule_engine_service.py` with sliding window inspection and deterministic explainable evidence synthesis.
  - Normalized event contract results in `event_contract.py` (`BLOCKED` -> `DENIED`, `PENDING` -> `HELD`).
  - Authored comprehensive `ATTACK_TESTING_GUIDE.md` covering 28+ step-by-step attack scenarios for Burp Suite, cURL, and browser.
  - Verified live alert generation, attack dossier enrichment, and containment triggers end-to-end.

- [x] **Audible Threat Notifications, Real-Time Time Attacked Ticker & Multi-Alias Login (ADR-038)**:
  - Added multi-alias login support for `admin@ethiocybershield.et`, `admin@shieldbank.test`, `admin@honorpay.et`, and `admin` with `Testbed#2026`.
  - Added 1-click credential autofill to `login.html` and patched `api.js` to eliminate false "Unauthorized" error masking.
  - Implemented real-time dynamic ticking timer in `common.js` updating threat elapsed times (`Just now`, `x seconds ago`) every second.
  - Added explicit **Time Attacked** column and badge across `dashboard.html`, `alerts.html`, and Attack Investigation Dossier Modal.
  - Integrated procedural Web Audio API sound alerts (Critical siren, High double-pulse, Medium chime) with header sound toggle and "Test Audio Alert" control.

- [x] **Enterprise SOC Navigation Redesign & UI De-Fancification (ADR-039)**:
  - Solved root cause of missing navbar: fixed unexpected bracket syntax error in `ui/js/common.js` that caused browser execution to abort during page render.
  - Replaced collapsible, mobile-collapsed Bootstrap navbar with permanent, non-collapsing enterprise SOC header (`.ecs-navbar-header`).
  - Rendered all 6 core security operation views with 1-click persistent visibility across all viewports: **Overview** (`dashboard.html`), **Alerts** (`alerts.html`), **Incidents** (`incidents.html`), **Threat Intel** (`intelligence.html`), **Audit & Compliance** (`audit.html`), and **Settings & Rules** (`settings.html`).
  - Purged toyish/web3 styling: removed rainbow flowing animations (`@keyframes flow`), candy gradient text fills, and blinking neon halos in `login.html` and `style.css`.
  - Replaced flashing pulse dots with crisp, solid status dots.
  - Standardized on an institutional, high-contrast, deep-slate SOC visual design language matching global standards (CrowdStrike Falcon, Splunk ES, Datadog SIEM).
  - All test suites passing (targetsys 109/109 tests passing, backend unit tests passing).

- [x] **HonorPay Target Banking System Vercel Cloud Deployment (ADR-040)**:
  - Linked `targetsys` to Vercel team `rammisos-projects` as project `honorpay`.
  - Configured 9 production environment variables on Vercel: `NITRO_PRESET=vercel`, `APP_ENCRYPTION_KEY`, `SUPABASE_PROJECT_ID`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `VITE_SUPABASE_PROJECT_ID`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_SUPABASE_URL`.
  - Disabled deployment SSO protection to permit public access without authentication barriers.
  - Deployed production build to Vercel and assigned clean domain alias: `https://honorpay-banking.vercel.app`.
  - Verified live endpoint responses over HTTP/2: `/` (200 OK), `/login` (200 OK), `/employee` (200 OK), and `/admin` (307 redirect).

- [x] **Render Cloud Deployment Architecture & 1-Click Blueprint (ADR-041)**:
  - Enabled unified single-port architecture in `core/app/__init__.py` to serve static console files from `ui/` directly on port 5000 / cloud HTTPS, resolving cross-origin preflight overhead.
  - Updated `ui/js/config.js` to dynamically detect port 5500 vs cloud relative `/api`.
  - Created root `Procfile`, root `requirements.txt`, and `render.yaml` infrastructure-as-code Blueprint for 1-click Render web service deployment.

- [x] **Minimalist Institutional SOC UI/UX & High-Contrast Typography System (ADR-042)**:
  - Audited and eliminated all low-contrast/invisible text elements: elevated `--ecs-text-muted` to `#cbd5e1` (contrast ratio ~9.5:1) and `--ecs-text-dim` to `#94a3b8` (contrast ratio ~5.5:1, exceeding WCAG AA 4.5:1 minimum).
  - Enforced global high-contrast overrides on Bootstrap's `.text-muted`, `.text-dim`, and `.text-secondary`.
  - Upgraded table header surfaces (`#0d1527`), crisp `#e2e8f0` column titles, and clear `#f1f5f9` cell text.
  - Upgraded attack dossier modal metrics: `.label` to `#cbd5e1` (clearly readable) and `.val` to `#ffffff`.
  - Purged distracting rainbow coloring: eliminated rainbow borders and competing neon text colors on zero-state KPI cards, standardizing on calm, high-contrast `#ffffff` numbers with dynamic rose highlighting on active attacks.
  - Replaced rainbow top-bar outline buttons with minimalist institutional `.btn-soc` button components (`#111827`, border `#334155`, text `#f1f5f9`).
  - Refactored sub-tabs from radioactive neon green blocks to sleek dark slate active pills (`#1e293b`, border `#334155`, text `#ffffff`).
  - Standardized severity and status badges on modern, translucent, high-contrast pill badges (`badge-critical`, `badge-high`, `badge-medium`, `badge-soc-neutral`).
  - Upgraded `alerts.html`, `incidents.html`, `intelligence.html`, `audit.html`, `settings.html`, and `login.html` to the unified minimalist SOC standard.

- [x] **Full Cloud Production Deployment of ECS on Render via Render CLI (ADR-043)**:
  - Authenticated Render CLI with team workspace `My Workspace` (`musab` / `mushas1248@gmail.com`).
  - Provisioned Render PostgreSQL managed database `ecs-postgres` (ID: `dpg-dbefthom7kps73dp2bn0-a`, v18, Oregon).
  - Provisioned Render Redis managed Key-Value instance `ecs-redis` (ID: `red-dbeftkjncjis73e4gsb0`, v8.1.10, Oregon).
  - Executed `deploy/postgres/init.sql` schema and seeded core tables (`organizations`, `users`, `target_systems`, `security_events`, `alerts`, `incidents`, `declarative_rules`, `audit_log`).
  - Configured bcrypt hashed password `Testbed#2026` for administrative accounts (`admin@ethiocybershield.et`, `admin@shieldbank.test`, `admin@honorpay.et`).
  - Created Render Python Web Service `ethio-cyber-shield` (ID: `srv-dbefu6ss728c73c47d3g`, branch: `v3-independent`, Oregon) with automated health check `/api/health`.
  - Configured cloud production environment variables (`DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `ECS_MASTER_ENCRYPTION_KEY`, `TARGET_SYSTEM_URL=https://honorpay-banking.vercel.app`, etc.).
  - Successfully deployed to live URL: **`https://ethio-cyber-shield.onrender.com`**.
  - Verified live endpoint responses over HTTPS: `/api/health` (HTTP 200 OK, database healthy 1ms latency, Redis stream engine active), UI console (`/`, `/login.html`, `/dashboard.html`), and authenticated JWT session authentication (`/api/auth/login`).

- [x] **Project Root Submission Readiness & Redundant Documentation Cleanup (ADR-044)**:
  - Purged obsolete and duplicate markdown files from project root (`ATTACK_SIMULATION_GUIDE.md`, `ECS_COMPLETE_SYSTEM_ARCHITECTURE_AND_FLOWS.md`, `FULL_SYSTEM_SETUP_AND_RUN_GUIDE.md`, `TEAM_RUNBOOK.md`).
  - Purged obsolete prompt pack files from `targetsys` (`targetsys-promot.md`, `docs/shieldbank-spec.md`).
  - Purged superseded planning artifacts from `Ethio-Cyber-Shield` (`AUTOMATED_INTEGRATION_PLAN.md`, `ECS_Independent_Redesign_Execution_Plan.md`, `COMPETITION_DEMO_RUNBOOK.md`).
  - Created master institutional root `README.md` at project root linking the dual ecosystem (ECS + HonorPay), live cloud deployment endpoints (Render + Vercel), architecture, credentials, local runbook, and verification suites.
  - Upgraded `Ethio-Cyber-Shield/README.md` and `targetsys/README.md` to professional v3.0 platform specifications.

- [x] **Universal System Integration Guide & Multi-Language Implementation Reference (ADR-045)**:
  - Authored comprehensive `INTEGRATION_GUIDE.md` detailing how external banking and payment platforms integrate into ECS in under 15 minutes.
  - Documented Canonical Security Event Contract v1.1 schema with Ethiopian PDPP Zero-PII hashing rules.
  - Provided copy-paste drop-in implementations across 6 languages: cURL, Node.js/TypeScript, Python, Java/Spring Boot, Go, and PHP.
  - Documented no-code inbound webhook mapping for core banking engines and payment aggregators (telebirr, EthSwitch, Temenos T24).
  - Documented closed-loop automated mitigation webhook receivers (`POST /api/security/mitigate`) with idempotent rollback (`/revert`).

- [x] **Institutional SOC Command Dashboard Standardization & Version Decoupling (ADR-046)**:
  - Completely purged version text tags (e.g. `v3.0`, `.ecs-platform-version`) across all UI templates, navigation bars, headers, and stylesheets.
  - Upgraded SOC dashboard to global cybersecurity operations standard (inspired by CrowdStrike Falcon, Splunk ES, Microsoft Sentinel).
  - Expanded executive KPI bar to 6 metrics: Security Posture, Active Threats & Alerts, Auto-Contained Threats, Mean Time to Detect (MTTD < 15ms), Documented Incident Cases, and Telemetry Ingestion Velocity.
  - Integrated live East Africa Time (EAT, UTC+3) digital operations clock in command bar.
  - Added live threat category quick-filter tabs: All, Critical & High, Account Takeover (ATO), Fraud & Velocity, Injection & Web.
  - Added real-time client-side search across live attack feed.
  - Added visual GeoIP proportional distribution bars (Internal, Ethiopian Telco Rails, External/Cloud).
  - Added dedicated 4-Tier Detection Hierarchy (L1-L4) engine coverage monitor.

- [x] **High-Contrast Dark Theme Enforcement & Complete Text Visibility Remediation (ADR-047)**:
  - Enforced `data-bs-theme="dark"` attribute across all HTML templates to avoid Bootstrap 5.3 default light-mode body text color inheritance (`#212529`).
  - Added explicit Bootstrap CSS variables on `:root`: `--bs-body-color: #f8fafc`, `--bs-body-bg: #090d16`, `--bs-card-color: #f8fafc`, `--bs-card-bg: #0f172a`.
  - Upgraded `--ecs-text-muted` to `#e2e8f0` and `--ecs-text-dim` to `#cbd5e1` guaranteeing WCAG AAA compliant contrast against `#0f172a` navy card surfaces.
  - Upgraded Attack Origins (GeoIP & ASN) row labels to `<span class="small text-light fw-semibold">` and count badges to `<span class="badge bg-secondary text-light font-mono px-2">`.
  - Upgraded Target Infrastructure parameter titles to `text-light fw-medium`.
  - Upgraded 4-Tier Detection Hierarchy descriptions to `<div class="text-light" style="font-size:0.78rem;">`.
  - Upgraded Live Attack Feed table details (threat time date, rule ID/risk score, GeoIP country/IP, device OS/ID) to `text-light`.
  - Upgraded dynamic vector names in `updateBreakdown` to `text-light fw-medium text-capitalize`.

- [x] **HonorPay First-Time Login Password Change Synchronization & Instant Dashboard Unlock (ADR-048)**:
  - Resolved circular modal re-render bug where newly registered customers saving a new personal password were redirected back into the "First-Time Login Password Change" modal.
  - Root-caused issue to stale `x-honorpay-entities` headers re-syncing `must_change_password = true` in stateless serverless instances due to un-updated client `localStorage["hp_custom_entities"]`.
  - Implemented `markStoredEntityPasswordChanged(userIdOrEmail, newPassword)` and `isPasswordChangeCompleted(userIdOrEmail)` in `src/lib/client-headers.ts`.
  - Updated `CustomerShell` with instant local unlock state and modal bypass logic once new credentials are confirmed.
  - Verified with full test suite (111 tests passing), pushed to GitHub `main`, and deployed live to production on Vercel (`https://honorpay-banking.vercel.app`).






