# Ethio-Cyber-Shield (ECS) — Agent & Developer Engineering Guidelines

> **Product**: Ethio-Cyber-Shield (ECS) v3.0 Independent Defense Platform  
> **Mandate**: Transform ECS into an independent, multi-tenant, explainable, self-hostable cybersecurity detection and incident-readiness platform for Ethiopian critical infrastructure and digital finance operators.

---

## 1. Core Architectural & Product Principles

1. **Explainable by default**  
   Every detection and alert must display the exact rules, evaluation conditions, feature weights, and raw event evidence. Deterministic logic makes decisions; ML/LLM is strictly advisory/explanatory.
2. **Safe automation**  
   All automated response actions must follow progressive risk postures: `observe` (shadow) → `recommend` → `approve` (human-in-the-loop) → `auto`. Actions must enforce blast-radius limits, cooldowns, allowlists, and rollback capabilities (`revert`).
3. **Evidence first**  
   All incident telemetry, detections, and response actions must be hash-sealed (SHA-256), timestamped, and exportable for regulatory/audit review.
4. **Privacy-preserving sharing**  
   Cross-tenant community signals exchange only keyed hashes, indicator values, confidence, and TLP markings. Never export or exchange raw PII, account balances, or unmasked transaction details.
5. **Self-hostable & independent**  
   The platform must run independently via standard Docker Compose (`PostgreSQL` + `Redis`). No vendor lock-in to proprietary cloud services (e.g., Supabase cloud-only APIs) and no hard-coded dependency on ShieldBank.
6. **No overclaiming**  
   Always claim *"supports evidence for"* or *"incident readiness assistance"*, never *"guarantees compliance with INSA/NBE/PDPP"*.
7. **Ethiopian operational context**  
   Default to ETB currency units, Addis Ababa local timezone (`Africa/Addis_Ababa`, UTC+3), local payment rails (P2P, USSD, mobile money, EthSwitch), and multilingual support (Amharic/Afaan Oromo/English).

---

## 2. Non-Negotiable Hard Engineering Rules

1. **Tenancy everywhere**  
   Every database table must have an `organization_id UUID NOT NULL` column. All database queries, API endpoints, background workers, and cache keys must strictly scope by `organization_id`. Cross-tenant data leaks are considered P0 critical bugs.
2. **Zero secrets in logs or code**  
   Never log raw API secret keys, plaintext passwords, tokens, or sensitive customer PII. Secrets stored in database tables (e.g., connector credentials) must be encrypted at rest using envelope encryption.
3. **Rules are data**  
   Detection rules must be defined declaratively (YAML/JSON schema) with versioning, lifecycle states (`draft`, `backtest`, `shadow`, `live`), and per-tenant threshold overrides. Do not hardcode static rule logic into monolithic code branches.
4. **Durable event ingestion**  
   Telemetry ingest must decouple ingestion from detection processing via bounded durable streams (Redis Streams / transactional outbox), eliminating in-memory ring buffer data loss on process restart.
5. **Reversible automated mitigations**  
   Every automated action connector must either implement an idempotent rollback/revert method or be explicitly designated irreversible and guarded behind manual approval.
6. **Every feature ships with automated tests**  
   No code is merged without unit, integration, and security regression tests. Multi-tenancy isolation tests (ensuring Tenant A cannot read/write Tenant B) are mandatory for all entity routes.

---

## 3. Session Work Pattern

When executing tasks:
- **One work item per session**: Focus exclusively on the targeted phase work item.
- **Test-driven verification**: Write failing tests first, implement the required module, verify all tests pass, and confirm no regressions.
- **Update documentation**: Log architecture decisions in `docs/DECISIONS.md` and progress status in `docs/PROGRESS.md`.
