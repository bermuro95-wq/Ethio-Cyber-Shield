# ECS Redesign — Independent Ethiopian Threat-Detection & Incident-Readiness Platform

> **Document type:** Market/gap analysis + phased execution plan
> **Product:** Ethio-Cyber-Shield (ECS) v2.0 → v3.0 ("independent platform")
> **Prepared:** 16 October 2026
> **Method:** Public web research (INSA, Ethiopian press, regulators' summaries, local vendors) + analysis of your `ECS_COMPLETE_SYSTEM_ARCHITECTURE_AND_FLOWS.md` and the LocalShield specification.
> **Reading rule:** Every claim is tagged **[Sourced]** (found online, see §10), **[Vendor]** (a local vendor's own marketing, unverified), or **[Inference]** (my reasoning, a hypothesis to validate with real customers). Do not put **[Inference]** items in a pitch as facts.

---

## 0. Executive summary

**The opportunity.** Ethiopia has just enacted a critical-infrastructure cybersecurity law (Proclamation No. 1426/2026) that makes incident detection, 48-hour reporting, audits and certified security programs legally mandatory for banks and 10+ other sectors, with fines of up to ETB 2 million. At the same time, official policy documents describe cyber-incident and fraud data as *siloed* between institutions, with no sector-wide threat-intelligence mechanism, while digital payments are growing fast. Local security services appear to be expensive, staff-heavy (SOC-as-a-service) or regulator-built products centered on WAF/VPN/antivirus/messaging.

**The recommended wedge for ECS** — *not* "another SIEM/WAF" and *not* a clone of INSA's product line:

> **ECS = an independent, self-hostable detection-and-response platform for Ethiopian digital finance and critical-infrastructure operators that (1) detects fraud and account-takeover chains with explainable evidence, (2) contains them safely, (3) produces regulator-ready 48-hour incident packages, and (4) lets institutions share privacy-preserving threat signals with each other.**

**Why ECS can win this.** It already has what most local offerings reportedly lack: a transaction-aware, explainable detection engine (L1–L4, `ATO-001`), signed telemetry, closed-loop containment with rollback, an audit trail, and a 48-hour report generator. What it lacks is **independence from ShieldBank, tenancy, configurability, safe-rollout controls, a real integration story, and the community layer**. This plan builds those in eight phases (~7–9 months for a solo developer using AI coding agents; my estimate).

**What "independent" means here** (all four are goals):
1. **Technically independent** — works against any customer system through a published contract + SDKs, not just ShieldBank; no mandatory Supabase/cloud dependency.
2. **Operationally independent** — self-hostable on a customer's own Linux server; customer data stays under customer control.
3. **Commercially independent** — vendor-neutral, not tied to a regulator's product line or a hosting provider; open core + services.
4. **Differentiated** — solves gaps INSA's visible products and local MSSPs do not obviously solve (§2), while integrating with (not replacing) INSA/EthioCERT reporting.

---

## 1. Landscape analysis: what exists in Ethiopia

### 1.1 INSA (Information Network Security Administration/Agency) — regulator, CERT host, and product vendor

| Fact | Status |
|---|---|
| INSA lists these public products: **Gasha VPN, Derash** (bill aggregator), **Gasha Antivirus, Gasha WAF, Sirkuni** (secure government messaging), **Erga** (government email), **Debo**, **Enyuma IAM** | **[Sourced]** insa.gov.et/product. The page text is partly truncated/duplicated, so descriptions of Debo and Enyuma IAM are unclear. |
| INSA web services menu: Request Cyber Audit, Request Secure Systems, Register as SubCon, GRC portal, Report a Cyber Issue | **[Sourced]** same page |
| No SIEM, SOC, fraud-detection, or transaction-monitoring *product* is named on the page I could read | **[Sourced]** absence on that page; **not proof** none exists internally |
| INSA hosts the national CERT (EthioCERT/etCERT), a FIRST member and AfricaCERT partner; built an incident-notification service with AUSCERT's help, but no operational results are published | **[Sourced]** AUSCERT blog; CREST CMAGE page |
| A CREST assessment found **no evidence of sector-specific information-sharing initiatives** and no sector-specific CERTs in Ethiopia | **[Sourced]** CREST CMAGE (undated page; treat as indicative) |
| INSA is the audit/certification authority under the new law and will issue directives, standards and transition support | **[Sourced]** Ethiopia Today, BanksEthiopia |

**Reading:** INSA is simultaneously regulator, national CERT, auditor and vendor of its own security products. That is normal for a national agency, but it leaves room for an **independent, vendor-neutral, deployable tool** that helps operators *meet* INSA's requirements and *feed* EthioCERT — rather than compete with INSA's catalog **[Inference]**.

### 1.2 The new legal driver — Proclamation No. 1426/2026 (Critical Infrastructure Cybersecurity)

| Item | Finding | Status |
|---|---|---|
| Number & status | Enacted by the House of Peoples' Representatives; reported Aug 2026; legal analysis published by Shega/Aman & Partners 13 Oct 2026 | **[Sourced]** |
| Sectors | Reported as 12 sectors (one article lists 11): IT & Communications, **Finance**, Security, Transportation, Education, Health, Water & Energy, Public Services, Emergency Services, Agriculture, Trade & Industry. INSA may expand the list by directive | **[Sourced]** |
| Incident reporting | Report to the **National Computer Emergency Response Center/Team within 48 hours of detection** | **[Sourced]** (2 articles) |
| Fines | Reported as **ETB 1.5–2 million** (Ethiopia Today) or **ETB 500,000–2 million** (BanksEthiopia) — *sources disagree; read the official text* | **[Sourced]**, conflicting |
| Obligations | **18 core obligations**, including internal cybersecurity frameworks, periodic risk assessments, cyber-audit certificates, certified security professionals, vetting software before go-live | **[Sourced]** |
| Timeline | One-year grace period from publication in *Negarit Gazette* (BanksEthiopia estimates about July 2027); INSA to issue directives/standards meanwhile | **[Sourced]**; exact date unverified |
| Funding | Permanent Critical Infrastructure Cybersecurity Fund fed by operator contributions (amount not yet set) | **[Sourced]** |
| Open compliance questions | Overlap between NBE directive, PDPP 1321/2024 and INSA audits; whether core banking can outsource compliance work to licensed private firms; unknown fund cost | **[Sourced]** BanksEthiopia |

**This resolves a doubt from my first answer:** your ECS document's reference to "Proclamation No. 1426/2026" and the 48-hour National CERT reporting duty is **real**. The *report format* the National CERT expects is **not public in anything I found** — you must obtain it from INSA (Phase 0).

### 1.3 Other regulation that touches ECS's customers

- **NBE cybersecurity/IT directives** — banks (2023 directive) and microfinance (Directive MFI/33/2022, "IT management including cybersecurity") **[Sourced]** (existence); a vendor blog adds specifics (24-hour incident reporting, annual third-party assessment, MFA for privileged access) **[Vendor]** — verify against NBE's text.
- **Personal Data Protection Proclamation No. 1321/2024** — controller/processor duties and breach reporting **[Sourced]** via law references and vendor summary.
- **Digital payment strategy (2nd National Digital Payment Strategy, as reported Dec 2025)** — calls the lack of a coordinated, sector-wide cybersecurity and threat-intelligence mechanism "a major vulnerability" and proposes NBE-level shared intelligence, a joint NBE/INSA/FIS fraud function, a national financial-sector cybersecurity framework within a year, and an authorized-push-payment fraud directive **[Sourced]** The Reporter.

### 1.4 Threat picture (numbers need care)

| Claim | Status / caution |
|---|---|
| INSA reported 5,856 attacks in nine months of FY2021/22 and said 97.7% were foiled | **[Sourced]** but **2022 data — stale**; do not present as current |
| Ethiopia ranked 1st globally for malware detections (2024) and ~4,623 attacks on banks in H1 2024, per a vendor executive at a Jan 2026 workshop citing INTERPOL | **[Sourced]** (Capital) as *reported speech*; underlying data not verified |
| >2,400 confirmed incidents in 2024 per "INSA/etCERT", with finance and government most targeted | **[Vendor]** (UT Solutions blog) — unverified |
| Mobile-money fraud (SIM swap, staff social engineering, USSD/P2P abuse) described as dominant retail-banking attack; phishing is the initial vector in >70% of cases; ransomware downtime 4–21 days | **[Vendor]** — plausible, unverified |
| P2P transfers overtook ATM withdrawals; EthSwitch reported 128M+ P2P transactions worth ~ETB 578B in a year | **[Sourced]** The Reporter (Dec 2025) |
| Fraud losses fall largely on consumers because liability for authorized-push-payment fraud is unclear, weakening institutions' incentive to invest; institutions lack end-to-end transaction-chain visibility | **[Sourced]** The Reporter (summarizing the strategy) |

### 1.5 Local commercial alternatives

| Alternative | What it appears to offer | Weakness visible from public info |
|---|---|---|
| Local MSSP/SOC vendors (e.g., UT Solutions, eSafe IT) | 24/7 SOC, SIEM/EDR/SOAR, pen-testing, GRC, IR retainers | **Service-heavy and priced accordingly**: one vendor publishes Bronze SOC at USD 8–14K/month, MDR at 22–45K/month **[Vendor]**; marketing is generic, without named tools, SLA figures or proof (eSafe page) |
| Global tools (Wazuh, Elastic, Splunk, Cloudflare, etc.) | Broad SIEM/WAF capabilities | Generic rules, no Ethiopian fraud patterns, English-only, require skilled staff; "SIEMs are bought but nobody works the alerts" **[Vendor]** |
| INSA products and services | WAF/VPN/AV, audits, GRC, CERT reporting | See §1.1 |
| Manual process + spreadsheets | Fraud teams reviewing logs and complaints | Slow; no shared evidence trail **[Inference]** |

---

## 2. Gap analysis → where ECS can be genuinely different

Each gap links the evidence to an ECS capability. **Gaps G1–G4 are the strongest; validate them first.**

| # | Gap | Evidence | What ECS must become | Strength |
|---|---|---|---|---|
| **G1** | **No sector-wide, operator-driven threat/fraud signal sharing.** Incident data stays within institutions, so the same weakness is exploited across banks, MFIs, payment operators and telcos | The Reporter/payment strategy; CREST CMAGE | **Opt-in federated signal exchange** between ECS tenants (hashed indicators, confidence, TTL, reviewer workflow) — "when one institution sees a mule account, the others learn within minutes" | ★★★ Sourced, unaddressed by visible products |
| **G2** | **48-hour reporting duty with heavy fines, with no obvious tool support.** Operators need a detection clock, evidence, and a submission-ready package | Proclamation 1426/2026 coverage | **Incident Readiness Engine**: detection-time clock, evidence bundle (hash-sealed), draft report, deadline alerts, audit trail | ★★★ Sourced; effective ~mid-2027, so timing is good |
| **G3** | **Fraud/transaction-chain visibility is weak** and liability is unclear; no end-to-end view | The Reporter | **Transaction-aware fraud pack** (ATO, mule, APP, SIM-swap/USSD abuse) with an evidence timeline that supports dispute resolution and liability decisions | ★★★ Sourced need; the product gap is **[Inference]** because INSA's page lists no such product |
| **G4** | **Skills shortage / "tools without staff"** | UT Solutions blog **[Vendor]**; MSSP pricing | **SOC-in-a-box for small teams**: explainable alerts, guided playbooks, safe automation, plain-language summaries (incl. Amharic/Afaan Oromo) | ★★ Vendor-sourced, plausible |
| **G5** | **Compliance evidence is scattered across overlapping regimes** (NBE, INSA, PDPP) | BanksEthiopia | **Evidence-once, map-many**: tag incidents and controls to INSA obligations, NBE directive and PDPP breach duties, export audit packs. *Never claim "compliance"* — claim "evidence support" | ★★ Sourced concern; mapping depends on official texts |
| **G6** | **Underserved mid/small segment**: MFIs, payment operators (PIIs/PSOs), fintechs, agencies priced out of SOC services | MFI directive existence; vendor price points | Low-cost self-hosted tier (Community) + paid support/managed tiers | ★★ **[Inference]** — validate willingness to pay |
| **G7** | **Data-sovereignty and portability concerns** | National Data Center markets local hosting (from LocalShield research) | Self-host first; export everything; no mandatory foreign cloud | ★★ **[Inference]** |
| **G8** | **Regulator-neutral tooling**: one entity is regulator, auditor, CERT and product vendor | §1.1 | Independent platform that exports to EthioCERT and supports INSA audits without depending on INSA products | ★ **[Inference]**; handle diplomatically |

**What not to do:** compete on WAF, VPN, antivirus, DDoS absorption, 24/7 human SOC at launch, or endpoint/EDR. Those are crowded or capital-heavy.

### 2.1 ECS honest current-state assessment

| Strength to keep | Weakness to fix |
|---|---|
| Explainable deterministic L1–L4 scoring (a trust advantage for auditors/regulators) | Hard-coded rules; no tenant tuning, no backtesting |
| Signed HMAC + nonce contract; idempotent ingest | Contract tied to ShieldBank; no SDKs; plaintext `secret_key` column |
| Closed-loop containment with rollback and audit | No shadow mode, allowlists, approvals or blast-radius limits — one false block can end a pilot |
| Incident dedupe, indicators, watchlists | In-memory 5,000-event ring buffer: single-process only |
| 48-hour report generator (Feature 21) | Not a clock/evidence workflow; format unconfirmed |
| Attack Lab for demonstrations | No measured precision/recall; ShieldBank-only scenarios |
| Postgres schema | No `organization_id` (no tenancy); Supabase dependency; static HTML UI |

---

## 3. Product definition after redesign

### 3.1 Positioning statement
**ECS — "Detect. Contain. Prove. Report. Share."** An independent, explainable, self-hostable defense platform for Ethiopian digital-finance and critical-infrastructure operators.

### 3.2 Target segments (priority order — **[Inference]**, validate in Phase 0)
1. Payment/fintech operators, MFIs, and small/mid banks with a small security team.
2. Web/mobile agencies and providers running fintech, e-commerce or government-facing systems for clients (multi-tenant mode).
3. Other designated critical-infrastructure operators (telecom services, utilities, health, education) needing reporting readiness.
4. Sector hub operators (a bank association, switch operator or regulator-sponsored hub) — only after multi-tenant federation proves out.

### 3.3 Design principles
1. **Explainable by default** — every alert shows rules, weights, and raw evidence. ML/LLM may *assist*; deterministic logic decides.
2. **Safe automation** — shadow → recommend → approve → auto, per action type, with limits and rollback.
3. **Evidence first** — hash-sealed, time-stamped, exportable.
4. **Privacy-preserving sharing** — share hashes and signals, never raw customer data, only with opt-in.
5. **Self-hostable and portable** — one `docker compose up`; full export.
6. **No overclaiming** — "supports evidence for", never "ensures compliance"; no "AI-powered" marketing without proof.
7. **Local context** — ETB thresholds, Addis Ababa time, Amharic/Afaan Oromo summaries, local payment-channel semantics.

---
## 4. Target architecture (v3.0)

```
 CUSTOMER SYSTEMS (any)                         ECS PLATFORM (self-hosted or managed)
┌────────────────────────┐   signed events   ┌──────────────────────────────────────────────┐
│ Banking/MFI/payment app│ ───────────────►  │ Ingest API  (HMAC v1.1, per-tenant keys)     │
│ Web/API (SDK)          │                   │   └► Durable queue (Redis Streams / Postgres)│
│ Nginx/Apache logs agent│                   │ Normalizer + Enrichment (GeoIP/ASN/Tor/dev.) │
│ Syslog/CEF/webhook     │                   │ Detection Engine v2                          │
└────────────▲───────────┘                   │   rules-as-data • packs • baselines • L3 chain│
             │ signed controls               │ Scoring + Explainability (L4)                │
             │ (freeze/block/step-up…)       │ Alerts → Cases/Incidents → Evidence vault    │
┌────────────┴───────────┐                   │ Response Orchestrator                         │
│ Response connectors    │ ◄───────────────  │   shadow│recommend│approve│auto + guardrails  │
└────────────────────────┘                   │ Readiness Engine (48h clock, report, audit)  │
                                             │ Signal Exchange (opt-in hashed indicators)   │
 ANALYST / MANAGER UI  ◄──────────────────►  │ Tenancy • RBAC • MFA • Immutable audit       │
 Notifications (Telegram/Email/SMS/Webhook)  │ PostgreSQL (RLS)  • Object store (evidence)  │
                                             └───────────────┬──────────────────────────────┘
                                                             ▼ optional, opt-in
                                              Sector hub / EthioCERT-compatible export
```

**Key shifts from v2.0:** pluggable connectors instead of a ShieldBank contract; durable queue instead of in-memory ring buffer; rules as data; tenancy everywhere; a new Readiness Engine and Signal Exchange.

---

## 5. Execution plan — phase by phase

> **Durations** are my estimates for one developer using AI coding agents and are **not** commitments. **Gates** are pass/fail; do not start the next phase's dependent work until the gate passes. Phases 1–3 can overlap with the end of Phase 0 once scope is frozen.

### Phase 0 — Validate, obtain official texts, freeze scope (2–3 weeks)

**Goal:** make sure you are building what Ethiopian operators will adopt, using primary documents rather than press summaries.

**Work items**
1. **Obtain primary texts:** official Proclamation 1426/2026 (Negarit Gazette), the NBE 2023 cybersecurity directive and the MFI directive, PDPP 1321/2024, and any INSA directives. Ask INSA (via the Report/Request channels or contacts) for the **National CERT incident-report format** and whether private tools may submit reports.
2. **Interview 12–15 people:** bank/MFI/PSO security and fraud officers, IT managers, 3–5 agencies running fintech/e-commerce systems, and 1–2 people close to EthioCERT or the Ethiopian Cyber Security Association. Ask: how do you detect fraud today; what happens in the first 48 hours after an incident; what data may leave your premises; what would you pay for; what would make you refuse.
3. **Legal check** with a qualified Ethiopian lawyer: data-sharing between institutions, hashing of personal identifiers, liability for automated blocking, and open-source licensing.
4. **Pick the wedge** from G1–G6 using interview evidence (default: G2 + G3 + G1).
5. **Define success metrics** (§7) and record them in `docs/DECISIONS.md`.
6. **Naming/IP:** validate the product name and domain; avoid any wording implying INSA endorsement.

**Deliverables:** `docs/VALIDATION_REPORT.md`, `docs/DECISIONS.md`, frozen MVP scope, list of ≥3 pilot candidates.
**Gate 0:** ≥3 organizations agree to a pilot or design-partner conversation; the 48-hour report format is obtained **or** a documented fallback assumption is approved; top 3 pains are evidence-backed.

---

### Phase 1 — Make ECS independent: decouple, harden, make multi-tenant (4–5 weeks)

**Goal:** ECS runs without ShieldBank, Supabase or any single vendor, and is safe for more than one customer.

**Work items**
| # | Work | ECS areas affected |
|---|---|---|
| 1.1 | **Repository restructure:** `core/` (engine), `connectors/`, `sdk/`, `ui/`, `deploy/`, `docs/`, `labs/` (ShieldBank becomes one demo lab, not a dependency). Tag current code `ecs-v2.0`. | whole repo |
| 1.2 | **Tenancy:** add `organization_id` to every table; Postgres row-level security; tenant-scoped queries and API tokens; cross-tenant test suite (reads *and* writes denied). | all models/routes |
| 1.3 | **Self-host stack:** plain PostgreSQL + Redis (or Postgres-only queue) in Docker Compose; remove Supabase-specific code paths; health checks; backup/restore script; documented hardened install. | `deploy/`, config |
| 1.4 | **Durable ingest queue:** replace the in-memory ring buffer with a bounded durable stream; detection workers consume it; sliding-window state in Redis or windowed SQL; backpressure and dead-letter handling. | `events.py`, `event_service.py`, `detection_engine.py` |
| 1.5 | **Secrets:** encrypt `secret_key` at rest (envelope encryption with a master key from env/KMS/file), per-tenant keys, key rotation with overlap window, rate-limit ingest. Contract **v1.1**: add `X-ECS-Tenant`/key-scoped tenancy, keep v1.0 compatible. | `auth`, `targets.py` |
| 1.6 | **Identity:** add MFA (TOTP), session management, roles `admin / analyst / responder / viewer / auditor`, API tokens with scopes and revocation. | `auth_service.py`, `auth.py` |
| 1.7 | **Tamper-evident audit:** hash-chain `audit_logs` (each row stores hash of previous), append-only DB role, periodic anchor export. | `audit_service.py` |
| 1.8 | **CI/CD & supply chain:** tests, linting, dependency audit, secret scanning, container scan, SBOM; `SECURITY.md`, `THREAT_MODEL.md`. | repo |
| 1.9 | **UI foundation:** replace static pages with a componentized frontend (React/Vite or equivalent) with role-aware navigation; keep API-first. | `frontend/` |

**Deliverables:** one-command install; tenant isolation test report; threat model; performance baseline (events/sec on a modest VPS).
**Gate 1:** a clean machine runs ECS from docs in <30 min; two tenants cannot read each other's data (automated tests); ECS survives restart with no event loss; ShieldBank is removable with zero code change in `core/`.

---

### Phase 2 — Connectors, SDKs and a richer event model (3–4 weeks)

**Goal:** a real Ethiopian operator can send data in a day, not a month.

**Work items**
1. **Publish "ECS Event Contract v1.1"** as an OpenAPI + JSON Schema spec. Extend the canonical event with generic, channel-aware fields: `channel` (web, mobile, USSD, API, agent, branch), `payment_rail` (generic: P2P, card, wallet, bill-pay, interbank), `counterparty_ref` (hashed), `device_fingerprint`, `msisdn_hash`, `agent_id`, `national_id_hash`, `locale/tz`. Avoid hard-coding brand names; map them via config.
2. **SDKs + middleware:** Node/Express, Python (Flask/Django/FastAPI), PHP/Laravel; outbox pattern built in (retry, signing, idempotency) — generalizing ShieldBank's `outbox.server.ts`.
3. **Log agent:** lightweight collector for Nginx/Apache access/error logs and syslog/CEF; parses to canonical events with bounded CPU/RAM.
4. **Generic webhook receiver** with per-source field-mapping UI (JSONPath mapping, test-with-sample).
5. **Enrichment service:** GeoIP/ASN (offline DB for low-bandwidth), Tor/VPN/hosting-provider flags, optional external TI feeds with caching, device-reputation from internal history.
6. **Entity graph:** unified entity model (account, device, IP, session, beneficiary, phone-hash) with first/last seen and linkage — feeds investigation and sharing later.
7. **Health & data-quality monitor:** silent-source alerts ("no events from tenant X in 15 min"), schema-violation counters.
8. **Replace the poller's single-target assumption** with per-connector schedulers.

**Deliverables:** `docs/INTEGRATION_GUIDE.md`, three SDKs, log agent, sample apps.
**Gate 2:** a developer unfamiliar with ECS integrates a sample app in ≤1 day; schema validation rejects malformed events safely; ShieldBank runs as just another connector.

---

### Phase 3 — Detection Engine v2: configurable, measurable, locally relevant (4–5 weeks)

**Goal:** detection that adapts per customer and is *proven* with numbers.

**Work items**
1. **Rules as data:** rule definitions in YAML/JSON (Sigma-inspired) with conditions, windows, group-by, weight, severity, ATT&CK tags, remediation hints; per-tenant overrides (thresholds, enable/disable, weights); versioned and audited. Keep L1–L4 semantics; migrate existing rules (`AUTH-001…API-002`, `ATO-001`) into packs.
2. **Rule lifecycle tooling:** draft → backtest on stored events → shadow → live; "what would have fired last 7 days" preview; rule-level precision stats from analyst feedback.
3. **Rule packs**
   - **Fraud & Payments Pack:** account takeover chain (existing `ATO-001`), mule/pass-through account pattern, rapid beneficiary-add + transfer, authorized-push-payment indicators (new payee + large first transfer + coached-session signs), SIM-swap/OTP-reset-then-transfer, USSD/agent abuse bursts, structuring below thresholds, off-hours and impossible-travel patterns, configurable ETB thresholds per segment.
   - **Web/API Pack:** credential stuffing, IDOR enumeration, privilege abuse, token misuse, bot patterns.
   - **Insider/Admin Pack:** privileged action anomalies, mass data export, dormant-admin activation.
4. **Behavioral baselines (explainable):** per-entity statistical baselines (typical amount, hours, devices, geos). Output as scored signals with plain explanations ("amount is 9× this account's 90-day median"). Deterministic fallback when data is thin.
5. **Risk model v2:** keep the additive 0–100 model but add rule confidence, entity criticality and recency decay; express severity tiers with rationale; **do not present as a probability**. Document the model.
6. **Benchmark corpus + CI:** labeled synthetic and (consented, anonymized) real datasets; automated precision/recall/false-positive reports per rule and per pack; Attack Lab becomes a scenario library (≥12 scenarios incl. fraud, API abuse, insider) that runs in CI.
7. **Alert quality:** dedupe, suppression windows, grouping, alert fatigue metrics.

**Deliverables:** rule pack spec, ≥25 rules across packs, benchmark report, `docs/DETECTION_MODEL.md`.
**Gate 3:** published precision/recall per pack on the corpus; ≥90% of pilot-seeded attack scenarios detected with a stated false-positive rate; a rule change can be backtested and rolled out without a code deploy.

---

### Phase 4 — Safe, trustworthy response and case management (3–4 weeks)

**Goal:** automation that customers are willing to switch on.

**Work items**
1. **Response modes per action type and per tenant:** `observe` (shadow) → `recommend` → `approve` (one-click/two-person for risky actions) → `auto`. Default for new tenants: shadow for ≥14 days with a "would-have-done" report.
2. **Guardrails:** allowlists (customer IPs, VIP/staff accounts, partner systems), automatic expiry of blocks/freezes, cooldowns, max actions per hour/day per tenant, confidence thresholds, protected-entity rules, "kill switch" per tenant. Every guardrail hit is logged.
3. **Playbooks:** declarative playbooks (conditions → actions → notifications → follow-ups) with dry-run; keep the existing seven operations and rollback (`revert_target_action`) and generalize them as **response connectors** with a documented control contract.
4. **Case management:** assignment, status/SLA timers, notes, attachments, entity pages (account/IP/device timeline), related-alert graph, saved searches, event search across time.
5. **Notifications:** Telegram, email, SMS gateway, signed outbound webhooks; severity routing, quiet hours, escalation; minimal data in messages.
6. **Analyst feedback loop:** true/false-positive tags feed rule statistics and suppression suggestions.
7. **Post-incident review template** with lessons learned and rule-tuning tasks.

**Deliverables:** response-mode docs, playbook library, case UI, notification service.
**Gate 4:** in shadow mode ECS produces a would-have-done report; no guardrail bypass in adversarial tests; every automated action is reversible or explicitly marked irreversible and requires approval.

---

### Phase 5 — Incident Readiness Engine: the 48-hour clock, evidence and compliance support (3–4 weeks)

**Goal:** turn detection into regulator-ready outcomes. This is the clearest **legal** value driver (G2, G5).

> **Dependency:** the National CERT report format and INSA directives from Phase 0. If unavailable, build a configurable template and mark it "draft, format unconfirmed."

**Work items**
1. **Reportable-incident classification:** configurable policy (what counts as a reportable incident per tenant/sector); analyst confirmation step; record "time of detection" explicitly, since the law counts from detection.
2. **48-hour clock:** countdown on every reportable incident, escalating reminders at 24/36/44h, manager visibility, breach log.
3. **Report generator:** structured report (timeline, affected assets/accounts, impact, indicators, containment, root cause, actions taken, contacts), export as PDF/JSON/CSV, with an **Amharic and English** summary; submission-ready package for EthioCERT (manual upload initially; API/email integration only if INSA provides one).
4. **Evidence vault:** immutable snapshot of events, alerts, response actions, analyst notes; SHA-256 manifest and optional time-stamp anchor; chain-of-custody log; retention policy.
5. **Obligation-to-evidence mapping:** maintain a versioned register that maps ECS outputs to specific clauses of INSA/1426, the NBE directive and PDPP 1321/2024 (breach notification). Show "supported / partially / not covered" — never "compliant."
6. **Audit pack export:** one-click bundle for auditors (config history, audit log extract, incident register, response metrics, access reviews).
7. **Regulator/auditor read-only role** with scoped, time-boxed access.
8. **Data-protection controls:** PII minimization and redaction in evidence, retention/deletion, access logging, local-only mode.

**Deliverables:** Readiness module, report templates, mapping register, `docs/COMPLIANCE_SUPPORT.md` (with limits).
**Gate 5:** tabletop exercise: from a simulated attack, a pilot customer produces a complete report package in <2 hours, the clock and audit trail are correct, and a legal reviewer confirms wording avoids compliance overclaims.

---

### Phase 6 — Community Defense: privacy-preserving signal exchange (5–6 weeks)

**Goal:** the differentiator and long-term moat. Directly addresses G1. Start only when ≥3 tenants (or friendly partners) are live.

**Design**
- **What is shared** (opt-in, per signal type): hashed indicators (IP, device fingerprint, phone, beneficiary account, mule-account ID using a keyed hash with a hub-held salt), indicator type, confidence, first/last seen, TTL, TLP marking (white/green/amber/red), reason code. **Never** raw PII, balances, or transaction details.
- **How it flows:** tenant → local review (auto or analyst) → hub (can be self-hosted by a sector body, or ECS-run) → subscribing tenants → local match → `IOC` detections with "community-sourced" provenance and lower default weight until corroborated.

**Work items**
1. Signal schema and TLP policy; per-tenant sharing preferences and consent log.
2. **Anti-poisoning:** reporter reputation, corroboration thresholds (N independent reporters), analyst-review queue, expiry, appeal/retraction flow; **no automatic blocking from one unverified signal.**
3. Hub service with tenant authentication, rate limits, audit, and metrics; federation-ready (multiple hubs).
4. Matching in the detection engine (extends `IOC-001` and watchlists).
5. **EthioCERT-compatible export** (STIX/TAXII or a simple CSV/JSON mapped to what INSA accepts) and import of CERT advisories, if INSA agrees.
6. Governance document: membership terms, liability, data-handling, takedown, dispute process — reviewed by counsel.
7. "Network effect" dashboard: signals contributed/consumed, attacks prevented via community signals.

**Deliverables:** Signal Exchange module, governance charter, privacy impact assessment.
**Gate 6:** two or more tenants exchange signals end-to-end; a signal from tenant A prevents or flags a seeded attack at tenant B; poisoning tests (false signals) do not trigger automatic harm; privacy review finds no raw-PII leakage.

---

### Phase 7 — Productization, packaging and go-to-market (continuous from month 4; 4–6 weeks of focused work)

**Goal:** a professional product that can be installed, trusted, bought and supported.

**Work items**
1. **Editions** (hypotheses — test pricing in Phase 0 interviews and pilots):
   | Edition | Contents | Revenue |
   |---|---|---|
   | Community (self-hosted) | Core engine, rules, SDKs, basic response, docs | Free; builds trust and adoption |
   | Pro / Operator | Readiness Engine, advanced packs, SSO/MFA integrations, support SLA | Subscription + support |
   | Managed | ECS run for the customer (cloud or on-prem) with monthly review reports | Recurring service |
   | Sector Hub | Signal exchange hub operation and governance tooling | Contract/consortium funded |
   | Services | Installation/hardening, integration, rule tuning, tabletop exercises, training | Project fees |
2. **Open-source decision:** choose license with counsel (Apache-2.0 for adoption, AGPLv3 if closed hosted forks are a concern); add `LICENSE`, `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, public roadmap.
3. **Professional UX:** analyst workbench, executive dashboard (MTTD, MTTR, incidents, ETB protected, 48h-readiness status), dark/light themes, accessibility, low-bandwidth mode, Amharic/Afaan Oromo UI strings with terminology review.
4. **Documentation & training:** install, operations, integration, playbook authoring, incident-readiness runbook, analyst training, demo lab.
5. **Security of ECS itself:** independent penetration test, dependency/container scanning, secrets handling review, backup/restore and disaster-recovery drill. Plan ISO 27001 alignment later; do not claim certification until obtained.
6. **Pilots:** 2–3 time-boxed pilots (shadow mode first), weekly reviews, honest metrics (including false positives), written case studies **with permission only**.
7. **Stakeholder engagement:** present to INSA/EthioCERT/NBE as *complementary* (supports 48-hour reporting and sector sharing). Ask for technical feedback; **do not imply endorsement**.
8. **Support model:** business-hours support, ticketing, severity definitions; **no 24/7 SOC promise** unless staffed.

**Gate 7:** ≥1 paying customer or signed paid pilot; renewal/usage evidence; an external pen-test with all high findings fixed; documented support boundaries.

---

### Phase 8 — Selective expansion (only with demand evidence)

| Option | Condition to start |
|---|---|
| **LLM-assisted narratives & Amharic summaries** (explanation only, built on deterministic evidence, no decisions) | Pilots ask for it; evaluation shows accuracy; no sensitive data leaves tenant boundary |
| **Endpoint/EDR and email-security ingestion** (phishing, BEC, ransomware precursors) | Customers want unified view; adapter (e.g., Wazuh/Sysmon logs), not building an EDR |
| **OT/ICS monitoring adapters** (energy, water) | A pilot in a designated sector and a domain partner |
| **Exposure-management module** (LocalShield concepts: asset inventory, TLS/DNS/headers checks, closure verification) feeding ECS risk context | Detection side validated; keeps the two products complementary rather than merging prematurely |
| **National PKI / Fayda ID signals** as identity-assurance inputs | Official integration APIs published and customers ready |
| **Regulator/sector dashboards** (aggregate, anonymized) | A hub operator or regulator sponsors it |

---
## 6. Timeline overview (estimate)

| Phase | Focus | Weeks | Cumulative |
|---|---|---|---|
| 0 | Validate, official texts, scope freeze | 2–3 | 3 |
| 1 | Independence, tenancy, hardening | 4–5 | 8 |
| 2 | Connectors, SDKs, event model | 3–4 | 12 |
| 3 | Detection v2 + benchmarks | 4–5 | 17 |
| 4 | Safe response + case management | 3–4 | 21 |
| 5 | Incident Readiness Engine | 3–4 | 25 |
| 6 | Community Defense (signal exchange) | 5–6 | 31 |
| 7 | Productization + GTM (overlaps) | 4–6 | ~33 |
| 8 | Selective expansion | — | demand-driven |

**Timing logic:** the law's implementation window appears to run to roughly mid-2027. A usable Readiness Engine (Phase 5) by about month 6 would land before operators are forced to buy. Re-check the effective date once you have the official text.

**Fast path if time is short (about 10 weeks):** Phase 0 (condensed) → Phase 1 items 1.2–1.5 → Phase 2 (one SDK + log agent) → Phase 4 shadow mode + guardrails → Phase 5 report generator + 48h clock. Postpone Phases 3 (advanced), 6 and 8.

---

## 7. Success metrics

| Category | Metric | Target (initial, adjust after pilots) |
|---|---|---|
| Detection | Precision/recall per rule pack on corpus | Report publicly; ≥90% recall on seeded scenarios |
| Detection | False-positive rate after tuning | Track per rule; trend down each month |
| Speed | MTTD / MTTR (median, p95) | Measured per tenant; dashboard |
| Safety | Guardrail incidents; unintended blocks | 0 uncontained unintended blocks during pilots |
| Readiness | Time from detection to complete report package | < 2 hours in tabletop; 48h clock breaches = 0 |
| Integration | Time-to-first-event for a new connector | ≤ 1 day for SDK users |
| Platform | Events/sec per vCPU; install time; recovery time | Documented on modest VPS |
| Community | Signals shared/consumed; corroborated-signal precision | Reported once ≥3 tenants |
| Business | Pilots, paying customers, renewal intent, support hours per tenant | ≥1 paying by Gate 7 |
| Trust | Open vulnerabilities, pen-test findings closed | All high/critical closed before launch |

---

## 8. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| **Gap analysis rests partly on press and vendor claims** | Building for a problem that is smaller than assumed | Phase 0 interviews and primary documents; gates before heavy investment |
| **Report format/legal details unavailable** | Readiness Engine misaligned | Configurable template; mark as draft; engage INSA early |
| **Regulator relationship** — INSA is regulator and vendor | Perceived competition or blocked access | Position as complementary; formal feedback requests; no endorsement claims |
| **False positives → customer trust loss** | Pilot failure | Shadow mode, guardrails, tuning tools, honest metrics |
| **Signal-sharing legal/privacy risk** | Liability, refusal to participate | Hash-only, opt-in, counsel-reviewed charter, privacy impact assessment |
| **Signal poisoning** | Harm to innocent users | Corroboration, reviewer queue, no auto-block from a single signal |
| **Platform becomes an attack target** (holds sensitive telemetry) | Reputational collapse | Data minimization, encryption, MFA, pen-test, local deployment option |
| **Scope creep** (SIEM+EDR+WAF+SOC) | Never ships | Phase gates; Phase 8 only with demand evidence |
| **Founder dependency** | Bus factor | Documentation, tests, CI, gradual maintainers |
| **Low willingness to pay** | No revenue | Early paid pilots; agency/MSP and sector-hub channels; services revenue |
| **Competitor response** (local MSSP or INSA adds similar features) | Differentiation erodes | Move fastest on Signal Exchange network effect and explainable evidence; keep self-hostable and open |

---

## 9. How to execute this with your coding agent (Gemini Flash / Antigravity CLI or any other)

I cannot verify the exact model name or CLI flags, so check its documentation. The method is tool-agnostic:

1. **Keep the plan in the repo:** copy this file to `docs/EXECUTION_PLAN.md`, plus `docs/ECS_LEGACY.md` (your current architecture doc). Add a rules file the CLI reads (often `GEMINI.md` or `AGENTS.md`) with the principles in §3.3 and these hard rules: *every table has `organization_id`; no secrets in logs; automated actions must be reversible or approval-gated; rules are data; every feature ships with tests; never claim compliance.*
2. **One work item per session** (e.g., "1.2 Tenancy"). Prompt shape: *"Read `docs/EXECUTION_PLAN.md` §Phase 1 item 1.2 and `AGENTS.md`. Write the plan and failing tests first, then implement only this item. Do not touch unrelated modules. Stop when the acceptance gate for this item passes and update `docs/PROGRESS.md`."*
3. **Use the stronger model for design, the fast model for implementation.** Flash-tier models are good at bounded edits and weaker at cross-cutting architecture. Make schema, tenancy and security decisions yourself or with a stronger model, then hand over small tasks.
4. **Security-critical items get manual review and adversarial tests:** tenant isolation (1.2), secrets (1.5), audit hash chain (1.7), guardrails (4.2), signal privacy (Phase 6). Ask the agent to write attack tests, but read the code yourself.
5. **Branch + commit per work item; run the full test suite and benchmark before moving on.**

---

## 10. Sources and verification notes

**Sources used (all accessed 16 Oct 2026):**
- INSA products and services page — https://www.insa.gov.et/product (partly truncated text)
- Ethiopia Today, *Ethiopia Enacts Proclamation No. 1426/2026 Mandating Fines Up to 2 Million Birr for Unreported Cyberattacks* — https://ethiopiatoday.net/ethiopia-enacts-strict-cybersecurity-law-institutions-face-up-to-2-million-birr-fine-for-unreported-cyberattacks/
- Banks in Ethiopia, *New Cybersecurity Law Puts Ethiopian Banks Under a Second Regulator* — https://banksethiopia.com/news/new-cybersecurity-law-ethiopian-banks/
- The Reporter, *INSA Introduces Critical Infrastructure Cybersecurity Fund* — https://www.thereporterethiopia.com/52225/
- Shega / Aman & Partners, *Overview of Ethiopia's Critical Infrastructure Cybersecurity Proclamation* — https://shega.co/news/overview-of-ethiopia-s-critical-infrastructure-cybersecurity-proclamation (only metadata retrievable; I did not read the full analysis)
- The Reporter (13 Dec 2025), *Fragmented Cybersecurity Approach Threatens Ethiopia's Digital Payment System* — https://www.thereporterethiopia.com/48148/
- Capital Ethiopia (25 Jan 2026), *Ethiopia faces alarming surge in cyberattacks targeting critical infrastructure* — https://capitalethiopia.com/2026/01/25/ethiopia-faces-alarming-surge-in-cyberattacks-targeting-critical-infrastructure/
- Capital FM / Xinhua (May 2022), *Ethiopia says records 5,856 cyber attacks in nine months* — https://capitalfm.africa/ethiopia-says-records-5856-cyber-attacks-in-nine-months/ (stale data)
- AUSCERT, *Supporting Ethio-CERT's incident notification service* — https://auscert.org.au/blogs/supporting-ethio-cert-incident-notification-service/
- CREST CMAGE, *Ethiopia — CERTs and information sharing* — https://cmage.crest-approved.org/countries/ethiopia/reports/certs_and_information_sharing.html
- UT Solutions PLC (1 Jul 2026), *Cybersecurity in Ethiopia: The 2026 Threat Landscape and Defenses* — https://www.utsolutionsplc.com/insights/cybersecurity-ethiopia-guide/ **(vendor marketing)**
- eSafe IT, *Managed Security Services & SOC in Ethiopia* — https://www.esafeit.net/services/managed/ **(vendor marketing)**
- Digital Policy Alert entries on NBE Directive MFI/33/2022 — https://digitalpolicyalert.org/ (existence of microfinance IT/cybersecurity directive; details not read)

**Could not verify / open items:**
1. The official text of Proclamation 1426/2026 (fine range conflicts between sources: ETB 1.5–2M vs 500K–2M; effective date approximate).
2. The National CERT's required incident-report format, and whether private tools may submit to it.
3. NBE directive specifics (24-hour reporting, annual third-party assessment) — only from a vendor blog.
4. Whether INSA, NBE, EthSwitch or a private vendor operates an internal fraud/transaction-monitoring system not visible publicly. **Validate before claiming ECS fills an unmet gap.**
5. Current attack statistics: the only INSA-attributed figure I found is from 2022; other numbers are reported speech or vendor claims.
6. Willingness to pay and pricing: all editions and prices above are hypotheses.
7. Gemini/Antigravity specifics (model name, CLI flags, rules-file names).

---

## 11. Immediate next actions (this week)

1. Create the `docs/` folder with this plan, the ECS architecture doc and the LocalShield spec (as reference only).
2. Tag the repo `ecs-v2.0` and create branch `v3-independent`.
3. Request the official Proclamation 1426/2026 text and the National CERT report format from INSA; start a list of 15 interview targets.
4. Write the interview script (§Phase 0 item 2) and book the first five conversations.
5. Start Phase 1 items 1.1 (restructure) and 1.3 (self-host stack), since they do not depend on interview results.
