# ETHIO-CYBER SHIELD (ECS) v2.0: FULLY AUTOMATED TARGET SYSTEM INTEGRATION & INCIDENT RESPONSE PLATFORM
## Master Architecture & Step-by-Step Implementation Plan

---

### Executive Summary

**Ethio-Cyber Shield (ECS)** was originally designed with a foundation where security analysts manually entered incidents, indicators of compromise (IOCs), and banking transactions, subsequently clicking an "Analyze" button to evaluate deterministic rules.

As mandated by the **Ethio-Cyber Shield Software Requirements Specification (SRS v2.0)**, ECS is now undergoing a complete architectural transformation:
> **The Core Thesis (SRS §0 & §1):**  
> *"ECS does not depend on an analyst manually entering every suspicious event. It observes a live, controlled target application through structured security telemetry, correlates events, detects explainable attack patterns, raises incidents in real time, and performs controlled response actions against high-confidence threats."*

This implementation plan details the precise, modular steps required to transform the existing ECS codebase into a fully automated, real-time cyber defense platform capable of connecting via secure APIs to **any target application** (including the [ShieldBank Testbed](file:///home/neuron/dev/cybershield/targetsys) built in `targetsys`).

---

## 1. Architectural Paradigm Shift: v1.0 vs v2.0

```
+---------------------------------------------------------------------------------------------------------+
|                                        v1.0 (LEGACY MANUAL FLOW)                                        |
|                                                                                                         |
|   Analyst fills form  --->  Manual DB Insert  --->  Analyst clicks "Analyze"  --->  Static Alert/Score  |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                    v2.0 (AUTOMATED OBSERVATION FLOW)                                    |
|                                                                                                         |
|   Target App API                                                                                        |
|   [Telemetry Push / Pull]                                                                               |
|             |                                                                                           |
|             v                                                                                           |
|   +-------------------+       +-----------------------+       +------------------------------------+    |
|   | Telemetry Ingest  | ----> | Real-Time Multi-Layer | ----> | Autonomous Alert & Incident Engine |    |
|   | & Normalization   |       | Detection Engine      |       | (0-100 Explainable Risk Synthesis) |    |
|   +-------------------+       +-----------------------+       +------------------------------------+    |
|                                                                                 |                       |
|                                                                                 v                       |
|   +-------------------+       +-----------------------+       +------------------------------------+    |
|   | Target System     | <---- | HMAC-Signed API Call  | <---- | Closed-Loop Controlled Response    |    |
|   | Mitigation State  |       | (Freeze/Revoke/Block) |       | (Policy-Driven Auto-Containment)   |    |
|   +-------------------+       +-----------------------+       +------------------------------------+    |
+---------------------------------------------------------------------------------------------------------+
```

| Dimension | Legacy ECS (v1.0) | Automated ECS (v2.0) |
| :--- | :--- | :--- |
| **Data Ingestion** | Analyst manually enters transactions and incidents in web UI | Continuous, automated event telemetry pushed via webhook (`POST /api/events`) or polled via API (`GET /api/public/security/events`) |
| **Detection Trigger** | On-demand button click per incident or per transaction | Event-driven pipeline executing immediately upon ingestion across sliding time-windows |
| **Detection Scope** | Single transaction or single incident evaluation | **L1 to L4 Multi-Layer**: Threshold $\rightarrow$ Contextual $\rightarrow$ Multi-Event Correlation (e.g. Account Takeover Chain) |
| **Alert & Incident Creation** | Created manually by analyst or basic threshold flag | Automatically promoted from high-confidence correlation findings with complete evidence chains |
| **Response Actions** | None (purely informational UI) | **Controlled Response Engine** dispatching authenticated mitigation commands (`freeze-transaction`, `revoke-session`, `block-ip`) to target |
| **System Boundary** | Isolated standalone application | Secure bidirectional connection with Target Systems using HMAC-SHA256 authenticated APIs |

---

## 2. Current Codebase Gap Analysis

An exhaustive review of the existing repository in [`/home/neuron/dev/cybershield/Ethio-Cyber-Shield`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield) identified the following architectural gaps:

1. **Database Schema (`sql/schema.sql`, `sql/migrations_v2.sql`)**:
   - Lacks a `target_systems` configuration table to store target API endpoints, credentials, and sync settings.
   - Lacks a canonical `security_events` table implementing the frozen Telemetry Contract v1.0 envelope.
   - Lacks `detections`, `risk_assessments`, and `response_actions` tables specified in SRS §16.
   - Nonce replay defense (`api_nonces`) is in-memory only in `routes/events.py` rather than persistent.

2. **Ingestion & Synchronization (`backend/app/routes/events.py`)**:
   - `events.py` receives pushed events, but there is no **outbound polling worker** (Direction B) to pull events from target systems that do not push.
   - Telemetry normalization directly touches `transactions` and `indicators` instead of first recording the immutable security event and piping it through an event processing bus.

3. **Detection Engine (`backend/app/services/security_rules.py`)**:
   - `analyze_transaction` and `calculate_incident_risk` inspect static fields of single rows.
   - Does not maintain in-memory or database sliding windows to detect multi-event sequences across time (e.g., failed logins followed by new device login, beneficiary creation, and off-hours transfer within 10 minutes).
   - Lacks rule execution tracing (`rule_id`, contribution weight, evidence tags) required for SRS §9 explainability.

4. **Mitigation Engine (`backend/app/services/target_system_service.py`)**:
   - Service functions exist, but there is no policy evaluation layer that automatically triggers them when high-confidence alerts/incidents are generated.
   - Response actions are not tracked in a dedicated `response_actions` lifecycle table (`REQUESTED` $\rightarrow$ `CONFIRMED` $\rightarrow$ `REVERTED`).

5. **Frontend SOC Experience (`frontend/*.html`)**:
   - Pages assume manual entry (`incidents.html`, `fraud.html`).
   - Lacks a live, streaming security event ticker (`live-stream.html`).
   - Lacks visual attack chain and correlation timeline on `incident-detail.html`.
   - Lacks Target System Management UI (`targets.html` / `settings.html`) to pair target credentials and view connection health.

---

## 3. Generic Target System Integration Specification

To allow ECS to connect to **any target application** (banking core, ERP, fintech portal, or the ShieldBank testbed), ECS defines a generic **Target Adapter Contract**:

```
+----------------------------------------------------------------------------------------------------+
|                                    GENERIC TARGET ADAPTER MODEL                                    |
|                                                                                                    |
|   Target System (Any Banking Core / Testbed)                     Ethio-Cyber Shield (ECS)          |
|   +---------------------------------------+                     +-------------------------------+  |
|   | 1. Outbox Telemetry Emitter           | --- Direction A --> | Inbound Webhook:              |  |
|   |    (POST /api/events on ECS)          |   (Webhook Push)    | POST /api/events              |  |
|   |                                       |                     |                               |  |
|   | 2. Events Pull API                    | <-- Direction B --- | Outbound Collector Worker:    |  |
|   |    (GET /api/public/security/events)  |   (Poller Pull)     | Background Polling Daemon     |  |
|   |                                       |                     |                               |  |
|   | 3. Security Controls API              | <-- Direction B --- | Controlled Response Engine:   |  |
|   |    (POST /api/public/security/controls|   (Mitigation Cmd)  | Outbound Action Dispatcher    |  |
|   |     /freeze-transaction, etc.)        |                     |                               |  |
|   |                                       |                     |                               |  |
|   | 4. Health & Posture API               | <-- Direction B --- | Target Health Monitor:        |  |
|   |    (GET /api/public/security/health)  |   (Liveness Check)  | Heartbeat & Status Checker    |  |
|   +---------------------------------------+                     +-------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

### 3.1 Ingestion Protocols (Direction A & Direction B)
1. **Direction A (Push / Webhook)**:
   - Target System pushes signed v1.0 JSON telemetry events to `POST https://ecs.domain/api/events`.
   - ECS authenticates the request using the target's shared secret and HMAC-SHA256 headers.
2. **Direction B (Pull / Polling Worker)**:
   - For targets that cannot initiate outbound webhooks, ECS runs a background synchronization worker.
   - ECS requests `GET {target_base_url}/api/public/security/events?since_seq={last_seq}&limit=100`, signing the outbound request using its HMAC credentials.
   - Sequentially updates the high-water mark (`last_synced_seq`) in `target_systems`.

### 3.2 Canonical HMAC-SHA256 Authentication (§10 Standard)
Both directions mandate the 4 canonical headers:
- `X-ECS-Key-Id`: Public identifier of the integration credential.
- `X-ECS-Timestamp`: Unix timestamp in seconds (must be within $\pm 300\text{s}$ of server time).
- `X-ECS-Nonce`: UUIDv4 string, strictly checked against `api_nonces` table to eliminate replay attacks.
- `X-ECS-Signature`: Hex-encoded HMAC-SHA256 signature calculated over the canonical string:
$$\text{CanonicalString} = \text{Timestamp} + \text{"\textbackslash n"} + \text{Nonce} + \text{"\textbackslash n"} + \text{Method.toUpperCase()} + \text{"\textbackslash n"} + \text{PathWithQuery} + \text{"\textbackslash n"} + \text{SHA256}(\text{RawBody})$$

---

## 4. Part-by-Part Implementation Plan

---

### PART 1: Database Migration & Schema Upgrade (v2.0 Entities)
**Objective**: Provision the database tables required for telemetry, detections, target registration, nonces, and response tracking.

#### 1.1 New Migration: `sql/migrations_v3_automated_platform.sql`
Implement and execute the migration containing:
1. `target_systems`:
   - `id UUID PRIMARY KEY`, `name VARCHAR(255)`, `base_url TEXT`, `key_id VARCHAR(100)`, `secret_key TEXT`, `sync_mode VARCHAR(20) CHECK (sync_mode IN ('push', 'pull', 'bidirectional'))`, `poll_interval_seconds INT DEFAULT 5`, `last_synced_seq BIGINT DEFAULT 0`, `is_active BOOLEAN DEFAULT TRUE`, `health_status VARCHAR(50)`, `last_health_check TIMESTAMPTZ`.
2. `security_events`:
   - `id UUID PRIMARY KEY`, `target_system_id UUID REFERENCES target_systems(id)`, `event_id VARCHAR(100) UNIQUE NOT NULL`, `seq BIGINT`, `event_type VARCHAR(100) NOT NULL`, `occurred_at TIMESTAMPTZ NOT NULL`, `source_system VARCHAR(100) NOT NULL`, `user_id_pub VARCHAR(100)`, `account_id_pub VARCHAR(100)`, `session_id_pub VARCHAR(100)`, `device_id_pub VARCHAR(100)`, `source_ip VARCHAR(50)`, `endpoint VARCHAR(255)`, `result VARCHAR(50) NOT NULL`, `amount_minor BIGINT`, `currency VARCHAR(10)`, `attributes JSONB NOT NULL DEFAULT '{}'`, `raw_payload JSONB`, `created_at TIMESTAMPTZ DEFAULT NOW()`.
   - B-tree indexes on `(event_type, occurred_at)`, `source_ip`, `account_id_pub`, `user_id_pub`, `occurred_at DESC`.
3. `detection_rules`:
   - `id VARCHAR(50) PRIMARY KEY` (e.g. `AUTH-001`, `ATO-001`), `name VARCHAR(255)`, `category VARCHAR(50)`, `layer VARCHAR(10) CHECK (layer IN ('L1', 'L2', 'L3', 'L4'))`, `severity VARCHAR(50)`, `weight INT DEFAULT 20`, `thresholds JSONB DEFAULT '{}'`, `is_enabled BOOLEAN DEFAULT TRUE`.
4. `detections`:
   - `id UUID PRIMARY KEY`, `rule_id VARCHAR(50) REFERENCES detection_rules(id)`, `severity VARCHAR(50)`, `score_contribution INT`, `entity_type VARCHAR(50)`, `entity_id VARCHAR(100)`, `summary TEXT`, `evidence JSONB DEFAULT '{}'`, `trigger_event_ids UUID[]`, `detected_at TIMESTAMPTZ DEFAULT NOW()`.
5. `risk_assessments`:
   - `id UUID PRIMARY KEY`, `entity_type VARCHAR(50)`, `entity_id VARCHAR(100)`, `risk_score INT CHECK (risk_score BETWEEN 0 AND 100)`, `risk_level VARCHAR(50)`, `confidence VARCHAR(50)`, `reasons TEXT[]`, `breakdown JSONB`, `assessed_at TIMESTAMPTZ DEFAULT NOW()`.
6. `response_actions`:
   - `id UUID PRIMARY KEY`, `target_system_id UUID REFERENCES target_systems(id)`, `action_type VARCHAR(100) NOT NULL CHECK (action_type IN ('freeze_transaction', 'revoke_session', 'block_ip', 'require_step_up', 'disable_beneficiary', 'lock_account', 'revert'))`, `target_entity_type VARCHAR(50)`, `target_entity_id VARCHAR(100)`, `status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'failed', 'reverted'))`, `alert_id UUID REFERENCES alerts(id)`, `incident_id UUID REFERENCES incidents(id)`, `reason TEXT NOT NULL`, `requested_by UUID REFERENCES users(id)`, `requested_at TIMESTAMPTZ DEFAULT NOW()`, `confirmed_at TIMESTAMPTZ`, `target_response JSONB`.
7. `api_nonces`:
   - `id UUID PRIMARY KEY`, `key_id VARCHAR(100) NOT NULL`, `nonce VARCHAR(100) NOT NULL UNIQUE`, `expires_at TIMESTAMPTZ NOT NULL`, `created_at TIMESTAMPTZ DEFAULT NOW()`.
   - Index on `expires_at` for TTL purging.
8. Update existing tables:
   - Add `target_system_id UUID` to `transactions`, `alerts`, `incidents`.
   - Add `evidence JSONB` and `risk_score INT` to `alerts`.

---

### PART 2: Ingestion & Target Synchronization Engine
**Objective**: Build reliable ingestion via push (webhook) and pull (poller) that streams data into `security_events` and entity tables.

#### 2.1 Persistent Nonce Replay & HMAC Middleware
- Update [`backend/app/routes/events.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/routes/events.py):
  - Replace in-memory `SEEN_NONCES` with atomic insert into `api_nonces` table.
  - Reject replayed nonces with 401 Unauthorized immediately.
  - Look up target system secret dynamically from `target_systems` based on `X-ECS-Key-Id`.

#### 2.2 Ingestion & Entity Extraction Pipeline
- In `events.py` `receive_event`:
  - Validate common envelope fields (`event_id`, `event_type`, `occurred_at`, `source_system`, `result`).
  - Idempotently insert into `security_events`.
  - Extract entities into existing tables:
    - If `TRANSFER_CREATED` or `TRANSFER_INITIATED`: insert/update normalized record in `transactions`.
    - If `source_ip` present with suspicious flag or failed authentication: insert/upsert into `indicators`.
    - If `device_id_pub`: record into target devices cache.
  - **Immediately invoke the Real-Time Detection Engine** on the new event:
    ```python
    from app.services.detection_engine import evaluate_event_stream
    evaluate_event_stream(event_record)
    ```

#### 2.3 Outbound Target Polling Daemon
- Create [`backend/app/services/poller_service.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/services/poller_service.py):
  - Background worker running via thread or scheduled task.
  - Queries active targets with `sync_mode IN ('pull', 'bidirectional')`.
  - Makes HMAC-signed request to `GET {target_base_url}/api/public/security/events?since_seq={last_seq}&limit=100`.
  - Ingests batch through the same pipeline as the push endpoint.
  - Updates `last_synced_seq` atomically.
  - Checks health via `GET {target_base_url}/api/public/security/health` every 60s and updates `target_systems.health_status`.

---

### PART 3: Automated Multi-Layer Detection, Correlation & Risk Engine
**Objective**: Replace ad-hoc evaluation with a continuous 4-layer detection engine conforming to SRS §9 and §21.

Create [`backend/app/services/detection_engine.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/services/detection_engine.py):

#### 3.1 Layer 1: Threshold & Signature Rules (Fast Filter)
- `AUTH-001 (Login Failure Burst)`:
  - Trigger: $\ge 5$ `LOGIN_FAILED` events for the same identifier/user within a 60-second sliding window.
  - Contribution: $+25$ points. Severity: `medium`.
- `API-001 (Authorization Failure Burst)`:
  - Trigger: $\ge 4$ `AUTHZ_DENIED` events from the same source IP/session within 60 seconds.
  - Contribution: $+30$ points. Severity: `medium`/`high`.

#### 3.2 Layer 2: Contextual Entity Rules (Stateful Context)
- `AUTH-003 (New Device Login After Failures)`:
  - Trigger: `LOGIN_SUCCESS` where `attributes.new_device == true` within 5 minutes after `LOGIN_FAILED` burst on the same account.
  - Contribution: $+35$ points. Severity: `high`.
- `TX-003 (Off-Hours High-Value Transfer)`:
  - Trigger: `TRANSFER_CREATED` where amount $\ge 100,000\text{ ETB}$ occurring between 00:00 and 05:00 Addis Ababa time (`attributes.off_hours == true`).
  - Contribution: $+25$ points. Severity: `high`.
- `TX-004 (Untrusted / First-Time Device Transfer)`:
  - Trigger: `TRANSFER_CREATED` initiated from a device marked `is_trusted == false` or device age $< 1\text{ hour}$.
  - Contribution: $+25$ points. Severity: `high`.

#### 3.3 Layer 3: Multi-Event Correlation Engine (Attack Chains)
- `ATO-001 (Account Takeover Chain)`:
  - Evaluates sliding window across 15 minutes for the target account:
    $$\text{LOGIN\_FAILED} \ge 3 \longrightarrow \text{LOGIN\_SUCCESS (new device)} \longrightarrow \text{DEVICE\_REGISTERED} \longrightarrow \text{BENEFICIARY\_CREATED} \longrightarrow \text{TRANSFER\_CREATED}$$
  - Trigger: Detection of this sequential chain.
  - Contribution: $+80$ points. Severity: `critical`.
- `CORR-001 (Shared Device Across Accounts)`:
  - Trigger: Same `device_id` observed across $\ge 3$ distinct accounts within 48 hours.
  - Contribution: $+40$ points. Severity: `high`.
- `API-002 (Enumeration Probing Pattern)`:
  - Trigger: Sequential parameter probing across distinct numeric IDs resulting in mixed DENIED/SUCCESS.
  - Contribution: $+35$ points. Severity: `high`.

#### 3.4 Layer 4: Explainable Risk Synthesis & Scoring Model (§9.3)
- Calculates cumulative risk:
  $$\text{RawScore} = \text{BaseRisk} + \sum \text{RuleContributions}$$
  $$\text{CappedRiskScore} = \min(100, \text{RawScore})$$
- Severity mapping:
  - $0 - 24$: `low`
  - $25 - 49$: `medium`
  - $50 - 74$: `high`
  - $75 - 100$: `critical`
- Records `risk_assessments` row containing full explainability breakdown (`reasons`, `breakdown`, `trigger_event_ids`).

---

### PART 4: Autonomous Alerting, Incident Promotion & Threat Intelligence
**Objective**: Eliminate manual incident creation by automatically generating alerts and promoting critical findings into incidents with linked indicators.

#### 4.1 Automated Alert Dispatcher
- When any rule fires:
  - Create row in `alerts`:
    - `title`: e.g., `"CRITICAL: Account Takeover Chain Detected on ACC_CHALTU_1"`
    - `alert_type`: `'account_takeover'`, `'fraud'`, `'credential_attack'`, etc.
    - `severity`: derived from risk score (`critical`, `high`, `medium`).
    - `status`: `'open'`
    - `evidence`: JSON object containing triggering event IDs, rule contributions, and IP/device context.
    - `related_transaction_id`: linked if transfer event was part of evidence.

#### 4.2 Automated Incident Promotion
- For any alert with severity `critical` or `high` where multiple correlated rules fired:
  - Check if an active incident for that entity (`account` or `user`) already exists within the last 4 hours.
  - If exists: append alert and events to the existing incident; re-calculate incident risk score.
  - If not exists: **automatically create a new incident in `incidents` table**:
    - `title`: `"Investigate: Account Takeover on {account_id}"`
    - `incident_type`: `'account_takeover'`
    - `severity`: `'critical'`
    - `status`: `'open'`
    - `risk_score`: calculated risk score
    - `risk_level`: `'critical'`
    - `risk_reasons`: explainable rule triggers
  - Link the alert to `incidents.id`.

#### 4.3 Automated Threat Intelligence & Indicator Linking
- Automatically extract IPs and device hashes from triggering events.
- Upsert into `indicators` table with status `'malicious'` (for critical correlations) or `'suspicious'` (for bursts).
- Insert join row into `incident_indicators` linking the indicator to the new incident.
- Cross-reference with `watchlists`; if matched, escalate alert priority.

---

### PART 5: Closed-Loop Controlled Response & Mitigation Dispatcher
**Objective**: Safely execute target containment commands against high-confidence threats and verify enforcement.

#### 5.1 Outbound Mitigation Engine
Enhance [`backend/app/services/target_system_service.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/services/target_system_service.py):
- Implement standard mitigation functions:
  1. `freeze_target_transaction(target, tx_public_id, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/freeze-transaction`
  2. `revoke_target_session(target, session_public_id, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/revoke-session`
  3. `block_target_ip(target, ip_address, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/block-ip`
  4. `require_step_up(target, user_public_id, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/require-step-up`
  5. `disable_beneficiary(target, beneficiary_public_id, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/disable-beneficiary`
  6. `lock_account(target, account_public_id, reason, alert_id)` $\rightarrow$ calls `POST /api/public/security/controls/lock-account`
  7. `revert_target_action(target, control_action_id, reason)` $\rightarrow$ calls `POST /api/public/security/controls/revert`

#### 5.2 Auto-Containment Policy Engine
Create [`backend/app/services/response_policy.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/services/response_policy.py):
- Reads system containment settings:
  - If `auto_containment_enabled == true`:
    - When `ATO-001` (Account Takeover) fires on a `TRANSFER_CREATED` event held in `PROCESSING` state:
      1. Insert `response_actions` row (`status='pending'`).
      2. Call `freeze_target_transaction` to freeze funds before settlement.
      3. Call `revoke_target_session` to terminate the rogue attacker session.
      4. Verify target returns `200 CONFIRMED`.
      5. Update `response_actions.status = 'confirmed'`.
      6. Update incident status to `'contained'`.
      7. Record audit log entry.
  - If `auto_containment_enabled == false`:
    - Present containment action as a **1-click recommended action** in the analyst UI.

---

### PART 6: Target Lab Simulator & Scenario Orchestration Controller
**Objective**: Allow ECS analysts and judges to remotely launch testbed attack scenarios to demonstrate automated detection in real-time.

#### 6.1 Remote Scenario Dispatcher Endpoint
Create `POST /api/lab/trigger-scenario` in [`backend/app/routes/live.py`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/app/routes/live.py):
- Accepts: `{ "target_id": "...", "scenario": "account_takeover", "simulated_ip": "198.51.100.44" }`.
- Signs outbound request with `lab:run` scope HMAC credential.
- Dispatches to `{target_base_url}/api/public/lab/run-scenario`.
- Returns scenario timeline to the analyst UI.
- The target system then executes the scenario, pushing telemetry back to ECS, completing the live demonstration loop.

---

### PART 7: Real-Time SOC Experience & Frontend Transformation
**Objective**: Overhaul the vanilla JS frontend into a live, reactive security command center.

#### 7.1 New / Upgraded Frontend Pages
1. **Live Threat Stream ([`frontend/live-threats.html`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/frontend/live-threats.html))**:
   - Live streaming table of incoming `security_events` with color-coded event types.
   - Filter by Target System, Event Type, and Severity.
   - Live counter cards: Active Incidents, Suspicious Transactions, Blocked IPs, Contained Attacks.
2. **Incident Command & Evidence Timeline ([`frontend/incident-detail.html`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/frontend/incident-detail.html))**:
   - **Attack Chain Visualizer**: Horizontal timeline depicting each phase:
     $$\text{Failed Logins (6x)} \rightarrow \text{New Device} \rightarrow \text{Mule Beneficiary} \rightarrow \text{180k Transfer} \rightarrow \text{Auto-Freeze}$$
   - **Risk Score Breakdown**: Progress bar (0-100) with itemized score contribution badges.
   - **Mitigation Control Card**: Status of containment actions (`FROZEN`, `REVOKED`) with a 1-click **"Rollback / Revert Action"** button.
3. **Target Systems Configuration ([`frontend/settings.html`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/frontend/settings.html))**:
   - Register target application URL, Key ID, and Shared Secret.
   - Toggle Auto-Containment on/off.
   - "Test Connection & Health" button showing real-time ping and posture status.
4. **Forensics & Incident Replay ([`frontend/reports.html`](file:///home/neuron/dev/cybershield/Ethio-Cyber-Shield/frontend/reports.html) or `replay.html`)**:
   - Interactive replay slider allowing judges to scrub through historical incidents step-by-step.

---

### PART 8: Testing, Verification & Competition Demo Runbook
**Objective**: Ensure 100% test coverage and a foolproof competition demonstration script.

#### 8.1 Automated Test Suites in ECS Backend
- Create `backend/tests/test_automated_pipeline.py`:
  1. `test_hmac_verification_and_nonce_replay`: verifies valid HMAC succeeds, corrupted signature fails with 401, duplicate nonce rejected.
  2. `test_telemetry_ingestion_and_normalization`: verifies push of v1.0 event envelope populates `security_events` and entity caches.
  3. `test_ato_correlation_engine`: passes synthetic 10-event sequence for `account_takeover`; asserts `ATO-001` fires, risk score reaches 100, critical alert is emitted, and incident is automatically created.
  4. `test_auto_containment_mitigation`: verifies high-confidence incident triggers `freeze_target_transaction` and logs confirmed response action.
  5. `test_poller_worker_sync`: verifies polling worker pulls new events using `since_seq` and updates high-water mark.

#### 8.2 End-to-End Competition Live Demo Runbook (SRS §22)
1. **Baseline**: Open ECS Dashboard. Show clean system state, target system connected and reporting `healthy`.
2. **Normal Activity**: Run `normal_activity` from Lab Console. Show ordinary low-risk telemetry flowing into ECS with zero alerts created.
3. **Attack Execution**: Trigger `account_takeover` attack scenario via Lab Console.
4. **Automated Ingestion**: Live Telemetry Feed immediately displays 6 failed logins, 1 new device login, 1 beneficiary, and 1 high-value transfer.
5. **Detection & Correlation**: L3 correlation fires `ATO-001`. Risk score jumps to 100 (`critical`).
6. **Automated Incident Creation**: ECS automatically creates Incident `#ATO-XXXX` with full evidence chain and linked malicious IP indicator.
7. **Controlled Containment**: Auto-containment policy dispatches `freeze-transaction` (180,000 ETB held) and `revoke-session` to Target System.
8. **Verification on Target**: Switch to Target System UI. Show transaction status changed to `FROZEN` and sender refunded, attacker session terminated.
9. **Forensics Replay**: Switch back to ECS Incident Detail. Walk judges through the explainable evidence chain and audit log.

---

## 5. Implementation Roadmap & Milestones

```
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 1: Schema & Core Entities (v3 Migration)                                                       |
| - Apply sql/migrations_v3_automated_platform.sql to Supabase                                             |
| - Verify target_systems, security_events, detections, response_actions tables                            |
+----------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 2: Ingestion & Target Poller Engine                                                            |
| - Refactor backend/app/routes/events.py with persistent DB nonces                                         |
| - Build backend/app/services/poller_service.py for outbound pulling                                      |
| - Implement target health check heartbeat                                                                |
+----------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 3: Multi-Layer Detection & Explainable Risk Engine                                             |
| - Build backend/app/services/detection_engine.py (L1 threshold, L2 contextual, L3 correlation)            |
| - Implement L4 explainable risk scoring (0-100) with rule evidence tracking                              |
+----------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 4: Autonomous Incident Promotion & Controlled Response                                         |
| - Build auto-incident promoter in backend/app/services/incident_service.py                               |
| - Build response policy dispatcher in backend/app/services/response_policy.py                            |
| - Connect to target_system_service.py for signed HMAC containment                                        |
+----------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 5: Frontend SOC Transformation & Live Telemetry UI                                            |
| - Update frontend/live-threats.html with live streaming telemetry feed                                   |
| - Upgrade frontend/incident-detail.html with visual attack chain & 1-click mitigation                     |
| - Build target management & pairing screen in settings                                                   |
+----------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------------------------------------------------------------+
| MILESTONE 6: Full Verification & Competition Simulation Run                                              |
| - Execute backend test suite (test_automated_pipeline.py)                                                |
| - Execute end-to-end live attack scenario from target system and verify complete automated loop          |
+----------------------------------------------------------------------------------------------------------+
```

---

### Conclusion & Next Step
With this architecture, **Ethio-Cyber Shield** will fully transition from a manual incident database into an enterprise-grade, real-time autonomous Cyber Defense and SOC platform.

The execution begins with **Milestone 1**: authoring and applying the `migrations_v3_automated_platform.sql` schema migration and implementing the core database entity models.
