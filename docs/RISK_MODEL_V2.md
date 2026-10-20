# Ethio-Cyber-Shield (ECS) — Explainable Risk Model v2 Specification (Phase 3.5)

> **Document Version**: 2.0  
> **Status**: APPROVED & IMPLEMENTED  
> **Target Release**: ECS v3.0 Independent Platform  
> **Author**: Core Security Architecture Team  
> **Last Updated**: October 2026  

---

## 1. Executive Summary & Design Principles

**Risk Model v2** establishes a transparent, deterministic, additive risk scoring and prioritization architecture for Ethio-Cyber-Shield. It replaces monolithic heuristic alert scores with an explainable multi-factor formula evaluating **rule confidence**, **entity criticality**, and **temporal recency decay**, bounded strictly within $[0, 100]$.

### Core Design Principles
1. **Explainable by Default**  
   Every risk calculation produces a full mathematical breakdown displaying exact contributing weights, rule confidence factors, entity criticality multipliers, recency decay coefficients, and raw trigger reasons.
2. **Zero-Baseline False-Alarm Protection**  
   Critical infrastructure entities (e.g., EthSwitch nodes or Core Banking hosts) receive criticality multipliers and score boosts *only* when anomalous or policy-violating activity is present. If the pre-criticality score is 0, the final risk score remains strictly 0.
3. **Explicit Non-Probability Declaration**  
   Under Ethiopian legal requirements (Proclamation No. 1426/2026 and Personal Data Protection Proclamation 1321/2024), risk scores must **never be presented as statistical probabilities of fraud or criminal guilt**. Risk scores are operational priority indices reflecting threat severity and response urgency.
4. **Strict Tenancy Partitioning**  
   Every entity criticality configuration, custom rule threshold, and historical detection is partitioned strictly by `organization_id UUID NOT NULL`.

---

## 2. Mathematical Formulation

Risk Model v2 evaluates risk deterministically through four sequential stages:

```
┌────────────────────────────────┐
│ Fired Rules (L1 - L3)          │──► Confidence Adjuster (High=1.0, Med=0.85, Low=0.70)
└────────────────────────────────┘                                   │
                                                                     ▼
┌────────────────────────────────┐                     ┌───────────────────────────┐
│ Behavioral Baseline Anomaly    │────────────────────►│ Pre-Criticality Sum       │
└────────────────────────────────┘                     └───────────────────────────┘
                                                                     │
┌────────────────────────────────┐                                   ▼
│ Entity Criticality Tier        │────────────────────►┌───────────────────────────┐
│ (Critical, High, Medium, Low)  │                     │ Criticality Multiplier    │
└────────────────────────────────┘                     │ + Criticality Score Boost │
                                                       └───────────────────────────┘
                                                                     │
┌────────────────────────────────┐                                   ▼
│ Temporal Recency Decay         │────────────────────►┌───────────────────────────┐
│ (0-15m, 1h, 6h, 24h, >24h)     │                     │ Clamped Final Score       │
└────────────────────────────────┘                     │ [0, 100]                  │
                                                       └───────────────────────────┘
```

### Step 1: Rule Confidence Weighting
Each rule $r \in \text{FiredRules}$ contributes an effective score adjusted by its confidence rating $C_r$:

$$\text{effective\_rule\_contrib}(r) = \begin{cases} 0 & \text{if } r.\text{is\_shadow} \\ \text{round}(r.\text{weight} \times C_r) & \text{otherwise} \end{cases}$$

Where confidence factors $C_r$ are defined as:
- **`high` ($1.00$)**: High-confidence correlation rules (L3 attack chains, deterministic IOC hash matches, verified multi-factor failures).
- **`medium` ($0.85$)**: Robust single-event behavioral/statistical heuristics (L2 rules, velocity spikes).
- **`low` ($0.70$)**: Exploratory, broad, or advisory indicators (L1 scanner probes, loose parameter anomalies).

$$\text{confidence\_adjusted\_rules} = \sum_{r} \text{effective\_rule\_contrib}(r)$$

### Step 2: Pre-Criticality Additive Synthesis
The baseline anomaly score (from Phase 3.4 statistical deviations) is added to the confidence-adjusted rule contributions:

$$\text{pre\_score} = \text{confidence\_adjusted\_rules} + \text{baseline\_anomaly\_score}$$

### Step 3: Entity Criticality Adjustment & Zero-Baseline Protection
Entities are classified into four criticality tiers based on explicit tenant configuration or automatic keyword inference:

| Tier | Multiplier ($M_e$) | Boost ($B_e$) | Description & Scope |
| :--- | :---: | :---: | :--- |
| **`critical`** | **$1.40\times$** | **$+15$ pts** | National payment rails (EthSwitch Gateway), Core Banking systems, RTGS/ACH nodes, Treasury reserve accounts |
| **`high`** | **$1.20\times$** | **$+8$ pts** | Corporate accounts, branch manager terminals, cashier supervisor consoles, privileged IT admins |
| **`medium`** | **$1.00\times$** | **$+0$ pts** | Standard retail accounts, regular authenticated mobile/web users, standard API clients |
| **`low`** | **$0.90\times$** | **$+0$ pts** | QA/sandbox environments, unauthenticated public health check endpoints |

**Zero-Baseline Protection Rule:**
$$\text{criticality\_adjusted\_score} = \begin{cases} 0 & \text{if } \text{pre\_score} == 0 \\ \text{round}(\text{pre\_score} \times M_e) + B_e & \text{if } \text{pre\_score} > 0 \end{cases}$$

### Step 4: Clamping and Bounding
The operational risk score is clamped strictly between 0 and 100:

$$\text{final\_score} = \max(0, \min(100, \text{criticality\_adjusted\_score}))$$

---

## 3. Recency Decay for Historical Detections

When calculating an entity's current active risk posture over a 24-hour sliding window, historical detections undergo step-wise exponential decay based on elapsed time $\Delta t$:

$$\Delta t = t_{\text{ref}} - t_{\text{event}}$$

| Elapsed Time Window ($\Delta t$) | Decay Factor ($D_t$) | Operational Status |
| :--- | :---: | :--- |
| **$0 \le \Delta t \le 15\text{ minutes}$** | **$1.00$** | **Acute**: Active ongoing attack window |
| **$15\text{ min} < \Delta t \le 1\text{ hour}$** | **$0.85$** | **Elevated**: Recent containment or triage |
| **$1\text{ hour} < \Delta t \le 6\text{ hours}$** | **$0.65$** | **Residual**: Cooling off; residual threat posture |
| **$6\text{ hours} < \Delta t \le 24\text{ hours}$** | **$0.40$** | **Dormant**: Past threat requiring monitoring |
| **$\Delta t > 24\text{ hours}$** | **$0.20$** | **Historical Trace**: Archive baseline reference |

Composite active entity risk combines the peak decayed detection with a diminishing tail of secondary detections:

$$\text{active\_decayed\_risk} = \min\left(100, \text{round}\left(S_{\text{peak}} + 0.25 \sum_{i > 1} S_i\right) \times M_e\right)$$

---

## 4. Severity Tiers & Deterministic Operational Rationales

| Score Range | Severity | Operational Rationale | Recommended Response Action |
| :---: | :---: | :--- | :--- |
| **$75 - 100$** | **`critical`** | *Acute threat to critical infrastructure or high-value funds; immediate autonomous/assisted containment required.* | Autonomous transaction freeze, account freeze, IP block, immediate incident promotion |
| **$50 - 74$** | **`high`** | *Significant threat pattern detected; autonomous response or immediate SOC analyst triage recommended.* | Step-up MFA, temporary session revocation, assisted containment |
| **$25 - 49$** | **`medium`** | *Noticeable behavioral or policy anomaly; elevated monitoring and non-destructive inspection recommended.* | SOC analyst queue assignment, enhanced logging, silent observation |
| **$0 - 24$** | **`low`** | *Sub-threshold operational telemetry; baseline monitoring without escalation.* | Ingest to audit outbox; no analyst interruption |

---

## 5. Non-Probability Declaration

All evaluation payloads and API responses explicitly return:

> *"Deterministic operational risk priority index (0–100); NOT a statistical probability of guilt or fraud."*

This declaration is strictly preserved across all incident summaries, alert exports, and regulatory readiness packages to ensure compliance with INSA evidence admissibility guidelines and PDPP fairness provisions.

---

## 6. REST API Reference

All endpoints are authenticated with JWT and scoped to `g.organization_id`.

### 1. `GET /api/risk/model/spec`
Returns declarative specification, formulas, confidence factors, and recency tiers.

### 2. `POST /api/risk/evaluate`
Dry-run or evaluate risk given fired rules, baseline score, and entity metadata.
```json
{
  "entity_type": "system",
  "entity_id": "ETHSWITCH_CORE_GW",
  "fired_rules": [
    { "rule_id": "API-RULE-01", "name": "API Abuse", "weight": 30, "confidence": "high" }
  ],
  "baseline_score": 0
}
```

### 3. `GET /api/risk/criticality`
Lists entity criticality configurations for the current tenant. Query params: `entity_type`, `tier`.

### 4. `POST /api/risk/criticality`
Create or update entity criticality (Admin or Responder role required).
```json
{
  "entity_type": "system",
  "entity_id": "ETHSWITCH_CORE_GW",
  "criticality_tier": "critical",
  "owner_unit": "National Switch Rails",
  "notes": "Primary interbank clearing switch"
}
```

### 5. `DELETE /api/risk/criticality/<id>`
Delete entity criticality configuration (Admin role required).

### 6. `GET /api/risk/entities/<entity_type>/<entity_id>`
Retrieves composite decayed risk profile, recent detections, and criticality tier for an entity.

---

## 7. Automated Test Verification

The Risk Model v2 service is verified by comprehensive unit and integration test suites:
- **`core/tests/test_part23_risk_model_v2.py`**: 11 dedicated test cases covering confidence factors, criticality tiers, zero-baseline protection, keyword inference, recency decay, non-probability declarations, multi-tenant isolation, composite profiles, detection engine integration, and REST APIs.
- **`core/tests/test_part22_behavioral_baselines.py`**: 8 test cases verifying statistical baseline synthesis with Risk Model v2.
- **`core/tests/test_part19_rules_as_data.py`**: 9 test cases verifying declarative rules evaluation with Risk Model v2.
- **`core/tests/test_part3_detection_engine.py`**: 10 test cases verifying detection engine regression safety.
- **Result**: **100% test pass rate across all suites.**
