# Ethio-Cyber-Shield (ECS) — Detection Benchmark & Scenario Library Report (Phase 3.6)

> **Document Version**: 1.0  
> **Status**: APPROVED & VERIFIED (Gate 3 Criteria Satisfied)  
> **Target Release**: ECS v3.0 Independent Platform  
> **Author**: Core Security Architecture & Detection Engineering Team  
> **Last Evaluated**: October 2026  

---

## 1. Executive Summary & Gate 3 Criteria Verification

This report documents the performance of the Ethio-Cyber-Shield declarative detection engine evaluated against the **Attack Lab Benchmark Corpus**. The benchmark suite validates 16 standardized scenarios (13 distinct attack scenarios and 3 benign baseline sequences) across three specialized rule packs: **Fraud & Payments**, **Web & API Abuse**, and **Insider & Admin Threat**.

### Gate 3 Compliance Matrix

| Gate 3 Requirement | Threshold | Evaluated Result | Compliance Status |
| :--- | :---: | :---: | :---: |
| **Attack Scenario Detection Rate** | $\ge 90.0\%$ | **100.00%** | **PASSED** |
| **False Positive Rate (FPR)** | $\le 10.0\%$ | **0.00%** | **PASSED** |
| **Overall Detection Precision** | $\ge 80.0\%$ | **100.00%** | **PASSED** |
| **Overall F1 Score** | $\ge 0.8500$ | **1.0000** | **PASSED** |
| **Scenario Library Diversity** | $\ge 12$ attack scenarios | **13 attack scenarios** | **PASSED** |
| **CI Automated Verification** | Enforced in CI | Added to `.github/workflows/ci.yml` | **PASSED** |

---

## 2. Rule Pack Performance Summary

| Rule Pack | Target Surface | Total Scenarios | Detected Scenarios | Detection Rate | Precision |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`fraud_payments`** | Account Takeover, Mule Syndicates, SIM-Swap, Structuring, USSD Abuse, Coached APP Fraud | 6 | 6 | **100.0%** | **100.0%** |
| **`web_api`** | Credential Stuffing, IDOR Resource Enumeration, Scanner Probing, Bearer Token Replay | 4 | 4 | **100.0%** | **100.0%** |
| **`insider_admin`** | Mass Data Exfiltration, Security Audit Trail Tampering, Dormant Admin Activation | 3 | 3 | **100.0%** | **100.0%** |
| **`benign` (Baseline)** | Routine P2P Retail Transfers, In-Store Merchant QR Payments, Corporate Payroll Credits | 3 | 0 (0 False Positives) | **N/A** (0.0% FPR) | **100.0%** |

---

## 3. Scenario Execution Walkthrough

### A. Fraud & Payments Pack (6 Scenarios)
1. **`SCEN-01-ATO-CHAIN` (Account Takeover Multi-Stage Chain)**:
   - **Sequence**: 5 failed login attempts $\to$ login from new device $\to$ untrusted client hardware registration $\to$ rapid beneficiary addition $\to$ high-value fund transfer (>100k ETB).
   - **Target Rules Fired**: `ATO-001`, `AUTH-001`, `AUTH-003`, `FRAUD-001`, `TX-001`.
   - **Peak Severity**: `CRITICAL` (Score: 100/100).
   - **Outcome**: **DETECTED** (Autonomous containment triggered: transaction held, account locked).

2. **`SCEN-02-MULE-TRANSFER` (Mule Pass-Through Account Funnel)**:
   - **Sequence**: Inbound deposit of 180,000 ETB followed immediately by high-velocity outbound dissipation (>85%) to split destination accounts.
   - **Target Rules Fired**: `FRAUD-002`, `TX-001`.
   - **Peak Severity**: `CRITICAL` (Score: 100/100).
   - **Outcome**: **DETECTED**.

3. **`SCEN-03-SIM-SWAP` (SIM-Swap Credential Reset with Transfer)**:
   - **Sequence**: Telecom SIM-swap event indicator recorded on mobile subscriber within 2 hours followed by 120,000 ETB transfer.
   - **Target Rules Fired**: `FRAUD-003`, `TX-001`.
   - **Peak Severity**: `CRITICAL` (Score: 100/100).
   - **Outcome**: **DETECTED**.

4. **`SCEN-04-STRUCTURING` (Transaction Structuring Under Limits)**:
   - **Sequence**: Four rapid consecutive transfers of 48,000 ETB structured just below the 50,000 ETB regulatory reporting ceiling.
   - **Target Rules Fired**: `FRAUD-004`.
   - **Peak Severity**: `HIGH` (Score: 50/100).
   - **Outcome**: **DETECTED**.

5. **`SCEN-05-USSD-CASH-OUT` (USSD Session Burst & Agent Abuse)**:
   - **Sequence**: Six high-velocity cash-out operations on USSD/mobile-money agent terminals within 100 seconds.
   - **Target Rules Fired**: `FRAUD-005`.
   - **Peak Severity**: `HIGH` (Score: 50/100).
   - **Outcome**: **DETECTED**.

6. **`SCEN-06-APP-COACHED` (Authorized Push Payment Coached Transfer)**:
   - **Sequence**: 75,000 ETB transfer initiated while an active telephony voice call was in progress to a first-time beneficiary.
   - **Target Rules Fired**: `FRAUD-006`, `TX-001`.
   - **Peak Severity**: `HIGH` (Score: 70/100).
   - **Outcome**: **DETECTED**.

---

### B. Web & API Abuse Pack (4 Scenarios)
7. **`SCEN-07-CRED-STUFFING` (Credential Stuffing Bot Attack)**:
   - **Sequence**: Single botnet IP targeting 8 distinct customer accounts with authentication failures within 40 seconds.
   - **Target Rules Fired**: `AUTH-002`.
   - **Peak Severity**: `MEDIUM` / `HIGH` (Score: 40/100).
   - **Outcome**: **DETECTED**.

8. **`SCEN-08-IDOR-PROBE` (IDOR Sequential Resource Enumeration)**:
   - **Sequence**: Automated traversal probing across sequential account identifiers and statement endpoints.
   - **Target Rules Fired**: `API-002`.
   - **Peak Severity**: `HIGH` (Score: 50/100).
   - **Outcome**: **DETECTED**.

9. **`SCEN-09-BOT-SCANNER` (Automated Security Scanner Reconnaissance)**:
   - **Sequence**: Automated tool requests bearing `sqlmap/1.7#stable` user-agent with SQL injection parameters.
   - **Target Rules Fired**: `API-004`.
   - **Peak Severity**: `HIGH` (Score: 50/100).
   - **Outcome**: **DETECTED**.

10. **`SCEN-10-TOKEN-REPLAY` (Bearer Token Replay and Session Hijack)**:
    - **Sequence**: Intercepted authorization bearer token submitted simultaneously from conflicting IP addresses and device fingerprints.
    - **Target Rules Fired**: `API-003`.
    - **Peak Severity**: `MEDIUM` (Score: 35/100).
    - **Outcome**: **DETECTED**.

---

### C. Insider & Admin Threat Pack (3 Scenarios)
11. **`SCEN-11-MASS-EXFIL` (Mass Customer Data Export Exfiltration)**:
    - **Sequence**: Privileged administrator account invoking bulk export endpoint for 5,000 customer PII and balance records.
    - **Target Rules Fired**: `ADMIN-001`.
    - **Peak Severity**: `CRITICAL` (Score: 75/100).
    - **Outcome**: **DETECTED**.

12. **`SCEN-12-AUDIT-TAMPER` (Security Audit Trail Tampering Attempt)**:
    - **Sequence**: Rogue insider query executing `TRUNCATE TABLE audit_logs; DELETE FROM security_events;`.
    - **Target Rules Fired**: `ADMIN-005`.
    - **Peak Severity**: `CRITICAL` (Score: 85/100).
    - **Outcome**: **DETECTED**.

13. **`SCEN-16-DORMANT-ADMIN` (Dormant Admin Account Activation)**:
    - **Sequence**: Long-dormant administrator account (>30 days inactive) executing off-hours privilege grants at 23:00 EAT.
    - **Target Rules Fired**: `ADMIN-002`, `ADMIN-003`.
    - **Peak Severity**: `CRITICAL` (Score: 75/100).
    - **Outcome**: **DETECTED**.

---

### D. Benign Traffic Baselines (3 Scenarios)
14. **`SCEN-13-BENIGN-RETAIL` (Routine P2P Retail Transfer)**:
    - Normal daytime mobile banking transfers (1,500 ETB and 2,200 ETB) from trusted client devices.
    - **Alerts Fired**: None. **Peak Score**: 0/100 (`LOW`). **Outcome**: **CORRECT (NO FALSE ALARM)**.

15. **`SCEN-14-BENIGN-MERCHANT` (In-Store Merchant QR Payment)**:
    - Regular coffee shop and grocery point-of-sale payments (450 ETB and 600 ETB) in Addis Ababa during business hours.
    - **Alerts Fired**: None. **Peak Score**: 0/100 (`LOW`). **Outcome**: **CORRECT (NO FALSE ALARM)**.

16. **`SCEN-15-BENIGN-SALARY` (Corporate Payroll Credit)**:
    - Scheduled monthly salary disbursements (25,000 ETB and 28,000 ETB) processed via internal batch processing.
    - **Alerts Fired**: None. **Peak Score**: 0/100 (`LOW`). **Outcome**: **CORRECT (NO FALSE ALARM)**.

---

## 4. Continuous Integration (CI) Automation

The benchmark evaluation is integrated directly into the CI pipeline via `labs/run_benchmark.py`:

```bash
# Run standalone benchmark gate check
python labs/run_benchmark.py --min-recall 0.90 --max-fpr 0.10
```

GitHub Actions automatically executes this check on every pull request and push to `main` and `v3-independent`. Any rule modification or parameter regression that causes detection rate to fall below 90% or false positive rate to exceed 10% automatically breaks the build before deployment.
