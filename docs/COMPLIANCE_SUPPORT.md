# Ethio-Cyber-Shield (ECS) — Regulatory Compliance Support & Evidence Readiness Guide

> **Institutional Submission**: Official Regulatory Specification submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Document Version**: v1.0 (Phase 5 Deliverable)  
> **Platform Version**: ECS v3.0 Independent Defense  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)  
> **Applicable Mandates**:  
> 1. Proclamation No. 1426/2026 (Critical Infrastructure Cybersecurity)  
> 2. National Bank of Ethiopia (NBE) Financial Cyber Resilience Directives  
> 3. Personal Data Protection Proclamation No. 1321/2024 (PDPP)  
> **Target Audience**: Chief Information Security Officers (CISOs), SOC Directors, Internal Auditors, Regulatory Inspectors (INSA / NBE)

---

## 1. Important Legal Notice & Scope of Assistance

> [!IMPORTANT]
> **Strict Non-Overclaiming Statement (Rule #6 & ADR-001)**:  
> Ethio-Cyber-Shield (ECS) provides **technical evidence collection, automated timestamping, cryptographic hashing, and incident-readiness assistance**.  
> **ECS does not grant or guarantee legal compliance with INSA, NBE, or PDPP requirements.**  
> Compliance is an organizational, legal, and operational responsibility of the licensed operator. The platform strictly claims *"supports evidence for"* or *"partially supported"*, and never *"compliant"* or *"guarantees compliance"*.

---

## 2. Statutory Frameworks & Clause Mapping Register

The following register details the technical capabilities in ECS that support evidence collection for Ethiopian regulatory scrutiny:

| Framework | Statutory Clause | Requirement Summary | ECS Evidence Capability | Support Status |
| :--- | :--- | :--- | :--- | :--- |
| **INSA Proc. No. 1426/2026** | **Part 4, §18** | Mandatory incident reporting to National CERT within 48 hours of detection. | 48-Hour Countdown Clock with escalating reminders at 24h, 36h, and 44h (`Africa/Addis_Ababa` time); explicit detection timestamp lock; EthioCERT submission package generator (`incident_report_v1.0.json`). | **Supports Evidence For** |
| **INSA Proc. No. 1426/2026** | **Part 4, §19** | Immediate and safe operational incident containment. | Declarative response playbooks (`PB-001` through `PB-004`); emergency per-tenant Kill Switch; allowlists protecting critical settlement rails (EthSwitch, RTGS); two-person dual approvals for irreversible actions. | **Supports Evidence For** |
| **INSA Proc. No. 1426/2026** | **Part 4, §20** | Forensic telemetry preservation and immutable chain of custody. | Evidence Vault capturing raw events, IOCs, alerts, and actions with SHA-256 manifests (`telemetry_sha256_digest`, `manifest_sha256`); chain-of-custody audit trail. | **Supports Evidence For** |
| **NBE Directives** | **Section 6** | Real-time payment rail fraud monitoring and interception. | Real-time event contract v1.1 stream processing; Fraud & Payments Rule Pack (ATO, mule networks, SIM-swap, USSD bursts); explainable statistical baselines in ETB. | **Supports Evidence For** |
| **NBE Directives** | **Section 8** | Incident post-mortem documentation and financial loss mitigation. | Auto-compiled bilingual Post-Incident Reviews (PIR); ETB financial exposure and loss prevented assessment; 5 Whys root cause analysis; rule tuning tasks. | **Supports Evidence For** |
| **PDPP Proc. No. 1321/2024** | **Article 31** | Notification of personal data breach affecting customers (within 72h). | Automated reportability classification when customer account records $\ge 100$; data breach telemetry flagging. | **Supports Evidence For** |
| **PDPP Proc. No. 1321/2024** | **Article 32** | Data minimization & masking of financial identifiers. | Mandatory recursive PII scrubbing on notification dispatch and audit logs (`ACC-***1234`, `196.188.***.***`, `+25191****56`, `[MASKED_NATIONAL_ID]`). | **Supports Evidence For** |

---

## 3. The 48-Hour Statutory Clock Workflow

```
Event Occurrence
       │
       ▼
Detection Time ──► [Explicit Detection Timestamp Locked in Africa/Addis_Ababa (UTC+3)]
       │
       ├──► 00h - 24h : [GREEN]       Standard investigation & containment (On Track)
       ├──► 24h - 36h : [YELLOW]      24h Milestone Warning to SOC Responder
       ├──► 36h - 44h : [AMBER]       36h Urgent Warning to Lead CISO & Responder
       ├──► 44h - 48h : [RED]         44h Critical Deadline Notice to Executive Management
       │
       ├──► Submissions: EthioCERT Submission Dossier Dispatched
       │         └──► reported_to_cert_at recorded & cert_reference_no verified
       │
       └──► > 48h (if unsubmitted) : [BREACHED] Statutory Reporting Violation Logged
```

---

## 4. EthioCERT Bilingual Dossier Standard (`ECS-IRS-v1.0`)

When a reportable incident occurs, ECS auto-generates a standardized submission package conforming to `docs/INCIDENT_REPORT_FALLBACK_SPEC.md`.

### Dossier Contents:
1. **Statutory Letterhead & Reference**: Unique reference format `ECS-REP-YYYYMMDD-<short_id>`.
2. **Statutory Time Box**: Earliest activity, exact detection time, elapsed hours, deadline, and compliance status.
3. **Bilingual Executive Summaries**:
   - English: Technical and operational summary.
   - Amharic: Official submission statement (`በአዋጅ ቁጥር 1426/2026 መሰረት የቀረበ የ48 ሰዓት የሳይበር ደህንነት ክስተት ሪፖርት`).
4. **Impact Assessment**: Customer accounts affected, total ETB at risk, total ETB preserved, service downtime.
5. **Technical Findings & Indicators**: Observables (IP, device fingerprint, account hashes) with confidence tags.
6. **Containment Measures**: Target actions dispatched, execution times, reversibility status.
7. **Cryptographic Evidence Manifest**: SHA-256 digest of telemetry events and audit trails, with HMAC signature.
8. **Statutory Attestation**: Certified by CISO or lead officer under administrative sanctions.

---

## 5. Auditor Role & Inspection Access

ECS provisions a dedicated read-only role: `auditor`.
- **Allowed Capabilities**:
  - View Evidence Vaults, manifests, and verification endpoints.
  - Review 48-hour clock status and historical breach logs.
  - Inspect hash-chained audit trails and chain-of-custody records.
  - Export sealed regulatory Audit Packs (`/api/readiness/audit-pack`).
- **Disallowed Capabilities**:
  - Cannot create, modify, or delete detection rules or playbooks.
  - Cannot dispatch or roll back containment mitigations.
  - Cannot access unmasked sensitive PII or decrypted connector secrets.
