# End-to-End Cyber Attack Simulation & Detection Walkthrough
## Running ECS and HonorPay Banking with Burp Suite Interception

> **Institutional Submission**: Official Attack Simulation Guide submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Objective**: Guide security evaluators through executing simulated offensive attack workflows against **HonorPay Banking (`targetsys`)** with **Burp Suite**, and inspecting real-time detection, explainable risk scoring, automated containment, and statutory reporting in **Ethio-Cyber-Shield (ECS)**.  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)

---

## 1. System Architecture & Lab Topology

```
 ┌────────────────────────────────────────────────────────┐
 │                      ATTACKER                          │
 │         Burp Suite Proxy (127.0.0.1:8080)              │
 │         (Repeater / Intruder / Intercept)              │
 └───────────────────────────┬────────────────────────────┘
                             │
            HTTP/REST Attacks (Brute Force, Tampered Tx, IDOR)
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │             TARGET BANK: SHIELDBANK                    │
 │          http://localhost:8081 (targetsys)             │
 │                                                        │
 │  • Customer Portal: /login, /app/transfer              │
 │  • Transactional Outbox (outbox.server.ts)             │
 │  • Security Controls API (/api/public/security/*)      │
 └───────────────────────────┬────────────────────────────┘
                             │
            Signed HMAC-SHA256 Telemetry Ingestion
            (POST /api/events with Anti-Replay Nonce)
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │            DEFENSE PLATFORM: ETHIO-CYBER-SHIELD        │
 │                                                        │
 │  • Core API Engine: http://localhost:5000              │
 │  • SOC Analyst Console: http://localhost:5500          │
 │  • Real-Time Detection Engine (Rules-as-Data)          │
 │  • Risk Model v2 (0–100 Explainable Score)             │
 │  • Incident Readiness Engine (48-Hour Statutory Clock) │
 │  • Automated Safe Response (Freeze Tx, Block IP)       │
 └────────────────────────────────────────────────────────┘
```

---

## 2. Complete Startup Guide: Running the Whole Ecosystem

You will open **three terminal sessions** to launch all microservices:

### Terminal 1: Launch ECS Core API (Port 5000)
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core
source venv/bin/activate
python run.py
```
* **Status**: ECS Core API starts on `http://0.0.0.0:5000`.
* **Services Online**: Flask API, Redis Streams Ingestion Queue, Rule Engine v2, and Background Poller.

### Terminal 2: Launch ECS SOC Analyst Console (Port 5500)
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/ui
python3 -m http.server 5500
```
* **Status**: Web UI console ready at `http://localhost:5500/login.html`.

### Terminal 3: Launch ShieldBank Target Banking System (Port 8081)
```bash
cd /home/neuron/dev/cybershield/targetsys
npm run dev
```
* **Status**: Vite / TanStack Start server running on `http://localhost:8081` (or `8080`).

---

## 3. Credentials & Accounts Quick Reference

### A. Ethio-Cyber-Shield (ECS Security Operations Console)
- **URL**: `http://localhost:5500/login.html`
- **Email**: `admin@cbe.com.et` (or `admin@ethiocybershield.et`)
- **Password**: `Admin@123`
- **Role**: `admin` / Lead SOC Analyst

### B. ShieldBank Testbed (Target Banking App)
- **URL**: `http://localhost:8081/login`
- **Customer Account (Victim)**:
  - Email: `amina@shieldbank.test`
  - Password: `Testbed#2026`
  - Initial Balance: `120,000 ETB`
- **Admin Account**:
  - Email: `admin@shieldbank.test`
  - Password: `Testbed#2026`

---

## 4. Configuring Burp Suite Proxy

1. **Launch Burp Suite**: Open Community or Professional edition on your machine.
2. **Verify Proxy Listener**:
   - In Burp, go to **Proxy** $\to$ **Proxy Settings**.
   - Ensure the listener is running on `127.0.0.1:8080` with status **Running**.
3. **Open Burp's Embedded Browser**:
   - Go to **Proxy** $\to$ **Intercept**.
   - Click **Open Browser** (this uses Burp's pre-configured Chromium instance, which automatically trusts Burp's CA certificate and routes all traffic through `127.0.0.1:8080`).
4. **Target Scope**:
   - In the embedded browser, navigate to: `http://localhost:8081`
   - In Burp, go to **Target** $\to$ **Scope** and add `http://localhost:8081` to your target scope.

---

## 5. Attack Scenarios & Real-Time ECS Detection

---

### Scenario A: Brute-Force Credential Stuffing (`AUTH-001`)

#### Attack Objective
Simulate an attacker attempting to guess customer passwords or perform credential stuffing against `amina@shieldbank.test`.

#### Step 1: Capture Login Request in Burp
1. In the Burp embedded browser, go to `http://localhost:8081/login`.
2. Enter:
   - Email: `amina@shieldbank.test`
   - Password: `WrongPassword123!`
3. In Burp Suite, ensure **Intercept is ON**.
4. Click **Sign In** in the browser.
5. In Burp Suite, observe the captured HTTP request:
   ```http
   POST /login HTTP/1.1
   Host: localhost:8081
   Content-Type: application/json

   {"email":"amina@shieldbank.test","password":"WrongPassword123!"}
   ```

#### Step 2: Send to Burp Intruder / Repeater
1. Right-click the request and choose **Send to Repeater** (or press `Ctrl+R`).
2. Alternatively, for automated bursts, send to **Intruder** (`Ctrl+I`):
   - Set the payload marker on the password field: `{"email":"amina@shieldbank.test","password":"§Wrong§"}`
   - Under **Payloads**, add 5 to 10 arbitrary dictionary passwords.
3. In **Repeater**, click **Send** 5 consecutive times within 30 seconds.
4. Each request receives HTTP 401 `INVALID_CREDENTIALS` from ShieldBank.

#### Step 3: What Happens Under the Hood
1. ShieldBank writes 5 consecutive `LOGIN_FAILED` events to its `security_events` table.
2. The Outbox Worker signs each event with HMAC-SHA256 and dispatches them to ECS:
   `POST http://localhost:5000/api/events`
3. The ECS Ingestion Pipeline verifies the cryptographic signature, checks the nonce against `api_nonces` (anti-replay), and pushes the events to the Redis durable stream.
4. The Detection Engine evaluates rule **`AUTH-001` (Brute Force Detection)**:
   - Condition: $\ge 5$ failed logins on the same account within a 60-second window.
   - Severity: **HIGH**.
   - Risk Contribution: **+75 pts**.

#### Step 4: Inspecting the Attack in ECS
1. Open your browser to the **ECS SOC Console**: `http://localhost:5500/dashboard.html`.
2. Look at the **Live Threat Feed & Alerts Board** (`/alerts.html`):
   - You will see a new **HIGH SEVERITY ALERT**: `AUTH-001: Multiple Consecutive Failed Login Attempts`.
3. Click the Alert to open the **Explainable Evidence Inspector**:
   - **Evaluated Rule**: `AUTH-001`
   - **Target Account**: `amina@shieldbank.test`
   - **Source IP**: `127.0.0.1`
   - **Threshold Condition**: `5 / 5 failed attempts in 24 seconds`
   - **Risk Score**: `75 / 100` (High Risk)
4. Under **Automated Response Action**:
   - If ECS is in `auto` or `recommend` mode, an action `block_ip` or `require_step_up` is initiated for the source IP.

---

### Scenario B: High-Value Fraudulent Fund Transfer & Automated Freeze (`ATO-001` & `fraud_001`)

#### Attack Objective
Simulate an attacker who has hijacked a session and attempts an unauthorized, anomalous transfer of 180,000 ETB (exceeding typical retail thresholds) to an unverified mule account.

#### Step 1: Log in as the Customer
1. In the Burp embedded browser, log in legitimately:
   - Email: `amina@shieldbank.test`
   - Password: `Testbed#2026`
2. Navigate to **Transfer Funds**: `http://localhost:8081/app/transfer`.

#### Step 2: Intercept & Tamper with Transfer in Burp
1. In Burp Suite, toggle **Intercept is ON**.
2. In the transfer form, enter:
   - Amount: `500` ETB
   - Destination: `Bekele (CBE 100012345678)`
3. Click **Transfer Now**.
4. In Burp Proxy, intercept the outgoing request:
   ```http
   POST /app/transfer HTTP/1.1
   Host: localhost:8081
   Content-Type: application/json
   Cookie: sb_access_token=...

   {"from_account_id":"acc-101","beneficiary_account":"100012345678","amount":500,"currency":"ETB"}
   ```
5. **Tamper the Payload in Burp**:
   Change the `amount` from `500` to `180000` (or `250000` ETB):
   ```json
   {"from_account_id":"acc-101","beneficiary_account":"100099999999","amount":180000,"currency":"ETB"}
   ```
6. Click **Forward** in Burp.

#### Step 3: What Happens Under the Hood
1. ShieldBank receives the request, reserves the funds, transitions the transaction to `PROCESSING`, and writes a `TRANSFER_CREATED` security event.
2. The Outbox Worker dispatches the signed telemetry to ECS: `POST /api/events`.
3. ECS Detection Engine evaluates the transaction against the **Ethiopian Payment Fraud Pack**:
   - Rule `fraud_001_high_value_anomaly`: Amount $\ge 150,000$ ETB ($+40$ pts).
   - Rule `fraud_003_new_beneficiary_burst`: New unverified counterparty ($+35$ pts).
   - Rule `ATO-001`: Combined with recent credential anomalies ($+25$ pts).
   - **Total Risk Score**: **100 / 100 (CRITICAL SEVERITY)**.
4. **Autonomous Closed-Loop Containment Fires**:
   - Because severity is **CRITICAL** and risk score is **100**, ECS checks Guardrails (Emergency Kill Switch is OFF, account not allowlisted).
   - ECS dispatches a signed control callback directly to ShieldBank:
     ```http
     POST /api/public/security/controls/freeze-transaction HTTP/1.1
     Host: localhost:8081
     X-ECS-Key-Id: ecs_live_prod_key_01
     X-ECS-Signature: <hmac_sha256>

     {"transaction_id":"tx-critical-180k","reason":"High-velocity payment anomaly exceeding threshold"}
     ```
   - ShieldBank's [`controls.server.ts`](file:///home/neuron/dev/cybershield/targetsys/src/lib/controls.server.ts) intercepts the processing transfer, changes its status to `FROZEN`, and restores the reserved 180,000 ETB to the customer's balance.

#### Step 4: Inspecting the Ongoing Attack & Incident in ECS
1. In the **ECS SOC Console** (`http://localhost:5500/incidents.html`):
   - A new **CRITICAL INCIDENT** is automatically created.
   - **Incident Title**: `Critical Payment Fraud: High-Value Anomaly on Account acc-101`.
   - **Financial Volume Protected**: `ETB 180,000.00`.
2. Inspect the **48-Hour Statutory Clock**:
   - Real-time countdown tracking adherence under **INSA Proclamation No. 1426/2026** (displayed in Addis Ababa local time, UTC+3).
   - **Milestone**: `On Track (0h - 24h)`.
   - Click **Generate EthioCERT Package**: instantly produces submission-ready bilingual dossier (`ECS-IRS-v1.0`).
3. Inspect the **Mitigation Audit**:
   - Under Response Actions: `freeze_transaction` $\to$ `CONFIRMED`.
   - Target Response: `{"status": "CONFIRMED", "message": "Transaction frozen; funds reserved balance restored"}`.
4. Verify in **ShieldBank Admin Portal**:
   - Open `http://localhost:8081/admin/transactions`.
   - Find the 180,000 ETB transfer: its status clearly shows **`FROZEN`**, protecting customer funds from the attacker!

---

### Scenario C: API Reconnaissance & Sequential IDOR Probing (`API-001`)

#### Attack Objective
Simulate an attacker using Burp Intruder to enumerate bank accounts and customer records.

#### Step 1: Capture Account Lookup Request
1. In ShieldBank, perform a beneficiary search or account balance inquiry.
2. In Burp Proxy, send the request to **Intruder** (`Ctrl+I`).

#### Step 2: Configure Burp Intruder
1. In the Positions tab, set payload marker on the identifier:
   `GET /api/public/security/accounts/ACC_100§1§/summary`
2. In the Payloads tab:
   - Type: **Numbers**
   - From: `1`
   - To: `15`
   - Step: `1`
3. Click **Start Attack**.

#### Step 3: Observe ECS Detection
1. In ECS Console (`http://localhost:5500/alerts.html`):
   - ECS fires rule **`API-001: Sequential IDOR Enumeration Anomaly`**.
   - ECS identifies rapid unauthorized access attempts across non-adjacent customer accounts.
   - An alert is flagged with the source IP, and the IP is submitted to the **Temporary Quota Throttling Queue**.

---

## 6. Demonstrating Reversibility (Rollback)

In accordance with Hard Engineering Rule #5 (*Reversible Automated Mitigations*), every automated action can be cleanly undone by an analyst:

1. In the **ECS SOC Console**, open the Frozen Transfer incident.
2. Click **Revert / Rollback Action**.
3. ECS dispatches `POST /api/public/security/controls/revert` with the `control_action_id` to ShieldBank.
4. ShieldBank unfreezes the transaction and records the rollback in the audit ledger.

---

## 7. Summary of Key URLs & Endpoints

| Component | URL / Endpoint | Purpose |
| :--- | :--- | :--- |
| **ShieldBank Web App** | `http://localhost:8081/login` | Target banking portal for testing customer actions |
| **ShieldBank Admin** | `http://localhost:8081/admin` | Operational view of transactions, outbox, and controls |
| **ShieldBank Attack Lab** | `http://localhost:8081/admin/lab` | Built-in scenario generator for automated attack testing |
| **ECS SOC Dashboard** | `http://localhost:5500/dashboard.html` | Real-time threat feed, MTTD/MTTR KPIs, ETB protected |
| **ECS Alerts & Evidence** | `http://localhost:5500/alerts.html` | Explainable detection evidence, feature weights, rule conditions |
| **ECS Incident & 48h Clock**| `http://localhost:5500/incidents.html` | Case management, SLA timers, EthioCERT bilingual dossier |
| **ECS Ingestion API** | `POST http://localhost:5000/api/events` | HMAC-signed event ingress endpoint |
| **ECS Health Check** | `GET http://localhost:5000/api/health` | Platform diagnostics and database health status |
