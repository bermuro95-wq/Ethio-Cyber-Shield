# Ethio-Cyber-Shield (ECS) v3.0 — Comprehensive Attack Simulation & Detection Testing Guide

> **Target Audience**: SOC Analysts, Penetration Testers, Security Engineers, and Competition Evaluators.  
> **Platform Version**: Ethio-Cyber-Shield (ECS) Independent v3.0  
> **Target Application**: ShieldBank Digital Banking Application (`targetsys`)  
> **Classification**: Security Operations & Verification Runbook (TLP:CLEAR)

---

## 1. System Topology & Architecture

The testing lab consists of three decoupled components communicating over standard local networks:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ATTACKER WORKSTATION                            │
│  Burp Suite Pro / Community (Proxy: 127.0.0.1:8081 or 8080)            │
│  • Repeater (Payload Replay & Parameter Tampering)                     │
│  • Intruder (Credential Stuffing & Rate Limit Probing)                 │
│  • Automated Scripts (Python / cURL / Security Tool Scanners)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP Attacks / Probing
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   TARGET BANKING SYSTEM (ShieldBank)                   │
│  Web Application: http://localhost:8080 (targetsys)                    │
│  • Customer & Admin Portals (/login, /app/transfer, /admin)            │
│  • Security Instrumentation & Outbox (lib/outbox.server.ts)            │
│  • Bidirectional Security Controls API (/api/public/security/*)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Signed HMAC-SHA256 Telemetry
                                    │ (POST http://localhost:5000/api/events)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   ETHIO-CYBER-SHIELD (ECS PLATFORM)                    │
│  Defense Engine API: http://localhost:5000                             │
│  SOC Analyst Console: http://localhost:5500                            │
│  • Ingestion & Bounded Stream Queue (Redis / DB durable stream)        │
│  • Multi-Pack Detection Engine (27 Declarative Rules-as-Data)          │
│  • Real-Time Threat Dossier & Device Fingerprint Engine                │
│  • Instant SSE Live Alert Broadcaster (/api/live/stream)               │
│  • Closed-Loop Safe Containment (Freeze Tx, Block IP, Revoke Session)  │
└────────────────────────────────────────────────────────────────────────┘
```

### Lab Ports & Endpoints Reference

| Service | Local URL / Port | Purpose | Default Credentials |
| :--- | :--- | :--- | :--- |
| **Target Banking App** | `http://localhost:8080` | ShieldBank retail & corporate banking | `admin@shieldbank.test` / `Testbed#2026`<br>`amina@shieldbank.test` / `Testbed#2026` |
| **ECS Core API** | `http://localhost:5000` | Ingestion, Rule Evaluation, Risk Model | Scoped HMAC Keys / JWT Tokens |
| **ECS SOC Console** | `http://localhost:5500` | Security Operations Dashboard | `admin@ethiocybershield.et` / `Admin@123` |
| **Burp Suite Proxy** | `127.0.0.1:8081` *(or 8080)* | HTTP Interception, Repeater, Intruder | N/A |

---

## 2. Lab Startup: Running the Ecosystem

Open **three terminal tabs** to run the complete environment:

### Terminal 1: ECS Core Backend (Port 5000)
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend
source venv/bin/activate
python run.py
```
* **Expected Output**: `* Running on http://127.0.0.1:5000`

### Terminal 2: ECS SOC Web Console (Port 5500)
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/ui
python3 -m http.server 5500
```
* **Expected Output**: `Serving HTTP on 0.0.0.0 port 5500`
* **Access**: Navigate to `http://localhost:5500/login.html` and sign in with `admin@ethiocybershield.et` / `Admin@123`.

### Terminal 3: ShieldBank Target Application (Port 8080)
```bash
cd /home/neuron/dev/cybershield/targetsys
npm run dev
```
* **Expected Output**: `VITE v5.x ready in ... ms -> Local: http://localhost:8080/`

---

## 3. Configuring Burp Suite for Testing

1. **Launch Burp Suite** (Community or Professional).
2. **Verify Proxy Listener**:
   * Navigate to **Settings** $\to$ **Tools** $\to$ **Proxy**.
   * By default, Burp listens on `127.0.0.1:8080`.  
     *(Note: If ShieldBank is running on 8080, adjust Burp's Proxy Listener to port `8081`, or set ShieldBank to proxy through Burp).*
3. **Use Burp Embedded Browser (Recommended)**:
   * Go to **Proxy** $\to$ **Intercept**.
   * Click **Open Browser**. Burp launches an isolated Chromium instance pre-configured to trust its proxy CA certificate.
   * In the browser address bar, navigate to `http://localhost:8080`.
4. **Target Scope**:
   * Go to **Target** $\to$ **Scope Settings**.
   * Click **Add** and specify `http://localhost:8080`.

---

## 4. Attack Simulations & Detection Playbooks

---

### Scenario 1: Rapid Credential Brute-Force (`AUTH-001`)

* **Threat Objective**: Attackers attempt to guess customer credentials via rapid dictionary or brute-force attempts against a specific account.
* **Detection Rule**: `AUTH-001` (Login Failure Burst)
* **Trigger Threshold**: $\ge 5$ consecutive `LOGIN_FAILED` events on the same account within a 60-second sliding window.
* **Severity**: `MEDIUM` / `HIGH` (Risk Score +35 to +75).

#### Execution via Burp Suite:
1. In the Burp Embedded Browser, go to `http://localhost:8080/login`.
2. Enter:
   * **Email**: `amina@shieldbank.test`
   * **Password**: `WrongPass#2026!`
3. Ensure **Proxy Intercept** is ON, and click **Sign In**.
4. In Burp Proxy, inspect the captured POST request:
   ```http
   POST /_serverFn/6d4b29dcb4b664e5b9e190280c200c64479ce35a61ed4a534b0d4706e66654ba HTTP/1.1
   Host: localhost:8080
   User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
   Content-Type: application/json
   Origin: http://localhost:8080

   {"data":{"email":"amina@shieldbank.test","password":"WrongPass#2026!"}}
   ```
5. Press `Ctrl+R` to send to **Repeater**.
6. In Repeater, click **Send** **5 consecutive times** within 20 seconds.
7. Each response returns HTTP 200 with `{ "ok": false, "error": "Invalid email or password." }`.

#### What Happens Under the Hood:
1. ShieldBank logs 5 failed attempts in `security_events` table.
2. The Outbox Worker dispatches signed HMAC payloads to `http://localhost:5000/api/events`.
3. ECS Ingestion Pipeline verifies HMAC-SHA256 and feeds the event stream.
4. Detection Engine fires `AUTH-001`, synthesizes the attack dossier, and streams the alert via SSE.

#### Verifying in ECS Console:
1. Open `http://localhost:5500/dashboard.html`.
2. Observe the alert row appearing **immediately in real time** with a sound chime and pulsing animation:
   * **Rule**: `AUTH-001: Login Failure Burst`
   * **Target**: `amina@shieldbank.test`
   * **Origin**: Source IP with country flag and carrier (`Ethio Telecom (AS24757)`).
3. Click **Investigate** to open the **Attack Dossier Modal**:
   * Inspect the exact client User-Agent and OS.
   * View the SHA-256 evidence seal.
   * Click **[ ⛔ Block Attacker IP ]** to immediately blacklist the IP on ShieldBank.

---

### Scenario 2: Security Scanner & Penetration Tool Probing (`API-004`)

* **Threat Objective**: Attackers run offensive reconnaissance tools (Burp Suite Intruder, sqlmap, Nikto, dirbuster) against target endpoints.
* **Detection Rule**: `API-004` (Automated Bot and Security Tool Scanning)
* **Trigger Threshold**: HTTP request User-Agent containing known scanner signatures (`sqlmap`, `nikto`, `gobuster`, `dirbuster`, `burp`).
* **Severity**: `HIGH` (Risk Score +30).

#### Execution via Burp Suite / cURL:
Execute an HTTP probe with a custom scanner User-Agent:

```bash
curl -X POST http://localhost:8080/api/public/security/health \
  -H "User-Agent: sqlmap/1.8.4#stable (https://sqlmap.org)" \
  -H "X-Forwarded-For: 196.188.12.55"
```
Or with Burp Suite Repeater:
1. Intercept any request to `http://localhost:8080`.
2. In Burp Repeater, modify the `User-Agent` header to:
   ```http
   User-Agent: Mozilla/5.0 (compatible; Nikto/2.1.6; Host: shieldbank.test)
   ```
3. Send the request.

#### Verifying in ECS Console:
1. In the ECS Dashboard (`/dashboard.html` or `/alerts.html`), look at the newly generated alert.
2. The **Attacker Client & Device Fingerprint** card highlights:
   * **Tool Name**: `Nikto Web Vulnerability Scanner` (or `sqlmap SQL Injection Engine`).
   * **Category**: `Automated Offensive Security Scanner`.
   * **Reputation**: `Suspicious (Tool Detected)`.
   * **Raw Header**: Full captured User-Agent string.

---

### Scenario 3: High-Value Fraudulent Fund Transfer & Automated Freeze (`TX-001` & `fraud_001`)

* **Threat Objective**: An unauthorized actor initiates an anomalous high-value transfer (> 100,000 ETB) to an unverified beneficiary.
* **Detection Rule**: `TX-001` (High-Value Transfer Anomaly) + Risk Model v2 Criticality Multiplier.
* **Trigger Threshold**: Single transfer amount $\ge 100,000.00$ ETB.
* **Severity**: `HIGH` / `CRITICAL` (Risk Score +80 to +100).

#### Execution via Burp Suite:
1. Log into ShieldBank customer portal as `amina@shieldbank.test` / `Testbed#2026`.
2. Go to **Transfer Funds** (`/app/transfer`).
3. Fill in the transfer form:
   * **Beneficiary**: `100098765432` (Mule Account)
   * **Amount**: `250000` ETB
4. Turn on Burp **Intercept**.
5. Click **Transfer Now**.
6. In Burp Proxy, view the outgoing transfer payload. Tamper with the amount or beneficiary if desired, then click **Forward**.

#### What Happens Under the Hood:
1. ShieldBank marks the transaction as `held_for_review: true` if it exceeds high-value limits.
2. An event of type `TRANSFER_CREATED` is emitted with `amount: 250000` and `currency: ETB`.
3. ECS Detection Engine evaluates `TX-001`.
4. Because the score reaches Critical ($\ge 80$), ECS automatically initiates **Closed-Loop Autonomous Containment**:
   * Calls ShieldBank API: `POST /api/public/security/controls/freeze-transaction`
   * Transaction status is placed in `FROZEN` / `HELD`.

#### Verifying in ECS Console:
1. In `dashboard.html`, inspect the alert:
   * **Title**: `TX-001: High-Value Transfer Anomaly`
   * **Value**: `250,000 ETB`
   * **Action Dispatched**: `freeze-transaction` confirmed.
2. In the Attack Dossier Modal:
   * Review the victim account and recipient details.
   * If the transaction was verified legitimate, click **[ Revert Action ]** to unfreeze the transfer.

---

### Scenario 4: Full Multi-Stage Account Takeover Chain (`ATO-001`)

* **Threat Objective**: The complete attack chain: An adversary brute-forces customer credentials, logs in successfully, registers a new beneficiary, and attempts an immediate fund extraction.
* **Detection Rule**: `ATO-001` (Account Takeover Correlation Chain)
* **Trigger Sequence**:
  1. $\ge 3$ `LOGIN_FAILED` events.
  2. Followed by $1$ `LOGIN_SUCCESS`.
  3. Followed by `BENEFICIARY_CREATED`.
  4. Followed by `TRANSFER_CREATED` on the same account within 900 seconds.
* **Severity**: `CRITICAL` (Score: 100/100, MITRE ATT&CK T1078).

#### Execution Sequence:
* **Step 1 (Failures)**: Send 3 failed logins for `amina@shieldbank.test` via Burp Repeater.
* **Step 2 (Success)**: Log in legitimately with `amina@shieldbank.test` / `Testbed#2026`.
* **Step 3 (Beneficiary)**: Add a new beneficiary (`Bekele Mule`, `100088889999`).
* **Step 4 (Transfer)**: Submit a transfer of `120000` ETB.

#### Result in ECS:
* **Alert Fired**: `ATO-001: Full Account Takeover Chain Detected`.
* **Automatic Incident Promotion**: ECS automatically creates a **Severity 1 Incident** with an active statutory regulatory countdown clock (48 hours per NBE / INSA requirements).
* **Multi-Action Containment**: Triggers fund freeze, attacker session revocation, and IP blocklist entry simultaneously.

---

### Scenario 5: Sequential IDOR Resource Enumeration (`API-002`)

* **Threat Objective**: An attacker probes consecutive account numbers or sequence IDs to discover valid customer account details (Insecure Direct Object Reference).
* **Detection Rule**: `API-002` (Sequential Resource Enumeration Probing)
* **Trigger Threshold**: Rapid sequential integer increments on resource identifiers within 60 seconds.
* **Severity**: `HIGH` (Risk Score +35).

#### Execution via Burp Intruder:
1. In Burp Suite, make a GET request to:
   `http://localhost:8080/api/public/security/accounts/ACC_1001`
2. Send to **Intruder** (`Ctrl+I`).
3. Set payload marker: `/api/public/security/accounts/ACC_§1001§`.
4. Under **Payloads**:
   * Type: **Numbers**
   * From: `1001`
   * To: `1020`
   * Step: `1`
5. Click **Start Attack**.

#### Verifying in ECS Console:
* ECS flags `API-002: Sequential Resource Enumeration Probing`.
* The Dossier displays the probing pattern, tool signature, and origin IP.

---

## 5. Direct Telemetry Testing (Automated Simulation Scripts)

You can also trigger detections directly via the command line without browser interaction using the included Python simulation suite.

### Running the Python Attack Simulator

Create a script `scripts/test_simulations.py` (or execute via `python3`):

```python
#!/usr/bin/env python3
"""
Ethio-Cyber-Shield Attack Simulation Harness
Directly transmits signed telemetry events to verify real-time ECS detection.
"""
import time
import requests
import uuid

ECS_INGEST_URL = "http://localhost:5000/api/events"
TARGET_BANK = "shieldbank-testbed"

def send_event(event_type, account_id, ip, user_agent="Mozilla/5.0", amount=None, extra=None):
    payload = {
        "schema_version": "1.0",
        "event_id": f"sim-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_system": TARGET_BANK,
        "account_id": account_id,
        "source_ip": ip,
        "endpoint": "/login" if "LOGIN" in event_type else "/app/transfer",
        "result": "FAILURE" if "FAILED" in event_type else "SUCCESS",
        "amount": amount,
        "currency": "ETB" if amount else None,
        "attributes": {
            "user_agent": user_agent,
            **(extra or {})
        }
    }
    # FLASK_DEBUG allows 'dev-bypass' HMAC signature in development
    headers = {
        "Content-Type": "application/json",
        "X-ECS-Key-Id": "ecs-outbound-key-01",
        "X-ECS-Timestamp": str(int(time.time())),
        "X-ECS-Nonce": str(uuid.uuid4()),
        "X-ECS-Signature": "dev-bypass"
    }
    resp = requests.post(ECS_INGEST_URL, json=payload, headers=headers)
    print(f"[{event_type}] Account: {account_id} -> HTTP {resp.status_code}")
    return resp.json()

if __name__ == "__main__":
    print("=== 1. Simulating Burp Suite Brute Force (AUTH-001) ===")
    attacker_ip = "196.188.12.55"  # Addis Ababa Ethio Telecom IP
    burp_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) BurpSuite/2026.1"
    
    for i in range(5):
        send_event("LOGIN_FAILED", "amina@shieldbank.test", attacker_ip, user_agent=burp_ua)
        time.sleep(0.5)

    print("\n=== 2. Simulating Scanner Probe (API-004) ===")
    send_event("API_REQUEST", "admin@shieldbank.test", "197.156.70.1", user_agent="sqlmap/1.8.4 (https://sqlmap.org)")

    print("\n=== 3. Simulating High-Value Fraud (TX-001) ===")
    send_event("TRANSFER_CREATED", "amina@shieldbank.test", "196.188.12.55", amount=350000.0)

    print("\nSimulation complete. Open http://localhost:5500/dashboard.html to inspect real-time alerts!")
```

Run the script:
```bash
python3 scripts/test_simulations.py
```

---

## 6. Verifying Results in the ECS SOC Console

### A. Real-Time Overview (`http://localhost:5500/dashboard.html`)
* **KPI Metrics**: Watch the **Total Alerts**, **High Risk Detections**, and **Active Incidents** counters update instantly.
* **Target Pipeline Health**: Confirms ShieldBank connector status is **HEALTHY (Polling Active)** with current sequence numbers.
* **Live Feed Table**: Every attack appears as a distinct row detailing:
  * Local Time (`Africa/Addis_Ababa`, UTC+3)
  * Severity Badge (`CRITICAL`, `HIGH`, `MEDIUM`)
  * Matched Rule ID (`AUTH-001`, `API-004`, `TX-001`)
  * Origin Country Flag & Ethiopian Carrier (`🇪🇹 Ethio Telecom AS24757`)
  * Client Software & OS (`Burp Suite Professional`, `Linux x86_64`)
  * Targeted Account & Destination

### B. Attack Investigation Dossier Modal
Click any alert row to display the full forensic dossier:
1. **Origin Geolocation**: Verify ISP name, IP type (Hosting/VPN/Tor), and coordinates.
2. **Device Fingerprint**: Check client detection grade and raw User-Agent codebox.
3. **One-Click Actions**:
   * Click **[ ⛔ Block Attacker IP ]** $\to$ Transmits signed HMAC command to ShieldBank $\to$ IP is blacklisted for 60 minutes.
   * Click **[ 🔑 Revoke Session ]** $\to$ Terminates active session tokens on target.
   * Click **[ 💾 Download Evidence JSON ]** $\to$ Exports cryptographically sealed SHA-256 evidence package for compliance reporting.

---

## 7. Troubleshooting & FAQ

* **Q: Burp Suite shows connection refused on port 8080.**
  * *Fix*: ShieldBank dev server runs on `http://localhost:8080`. Ensure `npm run dev` is running in `targetsys/`. If Burp proxy is also bound to 8080, change Burp listener to port `8081` in Burp Proxy Settings.
* **Q: Alerts don't appear in the browser in real time without refreshing.**
  * *Fix*: Check the top-right status badge in the ECS console. It should say **`● Live Stream Active`**. If it displays disconnected, verify that the backend daemon (`python run.py`) is running on port 5000.
* **Q: I get "Authentication required" when clicking around the console.**
  * *Fix*: ECS enforces strict **Single-Device Admin Concurrency**. If you logged in from another browser or incognito window, the previous session was invalidated. Log in again at `/login.html`.
* **Q: Can I test manual revert of an automated containment?**
  * *Fix*: Yes! Open the Attack Dossier Modal or go to **Settings** $\to$ **Active Response Controls**, select the blocked IP or frozen transaction, and click **Revert Action**. ShieldBank will restore the entity state immediately.
