# Ethio-Cyber-Shield (ECS) & HonorPay Banking — Complete System Setup & Run Guide

> **Institutional Submission**: Official Operations & Setup Guide submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Document Classification**: System Operations & Architecture Guide (TLP:CLEAR)  
> **Platform Version**: Ethio-Cyber-Shield (ECS) Independent v3.0  
> **Target Application**: HonorPay Digital Banking Application (`targetsys`)  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)

---

## 1. System Overview & Architecture

The CyberShield ecosystem consists of two independent, decoupled systems communicating over signed REST APIs:

1. **Ethio-Cyber-Shield (ECS)**: An independent, multi-tenant cybersecurity detection, threat intelligence, and incident-readiness platform designed for Ethiopian critical infrastructure and digital finance operators.
2. **HonorPay Digital Banking (`targetsys`)**: A realistic Ethiopian digital banking application (built on TanStack Start, React, Vite, and Web Crypto) acting as the protected financial infrastructure.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ATTACKER / SECURITY TESTER                      │
│  Burp Suite (Proxy: 127.0.0.1:8081) / Automated Python Scripts / cURL   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP Requests (Brute-force, Tampered Tx, IDOR)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SHIELDBANK TARGET BANKING SYSTEM                     │
│  Base URL: http://localhost:8080 (Vite / TanStack Start)               │
│  • Customer & Admin Banking Portals (/login, /app/transfer)            │
│  • Transactional Outbox Pipeline (src/lib/outbox.server.ts)            │
│  • Bidirectional Security Controls API (/api/public/security/*)        │
└───────────────────┬────────────────────────────────▲───────────────────┘
                    │                                │
                    │ Signed HMAC-SHA256 Telemetry   │ Signed HMAC-SHA256 Mitigations
                    │ (POST /api/events)             │ (Freeze Tx, Block IP, Revoke)
                    ▼                                │
┌────────────────────────────────────────────────────┴───────────────────┐
│                      ETHIO-CYBER-SHIELD PLATFORM                       │
│  Defense Engine API: http://localhost:5000 (Flask / Python)            │
│  SOC Analyst Console: http://localhost:5500 (Modern Dark-Mode UI)     │
│  • Bounded Stream Queue & Ingestion Pipeline (Redis Streams / DB)      │
│  • Multi-Pack Detection Engine (27 Declarative Rules-as-Data)          │
│  • Real-Time Threat Dossier & Device Fingerprint Engine                │
│  • Instant SSE Live Stream Broadcaster (/api/live/stream)              │
│  • Safe Closed-Loop Mitigation Connector with Reversible Rollback      │
└────────────────────────────────────────────────────────────────────────┘
```

### Lab Ports & Access Credentials Reference

| Component | URL / Port | Technology | Purpose | Default Credentials |
| :--- | :--- | :--- | :--- | :--- |
| **ShieldBank Web App** | `http://localhost:8080` | React, Vite, TanStack Start | Digital Banking Application | **Admin**: `admin@shieldbank.test` / `Testbed#2026`<br>**Customer**: `amina@shieldbank.test` / `Testbed#2026` |
| **ECS Defense Engine API** | `http://localhost:5000` | Python 3.12, Flask, Redis | Ingestion, Rule Evaluation, Risk Model | Authenticated via JWT Tokens / HMAC-SHA256 |
| **ECS SOC Console** | `http://localhost:5500` | Pure Dark-Mode UI, Vanilla JS | Security Analyst Operations Center | **Lead SOC Admin**: `admin@ethiocybershield.et` / `Admin@123` |
| **Burp Suite Proxy** | `127.0.0.1:8081` *(or 8080)* | Java / Burp Suite | Interception, Repeater, Intruder | N/A (Local proxy listener) |

---

## 2. Prerequisites & Environment Requirements

Ensure the following runtimes and utilities are installed on your host system:

* **Operating System**: Linux (Ubuntu 22.04 / 24.04 LTS recommended), Debian, macOS, or WSL2 on Windows.
* **Python**: `Python 3.11` or `3.12` with `python3-venv` and `pip`.
* **Node.js**: `Node.js v18.x` or `v20.x LTS` with `npm v9+`.
* **Network & CLI Tools**: `curl`, `jq`, `lsof`, `git`.
* **Database & Stream Cache**: PostgreSQL database (Supabase managed or Docker container) and optional Redis instance.

---

## 3. Repository Directory Layout

The workspace root is `/home/neuron/dev/cybershield` containing two distinct repositories:

```
/home/neuron/dev/cybershield/
├── Ethio-Cyber-Shield/                 # Repository 1: Central Defense Platform
│   ├── backend -> core                 # Symlink pointing to core engine
│   ├── core/                           # Python Flask API & Detection Services
│   │   ├── app/
│   │   │   ├── routes/                 # REST & SSE endpoints (/api/events, /api/alerts, /api/live)
│   │   │   ├── services/               # Detection Engine, Poller, Enrichment, Response Policy
│   │   │   ├── rules/definitions/      # 27 Declarative Rule Packs (YAML)
│   │   │   └── playbooks/              # Automated Incident Response Playbooks
│   │   ├── tests/                      # 32 Comprehensive Test Suites (250+ unit/integration tests)
│   │   ├── venv/                       # Python Virtual Environment
│   │   ├── .env                        # Core environment secrets & configuration
│   │   ├── requirements.txt            # Python dependencies
│   │   └── run.py                      # Flask API Application Runner
│   ├── ui/                             # Minimalist SOC Analyst Web Console
│   │   ├── dashboard.html              # High-density Overview & Real-Time Alert Feed
│   │   ├── alerts.html                 # Dedicated Alerts Management & Dossier Viewer
│   │   ├── incidents.html              # 48-Hour Statutory Regulatory Incident Triage
│   │   ├── intelligence.html           # Indicators, Fraud Rails & Watchlists (3-Tab Pill)
│   │   ├── audit.html                  # Cryptographic SHA-256 Audit Verification & Replay
│   │   ├── settings.html               # Connectors, Closed-Loop Automation & User Admin
│   │   ├── login.html                  # Secure Authentication & Concurrent Session Notice
│   │   ├── css/style.css               # Modern SOC Dark-Mode Design System
│   │   └── js/api.js, common.js        # REST client & auto-reconnecting SSE listener
│   ├── docs/                           # Architecture Decision Records & Runbooks
│   └── scripts/                        # Automated Simulation Test Harnesses
│
└── targetsys/                          # Repository 2: ShieldBank Banking Testbed
    ├── src/
    │   ├── routes/                     # TanStack Start Route Handlers (/login, /app/transfer)
    │   ├── lib/
    │   │   ├── outbox.server.ts        # Signed HMAC Outbox Telemetry Worker
    │   │   ├── public-api.server.ts    # Public Security & Containment Endpoints
    │   │   ├── hmac.server.ts          # Cryptographic HMAC-SHA256 Verification & Nonce Check
    │   │   └── telemetry.server.ts     # Internal Banking Event Emission
    │   ├── integrations/supabase/      # In-memory mock store & seed data
    │   └── test/                       # Vitest integration tests (101 tests passing)
    ├── package.json                    # Node dependencies and scripts
    └── .env                            # Target system environment secrets
```

---

## 4. Step-by-Step Flow 1: Setting up Ethio-Cyber-Shield (ECS)

### Step 1.1: Initialize Python Virtual Environment
Navigate to the `core` directory and create/activate the Python virtual environment:

```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core
python3 -m venv venv
source venv/bin/activate
```

### Step 1.2: Install Required Dependencies
Install the required packages from `requirements.txt`:

```bash
pip install -r requirements.txt
```

*Core packages include:* `flask`, `flask-cors`, `python-dotenv`, `supabase`, `bcrypt`, `pyjwt`, `cryptography`, `requests`, `pyyaml`, `redis`, and `python-dateutil`.

### Step 1.3: Configure Environment Variables
Verify or create the `/home/neuron/dev/cybershield/Ethio-Cyber-Shield/core/.env` file with the following settings:

```dotenv
# Database & Cloud Store Configuration
SUPABASE_URL=https://ibxbsaeeouctuzvpbghl.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Cryptographic & Session Secrets
JWT_SECRET=e7c4a91f2b8d3e6a0f5c9b2d7e1a4f8c3b6d0e9a2f5c8b1d4e7a0f3c6b9d2e5
FLASK_ENV=development
FLASK_DEBUG=1
PORT=5000

# CORS Allowed Origins
ALLOWED_ORIGINS=http://localhost:8081,http://127.0.0.1:8081,http://localhost:8080,http://127.0.0.1:8080,http://localhost:5500,http://127.0.0.1:5500

# Target System Integration
TARGET_SYSTEM_URL=http://127.0.0.1:8080
TARGET_KEY_ID=ecs-outbound-key-01
TARGET_SECRET=super-secret-key-32b
```

### Step 1.4: Run Platform Regression Tests
Confirm that all core modules, isolation rules, and detection services pass:

```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core
PYTHONPATH=. venv/bin/python -m unittest tests/test_single_device_session.py
PYTHONPATH=. venv/bin/python -m unittest tests/test_part7_multi_tenancy_isolation.py
```
*Expected Result:* `OK` (All tests passing).

---

## 5. Step-by-Step Flow 2: Setting up ShieldBank (`targetsys`)

### Step 2.1: Install Node.js Dependencies
Navigate to `targetsys` and install npm packages:

```bash
cd /home/neuron/dev/cybershield/targetsys
npm install
```

### Step 2.2: Configure Environment Variables
Confirm `/home/neuron/dev/cybershield/targetsys/.env` contains the local encryption and target parameters:

```dotenv
SUPABASE_PROJECT_ID="cqdilgotoeweripooeki"
SUPABASE_PUBLISHABLE_KEY="sb_publishable_x5wkrdjRDaCR0f33JmZxDQ_cTSMmQoK"
SUPABASE_URL="https://cqdilgotoeweripooeki.supabase.co"
SUPABASE_SERVICE_ROLE_KEY="shieldbank_local_dev_service_role_key"
VITE_SUPABASE_PROJECT_ID="cqdilgotoeweripooeki"
VITE_SUPABASE_PUBLISHABLE_KEY="sb_publishable_x5wkrdjRDaCR0f33JmZxDQ_cTSMmQoK"
VITE_SUPABASE_URL="https://cqdilgotoeweripooeki.supabase.co"
APP_ENCRYPTION_KEY="shieldbank_testbed_encryption_key_2026_super_secure_32b"
```

### Step 2.3: Verify Target Integration Credentials
In `targetsys/src/integrations/supabase/local-store.ts`, the default integration is pre-configured with:
* **Outbound Key ID**: `ecs-outbound-key-01`
* **Inbound Key ID**: `ecs_live_prod_key_01`
* **HMAC Secret**: `super-secret-key-32b`
* **Scoped Permissions**: `read:investigation`, `control:freeze-transaction`, `control:revoke-session`, `control:block-ip`, `control:lock-account`, `control:disable-beneficiary`, `control:require-step-up`, and `control:revert`.

### Step 2.4: Run Target System Tests
Verify the target test suite:

```bash
cd /home/neuron/dev/cybershield/targetsys
npm test
```
*Expected Result:* `8 passed (8 test files), 101 passed (101 tests)`.

---

## 6. Step-by-Step Flow 3: Running Both Systems (Startup Runbook)

Open **three separate terminal sessions** to launch the microservices:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TERMINAL 1: ECS Core Backend (Port 5000)                               │
│ $ cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend           │
│ $ source venv/bin/activate                                             │
│ $ python run.py                                                        │
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 2: ECS SOC Web Console (Port 5500)                            │
│ $ cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/ui                 │
│ $ python3 -m http.server 5500                                          │
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 3: ShieldBank Target Application (Port 8080)                  │
│ $ cd /home/neuron/dev/cybershield/targetsys                            │
│ $ npm run dev                                                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Detailed Terminal Commands

#### Terminal 1: Launch ECS Core Backend API
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend
source venv/bin/activate
python run.py
```
* **Status**: Listens on `http://0.0.0.0:5000`.
* **Background Workers**: Starts the Ingestion Engine, Rule Evaluator, and Background Target Poller.

#### Terminal 2: Launch ECS SOC Web Console
```bash
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/ui
python3 -m http.server 5500
```
* **Status**: Serves static dark-mode console on `http://localhost:5500`.

#### Terminal 3: Launch ShieldBank Target Banking System
```bash
cd /home/neuron/dev/cybershield/targetsys
npm run dev
```
* **Status**: Vite dev server online at `http://localhost:8080`.

---

## 7. Step-by-Step Flow 4: Verifying Connectivity & Health

Once all three terminals are active, verify the health status across the ecosystem:

### 1. Check ECS Backend Health
```bash
curl -s http://127.0.0.1:5000/health | jq .
```
*Expected Response:*
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "service": "Ethio-Cyber-Shield Core API"
}
```

### 2. Check ShieldBank Security Health
```bash
curl -s http://127.0.0.1:8080/api/public/security/health | jq .
```
*Expected Response:*
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "lab_mode": true
}
```

### 3. Verify Target Sync via ECS Poller
```bash
PYTHONPATH=/home/neuron/dev/cybershield/Ethio-Cyber-Shield/core \
  /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/venv/bin/python -c "
from dotenv import load_dotenv; load_dotenv('/home/neuron/dev/cybershield/Ethio-Cyber-Shield/core/.env')
from app.services.poller_service import poll_target_once
print(poll_target_once('default-target-shieldbank'))
"
```
*Expected Response:* `{'target_id': 'default-target-shieldbank', 'events_synced': 0, 'status': 'success'}`

### 4. Log in to ECS SOC Console
1. Open your web browser to `http://localhost:5500/login.html`.
2. Enter:
   * **Email**: `admin@ethiocybershield.et`
   * **Password**: `Admin@123`
3. Click **Sign In**.
4. Confirm you are redirected to `/dashboard.html` and the top right badge displays **`● Live Stream Active`**.

---

## 8. Step-by-Step Flow 5: Testing Attacks & Real-Time Alerts

You can simulate attacks using either **Burp Suite** or the **Automated Python Harness**.

### Method A: Automated Test Script (Fastest Verification)

Run the simulation script to test 4 attack vectors in sequence:
```bash
/home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/venv/bin/python \
  /home/neuron/dev/cybershield/Ethio-Cyber-Shield/scripts/test_simulations.py
```

*What this executes:*
1. **Burp Suite Credential Brute-Force Burst (`AUTH-001`)**: 5 rapid failed logins from `196.188.12.55`.
2. **Offensive Security Tool Scanner Probe (`API-004`)**: Automated SQL injection scanner signature (`sqlmap/1.8.4`).
3. **High-Value Fraud Transfer Anomaly (`TX-001`)**: Transfer of `350,000 ETB` exceeding thresholds.
4. **Sequential IDOR Resource Probing (`API-002`)**: Resource enumeration on `/api/public/security/accounts/ACC_1001`.

*Result in Dashboard*:
* Without page refresh, the **Overview Table** flashes new rows with audible chimes.
* Tool software is identified as `sqlmap (Automated SQL Injection Scanner)` and `Burp Suite Professional`.
* Geolocation resolves to `🇪🇹 Addis Ababa, Ethiopia · Ethio Telecom (AS24757)`.

---

### Method B: Testing via Burp Suite Interception

#### Scenario: Brute-Force Password Guessing (`AUTH-001`)
1. Open **Burp Suite** and set proxy listener on `127.0.0.1:8081` (so it does not collide with ShieldBank on 8080).
2. Go to **Proxy** $\to$ **Intercept** $\to$ **Open Browser** in Burp.
3. In the Burp browser, navigate to `http://localhost:8080/login`.
4. Enter `amina@shieldbank.test` and password `WrongPassword!`.
5. Ensure Intercept is **ON** and click **Sign In**.
6. In Burp Proxy, view the POST request, right-click, and select **Send to Repeater** (`Ctrl+R`).
7. In Repeater, click **Send** **5 consecutive times** within 30 seconds.
8. Switch to the **ECS SOC Console** (`http://localhost:5500/dashboard.html`):
   * A **HIGH/MEDIUM SEVERITY ALERT** pops up immediately: `AUTH-001: Login Failure Burst`.
   * Click **Investigate** to open the **Attack Dossier Modal**.

---

## 9. Step-by-Step Flow 6: Closed-Loop Containment & Rollback

ECS can dispatch automated or manual containment actions directly into ShieldBank over signed HMAC APIs:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      ATTACK DOSSIER ACTION MODAL                       │
│                                                                        │
│   [ ⛔ Block Attacker IP ]      [ 🔑 Revoke Session ]                 │
│   [ 🚨 Escalate to Incident ]   [ 💾 Download Evidence JSON ]          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Signed HMAC POST
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SHIELDBANK CONTROL ENDPOINT                          │
│   POST /api/public/security/controls/block-ip                          │
│   POST /api/public/security/controls/revoke-session                    │
│   POST /api/public/security/controls/freeze-transaction                │
│   POST /api/public/security/controls/revert                            │
└────────────────────────────────────────────────────────────────────────┘
```

### Testing Containment Actions

1. In the **ECS Dashboard** (`/dashboard.html` or `/alerts.html`), click on an alert row to open the **Attack Dossier Modal**.
2. Click **`[ ⛔ Block Attacker IP ]`**:
   * ECS sends a signed request to `POST http://localhost:8080/api/public/security/controls/block-ip`.
   * ShieldBank confirms the IP block for 60 minutes.
3. Click **`[ 🔑 Revoke Session ]`**:
   * ECS sends a signed command to terminate compromised session tokens.
4. Testing Immediate Rollback (`Revert`):
   * Navigate to **Settings** $\to$ **Active Response Controls** tab.
   * Locate the active mitigation.
   * Click **Revert Action**. ShieldBank verifies the `control:revert` scope and restores the entity immediately.

---

## 10. Platform Security Policies & Hard Engineering Rules

### Single-Device Admin Concurrency Policy
* ECS strictly enforces a single active device session per administrator account.
* Logging into `admin@ethiocybershield.et` on a second browser or device immediately revokes the previous JWT `jti`.
* Superseded sessions return `HTTP 401 Unauthorized` and are automatically redirected to `login.html?session_expired=concurrent`.

### Zero-PII Regulatory Compliance (NBE / INSA Readiness)
* Cross-tenant and external telemetry feeds exchange only keyed hashes (`counterparty_ref_hash`, `device_fingerprint`), TLP markings, and confidence scores.
* Raw bank account balances, customer PII, and credentials are never exported or leaked.

### Cryptographic Hash-Chain Integrity
* All security actions and audit logs are envelope-sealed with predecessor SHA-256 digests (`_audit_seal`).
* Navigate to **Audit & Reports** (`/audit.html`) $\to$ **Verify Chain Integrity** to validate the tamper-evident log sequence.

---

## 11. Troubleshooting & Diagnostics

| Symptom | Probable Cause | Corrective Action |
| :--- | :--- | :--- |
| **Connection Refused on port 8080** | ShieldBank Vite server is offline | Run `cd /home/neuron/dev/cybershield/targetsys && npm run dev` in Terminal 3. |
| **Port 8080 in use; Vite runs on 8081** | Burp Suite or another process occupies 8080 | Change Burp listener to port `8082` in Burp Proxy Settings, or update `TARGET_SYSTEM_URL=http://127.0.0.1:8081` in `core/.env`. |
| **`Authentication required` in ECS UI** | Single-Device session superseded | Another device signed in as `admin`. Log in again at `http://localhost:5500/login.html`. |
| **Live Stream Disconnected badge** | ECS Core API is offline | Start backend with `python run.py` in `Ethio-Cyber-Shield/backend`. |
| **HMAC Timestamp Skew Error (> 300s)** | System clock desynchronized | Ensure system time is synchronized via NTP (`sudo timedatectl set-ntp on`). |
| **Database `PGRST204` Column Cache Error** | PostgREST schema cache out of date | Handled automatically: ECS sanitizes payload fields and stores envelope seals in `details`. |

---

## 12. Quick Reference Commands Cheat Sheet

```bash
# === 1. Start ECS Backend (Port 5000) ===
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend && source venv/bin/activate && python run.py

# === 2. Start ECS Web Console (Port 5500) ===
cd /home/neuron/dev/cybershield/Ethio-Cyber-Shield/ui && python3 -m http.server 5500

# === 3. Start ShieldBank Target System (Port 8080) ===
cd /home/neuron/dev/cybershield/targetsys && npm run dev

# === 4. Run Automated Attack Simulation ===
/home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/venv/bin/python /home/neuron/dev/cybershield/Ethio-Cyber-Shield/scripts/test_simulations.py

# === 5. Run ECS Regression Test Suite ===
PYTHONPATH=/home/neuron/dev/cybershield/Ethio-Cyber-Shield/core /home/neuron/dev/cybershield/Ethio-Cyber-Shield/backend/venv/bin/python -m unittest discover -s /home/neuron/dev/cybershield/Ethio-Cyber-Shield/core/tests -p "test_*.py"

# === 6. Run ShieldBank Vitest Suite ===
cd /home/neuron/dev/cybershield/targetsys && npm test
```
