# Ethio-Cyber-Shield (ECS) — Attack Labs & Synthetic Testbeds

> **Purpose**: Decoupled testing and demonstration testbeds for ECS detection, explainable risk scoring, and automated containment.

---

## 1. Overview

In ECS v3.0, the core detection engine is fully decoupled from any specific bank or application.
To facilitate testing, evaluation, and security demonstrations, the platform supports synthetic labs:

1. **ShieldBank Testbed (`targetsys`)**:
   - Location: `../targetsys`
   - Role: Realistic Ethiopian commercial banking testbed (Vite + TanStack + Drizzle).
   - Features: Customer portal, admin operations console, and interactive Attack Simulator (`/admin/lab`).
2. **Scenario Simulator (`labs/scenarios/simulator.py`)**:
   - A standalone Python CLI tool to fire realistic attacks (brute force, high-value transfer, IDOR probing, new device account takeover) directly against ECS Ingest or a connected target.

---

## 2. Running the ShieldBank Lab

To run ShieldBank alongside ECS:
```bash
# Terminal 1: ShieldBank
cd ../targetsys
npm run dev
# Running on http://localhost:8081

# Terminal 2: ECS Core
cd ../Ethio-Cyber-Shield/core
source venv/bin/activate
python run.py
# Running on http://localhost:5000

# Terminal 3: ECS Console
cd ../Ethio-Cyber-Shield/ui
python3 -m http.server 5500
# Running on http://localhost:5500
```
