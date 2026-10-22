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
    print("=================================================================")
    print("Ethio-Cyber-Shield (ECS) v3.0 Real-Time Attack Simulation Harness")
    print("=================================================================\n")
    
    print("=== 1. Simulating Burp Suite Brute Force (AUTH-001) ===")
    attacker_ip = "196.188.12.55"  # Addis Ababa Ethio Telecom IP
    burp_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) BurpSuite/2026.1"
    
    for i in range(5):
        send_event("LOGIN_FAILED", "amina@shieldbank.test", attacker_ip, user_agent=burp_ua)
        time.sleep(0.5)

    print("\n=== 2. Simulating Security Tool Scanner Probe (API-004) ===")
    send_event("API_REQUEST", "admin@shieldbank.test", "197.156.70.1", user_agent="sqlmap/1.8.4 (https://sqlmap.org)")

    print("\n=== 3. Simulating High-Value Fraud Anomaly (TX-001) ===")
    send_event("TRANSFER_CREATED", "amina@shieldbank.test", "196.188.12.55", amount=350000.0)

    print("\n=== 4. Simulating Sequential Resource Enumeration (API-002) ===")
    send_event("API_REQUEST", "ACC_1001", "196.188.12.55", extra={"sequential_probe": True})

    print("\n=================================================================")
    print("All simulations dispatched!")
    print("Open http://localhost:5500/dashboard.html to inspect real-time alerts!")
    print("=================================================================")
