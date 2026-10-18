# Ethio-Cyber-Shield (ECS) v3.0 — Target Integration & SDK Guide

> **Audience**: Bank, MFI, PSO, and Fintech Integration Engineers  
> **Contract**: ECS Event Contract v1.1 (OpenAPI 3.1 & JSON Schema)  
> **Mandate**: Real-time fraud detection and statutory 48-hour incident-readiness telemetry ingestion under Proclamation No. 1426/2026, NBE Directives, and PDPP 1321/2024.

---

## 1. Architectural Overview & Reliability Guarantee

ECS decouples application traffic from detection processing using the **Transactional Outbox Pattern**:
1. When a transaction or authentication event occurs, your application enqueues the canonical event into a local, thread-safe, durable store (SQLite, DB, or in-memory) within the primary transaction.
2. An asynchronous worker thread or sweeper pulls pending events and dispatches them to ECS via cryptographically signed HTTP POST requests (`/api/events`).
3. If ECS or network connectivity is temporarily unavailable, events automatically back off exponentially (`2s * 2^attempts`, capped at 5 minutes, up to 8 attempts) until acknowledged.
4. **Zero Telemetry Loss**: Application requests are never blocked or delayed, and security telemetry survives application and network restarts.

```
+--------------------------------------------------------------------------+
| Bank / PSO Target Application                                           |
|                                                                          |
|  [ User Request ] ---> [ Web Route / Controller ]                        |
|                                |                                         |
|                                v                                         |
|                      [ Transactional Outbox ] (Local SQLite / DB)        |
|                                |                                         |
|                                v (Background Worker Thread)              |
|                      [ HMAC-SHA256 Signer ]                              |
+--------------------------------|-----------------------------------------+
                                 |
                                 v  HTTPS POST /api/events (Signed)
+--------------------------------|-----------------------------------------+
| Ethio-Cyber-Shield (ECS)       |                                         |
|                      [ Ingestion Gateway ]                               |
|                                |                                         |
|                                v                                         |
|                      [ Durable Stream (Redis) ] ---> [ Detection Engine ]|
+--------------------------------------------------------------------------+
```

---

## 2. Cryptographic Authentication & Zero-PII Rules

All requests to ECS must include four cryptographic authentication headers:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-ECS-Key-Id` | Pre-shared API Key Identifier issued by ECS SOC admin | `cbe_core_prod_key_01` |
| `X-ECS-Timestamp` | Current UNIX epoch timestamp in seconds (clock skew must be &le; 300s) | `1760867890` |
| `X-ECS-Nonce` | Cryptographically random UUID v4 nonce (anti-replay guard) | `a8b1c4e9-1234-4567-89ab-cdef01234567` |
| `X-ECS-Signature` | Hex-encoded HMAC-SHA256 signature calculated over canonical string | `5f2e8d...` |
| `X-ECS-Tenant` | *(Optional)* Organization UUID for multi-tenant gateways | `3a1e2f...` |

### Zero-PII Rule (Non-Negotiable)
Under Ethiopian Personal Data Protection Proclamation 1321/2024, **never transmit raw customer phone numbers, National IDs, or account numbers**. All SDKs provide built-in hashing helpers:
- `msisdn_hash`: SHA-256 hash of standardized phone (e.g. `+251911223344`)
- `national_id_hash`: SHA-256 hash of Fayda / Kebele National ID
- `counterparty_ref_hash`: SHA-256 hash of beneficiary destination account

---

## 3. Python Integration (Flask, FastAPI, Django)

### Installation
```bash
pip install ethio-cyber-shield-sdk
```

### 3.1 Flask Integration
```python
from flask import Flask, request, jsonify
from sdk.python import ECSClient, TransactionalOutbox, ECSFlaskMiddleware

app = Flask(__name__)

# 1. Initialize ECS Client
client = ECSClient(
    ecs_url="https://ecs.internal.bank.et",
    key_id="cbe_mobile_banking_key_01",
    secret_key="your-32-byte-hex-secret-key-at-rest",
    organization_id="11111111-2222-3333-4444-555555555555"
)

# 2. Attach Transactional Outbox (uses local SQLite outbox.db by default)
outbox = TransactionalOutbox(client=client, batch_size=50)
outbox.start_worker(interval_seconds=5.0)

# 3. Register Middleware to auto-capture auth and financial routes
ECSFlaskMiddleware(app=app, client=client, outbox=outbox)

@app.route("/api/transfer", methods=["POST"])
def transfer_funds():
    # Application business logic executes normally
    return jsonify({"status": "transferred", "tx_id": "TXN_991827"}), 200
```

### 3.2 FastAPI Integration
```python
from fastapi import FastAPI
from sdk.python import ECSClient, TransactionalOutbox, ECSFastAPIMiddleware

app = FastAPI(title="Fintech Transfer Service")

client = ECSClient(
    ecs_url="https://ecs.internal.fintech.et",
    key_id="fintech_pso_key",
    secret_key="your-32-byte-secret"
)
outbox = TransactionalOutbox(client=client)
outbox.start_worker()

app.add_middleware(
    ECSFastAPIMiddleware,
    client=client,
    outbox=outbox,
    source_system="fintech-api"
)
```

### 3.3 Manual Telemetry Enqueueing
```python
from sdk.python import CanonicalEventBuilder

event = CanonicalEventBuilder.build(
    event_type="transaction.transfer.created",
    result="SUCCESS",
    source_system="cbe-ussd-core",
    channel="ussd",
    payment_rail="wallet",
    amount_minor=500000, # 5,000.00 ETB
    currency="ETB",
    user_id_pub="USR_88129",
    account_id_pub="ACC_10029",
    msisdn_hash=CanonicalEventBuilder.hash_phone("+251911223344"),
    national_id_hash=CanonicalEventBuilder.hash_national_id("FAYDA-882711"),
    counterparty_ref_hash=CanonicalEventBuilder.hash_counterparty("ACC_DEST_9981"),
    attributes={"ussd_session_id": "SES-99812", "shortcode": "*889#"}
)

outbox.enqueue(event)
```

---

## 4. Node.js & TypeScript Integration (Express)

### Installation
```bash
npm install @ethio-cyber-shield/sdk
```

### 4.1 Express Middleware Setup
```typescript
import express from 'express';
import { ECSClient, TransactionalOutbox, ecsExpressMiddleware, hashPhone, hashNationalId } from '@ethio-cyber-shield/sdk';

const app = express();
app.use(express.json());

const client = new ECSClient({
  ecsUrl: 'https://ecs.internal.bank.et',
  keyId: 'awash_switch_key_01',
  secretKey: '32-character-secret-key-prod',
  organizationId: '22222222-3333-4444-5555-666666666666'
});

const outbox = new TransactionalOutbox({ client });
outbox.startWorker(5000); // Polls and sweeps every 5s

app.use(ecsExpressMiddleware({ client, outbox, sourceSystem: 'awash-digital-web' }));

app.post('/api/auth/login', (req, res) => {
  // Login logic here
  res.status(200).json({ ok: true });
});

app.listen(3000, () => console.log('Banking server listening on port 3000'));
```

---

## 5. PHP & Laravel Integration

### Installation
```bash
composer require ethio-cyber-shield/ecs-php-sdk
```

### 5.1 Standalone Outbox Usage
```php
use EthioCyberShield\ECSClient;
use EthioCyberShield\TransactionalOutbox;

$client = new ECSClient(
    'https://ecs.internal.bank.et',
    'dashen_core_key',
    '32-byte-secret-key-at-rest',
    '33333333-4444-5555-6666-777777777777'
);

$outbox = new TransactionalOutbox($client);

// Enqueue event safely
$outbox->enqueue([
    'event_type' => 'transaction.transfer.created',
    'result' => 'SUCCESS',
    'channel' => 'mobile',
    'payment_rail' => 'interbank',
    'amount_minor' => 1250000, // 12,500.00 ETB
    'currency' => 'ETB',
    'msisdn_hash' => ECSClient::hashPhone('+251912345678'),
    'attributes' => ['interbank_switch' => 'EthSwitch']
]);

// Dispatch in background cron: * * * * * php artisan ecs:flush-outbox
$outbox->flush();
```

---

## 6. Resilience & Outbox SLAs

| Parameter | Default Value | Configurable Range | Description |
| :--- | :--- | :--- | :--- |
| `initial_backoff` | `2.0 seconds` | `0.5s – 10.0s` | Initial wait time after 1st network failure |
| `max_backoff` | `300.0 seconds` | `60s – 1800s` | Exponential ceiling (5 minutes) |
| `max_attempts` | `8 attempts` | `3 – 20` | Max delivery attempts before dead-letter escalation |
| `batch_size` | `50 events` | `1 – 200` | Max events bundled in a single POST request |
| `worker_interval` | `5.0 seconds` | `1s – 60s` | Sweeper frequency in background thread |

If an event reaches `max_attempts`, it transitions to `DEAD_LETTER` status and triggers an alert for SOC review. The raw event payload is never dropped.
