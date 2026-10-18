"""
Test Suite: Part 12 — Official Client SDKs, Transactional Outbox Pattern,
Framework Middlewares (Flask/Django/FastAPI/Express), and Retry Resilience.
"""
import unittest
import os
import sys
import tempfile
import time
import uuid
import hashlib
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify, request

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from sdk.python.ecs_client import ECSClient, CanonicalEventBuilder
from sdk.python.outbox import (
    BaseOutboxStorage,
    SQLiteOutboxStorage,
    InMemoryOutboxStorage,
    TransactionalOutbox,
    OutboxItem,
)
from sdk.python.middleware import ECSFlaskMiddleware


class TestSDKsAndTransactionalOutbox(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "outbox_test.db")
        self.key_id = "test-key-id-001"
        self.secret_key = "test-secret-key-32b-very-secure"
        self.org_id = str(uuid.uuid4())
        self.ecs_url = "http://127.0.0.1:5000"
        self.client = ECSClient(
            ecs_url=self.ecs_url,
            key_id=self.key_id,
            secret_key=self.secret_key,
            organization_id=self.org_id,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sqlite_outbox_storage_lifecycle(self):
        """Test SQLiteOutboxStorage creates table, inserts, updates, and fetches records."""
        storage = SQLiteOutboxStorage(self.db_path)
        evt_id = f"evt-{uuid.uuid4().hex[:10]}"
        payload = {"event_id": evt_id, "event_type": "auth.login.failed"}

        # 1. Enqueue
        storage.save(evt_id, payload)
        pending = storage.get_pending_and_retryable(limit=10, now=time.time())
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].event_id, evt_id)
        self.assertEqual(pending[0].status, "PENDING")
        self.assertEqual(pending[0].attempts, 0)

        # 2. Mark Failed
        storage.mark_failed(evt_id, attempts=1, error="Connection timeout")
        item = storage.get_by_id(evt_id)
        self.assertEqual(item.status, "FAILED")
        self.assertEqual(item.attempts, 1)
        self.assertEqual(item.last_error, "Connection timeout")

        # 3. Mark Delivered
        storage.mark_delivered(evt_id)
        item_delivered = storage.get_by_id(evt_id)
        self.assertEqual(item_delivered.status, "DELIVERED")
        self.assertIsNotNone(item_delivered.delivered_at)

        # 4. Stats
        stats = storage.get_stats()
        self.assertEqual(stats["DELIVERED"], 1)
        self.assertEqual(stats["PENDING"], 0)

    def test_in_memory_outbox_storage(self):
        """Test InMemoryOutboxStorage adheres to BaseOutboxStorage contract."""
        storage = InMemoryOutboxStorage()
        evt_id = "evt-mem-1"
        storage.save(evt_id, {"event_id": evt_id})
        self.assertEqual(len(storage.get_pending_and_retryable(10, time.time())), 1)
        storage.mark_delivered(evt_id)
        self.assertEqual(storage.get_by_id(evt_id).status, "DELIVERED")

    @patch("requests.post")
    def test_transactional_outbox_successful_delivery(self, mock_post):
        """Test outbox flushes items successfully when ECS returns HTTP 200."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "ingested": 1}
        mock_post.return_value = mock_response

        storage = SQLiteOutboxStorage(self.db_path)
        outbox = TransactionalOutbox(client=self.client, storage=storage, batch_size=5)

        evt_id = f"evt-tx-{uuid.uuid4().hex[:8]}"
        outbox.enqueue({
            "event_id": evt_id,
            "event_type": "transaction.transfer.created",
            "channel": "mobile",
            "payment_rail": "wallet",
            "amount_minor": 150000,
        })

        result = outbox.flush()
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["delivered"], 1)
        self.assertEqual(result["failed"], 0)

        # Verify state in storage
        item = storage.get_by_id(evt_id)
        self.assertEqual(item.status, "DELIVERED")
        self.assertIsNotNone(item.delivered_at)

        # Verify HMAC headers were passed
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        headers = kwargs["headers"]
        self.assertEqual(headers["X-ECS-Key-Id"], self.key_id)
        self.assertIn("X-ECS-Signature", headers)
        self.assertEqual(headers["X-ECS-Tenant"], self.org_id)

    @patch("requests.post")
    def test_transactional_outbox_retry_exponential_backoff(self, mock_post):
        """Test failed events back off exponentially and are not retried prematurely."""
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        mock_post.return_value = mock_response

        storage = SQLiteOutboxStorage(self.db_path)
        # initial backoff of 10 seconds
        outbox = TransactionalOutbox(
            client=self.client,
            storage=storage,
            initial_backoff=10.0,
            max_attempts=3
        )

        evt_id = "evt-retry-1"
        outbox.enqueue({"event_id": evt_id, "event_type": "auth.login.failed"})

        # Attempt 1: Fails
        res1 = outbox.flush()
        self.assertEqual(res1["failed"], 1)
        item1 = storage.get_by_id(evt_id)
        self.assertEqual(item1.status, "FAILED")
        self.assertEqual(item1.attempts, 1)

        # Attempt 2: Immediately afterwards (should be skipped due to backoff)
        res2 = outbox.flush()
        self.assertEqual(res2["processed"], 0, "Event was retried before backoff elapsed!")

        # Advance time artificially past the 10-second backoff
        item1.next_retry_at = time.time() - 1
        storage._update_item(item1)

        # Attempt 3: Retries and fails again -> attempts=2
        res3 = outbox.flush()
        self.assertEqual(res3["processed"], 1)
        self.assertEqual(res3["failed"], 1)
        item3 = storage.get_by_id(evt_id)
        self.assertEqual(item3.attempts, 2)

    @patch("requests.post")
    def test_transactional_outbox_dead_letter_escalation(self, mock_post):
        """Test events that exceed max_attempts transition to DEAD_LETTER status."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Malformed request"
        mock_post.return_value = mock_response

        storage = SQLiteOutboxStorage(self.db_path)
        outbox = TransactionalOutbox(
            client=self.client,
            storage=storage,
            initial_backoff=0.01,
            max_attempts=2
        )

        evt_id = "evt-dead-letter-1"
        outbox.enqueue({"event_id": evt_id, "event_type": "bad.event"})

        # Flush 1 -> attempt 1
        outbox.flush()
        time.sleep(0.02)
        # Flush 2 -> attempt 2 (max_attempts reached)
        outbox.flush()

        item = storage.get_by_id(evt_id)
        self.assertEqual(item.status, "DEAD_LETTER")
        self.assertEqual(item.attempts, 2)
        stats = storage.get_stats()
        self.assertEqual(stats["DEAD_LETTER"], 1)

    @patch("requests.post")
    def test_background_worker_lifecycle(self, mock_post):
        """Test outbox background daemon worker periodically flushes queue."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "ingested": 1}
        mock_post.return_value = mock_response

        storage = InMemoryOutboxStorage()
        outbox = TransactionalOutbox(client=self.client, storage=storage)

        outbox.start_worker(interval_seconds=0.1)
        self.assertTrue(outbox.is_worker_running())

        evt_id = "evt-bg-1"
        outbox.enqueue({"event_id": evt_id, "event_type": "test.bg"})

        # Give worker a moment to process
        time.sleep(0.3)
        item = storage.get_by_id(evt_id)
        self.assertEqual(item.status, "DELIVERED")

        outbox.stop_worker()
        self.assertFalse(outbox.is_worker_running())

    def test_flask_middleware_telemetry_capture(self):
        """Test ECSFlaskMiddleware automatically captures route telemetry into outbox."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        storage = InMemoryOutboxStorage()
        outbox = TransactionalOutbox(client=self.client, storage=storage)
        ECSFlaskMiddleware(app=app, client=self.client, outbox=outbox)

        @app.route("/api/login", methods=["POST"])
        def mock_login():
            data = request.get_json() or {}
            if data.get("password") == "secret":
                return jsonify({"status": "ok"}), 200
            return jsonify({"error": "unauthorized"}), 401

        test_client = app.test_client()

        # 1. Failed login
        res1 = test_client.post("/api/login", json={"username": "abebe", "password": "wrong"})
        self.assertEqual(res1.status_code, 401)

        # 2. Succeeded login
        res2 = test_client.post("/api/login", json={"username": "abebe", "password": "secret"})
        self.assertEqual(res2.status_code, 200)

        # Verify outbox captured 2 events
        items = storage.get_pending_and_retryable(10, time.time())
        self.assertEqual(len(items), 2)

        failed_evt = next(i for i in items if i.payload.get("result") == "FAILURE")
        self.assertEqual(failed_evt.payload["event_type"], "auth.login.failed")
        self.assertEqual(failed_evt.payload["endpoint"], "/api/login")
        self.assertEqual(failed_evt.payload["channel"], "web")

        success_evt = next(i for i in items if i.payload.get("result") == "SUCCESS")
        self.assertEqual(success_evt.payload["event_type"], "auth.login.succeeded")

    def test_pii_protection_in_outbox(self):
        """Test that outbox builder hashes sensitive identifiers before persisting."""
        builder = CanonicalEventBuilder()
        raw_phone = "+251911223344"
        raw_fayda = "FAYDA-987654"

        event = builder.build(
            event_type="transaction.transfer.created",
            result="SUCCESS",
            source_system="mobile-app",
            channel="mobile",
            payment_rail="wallet",
            msisdn_hash=builder.hash_phone(raw_phone),
            national_id_hash=builder.hash_national_id(raw_fayda),
            attributes={"client": "android"}
        )

        storage = InMemoryOutboxStorage()
        outbox = TransactionalOutbox(client=self.client, storage=storage)
        outbox.enqueue(event)

        item = storage.get_by_id(event["event_id"])
        payload_str = str(item.payload)
        self.assertNotIn(raw_phone, payload_str, "Raw phone number leaked into outbox storage!")
        self.assertNotIn(raw_fayda, payload_str, "Raw National ID leaked into outbox storage!")
        self.assertIn(hashlib.sha256(raw_phone.encode()).hexdigest(), payload_str)


if __name__ == "__main__":
    unittest.main()
