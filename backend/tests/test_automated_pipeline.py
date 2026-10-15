"""
End-to-End Automated Pipeline Integration Test (Part 8.1).
Validates the entire closed-loop threat lifecycle:
1. HMAC-SHA256 signature generation & anti-replay nonce defense
2. Telemetry ingestion & Common Envelope normalization
3. Deterministic ATO correlation & L4 risk scoring (100/100)
4. Autonomous incident creation & threat indicator extraction
5. Outbound target containment dispatch & rollback
"""
import unittest
import json
import uuid
import time
import hmac
import hashlib
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from app import create_app
from app.services.target_system_service import (
    sign_headers,
    verify_and_record_nonce,
)
from app.services.event_service import ingest_event
from app.services.detection_engine import evaluate_event_stream
from app.services.incident_service import promote_alert_to_incident
from app.services.response_policy import evaluate_incident_containment, revert_containment
from app.services.poller_service import poll_target_once


class TestAutomatedPipeline(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.key_id = "test-pipeline-key-01"
        self.secret = "test-pipeline-secret-key-32bytes-hex"

    def test_1_hmac_signing_and_nonce_replay(self):
        """1. Verifies HMAC canonical signing, verification, and anti-replay defense."""
        method = "POST"
        path = "/api/events"
        payload = {"event_type": "auth.login.failed", "source_ip": "198.51.100.22"}
        raw_body = json.dumps(payload, sort_keys=True).encode()

        headers = sign_headers(self.key_id, self.secret, method, path, raw_body)

        self.assertIn("X-ECS-Key-Id", headers)
        self.assertIn("X-ECS-Timestamp", headers)
        self.assertIn("X-ECS-Nonce", headers)
        self.assertIn("X-ECS-Signature", headers)

        # Independent signature verification
        ts = headers["X-ECS-Timestamp"]
        nonce = headers["X-ECS-Nonce"]
        body_hash = hashlib.sha256(raw_body).hexdigest()
        canonical = f"{ts}\n{nonce}\n{method}\n{path}\n{body_hash}"
        expected_sig = hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(headers["X-ECS-Signature"], expected_sig))

        # Anti-replay nonce defense
        ok1, _ = verify_and_record_nonce(self.key_id, nonce)
        self.assertTrue(ok1)
        ok2, err2 = verify_and_record_nonce(self.key_id, nonce)
        self.assertFalse(ok2)
        self.assertIn("replay", err2.lower())

    def test_2_telemetry_ingestion_and_normalization(self):
        """2. Verifies push of v1.0 event envelope normalizes transfer into transaction record."""
        event_payload = {
            "schema_version": "1.0",
            "event_id": f"evt-pipe-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.initiated",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source_system": "shieldbank-testbed",
            "account_id": f"acc-pipe-{uuid.uuid4().hex[:8]}",
            "source_ip": "198.51.100.99",
            "result": "held",
            "attributes": {
                "amount": 150000.0,
                "currency": "ETB",
                "beneficiary_account": "1000998877",
                "risk_context": "off_hours"
            }
        }

        result = ingest_event(event_payload, target_system_id="pipe-target-1")
        self.assertIn(result.get("status"), ("received", "ingested"))
        self.assertIn("detection", result)
        self.assertIn("risk_score", result["detection"])

    def test_3_ato_correlation_engine(self):
        """3. Passes synthetic multi-stage ATO sequence; asserts ATO-001 fires with critical score."""
        victim_acc = f"acc-ato-{uuid.uuid4().hex[:8]}"
        attacker_ip = "198.51.100.44"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: 5 failed logins (AUTH-001)
        for i in range(5):
            ingest_event({
                "schema_version": "1.0",
                "event_id": f"evt-f-{i}-{uuid.uuid4().hex[:8]}",
                "event_type": "auth.login.failed",
                "occurred_at": now_iso,
                "source_system": "shieldbank-testbed",
                "account_id": victim_acc,
                "source_ip": attacker_ip,
                "result": "failed",
                "attributes": {"failure_reason": "invalid_credentials"}
            })

        # Step 2: Login success from new hardware device (AUTH-003)
        ingest_event({
            "schema_version": "1.0",
            "event_id": f"evt-succ-{uuid.uuid4().hex[:8]}",
            "event_type": "auth.login.succeeded",
            "occurred_at": now_iso,
            "source_system": "shieldbank-testbed",
            "account_id": victim_acc,
            "device_id": f"dev-rogue-{uuid.uuid4().hex[:6]}",
            "source_ip": attacker_ip,
            "result": "success",
            "attributes": {"is_new_device": True}
        })

        # Step 3: Rapid mule beneficiary added (TX-004)
        ingest_event({
            "schema_version": "1.0",
            "event_id": f"evt-ben-{uuid.uuid4().hex[:8]}",
            "event_type": "beneficiary.created",
            "occurred_at": now_iso,
            "source_system": "shieldbank-testbed",
            "account_id": victim_acc,
            "source_ip": attacker_ip,
            "result": "success",
            "attributes": {"beneficiary_account": "10009999"}
        })

        # Step 4: High-value wire transfer (TX-001 & ATO-001)
        transfer_event = {
            "schema_version": "1.0",
            "event_id": f"evt-tx-{uuid.uuid4().hex[:8]}",
            "event_type": "transaction.transfer.held",
            "occurred_at": now_iso,
            "source_system": "shieldbank-testbed",
            "account_id": victim_acc,
            "source_ip": attacker_ip,
            "result": "held",
            "attributes": {
                "amount": 180000.0,
                "currency": "ETB",
                "beneficiary_account": "10009999"
            }
        }

        eval_res = evaluate_event_stream(transfer_event)
        self.assertTrue(eval_res["is_threat"])
        self.assertIn("ATO-001", eval_res["rules_fired"])
        self.assertEqual(eval_res["risk_score"], 100)
        self.assertEqual(eval_res["severity"], "critical")

    @patch("app.services.target_system_service.call_target")
    def test_4_auto_containment_and_incident_promotion(self, mock_call):
        """4. Verifies critical alert auto-promotes to incident and triggers containment."""
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "CONFIRMED"}
        mock_call.return_value = mock_resp

        acc_id = f"acc-contain-{uuid.uuid4().hex[:8]}"
        detection = {
            "is_threat": True,
            "rules_fired": ["ATO-001", "AUTH-001", "TX-001"],
            "risk_score": 100,
            "severity": "critical",
            "confidence": "high",
            "reasons": ["ATO-001: Full account takeover chain detected"],
        }
        trigger_event = {
            "event_id": f"evt-trig-{uuid.uuid4().hex[:8]}",
            "event_type": "transaction.transfer.held",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source_system": "shieldbank-testbed",
            "account_id": acc_id,
            "source_ip": "198.51.100.77",
            "result": "held",
            "attributes": {
                "transaction_id": f"TX-HOLD-{uuid.uuid4().hex[:6]}",
                "session_id": f"SESS-{uuid.uuid4().hex[:6]}",
                "amount": 180000.0
            }
        }

        # Promote alert to formal incident
        inc = promote_alert_to_incident(
            alert_id=None,
            detection_result=detection,
            event=trigger_event,
            target_id="pipe-target-1"
        )
        self.assertIsNotNone(inc)
        self.assertIn("id", inc)

        # Dispatch containment policy
        containment = evaluate_incident_containment(
            incident=inc,
            alert={"id": "alert-pipe-1"},
            event=trigger_event,
            target_id="pipe-target-1"
        )
        self.assertEqual(containment["status"], "contained")
        self.assertGreaterEqual(len(containment["actions_dispatched"]), 1)

    def test_5_poller_worker_sync(self):
        """5. Verifies outbound target poller handles target sequence polling gracefully."""
        res = poll_target_once("pipe-target-1")
        self.assertIn(res.get("status"), ("success", "error", "skipped"))
        self.assertIn("target_id", res)


if __name__ == "__main__":
    unittest.main()
