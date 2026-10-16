"""
Unit & Integration Tests for Part 1: Database Migration, Entities, & Target System Service.
Run with: python3 -m unittest discover -s tests -p "test_*.py"
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import time
import uuid
import hmac
import hashlib

from app import create_app
from app.services.target_system_service import (
    sign_headers,
    execute_target_control,
    freeze_target_transaction,
    revoke_target_session,
    block_target_ip,
    require_step_up,
    disable_beneficiary,
    lock_account,
    revert_target_action,
    verify_and_record_nonce,
)


class TestPart1EntitiesAndServices(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. HMAC Signing & Canonical Formats (§10)
    # =========================================================================

    def test_sign_headers_structure_and_digest(self):
        key_id = "test_key_001"
        secret = "test_secret_32b_length_valid!!"
        method = "POST"
        path = "/api/public/security/controls/freeze-transaction"
        payload = {"transaction_id": "TX_1001", "reason": "ATO compromise"}
        raw_body = json.dumps(payload, separators=(",", ":")).encode()

        headers = sign_headers(key_id, secret, method, path, raw_body)

        self.assertIn("X-ECS-Key-Id", headers)
        self.assertIn("X-ECS-Timestamp", headers)
        self.assertIn("X-ECS-Nonce", headers)
        self.assertIn("X-ECS-Signature", headers)

        self.assertEqual(headers["X-ECS-Key-Id"], key_id)

        # Verify signature can be independently verified
        ts = headers["X-ECS-Timestamp"]
        nonce = headers["X-ECS-Nonce"]
        body_hash = hashlib.sha256(raw_body).hexdigest()
        canonical = f"{ts}\n{nonce}\n{method}\n{path}\n{body_hash}"
        expected_sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

        self.assertTrue(hmac.compare_digest(headers["X-ECS-Signature"], expected_sig))

    # =========================================================================
    # 2. Control Execution & Payload Builders (§11)
    # =========================================================================

    @patch("app.services.target_system_service.call_target")
    @patch("app.services.target_system_service.get_service_supabase")
    def test_freeze_target_transaction_dispatches_correct_payload(self, mock_sb, mock_call):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "CONFIRMED", "transaction_id": "TX_TEST_1"}
        mock_call.return_value = mock_resp

        # Mock supabase response_actions table
        mock_table = MagicMock()
        valid_id = "00000000-0000-0000-0000-000000000001"
        mock_table.insert.return_value.execute.return_value.data = [{"id": valid_id}]
        mock_table.update.return_value.eq.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        res = freeze_target_transaction(
            transaction_id="TX_TEST_1",
            reason="Suspected ATO transfer",
            alert_id="ALT-999"
        )

        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["action_id"], valid_id)

        mock_call.assert_called_once()
        args, kwargs = mock_call.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "/api/public/security/controls/freeze-transaction")
        self.assertEqual(args[2]["transaction_id"], "TX_TEST_1")
        self.assertEqual(args[2]["reason"], "Suspected ATO transfer")

    @patch("app.services.target_system_service.call_target")
    @patch("app.services.target_system_service.get_service_supabase")
    def test_revoke_target_session_dispatches_correct_payload(self, mock_sb, mock_call):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "CONFIRMED"}
        mock_call.return_value = mock_resp

        mock_table = MagicMock()
        valid_id = "00000000-0000-0000-0000-000000000002"
        mock_table.insert.return_value.execute.return_value.data = [{"id": valid_id}]
        mock_table.update.return_value.eq.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        res = revoke_target_session(
            session_id="SESS_ROGUE_99",
            reason="ATO attacker session terminated"
        )

        self.assertEqual(res["status"], "confirmed")
        mock_call.assert_called_once()
        args, _ = mock_call.call_args
        self.assertEqual(args[1], "/api/public/security/controls/revoke-session")
        self.assertEqual(args[2]["session_id"], "SESS_ROGUE_99")

    @patch("app.services.target_system_service.call_target")
    @patch("app.services.target_system_service.get_service_supabase")
    def test_block_target_ip_dispatches_correct_payload(self, mock_sb, mock_call):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "CONFIRMED"}
        mock_call.return_value = mock_resp

        mock_table = MagicMock()
        valid_id3 = "00000000-0000-0000-0000-000000000003"
        mock_table.insert.return_value.execute.return_value.data = [{"id": valid_id3}]
        mock_table.update.return_value.eq.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        res = block_target_ip(ip="198.51.100.44", reason="Brute force source")
        self.assertEqual(res["status"], "confirmed")
        args, _ = mock_call.call_args
        self.assertEqual(args[1], "/api/public/security/controls/block-ip")
        self.assertEqual(args[2]["ip"], "198.51.100.44")

    # =========================================================================
    # 3. Persistent Nonce Anti-Replay Defense
    # =========================================================================

    @patch("app.services.target_system_service.get_service_supabase")
    def test_verify_and_record_nonce_detects_replay(self, mock_sb):
        mock_table = MagicMock()
        # First call: nonce not in db -> returns empty
        mock_table.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        ok1, err1 = verify_and_record_nonce("key_1", "nonce-first-time")
        self.assertTrue(ok1)
        self.assertIsNone(err1)

        # Second call: nonce found in db -> returns existing row
        mock_table.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value.data = [{"id": "nonce-1"}]
        ok2, err2 = verify_and_record_nonce("key_1", "nonce-first-time")
        self.assertFalse(ok2)
        self.assertEqual(err2, "Replayed nonce detected")

    # =========================================================================
    # 4. Inbound Telemetry Webhook Ingestion (/api/events)
    # =========================================================================

    def test_inbound_events_rejects_missing_hmac_headers(self):
        resp = self.client.post("/api/events", json={"event_id": "ev-1", "event_type": "LOGIN_FAILED"})
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertEqual(data["error"], "Unauthorized")

    def test_inbound_events_rejects_stale_timestamp(self):
        stale_ts = str(int(time.time()) - 400)  # > 300s skew
        headers = {
            "X-ECS-Key-Id": "test_key",
            "X-ECS-Timestamp": stale_ts,
            "X-ECS-Nonce": str(uuid.uuid4()),
            "X-ECS-Signature": "dummy_sig",
            "Content-Type": "application/json",
        }
        resp = self.client.post("/api/events", json={"event_id": "ev-1", "event_type": "LOGIN_FAILED"}, headers=headers)
        self.assertEqual(resp.status_code, 401)

    @patch("app.routes.events.verify_and_record_nonce")
    @patch("app.services.event_service.get_service_supabase")
    def test_inbound_events_accepts_valid_signature_and_persists_event(self, mock_sb, mock_nonce):
        mock_nonce.return_value = (True, None)

        mock_table = MagicMock()
        mock_table.upsert.return_value.execute.return_value.data = [{"id": "ev-stored-uuid"}]
        mock_table.insert.return_value.execute.return_value.data = [{"id": "tx-stored-uuid"}]
        mock_sb.return_value.table.return_value = mock_table

        secret = "super-secret-key-32b"
        key_id = "ecs_live_prod_key_01"
        payload = {
            "event_id": "ev-ingest-test-1",
            "event_type": "TRANSFER_CREATED",
            "occurred_at": "2026-10-15T19:00:00Z",
            "source_system": "shieldbank-testbed",
            "user_id_pub": "USR_ALICE",
            "account_id_pub": "ACC_1001",
            "amount": 25000.0,
            "source_ip": "198.51.100.22",
            "result": "SUCCESS",
            "attributes": {"held_for_review": False}
        }

        raw_body = json.dumps(payload, separators=(",", ":")).encode()
        headers = sign_headers(key_id, secret, "POST", "/api/events", raw_body)

        resp = self.client.post("/api/events", data=raw_body, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "received")
        self.assertEqual(data["event_id"], "ev-ingest-test-1")

    # =========================================================================
    # 5. Target Systems API Blueprint Registration (/api/targets)
    # =========================================================================

    def test_targets_route_registered_and_requires_auth(self):
        resp = self.client.get("/api/targets")
        # Without auth header, should return 401
        self.assertEqual(resp.status_code, 401)

    def test_api_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")


if __name__ == "__main__":
    unittest.main()
