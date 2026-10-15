"""
Unit & Integration Tests for Part 2: Ingestion & Target Synchronization Engine.
Run with: ./venv/bin/python3 -m unittest discover -s tests -p "test_*.py" -v
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import uuid

from app import create_app
from app.services.event_service import ingest_event, ingest_batch, query_events
from app.services.poller_service import (
    poll_target_once,
    poll_all_active_targets,
    check_and_update_all_targets_health,
)


class TestPart2PollerAndIngestion(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. Event Ingestion & Entity Normalization
    # =========================================================================

    def test_ingest_event_validates_mandatory_envelope_fields(self):
        with self.assertRaises(ValueError):
            ingest_event({"event_type": "LOGIN_FAILED"})  # Missing event_id

        with self.assertRaises(ValueError):
            ingest_event({"event_id": "ev-1"})  # Missing event_type

    @patch("app.services.event_service.get_service_supabase")
    def test_ingest_event_persists_canonical_security_event(self, mock_sb):
        mock_table = MagicMock()
        mock_table.upsert.return_value.execute.return_value.data = [{"id": "ev-uuid-1"}]
        mock_sb.return_value.table.return_value = mock_table

        raw_event = {
            "event_id": "ev-canonical-test-1",
            "seq": 42,
            "event_type": "LOGIN_SUCCESS",
            "occurred_at": "2026-10-15T20:00:00Z",
            "source_system": "shieldbank-testbed",
            "user_id_pub": "USR_BEKELE",
            "account_id_pub": "ACC_BEKELE_1",
            "session_id_pub": "SESS_123",
            "device_id_pub": "DEV_456",
            "source_ip": "198.51.100.10",
            "result": "SUCCESS",
            "attributes": {"new_device": True}
        }

        res = ingest_event(raw_event, target={"id": "00000000-0000-0000-0000-000000000001", "name": "ShieldBank"})
        self.assertEqual(res["status"], "received")
        self.assertEqual(res["event_id"], "ev-canonical-test-1")

        mock_sb.return_value.table.assert_any_call("security_events")
        upsert_arg = mock_table.upsert.call_args[0][0]
        self.assertEqual(upsert_arg["event_id"], "ev-canonical-test-1")
        self.assertEqual(upsert_arg["seq"], 42)
        self.assertEqual(upsert_arg["attributes"]["new_device"], True)

    @patch("app.services.event_service.analyze_transaction")
    @patch("app.services.event_service.get_service_supabase")
    def test_ingest_event_normalizes_transfer_into_transactions(self, mock_sb, mock_analyze):
        mock_table = MagicMock()
        mock_table.upsert.return_value.execute.return_value.data = [{"id": "ev-uuid-2"}]
        mock_table.insert.return_value.execute.return_value.data = [{"id": "00000000-0000-0000-0000-000000000099"}]
        mock_sb.return_value.table.return_value = mock_table

        transfer_event = {
            "event_id": "ev-tx-normalize-1",
            "event_type": "TRANSFER_CREATED",
            "account_id": "ACC_VICTIM_9",
            "amount": 180000.0,
            "amount_minor": 18000000,
            "currency": "ETB",
            "source_ip": "198.51.100.22",
            "device_id": "DEV_ROGUE_SAFARI",
            "result": "SUCCESS",
            "attributes": {
                "lab_scenario_id": "account_takeover",
                "held_for_review": True
            }
        }

        res = ingest_event(transfer_event)
        self.assertEqual(res["status"], "received")
        self.assertEqual(res["lab_scenario_id"], "account_takeover")

        # Verify transaction inserted
        insert_calls = [c[0][0] for c in mock_table.insert.call_args_list]
        tx_row = next(r for r in insert_calls if "account_number" in r)
        self.assertEqual(tx_row["account_number"], "ACC_VICTIM_9")
        self.assertEqual(tx_row["amount"], 180000.0)
        self.assertEqual(tx_row["is_suspicious"], True)

        # Verify analyze_transaction called
        mock_analyze.assert_called_once_with("00000000-0000-0000-0000-000000000099")

    @patch("app.services.event_service.ingest_event")
    def test_ingest_batch_processes_all_events(self, mock_ingest):
        events = [
            {"event_id": "ev-1", "event_type": "LOGIN_FAILED"},
            {"event_id": "ev-2", "event_type": "LOGIN_SUCCESS"},
            {"event_id": "ev-3", "event_type": "TRANSFER_CREATED"},
        ]
        count = ingest_batch(events)
        self.assertEqual(count, 3)
        self.assertEqual(mock_ingest.call_count, 3)

    # =========================================================================
    # 2. Outbound Poller Service (Direction B Pull Sync)
    # =========================================================================

    @patch("app.services.poller_service.ingest_batch")
    @patch("app.services.poller_service.call_target")
    @patch("app.services.poller_service.get_service_supabase")
    @patch("app.services.poller_service.get_target_by_id")
    def test_poll_target_once_fetches_events_and_advances_sequence(self, mock_get_target, mock_sb, mock_call, mock_batch):
        target_uuid = "00000000-0000-0000-0000-000000000001"
        mock_get_target.return_value = {
            "id": target_uuid,
            "name": "ShieldBank Core Testbed",
            "base_url": "http://127.0.0.1:3000",
            "key_id": "ecs_live_key",
            "secret_key": "super-secret-key-32b",
            "last_synced_seq": 10,
        }

        # Mock target response
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "events": [
                {"event_id": "ev-pulled-1", "event_type": "LOGIN_FAILED", "seq": 11},
                {"event_id": "ev-pulled-2", "event_type": "LOGIN_SUCCESS", "seq": 12},
            ],
            "next_seq": 12
        }
        mock_call.return_value = mock_resp
        mock_batch.return_value = 2

        mock_table = MagicMock()
        mock_table.update.return_value.eq.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        res = poll_target_once(target_uuid)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["events_synced"], 2)
        self.assertEqual(res["previous_seq"], 10)
        self.assertEqual(res["new_seq"], 12)

        # Check call_target arguments
        mock_call.assert_called_once()
        args, kwargs = mock_call.call_args
        self.assertEqual(kwargs["method"], "GET")
        self.assertIn("since_seq=10", kwargs["path"])
        self.assertEqual(kwargs["base_url"], "http://127.0.0.1:3000")

        # Verify last_synced_seq updated in database
        mock_table.update.assert_called_once()
        update_data = mock_table.update.call_args[0][0]
        self.assertEqual(update_data["last_synced_seq"], 12)

    @patch("app.services.poller_service.call_target")
    @patch("app.services.poller_service.get_target_by_id")
    def test_poll_target_handles_target_error_gracefully(self, mock_get_target, mock_call):
        mock_get_target.return_value = {
            "id": "target-1",
            "base_url": "http://down.test",
            "key_id": "k1",
            "secret_key": "s1",
            "last_synced_seq": 5
        }
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 502
        mock_resp.text = "Bad Gateway"
        mock_call.return_value = mock_resp

        res = poll_target_once("target-1")
        self.assertEqual(res["events_synced"], 0)
        self.assertEqual(res["status_code"], 502)

    # =========================================================================
    # 3. Health Monitor Heartbeat
    # =========================================================================

    @patch("app.services.poller_service.check_target_health")
    @patch("app.services.poller_service.get_service_supabase")
    @patch("app.services.poller_service.list_active_targets")
    def test_check_and_update_all_targets_health(self, mock_list, mock_sb, mock_health):
        mock_list.return_value = [
            {"id": "t-1", "name": "Target 1", "base_url": "http://target1.test"},
            {"id": "t-2", "name": "Target 2", "base_url": "http://target2.test"},
        ]
        mock_health.side_effect = [
            {"status": "healthy", "version": "1.0.0"},
            {"status": "down", "error": "Connection refused"}
        ]

        mock_table = MagicMock()
        mock_table.update.return_value.eq.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        results = check_and_update_all_targets_health()

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["status"], "healthy")
        self.assertEqual(results[1]["status"], "down")

    # =========================================================================
    # 4. Target Stats & Poll-Now Endpoints
    # =========================================================================

    @patch("app.services.auth_service.jwt.decode")
    @patch("app.routes.targets.get_target_by_id")
    @patch("app.routes.targets.poll_target_once")
    @patch("app.routes.targets.log_action")
    def test_poll_now_endpoint_triggers_synchronization(self, mock_log, mock_poll, mock_get_target, mock_jwt):
        # Mock auth
        mock_jwt.return_value = {
            "sub": "00000000-0000-0000-0000-000000000001",
            "role": "analyst",
            "email": "analyst@cybershield.et"
        }
        mock_poll.return_value = {"target_id": "t-1", "events_synced": 5, "new_seq": 25}

        headers = {"Authorization": "Bearer mock-token"}
        resp = self.client.post("/api/targets/t-1/poll-now", headers=headers)

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["events_synced"], 5)
        self.assertEqual(data["new_seq"], 25)
        mock_poll.assert_called_once_with("t-1")


if __name__ == "__main__":
    unittest.main()
