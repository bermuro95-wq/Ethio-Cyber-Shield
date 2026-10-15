"""
Unit & Integration Tests for Part 6: Target Lab Simulator & Scenario Orchestration Controller.
Validates remote attack triggering, scenario catalog, and immediate telemetry synchronization.
Run with: ./venv/bin/python3 -m unittest tests/test_part6_lab_simulator.py -v
"""
import unittest
from unittest.mock import patch, MagicMock
import json

from app import create_app
from app.services.auth_service import create_token


class TestPart6LabSimulator(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

        # Analyst test token
        self.analyst_token = create_token(
            "00000000-0000-0000-0000-000000000001",
            "analyst@shield.et",
            "analyst"
        )
        self.headers = {"Authorization": f"Bearer {self.analyst_token}"}

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. Scenarios Catalog
    # =========================================================================

    def test_list_scenarios_returns_catalog(self):
        """GET /api/live/scenarios returns available demonstration scenarios."""
        resp = self.client.get("/api/live/scenarios", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("scenarios", data)
        scenario_ids = [s["id"] for s in data["scenarios"]]
        self.assertIn("account_takeover", scenario_ids)
        self.assertIn("credential_stuffing", scenario_ids)
        self.assertIn("rapid_transfers", scenario_ids)
        self.assertIn("admin_probe", scenario_ids)
        self.assertIn("normal_traffic", scenario_ids)

    # =========================================================================
    # 2. Remote Attack Triggering & Sync
    # =========================================================================

    @patch("app.routes.live.log_action")
    @patch("app.routes.live.poll_target_once")
    @patch("app.routes.live.run_target_scenario")
    @patch("app.routes.live.get_target_by_id")
    def test_trigger_scenario_dispatches_to_target_and_syncs(self, mock_get_target, mock_run, mock_poll, mock_log):
        """POST /api/live/trigger-scenario executes scenario and immediately pulls telemetry."""
        target_uuid = "00000000-0000-0000-0000-000000000050"
        mock_get_target.return_value = {
            "id": target_uuid,
            "name": "ShieldBank Core Testbed",
            "base_url": "http://127.0.0.1:3000",
            "key_id": "ecs_live_key",
            "secret_key": "sec_01",
        }
        mock_run.return_value = ({"status": "COMPLETED", "scenario": "account_takeover", "steps_count": 5}, 200)
        mock_poll.return_value = {"status": "synced", "events_ingested": 5}

        payload = {
            "target_id": target_uuid,
            "scenario": "account_takeover",
            "target_account": "ACC_BEKELE_01",
            "simulated_ip": "198.51.100.44",
            "sync_immediately": True,
        }

        resp = self.client.post("/api/live/trigger-scenario", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "executed")
        self.assertEqual(data["scenario"], "account_takeover")
        self.assertEqual(data["target_name"], "ShieldBank Core Testbed")
        self.assertEqual(data["target_response"]["status"], "COMPLETED")
        self.assertIsNotNone(data["sync_result"])

        # Verify run_target_scenario called with correct parameters
        mock_run.assert_called_once_with(
            scenario_name="account_takeover",
            target_account="ACC_BEKELE_01",
            base_url="http://127.0.0.1:3000",
            key_id="ecs_live_key",
            secret="sec_01",
            simulated_ip="198.51.100.44"
        )
        # Verify immediate sync invoked
        mock_poll.assert_called_once_with(target_uuid)

    @patch("app.routes.live.log_action")
    @patch("app.routes.live.poll_target_once")
    @patch("app.routes.live.run_target_scenario")
    @patch("app.routes.live.list_active_targets")
    def test_trigger_scenario_uses_default_active_target_when_id_omitted(self, mock_list_active, mock_run, mock_poll, mock_log):
        """When target_id is omitted, automatically resolves to first active target."""
        default_target = {
            "id": "00000000-0000-0000-0000-000000000099",
            "name": "Default Testbed",
            "base_url": "http://127.0.0.1:3000",
            "key_id": "ecs_default_key",
            "secret_key": "sec_default",
        }
        mock_list_active.return_value = [default_target]
        mock_run.return_value = ({"status": "COMPLETED", "scenario": "credential_stuffing"}, 200)
        mock_poll.return_value = {"events_ingested": 6}

        payload = {"scenario": "credential_stuffing"}
        resp = self.client.post("/api/live/trigger-scenario", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        mock_run.assert_called_once()
        mock_poll.assert_called_once_with(default_target["id"])

    # =========================================================================
    # 3. Stream Events Endpoint
    # =========================================================================

    @patch("app.routes.live.get_service_supabase")
    def test_stream_events_returns_telemetry_feed(self, mock_sb):
        """GET /api/live/stream-events returns canonical events list for live dashboards."""
        mock_table = MagicMock()
        mock_table.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"event_id": "ev-1", "event_type": "LOGIN_FAILED", "occurred_at": "2026-10-15T20:00:00Z"},
            {"event_id": "ev-2", "event_type": "TRANSFER_CREATED", "occurred_at": "2026-10-15T20:01:00Z"},
        ]
        mock_sb.return_value.table.return_value = mock_table

        resp = self.client.get("/api/live/stream-events?limit=10", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["event_id"], "ev-1")


if __name__ == "__main__":
    unittest.main()
