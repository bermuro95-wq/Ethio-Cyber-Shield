"""
Unit & Integration Tests for Part 5: Closed-Loop Controlled Response & Mitigation Dispatcher.
Validates automated containment, rollback/revert, policy toggling, and target control execution.
Run with: ./venv/bin/python3 -m unittest tests/test_part5_controlled_response.py -v
"""
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json

from app import create_app
from app.services.response_policy import (
    is_auto_containment_enabled,
    set_auto_containment_enabled,
    evaluate_and_execute_containment,
    revert_containment,
)
from app.services.event_service import ingest_event


class TestPart5ControlledResponse(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
        try:
            from app.services.response_modes_service import clear_response_modes_caches
            clear_response_modes_caches()
        except Exception:
            pass
        try:
            from app.services.guardrails_service import clear_guardrails_caches
            clear_guardrails_caches()
        except Exception:
            pass

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. Policy Settings & Toggling
    # =========================================================================

    @patch("app.services.response_policy.get_service_supabase")
    def test_auto_containment_toggle_and_persistence(self, mock_sb):
        """Auto-containment setting can be retrieved and updated in system_settings."""
        mock_table = MagicMock()
        mock_table.select.return_value.eq.return_value.execute.return_value.data = [
            {"value": {"enabled": False}}
        ]
        mock_table.upsert.return_value.execute.return_value.data = [{"key": "auto_containment"}]
        mock_sb.return_value.table.return_value = mock_table

        with patch.dict("os.environ", {}, clear=True):
            # Check read from db
            self.assertFalse(is_auto_containment_enabled())

            # Check write to db
            success = set_auto_containment_enabled(True)
            self.assertTrue(success)
            mock_table.upsert.assert_called()

    # =========================================================================
    # 2. Automated Containment on High-Confidence Threats
    # =========================================================================

    @patch("app.services.response_policy.is_auto_containment_enabled", return_value=True)
    @patch("app.services.response_policy.freeze_target_transaction")
    @patch("app.services.response_policy.revoke_target_session")
    @patch("app.services.response_policy.block_target_ip")
    @patch("app.services.response_policy.get_service_supabase")
    def test_ato_001_executes_triple_containment_and_contains_incident(
        self, mock_sb, mock_block, mock_revoke, mock_freeze, mock_auto_enabled
    ):
        """Account Takeover triggers transaction freeze, session revocation, and IP block, setting incident to contained."""
        mock_freeze.return_value = {"status": "confirmed", "action_id": "act-1", "response": {"status": "CONFIRMED"}}
        mock_revoke.return_value = {"status": "confirmed", "action_id": "act-2", "response": {"status": "CONFIRMED"}}
        mock_block.return_value = {"status": "confirmed", "action_id": "act-3", "response": {"status": "CONFIRMED"}}

        mock_table = MagicMock()
        mock_sb.return_value.table.return_value = mock_table

        event = {
            "event_id": "ev-ato-contain-1",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_VICTIM_88",
            "session_id_pub": "SESS_ATTACKER_99",
            "source_ip": "198.51.100.200",
            "transaction_id_pub": "TX_HOLD_777",
            "target_system_id": "00000000-0000-0000-0000-000000000001",
        }
        alert = {"id": "00000000-0000-0000-0000-000000000010", "severity": "critical"}
        incident = {"id": "00000000-0000-0000-0000-000000000020", "status": "open"}
        detection_result = {
            "risk_score": 100,
            "severity": "critical",
            "rules_fired": ["ATO-001", "TX-001", "TX-004"],
            "is_attack_chain": True,
        }

        result = evaluate_and_execute_containment(event, alert, incident, detection_result)
        self.assertTrue(result["auto_contained"])
        self.assertEqual(result["incident_status"], "contained")
        self.assertEqual(len(result["actions"]), 3)

        # Verify all 3 outbound controls dispatched
        mock_freeze.assert_called_once()
        mock_revoke.assert_called_once()
        mock_block.assert_called_once()

        # Verify incident status transitioned to 'contained' in DB
        mock_table.update.assert_called_with({
            "status": "contained",
            "updated_at": unittest.mock.ANY,
        })

    @patch("app.services.response_policy.is_auto_containment_enabled", return_value=False)
    @patch("app.services.response_policy.freeze_target_transaction")
    def test_auto_containment_disabled_mode_generates_recommendations_only(self, mock_freeze, mock_auto_enabled):
        """When auto-containment is turned off, actions are queued as recommendations without target dispatch."""
        event = {
            "event_id": "ev-recom-1",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_TEST",
            "transaction_id_pub": "TX_TEST_1",
        }
        alert = {"id": "alert-1"}
        detection_result = {
            "risk_score": 100,
            "rules_fired": ["ATO-001"],
            "is_attack_chain": True,
        }

        result = evaluate_and_execute_containment(event, alert, None, detection_result)
        self.assertFalse(result["auto_contained"])
        self.assertTrue(result.get("recommended_only"))
        self.assertGreaterEqual(len(result["actions"]), 1)
        mock_freeze.assert_not_called()

    @patch("app.services.response_policy.is_auto_containment_enabled", return_value=True)
    @patch("app.services.response_policy.block_target_ip")
    def test_credential_stuffing_executes_ip_block(self, mock_block, mock_auto_enabled):
        """AUTH-002 triggers targeted IP block containment."""
        mock_block.return_value = {"status": "confirmed", "action_id": "act-ip-1"}
        event = {
            "event_id": "ev-stuffing-1",
            "event_type": "LOGIN_FAILED",
            "source_ip": "198.51.100.66",
        }
        detection_result = {
            "risk_score": 75,
            "rules_fired": ["AUTH-002"],
            "is_attack_chain": False,
        }

        result = evaluate_and_execute_containment(event, None, None, detection_result)
        self.assertTrue(result["auto_contained"])
        mock_block.assert_called_once_with(
            "198.51.100.66",
            unittest.mock.ANY,
            alert_id=None,
            target_id=None
        )

    # =========================================================================
    # 3. Rollback & Revert Execution
    # =========================================================================

    @patch("app.services.response_policy.revert_target_action")
    @patch("app.services.response_policy.get_service_supabase")
    def test_revert_containment_action_dispatches_target_revert(self, mock_sb, mock_revert_call):
        """Rollback invokes target revert control and updates response_actions status to reverted."""
        mock_revert_call.return_value = {
            "status": "confirmed",
            "response": {"status": "CONFIRMED", "message": "Transaction un-frozen"}
        }
        mock_table = MagicMock()
        mock_table.select.return_value.eq.return_value.execute.return_value.data = [{
            "id": "act-uuid-99",
            "target_system_id": "00000000-0000-0000-0000-000000000001",
            "target_response": {"action_id": "ctrl-target-123"},
        }]
        mock_sb.return_value.table.return_value = mock_table

        res = revert_containment("act-uuid-99", reason="False positive investigation")
        self.assertEqual(res["status"], "confirmed")
        mock_revert_call.assert_called_once_with(
            "ctrl-target-123",
            reason="False positive investigation",
            target_id="00000000-0000-0000-0000-000000000001",
            requested_by=None
        )

    # =========================================================================
    # 4. End-to-End Autonomous Closed-Loop Verification
    # =========================================================================

    @patch("app.services.response_policy.is_auto_containment_enabled", return_value=True)
    @patch("app.services.response_policy.freeze_target_transaction")
    @patch("app.services.response_policy.revoke_target_session")
    @patch("app.services.response_policy.block_target_ip")
    @patch("app.services.incident_service.get_service_supabase")
    @patch("app.services.detection_engine.get_service_supabase")
    @patch("app.services.event_service.get_service_supabase")
    @patch("app.services.event_service.analyze_transaction")
    def test_end_to_end_closed_loop_detection_to_containment(
        self, mock_analyze, mock_ev_sb, mock_det_sb, mock_inc_sb,
        mock_block, mock_revoke, mock_freeze, mock_auto
    ):
        """Telemetry ingestion of ATO triggers L3 detection, incident creation, and automated fund freeze."""
        mock_freeze.return_value = {"status": "confirmed", "action_id": "act-freeze-1"}
        mock_revoke.return_value = {"status": "confirmed", "action_id": "act-revoke-1"}
        mock_block.return_value = {"status": "confirmed", "action_id": "act-block-1"}

        inc_uuid = "00000000-0000-0000-0000-000000000999"
        alert_uuid = "00000000-0000-0000-0000-000000000888"

        m_table = MagicMock()
        m_table.insert.return_value.execute.return_value.data = [{"id": inc_uuid}]
        m_table.upsert.return_value.execute.return_value.data = [{"id": "ev-1"}]
        m_table.update.return_value.execute.return_value.data = [{"id": alert_uuid}]
        m_table.select.return_value.in_.return_value.gte.return_value.order.return_value.execute.return_value.data = []

        mock_ev_sb.return_value.table.return_value = m_table
        mock_det_sb.return_value.table.return_value = m_table
        mock_inc_sb.return_value.table.return_value = m_table

        raw_event = {
            "event_id": "ev-e2e-closed-loop-1",
            "event_type": "TRANSFER_CREATED",
            "account_id": "ACC_CHALTU_1",
            "amount": 180000.0,
            "currency": "ETB",
            "source_ip": "198.51.100.77",
            "device_id": "DEV_ROGUE_SAFARI",
            "session_id": "SESS_ROGUE_999",
            "transaction_id": "TX_CRITICAL_180K",
            "attributes": {
                "lab_scenario_id": "account_takeover",
                "held_for_review": True,
                "device_trusted": False
            }
        }

        res = ingest_event(raw_event)
        self.assertEqual(res["status"], "received")
        det = res.get("detection")
        self.assertIsNotNone(det)
        self.assertEqual(det["risk_score"], 100)
        self.assertEqual(det["severity"], "critical")
        self.assertIsNotNone(det.get("containment"))
        self.assertTrue(det["containment"]["auto_contained"])

        # Outbound freeze and revoke must have been triggered
        mock_freeze.assert_called_once()
        mock_revoke.assert_called_once()


if __name__ == "__main__":
    unittest.main()
