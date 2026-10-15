"""
Unit & Integration Tests for Part 3: Multi-Layer Threat Detection & Explainable Risk Engine.
Validates deterministic rules L1 to L4 per SRS §9 & §21.
Run with: ./venv/bin/python3 -m unittest tests/test_part3_detection_engine.py -v
"""
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.detection_engine import (
    evaluate_event_stream,
    check_ip_in_ioc_watchlists,
    _get_sliding_window_events,
)
from app.services.event_service import ingest_event


class TestPart3DetectionEngine(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. LAYER 1: THRESHOLD & SIGNATURE RULES
    # =========================================================================

    @patch("app.services.detection_engine._get_sliding_window_events")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_auth_001_login_failure_burst_triggers(self, mock_sb, mock_window):
        """AUTH-001: 5 failed attempts on an account within 60s triggers alert."""
        mock_window.return_value = [
            {"event_type": "LOGIN_FAILED", "account_id": "ACC_BEKELE"} for _ in range(5)
        ]
        event = {
            "event_id": "ev-auth-001",
            "event_type": "LOGIN_FAILED",
            "account_id_pub": "ACC_BEKELE",
            "source_ip": "198.51.100.5",
            "occurred_at": "2026-10-15T12:00:00Z",
            "attributes": {"consecutive_failures_for_identifier": 5}
        }
        res = evaluate_event_stream(event)
        self.assertIn("AUTH-001", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 25)
        self.assertIn("ACC_BEKELE", res["breakdown"][0]["summary"])

    @patch("app.services.detection_engine._get_sliding_window_events")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_auth_002_credential_stuffing_triggers(self, mock_sb, mock_window):
        """AUTH-002: Single IP targeting >= 3 distinct accounts triggers credential stuffing."""
        mock_window.return_value = [
            {"event_type": "LOGIN_FAILED", "account_id_pub": "ACC_1"},
            {"event_type": "LOGIN_FAILED", "account_id_pub": "ACC_2"},
            {"event_type": "LOGIN_FAILED", "account_id_pub": "ACC_3"},
        ]
        event = {
            "event_id": "ev-auth-002",
            "event_type": "LOGIN_FAILED",
            "source_ip": "198.51.100.77",
            "account_id_pub": "ACC_4",
            "occurred_at": "2026-10-15T12:00:00Z",
            "attributes": {"distinct_identifiers_last_60s_for_ip": 4}
        }
        res = evaluate_event_stream(event)
        self.assertIn("AUTH-002", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertEqual(res["severity"], "medium")

    @patch("app.services.detection_engine.get_service_supabase")
    def test_tx_001_high_value_transfer_anomaly(self, mock_sb):
        """TX-001: Transfer of >= 100,000 ETB triggers high-value rule."""
        event = {
            "event_id": "ev-tx-001",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_MERCHANT",
            "amount": 250000.0,
            "currency": "ETB",
            "occurred_at": "2026-10-15T10:00:00Z",  # 13:00 Addis Ababa (business hours)
        }
        res = evaluate_event_stream(event)
        self.assertIn("TX-001", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 20)

    @patch("app.services.detection_engine.check_ip_in_ioc_watchlists")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_ioc_001_malicious_ip_match(self, mock_sb, mock_ioc):
        """IOC-001: Connection from malicious IP in indicators / watchlists."""
        mock_ioc.return_value = {"source": "Threat Indicators", "data": {"status": "malicious"}}
        event = {
            "event_id": "ev-ioc-001",
            "event_type": "LOGIN_FAILED",
            "source_ip": "203.0.113.55",
            "occurred_at": "2026-10-15T12:00:00Z",
        }
        res = evaluate_event_stream(event)
        self.assertIn("IOC-001", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 40)

    @patch("app.services.detection_engine._get_sliding_window_events")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_api_001_authorization_denial_burst(self, mock_sb, mock_window):
        """API-001: >= 4 authorization denials in 60s from single source IP."""
        mock_window.return_value = [
            {"event_type": "AUTHZ_DENIED", "source_ip": "198.51.100.9"} for _ in range(4)
        ]
        event = {
            "event_id": "ev-api-001",
            "event_type": "AUTHZ_DENIED",
            "source_ip": "198.51.100.9",
            "endpoint": "/api/admin/users",
            "occurred_at": "2026-10-15T12:00:00Z",
        }
        res = evaluate_event_stream(event)
        self.assertIn("API-001", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 25)

    # =========================================================================
    # 2. LAYER 2: CONTEXTUAL ENTITY RULES
    # =========================================================================

    @patch("app.services.detection_engine._get_sliding_window_events")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_auth_003_new_device_login_after_failures(self, mock_sb, mock_window):
        """AUTH-003: Login success from new hardware device after >= 3 failed logins."""
        mock_window.return_value = [
            {"event_type": "LOGIN_FAILED", "account_id": "ACC_TARGET"} for _ in range(3)
        ]
        event = {
            "event_id": "ev-auth-003",
            "event_type": "LOGIN_SUCCESS",
            "account_id_pub": "ACC_TARGET",
            "device_id_pub": "DEV_NEW_DEVICE",
            "occurred_at": "2026-10-15T12:00:00Z",
            "attributes": {"new_device": True, "failed_attempts_since_last_success": 3}
        }
        res = evaluate_event_stream(event)
        self.assertIn("AUTH-003", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 35)

    @patch("app.services.detection_engine.get_service_supabase")
    def test_tx_003_off_hours_high_value_transfer(self, mock_sb):
        """TX-003: High-value transfer initiated between 00:00 and 05:00 Addis Ababa time."""
        # UTC 23:00 is 02:00 Addis Ababa (UTC+3)
        event = {
            "event_id": "ev-tx-003",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_NIGHT_VICTIM",
            "amount": 120000.0,
            "currency": "ETB",
            "occurred_at": "2026-10-15T23:30:00Z",
            "attributes": {"local_hour": 2}
        }
        res = evaluate_event_stream(event)
        self.assertIn("TX-001", res["rules_fired"])  # High value >= 100k
        self.assertIn("TX-003", res["rules_fired"])  # Off hours
        self.assertGreaterEqual(res["risk_score"], 45)

    @patch("app.services.detection_engine.get_service_supabase")
    def test_priv_001_unauthorized_admin_abuse(self, mock_sb):
        """PRIV-001: Customer identity attempting administrative endpoints."""
        event = {
            "event_id": "ev-priv-001",
            "event_type": "AUTHZ_DENIED",
            "endpoint": "/api/admin/system/override",
            "source_ip": "198.51.100.12",
            "attributes": {"attempted_privilege": "admin"}
        }
        res = evaluate_event_stream(event)
        self.assertIn("PRIV-001", res["rules_fired"])
        self.assertGreaterEqual(res["risk_score"], 40)

    # =========================================================================
    # 3. LAYER 3 & LAYER 4: MULTI-EVENT CORRELATION (ATO) & EXPLAINABLE RISK
    # =========================================================================

    @patch("app.services.detection_engine.get_service_supabase")
    def test_ato_001_full_account_takeover_chain_triggers_critical_alert(self, mock_sb):
        """ATO-001: High-value transfer resulting from account takeover chain reaches score 100 & critical alert."""
        mock_table = MagicMock()
        mock_table.insert.return_value.execute.return_value.data = [{"id": "00000000-0000-0000-0000-000000000099"}]
        mock_sb.return_value.table.return_value = mock_table

        event = {
            "event_id": "ev-ato-chain-final",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_COMPROMISED_01",
            "amount": 180000.0,
            "currency": "ETB",
            "device_id_pub": "DEV_ATTACKER_BROWSER",
            "source_ip": "198.51.100.88",
            "occurred_at": "2026-10-15T01:30:00Z",  # 04:30 Addis Ababa (night)
            "attributes": {
                "lab_scenario_id": "account_takeover",
                "held_for_review": True,
                "off_hours": True,
                "device_trusted": False
            }
        }

        res = evaluate_event_stream(event)
        self.assertTrue(res["is_attack_chain"])
        self.assertIn("ATO-001", res["rules_fired"])
        self.assertIn("TX-001", res["rules_fired"])
        self.assertIn("TX-003", res["rules_fired"])
        self.assertIn("TX-004", res["rules_fired"])
        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["severity"], "critical")
        self.assertEqual(res["confidence"], "high")

        # Verify explainable evidence breakdown
        breakdown_rules = [b["rule_id"] for b in res["breakdown"]]
        self.assertIn("ATO-001", breakdown_rules)
        self.assertTrue(any("pts" in r for r in res["reasons"]))

    @patch("app.services.event_service.get_service_supabase")
    @patch("app.services.event_service.analyze_transaction")
    def test_ingest_event_executes_detection_engine_end_to_end(self, mock_analyze, mock_sb):
        """End-to-end event ingestion populates detection result with risk score."""
        mock_table = MagicMock()
        mock_table.upsert.return_value.execute.return_value.data = [{"id": "00000000-0000-0000-0000-000000000001"}]
        mock_table.insert.return_value.execute.return_value.data = [{"id": "00000000-0000-0000-0000-000000000002"}]
        mock_sb.return_value.table.return_value = mock_table

        raw_event = {
            "event_id": "ev-e2e-detection-test",
            "event_type": "TRANSFER_CREATED",
            "account_id": "ACC_E2E_01",
            "amount": 150000.0,
            "currency": "ETB",
            "source_ip": "198.51.100.99",
            "device_id": "DEV_ROGUE",
            "attributes": {
                "lab_scenario_id": "account_takeover",
                "held_for_review": True
            }
        }

        res = ingest_event(raw_event)
        self.assertEqual(res["status"], "received")
        self.assertIsNotNone(res.get("detection"))
        self.assertEqual(res["detection"]["risk_score"], 100)
        self.assertEqual(res["detection"]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
