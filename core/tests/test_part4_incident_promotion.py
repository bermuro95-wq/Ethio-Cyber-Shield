"""
Unit & Integration Tests for Part 4: Autonomous Alerting, Incident Promotion & Threat Intelligence.
Validates automated incident generation, deduplication, indicator linking, and attack graph synthesis.
Run with: ./venv/bin/python3 -m unittest tests/test_part4_incident_promotion.py -v
"""
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
import json

from app import create_app
from app.services.incident_service import (
    promote_alert_to_incident,
    find_active_incident_for_entity,
    link_threat_indicators,
    get_incident_attack_graph,
)
from app.services.event_service import ingest_event


class TestPart4IncidentPromotion(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

    def tearDown(self):
        self.app_ctx.pop()

    # =========================================================================
    # 1. Automated Incident Promotion & Deduplication
    # =========================================================================

    @patch("app.services.incident_service.link_threat_indicators")
    @patch("app.services.incident_service.find_active_incident_for_entity")
    @patch("app.services.incident_service.get_service_supabase")
    def test_promote_alert_creates_new_incident_for_critical_threat(self, mock_sb, mock_find, mock_link):
        """Critical alert auto-promotes to a new incident if no active incident exists."""
        mock_find.return_value = None  # No existing incident
        mock_table = MagicMock()
        created_uuid = "00000000-0000-0000-0000-000000000101"
        mock_table.insert.return_value.execute.return_value.data = [{
            "id": created_uuid,
            "title": "CRITICAL: Account Takeover Incident on ACC_VICTIM_01",
            "incident_type": "account_takeover",
            "severity": "critical",
            "risk_score": 100,
        }]
        mock_table.update.return_value.execute.return_value.data = [{"id": "alert-uuid-1"}]
        mock_sb.return_value.table.return_value = mock_table

        alert = {
            "id": "alert-uuid-1",
            "title": "CRITICAL: Account Takeover Detected on ACC_VICTIM_01",
            "severity": "critical",
        }
        event = {
            "event_id": "ev-ato-01",
            "event_type": "TRANSFER_CREATED",
            "account_id_pub": "ACC_VICTIM_01",
            "source_ip": "198.51.100.99",
            "source_system": "ShieldBank Testbed",
        }
        detection_result = {
            "risk_score": 100,
            "severity": "critical",
            "confidence": "high",
            "rules_fired": ["ATO-001", "TX-001", "TX-004"],
            "reasons": ["[ATO-001] Full ATO chain detected", "[TX-001] High value transfer"],
            "is_attack_chain": True,
        }

        incident = promote_alert_to_incident(alert, event, detection_result)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["id"], created_uuid)
        self.assertEqual(incident["incident_type"], "account_takeover")
        self.assertEqual(incident["severity"], "critical")

        # Verify alert was linked to incident
        mock_table.update.assert_called()

    @patch("app.services.incident_service.link_threat_indicators")
    @patch("app.services.incident_service.find_active_incident_for_entity")
    @patch("app.services.incident_service.get_service_supabase")
    def test_promote_alert_deduplicates_and_updates_existing_active_incident(self, mock_sb, mock_find, mock_link):
        """Subsequent alerts for the same account merge into the active incident without creating duplicates."""
        existing_uuid = "00000000-0000-0000-0000-000000000202"
        mock_find.return_value = {
            "id": existing_uuid,
            "title": "CRITICAL: Account Takeover Incident on ACC_VICTIM_02",
            "risk_score": 80,
            "risk_level": "high",
            "risk_reasons": ["[AUTH-001] Rapid login failures"],
            "status": "open",
        }
        mock_table = MagicMock()
        mock_table.update.return_value.execute.return_value.data = [{"id": existing_uuid}]
        mock_sb.return_value.table.return_value = mock_table

        alert = {"id": "alert-uuid-2", "title": "High Value Transfer", "severity": "critical"}
        event = {"event_id": "ev-followup-02", "account_id_pub": "ACC_VICTIM_02", "source_ip": "198.51.100.99"}
        detection_result = {
            "risk_score": 100,
            "severity": "critical",
            "confidence": "high",
            "rules_fired": ["TX-001"],
            "reasons": ["[TX-001] Transfer of 250,000 ETB"],
            "is_attack_chain": False,
        }

        incident = promote_alert_to_incident(alert, event, detection_result)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["id"], existing_uuid)
        self.assertEqual(incident["risk_score"], 100)
        self.assertEqual(incident["risk_level"], "critical")
        # Ensure insert was NOT called (no duplicate created)
        mock_table.insert.assert_not_called()

    def test_low_risk_alerts_are_not_promoted(self):
        """Low risk alerts (< 50 and not an attack chain) are ignored by incident promotion."""
        alert = {"id": "alert-low", "severity": "low"}
        event = {"event_id": "ev-low", "account_id_pub": "ACC_SAFE"}
        detection_result = {
            "risk_score": 20,
            "severity": "low",
            "is_attack_chain": False,
            "reasons": ["Minor anomaly"],
        }
        incident = promote_alert_to_incident(alert, event, detection_result)
        self.assertIsNone(incident)

    # =========================================================================
    # 2. Threat Indicator Extraction & Linking
    # =========================================================================

    @patch("app.services.incident_service.get_service_supabase")
    def test_link_threat_indicators_upserts_and_links_observable_ip(self, mock_sb):
        """Threat intelligence extractor upserts IP indicator and joins to incident_indicators."""
        mock_table = MagicMock()
        indicator_uuid = "00000000-0000-0000-0000-000000000303"
        mock_table.upsert.return_value.execute.return_value.data = [{"id": indicator_uuid}]
        mock_table.select.return_value.eq.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value.data = []
        mock_sb.return_value.table.return_value = mock_table

        event = {
            "event_id": "ev-ioc-link-01",
            "event_type": "LOGIN_FAILED",
            "source_ip": "198.51.100.44",
            "source_system": "ShieldBank Testbed",
        }
        detection_result = {
            "risk_score": 85,
            "rules_fired": ["AUTH-002", "IOC-001"],
            "is_attack_chain": False,
        }

        linked = link_threat_indicators("00000000-0000-0000-0000-000000000101", event, detection_result)
        self.assertIn(indicator_uuid, linked)

        # Verify indicators table was targeted
        mock_sb.return_value.table.assert_any_call("indicators")
        # Verify incident_indicators table was targeted
        mock_sb.return_value.table.assert_any_call("incident_indicators")

    # =========================================================================
    # 3. Visual Attack Graph Synthesis
    # =========================================================================

    @patch("app.services.incident_service.get_service_supabase")
    def test_get_incident_attack_graph_compiles_nodes_and_edges(self, mock_sb):
        """Graph builder compiles incident, alerts, indicators, and timeline events into graph structure."""
        incident_id = "00000000-0000-0000-0000-000000000404"
        mock_table = MagicMock()

        # Mock query return values
        mock_inc_res = MagicMock()
        mock_inc_res.data = [{
            "id": incident_id,
            "title": "CRITICAL: Account Takeover Incident on ACC_01",
            "severity": "critical",
        }]
        mock_alert_res = MagicMock()
        mock_alert_res.data = [{
            "id": "00000000-0000-0000-0000-000000000505",
            "title": "ATO Chain Alert",
            "severity": "critical",
            "evidence": {"trigger_event_id": "ev-timeline-1"}
        }]
        mock_link_res = MagicMock()
        mock_link_res.data = [{
            "indicator": {
                "id": "00000000-0000-0000-0000-000000000606",
                "indicator_type": "ip",
                "value": "198.51.100.99",
                "status": "malicious"
            }
        }]
        mock_ev_res = MagicMock()
        mock_ev_res.data = [{
            "event_id": "ev-timeline-1",
            "event_type": "TRANSFER_CREATED",
            "occurred_at": "2026-10-15T01:30:00Z",
            "result": "SUCCESS"
        }]

        def table_router(table_name):
            m = MagicMock()
            if table_name == "incidents":
                m.select.return_value.eq.return_value.execute.return_value = mock_inc_res
            elif table_name == "alerts":
                m.select.return_value.eq.return_value.execute.return_value = mock_alert_res
            elif table_name == "incident_indicators":
                m.select.return_value.eq.return_value.execute.return_value = mock_link_res
            elif table_name == "security_events":
                m.select.return_value.in_.return_value.order.return_value.execute.return_value = mock_ev_res
            return m

        mock_sb.return_value.table.side_effect = table_router

        graph = get_incident_attack_graph(incident_id)
        self.assertEqual(graph["incident"]["id"], incident_id)
        self.assertEqual(graph["alerts_count"], 1)
        self.assertEqual(graph["indicators_count"], 1)
        self.assertEqual(len(graph["timeline"]), 1)

        # Verify graph node types
        node_types = [n["type"] for n in graph["graph"]["nodes"]]
        self.assertIn("incident", node_types)
        self.assertIn("alert", node_types)
        self.assertIn("indicator", node_types)
        self.assertIn("event", node_types)

        # Verify graph edge relations
        relations = [e["relation"] for e in graph["graph"]["edges"]]
        self.assertIn("contains_alert", relations)
        self.assertIn("linked_indicator", relations)
        self.assertIn("correlated_event", relations)

    # =========================================================================
    # 4. End-to-End Pipeline & Route Verification
    # =========================================================================

    @patch("app.services.event_service.get_service_supabase")
    @patch("app.services.event_service.analyze_transaction")
    @patch("app.services.detection_engine.get_service_supabase")
    @patch("app.services.incident_service.get_service_supabase")
    def test_ingest_event_auto_promotes_incident_end_to_end(self, mock_inc_sb, mock_det_sb, mock_analyze, mock_ev_sb):
        """End-to-end event ingestion of account takeover triggers detection and creates an incident."""
        inc_uuid = "00000000-0000-0000-0000-000000000707"
        alert_uuid = "00000000-0000-0000-0000-000000000808"

        # Setup mock db responses
        m_table = MagicMock()
        m_table.insert.return_value.execute.return_value.data = [{"id": inc_uuid}]
        m_table.upsert.return_value.execute.return_value.data = [{"id": "ev-uuid"}]
        m_table.update.return_value.execute.return_value.data = [{"id": alert_uuid}]
        m_table.select.return_value.in_.return_value.gte.return_value.order.return_value.execute.return_value.data = []

        mock_inc_sb.return_value.table.return_value = m_table
        mock_det_sb.return_value.table.return_value = m_table
        mock_ev_sb.return_value.table.return_value = m_table

        raw_event = {
            "event_id": "ev-e2e-ato-incident-1",
            "event_type": "TRANSFER_CREATED",
            "account_id": "ACC_AUTO_VICTIM",
            "amount": 200000.0,
            "currency": "ETB",
            "source_ip": "198.51.100.33",
            "device_id": "DEV_ATTACKER_CHROME",
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
        self.assertEqual(det["incident_id"], inc_uuid)


if __name__ == "__main__":
    unittest.main()
