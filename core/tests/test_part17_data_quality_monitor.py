"""
Test Suite: Part 17 — Health & Data-Quality Monitor (Phase 2.7).
Verifies:
1. Source registration, tracking, and activity recording.
2. Silent-source anomaly detection (warning vs. critical severity based on silence threshold).
3. Tenant-level silence alert ('no events from tenant X in 15 min').
4. Schema-violation tracking, categorization, sanitization, and summary breakdown.
5. Ingestion throughput telemetry (rolling 1m, 5m, 1h, 24h counters).
6. Explainable composite Data Quality Score (0-100) with transparent rationale.
7. End-to-end integration with ingest_event and webhook processing.
8. Strict multi-tenant isolation across all data quality metrics.
9. REST API endpoints under /api/health/quality/*.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.data_quality_service import (
    register_or_update_source,
    touch_source_activity,
    list_monitored_sources,
    check_silent_sources,
    record_schema_violation,
    get_schema_violations_summary,
    get_ingestion_throughput,
    calculate_data_quality_score,
    clear_data_quality_stores
)
from app.services.event_service import ingest_event


class TestDataQualityMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())

        cls.user_admin_a = str(uuid.uuid4())
        cls.user_admin_b = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_admin_b = create_token(cls.user_admin_b, "admin@bank-b.et", "admin", organization_id=cls.org_b)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_data_quality_stores()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_touch_and_list_sources(self):
        """Test registering sources and touching activity."""
        source_id = "cbe-core-banking-outbox"
        source = register_or_update_source(
            org_id=self.org_a,
            source_id=source_id,
            source_name="CBE Core Banking Outbox",
            source_type="sdk",
            silence_threshold_seconds=900
        )
        self.assertEqual(source["source_id"], source_id)
        self.assertEqual(source["organization_id"], self.org_a)
        self.assertEqual(source["silence_threshold_seconds"], 900)

        # Touch source activity
        updated = touch_source_activity(
            org_id=self.org_a,
            source_id=source_id,
            source_name="CBE Core Banking Outbox",
            event_id="evt-dq-01"
        )
        self.assertEqual(updated["total_events"], 1)
        self.assertIsNotNone(updated["last_event_at"])

        # List sources
        sources = list_monitored_sources(self.org_a)
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["status"], "active")
        self.assertLessEqual(sources[0]["silence_duration_seconds"], 5)

    def test_02_silent_source_anomaly_detection_warning_and_critical(self):
        """Test silent source detection with warning (1x threshold) and critical (2x threshold) severities."""
        # Source 1: healthy (activity 2 minutes ago)
        register_or_update_source(
            org_id=self.org_a,
            source_id="src-healthy",
            source_name="Healthy Payment Gateway",
            silence_threshold_seconds=900  # 15 minutes
        )
        t_now = datetime.now(timezone.utc)
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-healthy",
            timestamp=(t_now - timedelta(minutes=2)).isoformat()
        )

        # Source 2: warning silent (activity 18 minutes ago, threshold 15m)
        register_or_update_source(
            org_id=self.org_a,
            source_id="src-warning",
            source_name="USSD Inbound Channel",
            silence_threshold_seconds=900  # 15 minutes
        )
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-warning",
            timestamp=(t_now - timedelta(minutes=18)).isoformat()
        )

        # Source 3: critical silent (activity 45 minutes ago, > 2x 15m threshold)
        register_or_update_source(
            org_id=self.org_a,
            source_id="src-critical",
            source_name="EthSwitch Interbank Gateway",
            silence_threshold_seconds=900  # 15 minutes
        )
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-critical",
            timestamp=(t_now - timedelta(minutes=45)).isoformat()
        )

        # Evaluate silent sources at t_now
        report = check_silent_sources(self.org_a, now=t_now)
        self.assertEqual(report["organization_id"], self.org_a)
        self.assertEqual(report["active_sources_count"], 1)
        self.assertEqual(report["silent_sources_count"], 2)

        alerts = {a["source_id"]: a for a in report["alerts"] if a.get("type") == "source_silence"}
        self.assertIn("src-warning", alerts)
        self.assertEqual(alerts["src-warning"]["severity"], "warning")
        self.assertGreaterEqual(alerts["src-warning"]["silence_duration_seconds"], 18 * 60)
        self.assertIn("threshold: 15m", alerts["src-warning"]["message"])

        self.assertIn("src-critical", alerts)
        self.assertEqual(alerts["src-critical"]["severity"], "critical")
        self.assertGreaterEqual(alerts["src-critical"]["silence_duration_seconds"], 45 * 60)

    def test_03_tenant_level_silence_detection(self):
        """Test tenant-level silence alert when an entire tenant has emitted zero events for > 15 minutes."""
        t_now = datetime.now(timezone.utc)
        register_or_update_source(
            org_id=self.org_a,
            source_id="src-telebirr",
            source_name="Telebirr Direct Webhook",
            silence_threshold_seconds=900
        )
        # Touch activity 25 minutes ago
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-telebirr",
            timestamp=(t_now - timedelta(minutes=25)).isoformat()
        )

        report = check_silent_sources(self.org_a, now=t_now)
        self.assertTrue(report["tenant_silent"])
        tenant_alerts = [a for a in report["alerts"] if a.get("type") == "tenant_silence"]
        self.assertEqual(len(tenant_alerts), 1)
        self.assertEqual(tenant_alerts[0]["severity"], "critical")
        self.assertIn(f"No events received from tenant '{self.org_a}'", tenant_alerts[0]["message"])

    def test_04_schema_violation_recording_and_breakdown(self):
        """Test recording schema violations, categorization, data sanitization, and summary breakdown."""
        # Record a validation error with sensitive fields
        raw_bad_payload = {
            "account_id": "ACC-12345",
            "password": "SuperSecretPassword123!",
            "secret_token": "bearer-token-abc",
            "source_ip": "invalid-ip-format",
            "amount": -50.0
        }

        v1 = record_schema_violation(
            org_id=self.org_a,
            source_id="src-mobile-api",
            source_name="Mobile Banking API",
            violation_type="SCHEMA_VALIDATION_ERROR",
            error_message="Invalid IP format and negative amount",
            raw_sample=raw_bad_payload
        )
        self.assertEqual(v1["violation_type"], "SCHEMA_VALIDATION_ERROR")
        # Ensure password and secret token are sanitized
        self.assertEqual(v1["raw_snippet"].get("password"), "[REDACTED]")
        self.assertEqual(v1["raw_snippet"].get("secret_token"), "[REDACTED]")
        self.assertEqual(v1["raw_snippet"].get("account_id"), "ACC-12345")

        # Record a mapping failure
        record_schema_violation(
            org_id=self.org_a,
            source_id="src-webhook-1",
            source_name="Legacy ATM Webhook",
            violation_type="MAPPING_FAILURE",
            error_message="JSONPath '$.transaction.id' not found in inbound payload"
        )

        # Record a crypto signature failure
        record_schema_violation(
            org_id=self.org_a,
            source_id="src-webhook-1",
            source_name="Legacy ATM Webhook",
            violation_type="CRYPTO_SIGNATURE_FAILURE",
            error_message="Invalid HMAC-SHA256 signature header"
        )

        summary = get_schema_violations_summary(self.org_a)
        self.assertEqual(summary["total_violations"], 3)
        self.assertEqual(summary["by_type"]["SCHEMA_VALIDATION_ERROR"], 1)
        self.assertEqual(summary["by_type"]["MAPPING_FAILURE"], 1)
        self.assertEqual(summary["by_type"]["CRYPTO_SIGNATURE_FAILURE"], 1)
        self.assertEqual(summary["by_source"]["src-mobile-api"], 1)
        self.assertEqual(summary["by_source"]["src-webhook-1"], 2)
        self.assertEqual(len(summary["recent_violations"]), 3)

    def test_05_throughput_telemetry(self):
        """Test ingestion throughput telemetry tracking."""
        # Ingest 5 events
        for i in range(5):
            touch_source_activity(
                org_id=self.org_a,
                source_id="src-perf",
                source_name="Performance Test Feed",
                event_id=f"evt-perf-{i}"
            )

        tp = get_ingestion_throughput(self.org_a)
        self.assertEqual(tp["events_1m"], 5)
        self.assertEqual(tp["events_5m"], 5)
        self.assertEqual(tp["events_1h"], 5)
        self.assertEqual(tp["events_24h"], 5)
        self.assertEqual(tp["total_events"], 5)
        self.assertGreaterEqual(tp["rate_per_sec_1m"], 0.0)

    def test_06_explainable_data_quality_score_calculation(self):
        """Test explainable composite Data Quality Score (0-100) and grade calculation."""
        # State A: Pure 100% healthy
        for i in range(10):
            touch_source_activity(
                org_id=self.org_a,
                source_id="src-pure",
                source_name="Clean Feed",
                event_id=f"clean-{i}",
                attributes={
                    "channel": "mobile",
                    "device_fingerprint": "dfp-12345",
                    "source_ip": "196.188.1.1",
                    "payment_rail": "P2P"
                }
            )

        score_res = calculate_data_quality_score(self.org_a)
        self.assertGreaterEqual(score_res["quality_score"], 90.0)
        self.assertEqual(score_res["grade"], "A")
        self.assertIn("breakdown", score_res)
        self.assertIn("schema_compliance", score_res["breakdown"])
        self.assertIn("source_vitality", score_res["breakdown"])
        self.assertIn("field_richness", score_res["breakdown"])
        self.assertTrue(len(score_res["rationale"]) > 0)

        # State B: Inject schema violations and silent source -> score drops
        for _ in range(5):
            record_schema_violation(
                org_id=self.org_a,
                source_id="src-pure",
                source_name="Clean Feed",
                violation_type="SCHEMA_VALIDATION_ERROR",
                error_message="Test violation"
            )

        # Register a silent source (last seen 30m ago)
        t_now = datetime.now(timezone.utc)
        register_or_update_source(
            org_id=self.org_a,
            source_id="src-broken",
            source_name="Broken Connector",
            silence_threshold_seconds=900
        )
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-broken",
            timestamp=(t_now - timedelta(minutes=30)).isoformat()
        )

        score_degraded = calculate_data_quality_score(self.org_a, now=t_now)
        self.assertLess(score_degraded["quality_score"], score_res["quality_score"])
        self.assertIn(score_degraded["grade"], ["B", "C", "D"])
        self.assertLess(score_degraded["breakdown"]["schema_compliance"], 100.0)
        self.assertLess(score_degraded["breakdown"]["source_vitality"], 100.0)

    def test_07_event_service_and_webhook_service_integration(self):
        """Test that event ingestion pipeline updates health metrics and records schema violations."""
        # 1. Valid event ingestion
        valid_event = {
            "event_id": f"evt_dq_valid_{uuid.uuid4().hex[:8]}",
            "event_type": "transaction.transfer.completed",
            "organization_id": self.org_a,
            "source_system": "cbe-retail-mobile",
            "account_id": "ACC_VALID_DQ_01",
            "amount": 2500.0,
            "currency": "ETB",
            "channel": "mobile",
            "payment_rail": "P2P",
            "source_ip": "196.188.10.5",
            "device_id": "dfp_dq_valid_01"
        }
        res = ingest_event(valid_event)

        self.assertIsNotNone(res.get("event_id"))

        # Verify source was automatically recorded and throughput incremented
        sources = list_monitored_sources(self.org_a)
        source_names = [s["source_name"] for s in sources]
        self.assertIn("cbe-retail-mobile", source_names)

        tp = get_ingestion_throughput(self.org_a)
        self.assertGreaterEqual(tp["total_events"], 1)

        # 2. Malformed event ingestion
        bad_event = {
            "event_type": "invalid.event.action",
            "organization_id": self.org_a,
            "source_system": "cbe-retail-mobile",
            "amount": "not-a-number"  # Invalid
        }
        with self.assertRaises(ValueError):
            ingest_event(bad_event)

        # Verify schema violation was automatically recorded
        summary = get_schema_violations_summary(self.org_a)
        self.assertGreaterEqual(summary["total_violations"], 1)
        self.assertGreaterEqual(summary["by_type"].get("SCHEMA_VALIDATION_ERROR", 0), 1)

    def test_08_strict_multi_tenant_isolation(self):
        """Verify Tenant A cannot view or manipulate Tenant B's data quality telemetry."""
        # Ingest event and violation in Tenant A
        touch_source_activity(
            org_id=self.org_a,
            source_id="src-tenant-a-only",
            source_name="Tenant A Feed",
            event_id="evt-tenant-a"
        )
        record_schema_violation(
            org_id=self.org_a,
            source_id="src-tenant-a-only",
            source_name="Tenant A Feed",
            violation_type="SCHEMA_VALIDATION_ERROR",
            error_message="Tenant A error"
        )

        # Inspect from Tenant B
        sources_b = list_monitored_sources(self.org_b)
        self.assertEqual(len(sources_b), 0)

        summary_b = get_schema_violations_summary(self.org_b)
        self.assertEqual(summary_b["total_violations"], 0)

        tp_b = get_ingestion_throughput(self.org_b)
        self.assertEqual(tp_b["total_events"], 0)

    def test_09_rest_api_endpoints(self):
        """Test REST API endpoints under /api/health/quality/* with tenant authentication."""
        headers_a = {"Authorization": f"Bearer {self.token_admin_a}"}
        headers_b = {"Authorization": f"Bearer {self.token_admin_b}"}

        # 1. Register a source via API
        reg_resp = self.client.post("/api/health/quality/sources", json={
            "source_id": "api-source-cbe",
            "source_name": "CBE Internet Banking",
            "source_type": "api",
            "silence_threshold_seconds": 600
        }, headers=headers_a)
        self.assertEqual(reg_resp.status_code, 201)
        self.assertEqual(reg_resp.get_json()["source_id"], "api-source-cbe")

        # 2. Record a schema violation via API
        viol_resp = self.client.post("/api/health/quality/record-violation", json={
            "source_id": "api-source-cbe",
            "source_name": "CBE Internet Banking",
            "violation_type": "MAPPING_FAILURE",
            "error_message": "Missing customer CIF reference",
            "raw_snippet": {"tx": 1234, "password": "leak"}
        }, headers=headers_a)
        self.assertEqual(viol_resp.status_code, 201)
        self.assertEqual(viol_resp.get_json()["violation"]["raw_snippet"]["password"], "[REDACTED]")

        # 3. GET /api/health/quality/overview
        overview_resp = self.client.get("/api/health/quality/overview", headers=headers_a)
        self.assertEqual(overview_resp.status_code, 200)
        overview_data = overview_resp.get_json()
        self.assertEqual(overview_data["organization_id"], self.org_a)
        self.assertIn("quality_score", overview_data)
        self.assertIn("grade", overview_data)
        self.assertIn("throughput", overview_data)

        # 4. GET /api/health/quality/sources
        sources_resp = self.client.get("/api/health/quality/sources", headers=headers_a)
        self.assertEqual(sources_resp.status_code, 200)
        self.assertEqual(len(sources_resp.get_json()["sources"]), 1)

        # 5. GET /api/health/quality/silent-alerts
        alerts_resp = self.client.get("/api/health/quality/silent-alerts", headers=headers_a)
        self.assertEqual(alerts_resp.status_code, 200)
        self.assertIn("alerts", alerts_resp.get_json())

        # 6. GET /api/health/quality/violations
        violations_resp = self.client.get("/api/health/quality/violations", headers=headers_a)
        self.assertEqual(violations_resp.status_code, 200)
        self.assertEqual(violations_resp.get_json()["total_violations"], 1)

        # 7. Cross-tenant check: Tenant B sees zero sources and zero violations
        overview_b_resp = self.client.get("/api/health/quality/overview", headers=headers_b)
        self.assertEqual(overview_b_resp.status_code, 200)
        self.assertEqual(overview_b_resp.get_json()["organization_id"], self.org_b)
        self.assertEqual(overview_b_resp.get_json()["monitored_sources_count"], 0)


if __name__ == '__main__':
    unittest.main()
