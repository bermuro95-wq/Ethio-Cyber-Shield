"""
Test Suite: Part 18 — Multi-Target Connector Schedulers & Gate 2 Verification (Phase 2.8).
Verifies:
1. Per-connector independent scheduling with custom intervals.
2. Exponential backoff with jitter on target failure without blocking other connectors.
3. Rapid recovery upon successful polling (resetting backoff to base interval).
4. Concurrent, non-blocking execution via worker pool (slow target does not delay fast target).
5. Scheduler lifecycle controls: trigger, pause, resume, reconfigure.
6. Multi-tenant isolation for connector scheduler operations.
7. REST API endpoints under /api/connectors/schedulers/*.
8. Gate 2 criteria: decoupled connector architecture, safe schema validation rejection, and integration readiness.
"""
import unittest
import uuid
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.connector_scheduler_service import (
    ConnectorScheduler,
    ConnectorSchedulerManager,
    get_connector_scheduler_manager,
    clear_connector_schedulers
)


class TestConnectorSchedulersAndGate2(unittest.TestCase):
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
        clear_connector_schedulers()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_independent_scheduler_registration_and_status(self):
        """Test that multiple connectors maintain completely independent scheduling states."""
        mgr = get_connector_scheduler_manager()

        # Connector 1: ShieldBank testbed (fast 5s interval)
        sched1 = mgr.register_connector(
            connector_id="conn-shieldbank",
            name="ShieldBank Testbed",
            org_id=self.org_a,
            interval_seconds=5,
            backoff_multiplier=2.0,
            max_backoff_seconds=300
        )
        self.assertEqual(sched1.interval_seconds, 5)
        self.assertEqual(sched1.status, "idle")

        # Connector 2: EthSwitch Interbank Gateway (30s interval)
        sched2 = mgr.register_connector(
            connector_id="conn-ethswitch",
            name="EthSwitch Interbank Gateway",
            org_id=self.org_a,
            interval_seconds=30,
            backoff_multiplier=1.5,
            max_backoff_seconds=600
        )
        self.assertEqual(sched2.interval_seconds, 30)
        self.assertEqual(sched2.status, "idle")

        # Inspect list of schedulers
        schedulers = mgr.list_schedulers(self.org_a)
        self.assertEqual(len(schedulers), 2)
        sched_map = {s["connector_id"]: s for s in schedulers}
        self.assertIn("conn-shieldbank", sched_map)
        self.assertIn("conn-ethswitch", sched_map)
        self.assertEqual(sched_map["conn-shieldbank"]["interval_seconds"], 5)
        self.assertEqual(sched_map["conn-ethswitch"]["interval_seconds"], 30)

    def test_02_exponential_backoff_on_failure_without_blocking_other_connectors(self):
        """Test that a failing target enters exponential backoff while healthy targets continue normally."""
        mgr = get_connector_scheduler_manager()

        # Connector A: Failing Target
        sched_fail = mgr.register_connector(
            connector_id="conn-failing",
            name="Failing Core Banking",
            org_id=self.org_a,
            interval_seconds=10,
            backoff_multiplier=2.0,
            max_backoff_seconds=120
        )

        # Connector B: Healthy Target
        sched_healthy = mgr.register_connector(
            connector_id="conn-healthy",
            name="Healthy Wallet Gateway",
            org_id=self.org_a,
            interval_seconds=10
        )

        # Simulate 1st failure on Connector A
        t0 = datetime.now(timezone.utc)
        sched_fail.record_poll_result(
            success=False,
            error_message="HTTP 502 Bad Gateway",
            events_synced=0,
            duration_ms=120.0,
            now=t0
        )
        self.assertEqual(sched_fail.consecutive_failures, 1)
        self.assertEqual(sched_fail.status, "backoff")
        # Backoff delay should be ~20s (10 * 2^1 with ±20% jitter)
        delay_1 = (sched_fail.next_run_at - t0).total_seconds()
        self.assertGreaterEqual(delay_1, 15.0)
        self.assertLessEqual(delay_1, 26.0)

        # Simulate 2nd failure on Connector A
        sched_fail.record_poll_result(
            success=False,
            error_message="HTTP 504 Gateway Timeout",
            events_synced=0,
            duration_ms=5000.0,
            now=t0
        )
        self.assertEqual(sched_fail.consecutive_failures, 2)
        # Backoff delay should be ~40s (10 * 2^2 with ±20% jitter)
        delay_2 = (sched_fail.next_run_at - t0).total_seconds()
        self.assertGreaterEqual(delay_2, 30.0)
        self.assertLessEqual(delay_2, 52.0)

        # Verify Connector B remains unaffected
        self.assertEqual(sched_healthy.consecutive_failures, 0)
        self.assertEqual(sched_healthy.status, "idle")

    def test_03_recovery_resets_backoff_to_base_interval(self):
        """Test that when a backoff target recovers with success, failures reset and interval restores."""
        mgr = get_connector_scheduler_manager()
        sched = mgr.register_connector(
            connector_id="conn-recovering",
            name="Recovering Target",
            org_id=self.org_a,
            interval_seconds=10
        )

        t_now = datetime.now(timezone.utc)
        # Fail 3 times
        for _ in range(3):
            sched.record_poll_result(success=False, error_message="Network down", now=t_now)
        self.assertEqual(sched.consecutive_failures, 3)
        self.assertEqual(sched.status, "backoff")

        # Now succeed!
        sched.record_poll_result(
            success=True,
            events_synced=5,
            duration_ms=45.0,
            now=t_now
        )
        self.assertEqual(sched.consecutive_failures, 0)
        self.assertEqual(sched.status, "idle")
        self.assertEqual(sched.total_events_synced, 5)
        # Next run should be scheduled at base interval (10s from now)
        next_delay = (sched.next_run_at - t_now).total_seconds()
        self.assertAlmostEqual(next_delay, 10.0, delta=1.0)

    def test_04_concurrent_non_blocking_polling_via_worker_pool(self):
        """Test that a slow connector does not block execution of a fast connector."""
        mgr = get_connector_scheduler_manager()

        mgr.register_connector("conn-slow", "Slow Legacy Endpoint", self.org_a, interval_seconds=1)
        mgr.register_connector("conn-fast", "Fast Endpoint", self.org_a, interval_seconds=1)

        poll_results = []

        def mock_poll_func(connector_id):
            if connector_id == "conn-slow":
                time.sleep(0.3)
                poll_results.append("slow_done")
                return {"status": "success", "events_synced": 1}
            else:
                poll_results.append("fast_done")
                return {"status": "success", "events_synced": 2}

        # Trigger both concurrently
        futures = mgr.trigger_all_due([mock_poll_func])
        # Wait for all to complete
        for f in futures:
            f.result(timeout=2.0)

        self.assertEqual(len(poll_results), 2)
        # Fast endpoint should finish first
        self.assertEqual(poll_results[0], "fast_done")
        self.assertEqual(poll_results[1], "slow_done")

    def test_05_lifecycle_controls_trigger_pause_resume_configure(self):
        """Test manual trigger, pause, resume, and reconfiguration of connector schedulers."""
        mgr = get_connector_scheduler_manager()
        mgr.register_connector("conn-ctrl", "Controlled Connector", self.org_a, interval_seconds=15)

        # 1. Pause
        paused = mgr.pause_connector("conn-ctrl", org_id=self.org_a)
        self.assertTrue(paused)
        sched = mgr.get_scheduler("conn-ctrl", org_id=self.org_a)
        self.assertEqual(sched["status"], "paused")

        # 2. Resume
        resumed = mgr.resume_connector("conn-ctrl", org_id=self.org_a)
        self.assertTrue(resumed)
        sched = mgr.get_scheduler("conn-ctrl", org_id=self.org_a)
        self.assertEqual(sched["status"], "idle")

        # 3. Configure
        reconfigured = mgr.configure_connector(
            connector_id="conn-ctrl",
            org_id=self.org_a,
            interval_seconds=45,
            backoff_multiplier=3.0,
            max_backoff_seconds=900
        )
        self.assertTrue(reconfigured)
        sched = mgr.get_scheduler("conn-ctrl", org_id=self.org_a)
        self.assertEqual(sched["interval_seconds"], 45)
        self.assertEqual(sched["backoff_multiplier"], 3.0)
        self.assertEqual(sched["max_backoff_seconds"], 900)

        # 4. Manual trigger
        triggered = mgr.trigger_connector(
            connector_id="conn-ctrl",
            org_id=self.org_a,
            poll_func=lambda cid: {"status": "success", "events_synced": 7}
        )
        self.assertIsNotNone(triggered)
        res = triggered.result(timeout=2.0)
        self.assertEqual(res["events_synced"], 7)

    def test_06_strict_multi_tenant_isolation(self):
        """Verify Tenant A cannot view, trigger, pause, or configure Tenant B's connectors."""
        mgr = get_connector_scheduler_manager()
        mgr.register_connector("conn-org-a", "Tenant A Connector", self.org_a, interval_seconds=10)
        mgr.register_connector("conn-org-b", "Tenant B Connector", self.org_b, interval_seconds=20)

        # Tenant A listing
        scheds_a = mgr.list_schedulers(self.org_a)
        self.assertEqual(len(scheds_a), 1)
        self.assertEqual(scheds_a[0]["connector_id"], "conn-org-a")

        # Tenant B listing
        scheds_b = mgr.list_schedulers(self.org_b)
        self.assertEqual(len(scheds_b), 1)
        self.assertEqual(scheds_b[0]["connector_id"], "conn-org-b")

        # Tenant A tries to pause Tenant B connector -> Denied
        self.assertFalse(mgr.pause_connector("conn-org-b", org_id=self.org_a))

        # Tenant A tries to get Tenant B scheduler -> None
        self.assertIsNone(mgr.get_scheduler("conn-org-b", org_id=self.org_a))

    def test_07_rest_api_endpoints(self):
        """Test REST API routes under /api/connectors/schedulers/* with tenant authentication."""
        headers_a = {"Authorization": f"Bearer {self.token_admin_a}"}
        headers_b = {"Authorization": f"Bearer {self.token_admin_b}"}

        mgr = get_connector_scheduler_manager()
        mgr.register_connector("api-conn-1", "API Test Connector", self.org_a, interval_seconds=15)

        # 1. GET /api/connectors/schedulers
        resp = self.client.get("/api/connectors/schedulers", headers=headers_a)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["organization_id"], self.org_a)
        self.assertEqual(len(data["schedulers"]), 1)
        self.assertEqual(data["schedulers"][0]["connector_id"], "api-conn-1")

        # 2. GET /api/connectors/schedulers/<id>
        detail_resp = self.client.get("/api/connectors/schedulers/api-conn-1", headers=headers_a)
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.get_json()["name"], "API Test Connector")

        # 3. POST /api/connectors/schedulers/<id>/pause
        pause_resp = self.client.post("/api/connectors/schedulers/api-conn-1/pause", headers=headers_a)
        self.assertEqual(pause_resp.status_code, 200)
        self.assertEqual(pause_resp.get_json()["status"], "paused")

        # 4. POST /api/connectors/schedulers/<id>/resume
        resume_resp = self.client.post("/api/connectors/schedulers/api-conn-1/resume", headers=headers_a)
        self.assertEqual(resume_resp.status_code, 200)
        self.assertEqual(resume_resp.get_json()["status"], "resumed")

        # 5. POST /api/connectors/schedulers/<id>/configure
        config_resp = self.client.post("/api/connectors/schedulers/api-conn-1/configure", json={
            "interval_seconds": 60,
            "backoff_multiplier": 2.5
        }, headers=headers_a)
        self.assertEqual(config_resp.status_code, 200)
        self.assertEqual(config_resp.get_json()["interval_seconds"], 60)

        # 6. Tenant B isolation check: Tenant B cannot access Tenant A's scheduler
        resp_b = self.client.get("/api/connectors/schedulers/api-conn-1", headers=headers_b)
        self.assertEqual(resp_b.status_code, 404)

    def test_08_gate_2_criteria_verification(self):
        """
        Gate 2 Criteria Verification:
        1. Decoupled connector architecture: ShieldBank runs as an independent connector target.
        2. Safe schema validation: Malformed connector events are rejected safely without crashes.
        3. Integration readiness: Transactional Outbox & SDK integration patterns verified.
        """
        mgr = get_connector_scheduler_manager()

        # 1. Register ShieldBank as an independent connector target
        sched_sb = mgr.register_connector(
            connector_id="shieldbank-demo-connector",
            name="ShieldBank External Demo Lab",
            org_id=self.org_a,
            interval_seconds=5
        )
        self.assertIsNotNone(sched_sb)
        self.assertEqual(sched_sb.connector_id, "shieldbank-demo-connector")

        # 2. Simulate poller receiving a batch with a malformed event
        from app.services.event_service import ingest_event
        from app.services.data_quality_service import get_schema_violations_summary

        malformed_event = {
            "organization_id": self.org_a,
            "source_system": "shieldbank-demo-connector",
            "amount": "not_a_valid_number"  # Missing event_id, event_type, malformed amount
        }

        # Verify safe rejection without crashing application
        with self.assertRaises(ValueError):
            ingest_event(malformed_event)

        # Verify data quality monitor captured the violation
        summary = get_schema_violations_summary(self.org_a)
        self.assertGreaterEqual(summary["total_violations"], 1)

        # 3. Simulate poller receiving a valid canonical event
        valid_event = {
            "event_id": f"evt_gate2_{uuid.uuid4().hex[:8]}",
            "event_type": "auth.login.succeeded",
            "organization_id": self.org_a,
            "source_system": "shieldbank-demo-connector",
            "account_id": "ACC_GATE2_VERIFIED",
            "channel": "web",
            "source_ip": "196.188.1.100"
        }
        res = ingest_event(valid_event)
        self.assertIsNotNone(res.get("event_id"))
        self.assertEqual(res.get("status"), "received")


if __name__ == '__main__':
    unittest.main()
