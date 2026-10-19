"""
Test Suite: Part 20 — Rule Lifecycle Tooling, Historical Backtesting & Precision Metrics (Phase 3.2).

Verifies:
1. Historical backtesting engine replaying stored events within sliding windows (default 7 days).
2. "What would have fired" preview for candidate rules and threshold variations without persistent mutations.
3. Rule lifecycle state transitions (draft -> backtest -> shadow -> live) with validation and audit history.
4. Analyst feedback recording (true_positive, false_positive, etc.) and precision / FPR calculation.
5. Automated high false-positive rate warnings (FPR >= 25%) and suppression suggestions.
6. Shadow mode promotion recommendation when low FPR and sufficient true positives observed.
7. Strict multi-tenant isolation across backtest runs, lifecycle history, and feedback metrics.
8. REST API endpoints under /api/rules/*.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.rule_engine_service import (
    get_rule_engine,
    clear_rule_engine_caches
)
from app.services.rule_lifecycle_service import (
    RuleBacktestEngine,
    RuleLifecycleManager,
    RulePrecisionService,
    clear_lifecycle_caches
)


class TestRuleLifecycleAndBacktesting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())

        cls.user_admin_a = str(uuid.uuid4())
        cls.user_admin_b = str(uuid.uuid4())
        cls.user_analyst_a = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_admin_b = create_token(cls.user_admin_b, "admin@bank-b.et", "admin", organization_id=cls.org_b)
        cls.token_analyst_a = create_token(cls.user_analyst_a, "analyst@bank-a.et", "analyst", organization_id=cls.org_a)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_rule_engine_caches()
        clear_lifecycle_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def _generate_mock_events(self, org_id: str, count: int = 10) -> list:
        """Helper to create simulated historical events spanning the last 7 days."""
        now = datetime.now(timezone.utc)
        events = []
        for i in range(count):
            event_time = now - timedelta(days=(i % 5), hours=(i * 2))
            # Every 3rd event is high-value transfer (>= 150,000 ETB)
            is_high = (i % 3 == 0)
            amount = 180000.0 if is_high else 25000.0
            events.append({
                'event_id': f"ev-hist-{org_id[:4]}-{i}",
                'organization_id': org_id,
                'event_type': 'TRANSFER_CREATED',
                'account_id': f"ACC_{i}",
                'account_id_pub': f"ACC_{i}",
                'amount': amount,
                'currency': 'ETB',
                'source_ip': f"192.168.1.{10 + i}",
                'occurred_at': event_time.isoformat(),
                'attributes': {'high_value': is_high}
            })
        return events

    def test_01_historical_backtesting_on_stored_events(self):
        """Test backtesting TX-001 on historical events over a 7-day window."""
        mock_events = self._generate_mock_events(self.org_a, count=12)
        # In 12 events: indices 0, 3, 6, 9 are high value (4 matches)

        run = RuleBacktestEngine.run_backtest(
            org_id=self.org_a,
            rule_id="TX-001",
            time_range_days=7,
            events_override=mock_events,
            user_id=self.user_admin_a
        )

        self.assertIsNotNone(run)
        self.assertEqual(run['rule_id'], "TX-001")
        self.assertEqual(run['status'], "completed")
        self.assertEqual(run['events_evaluated'], 12)
        self.assertEqual(run['matches_count'], 4)
        self.assertGreater(run['fire_rate_pct'], 0)
        self.assertEqual(run['estimated_risk_points'], 4 * 20)  # TX-001 weight is 20
        self.assertIn('daily_distribution', run['results_summary'])

        # Verify retrieval
        fetched = RuleBacktestEngine.get_backtest_run(self.org_a, run['id'])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['id'], run['id'])

    def test_02_what_would_have_fired_preview_with_threshold_variation(self):
        """Test 'what would have fired' preview comparing 100k ETB vs 200k ETB thresholds."""
        mock_events = [
            {'event_id': 'ev-1', 'event_type': 'TRANSFER_CREATED', 'amount': 150000.0, 'occurred_at': datetime.now(timezone.utc).isoformat()},
            {'event_id': 'ev-2', 'event_type': 'TRANSFER_CREATED', 'amount': 250000.0, 'occurred_at': datetime.now(timezone.utc).isoformat()},
            {'event_id': 'ev-3', 'event_type': 'TRANSFER_CREATED', 'amount': 50000.0, 'occurred_at': datetime.now(timezone.utc).isoformat()},
        ]

        # Preview with candidate threshold of 200,000 ETB
        candidate_spec = {
            'id': 'TX-001',
            'name': 'High-Value Transfer Anomaly (Custom)',
            'weight': 25,
            'thresholds': {'amount_threshold_etb': 200000.0}
        }

        preview = RuleBacktestEngine.preview_rule_evaluation(
            org_id=self.org_a,
            rule_spec=candidate_spec,
            time_range_days=7,
            events_override=mock_events
        )

        self.assertEqual(preview['events_evaluated'], 3)
        # Only the 250,000 ETB transfer exceeds 200k threshold
        self.assertEqual(preview['matches_count'], 1)
        self.assertTrue(preview['would_fire'])

    def test_03_lifecycle_state_machine_validation_and_transitions(self):
        """Test rule lifecycle state machine transitions and audit history."""
        # 1. Initially TX-001 is 'live'
        engine = get_rule_engine()
        rule = engine.get_rule("TX-001", org_id=self.org_a)
        self.assertEqual(rule['lifecycle_state'], 'live')

        # 2. Demote live -> shadow
        res_shadow = RuleLifecycleManager.transition_state(
            org_id=self.org_a,
            rule_id="TX-001",
            to_state="shadow",
            reason="Demoted for observation period",
            user_id=self.user_admin_a
        )
        self.assertEqual(res_shadow['status'], 'transitioned')
        self.assertEqual(res_shadow['to_state'], 'shadow')

        # Verify engine reflects shadow state
        updated_rule = engine.get_rule("TX-001", org_id=self.org_a)
        self.assertEqual(updated_rule['lifecycle_state'], 'shadow')

        # 3. Transition shadow -> draft
        RuleLifecycleManager.transition_state(
            org_id=self.org_a,
            rule_id="TX-001",
            to_state="draft",
            reason="Refining rule conditions",
            user_id=self.user_admin_a
        )

        # 4. Attempt to promote draft -> live without backtest -> Should fail validation
        with self.assertRaises(ValueError) as ctx:
            RuleLifecycleManager.transition_state(
                org_id=self.org_a,
                rule_id="TX-001",
                to_state="live",
                user_id=self.user_admin_a,
                force=False
            )
        self.assertIn("historical backtest", str(ctx.exception))

        # 5. Run backtest first
        mock_events = self._generate_mock_events(self.org_a, count=5)
        run = RuleBacktestEngine.run_backtest(
            org_id=self.org_a,
            rule_id="TX-001",
            events_override=mock_events,
            user_id=self.user_admin_a
        )

        # 6. Now promotion to shadow succeeds
        res_promoted = RuleLifecycleManager.transition_state(
            org_id=self.org_a,
            rule_id="TX-001",
            to_state="shadow",
            backtest_run_id=run['id'],
            user_id=self.user_admin_a
        )
        self.assertEqual(res_promoted['status'], 'transitioned')

        # 7. Check transition history
        history = RuleLifecycleManager.get_lifecycle_history(self.org_a, "TX-001")
        self.assertGreaterEqual(len(history), 3)
        states = [h['to_state'] for h in history]
        self.assertIn('shadow', states)
        self.assertIn('draft', states)

    def test_04_analyst_feedback_recording_and_precision_metrics(self):
        """Test recording true/false positive feedback and computing precision metrics."""
        # Record 4 True Positives and 1 False Positive
        for i in range(4):
            RulePrecisionService.record_feedback(
                org_id=self.org_a,
                rule_id="AUTH-001",
                verdict="true_positive",
                analyst_notes=f"Confirmed brute force attempt #{i}",
                user_id=self.user_analyst_a
            )

        RulePrecisionService.record_feedback(
            org_id=self.org_a,
            rule_id="AUTH-001",
            verdict="false_positive",
            analyst_notes="Legitimate customer password typo",
            suggested_suppression={"entity_account": "ACC_VIP_CUSTOMER"},
            user_id=self.user_analyst_a
        )

        metrics = RulePrecisionService.get_rule_precision_metrics(self.org_a, "AUTH-001")
        self.assertEqual(metrics['total_feedback_count'], 5)
        self.assertEqual(metrics['true_positives'], 4)
        self.assertEqual(metrics['false_positives'], 1)
        # Precision = 4 / (4 + 1) = 0.80 (80%)
        self.assertEqual(metrics['precision'], 0.8)
        self.assertEqual(metrics['precision_pct'], "80.0%")
        self.assertEqual(metrics['false_positive_rate'], 0.2)

    def test_05_high_false_positive_tuning_alert_and_suppression(self):
        """Test automated tuning warning when false positive rate is high (>= 25%)."""
        # Record 1 True Positive and 3 False Positives
        RulePrecisionService.record_feedback(
            org_id=self.org_a,
            rule_id="AUTH-002",
            verdict="true_positive",
            user_id=self.user_analyst_a
        )
        for i in range(3):
            RulePrecisionService.record_feedback(
                org_id=self.org_a,
                rule_id="AUTH-002",
                verdict="false_positive",
                suggested_suppression={"source_ip": f"10.0.0.{i}"},
                user_id=self.user_analyst_a
            )

        metrics = RulePrecisionService.get_rule_precision_metrics(self.org_a, "AUTH-002")
        self.assertIsNotNone(metrics['tuning_alert'])
        self.assertEqual(metrics['tuning_alert']['level'], 'warning')
        self.assertEqual(metrics['tuning_alert']['code'], 'HIGH_FALSE_POSITIVE_RATE')
        self.assertGreaterEqual(len(metrics['suppression_suggestions']), 3)

    def test_06_shadow_to_live_promotion_recommendation(self):
        """Test promotion recommendation when rule performs cleanly in shadow mode."""
        # 6 True Positives, 0 False Positives
        for _ in range(6):
            RulePrecisionService.record_feedback(
                org_id=self.org_a,
                rule_id="ATO-001",
                verdict="true_positive",
                user_id=self.user_analyst_a
            )

        metrics = RulePrecisionService.get_rule_precision_metrics(self.org_a, "ATO-001")
        self.assertIsNotNone(metrics['tuning_alert'])
        self.assertEqual(metrics['tuning_alert']['code'], 'PROMOTION_READY')

    def test_07_strict_multi_tenant_isolation_on_backtests_and_feedback(self):
        """Test that Tenant A's backtests, transitions, and feedback are completely invisible to Tenant B."""
        # 1. Run backtest for Tenant A
        mock_events_a = self._generate_mock_events(self.org_a, count=4)
        run_a = RuleBacktestEngine.run_backtest(
            org_id=self.org_a,
            rule_id="TX-001",
            events_override=mock_events_a
        )

        # Tenant B should NOT see Tenant A's backtest run
        self.assertIsNone(RuleBacktestEngine.get_backtest_run(self.org_b, run_a['id']))
        b_runs = RuleBacktestEngine.list_backtest_runs(self.org_b, rule_id="TX-001")
        self.assertEqual(len(b_runs), 0)

        # 2. Record feedback for Tenant A
        RulePrecisionService.record_feedback(
            org_id=self.org_a,
            rule_id="TX-001",
            verdict="true_positive"
        )

        # Tenant B metrics should be clean
        metrics_b = RulePrecisionService.get_rule_precision_metrics(self.org_b, "TX-001")
        self.assertEqual(metrics_b['total_feedback_count'], 0)

    def test_08_rest_api_lifecycle_and_feedback_endpoints(self):
        """Test REST API routes for backtests, previews, lifecycle state transitions, and feedback."""
        headers_admin = {"Authorization": f"Bearer {self.token_admin_a}"}
        headers_analyst = {"Authorization": f"Bearer {self.token_analyst_a}"}

        # 1. POST /api/rules/preview (What-would-have-fired preview)
        preview_payload = {
            "days": 7,
            "rule_spec": {
                "id": "TX-001",
                "name": "High Value Preview",
                "thresholds": {"amount_threshold_etb": 300000.0}
            }
        }
        res_prev = self.client.post("/api/rules/preview", json=preview_payload, headers=headers_analyst)
        self.assertEqual(res_prev.status_code, 200)
        self.assertIn("preview", res_prev.get_json())

        # 2. POST /api/rules/TX-001/backtest
        res_bt = self.client.post("/api/rules/TX-001/backtest", json={"days": 7}, headers=headers_admin)
        self.assertEqual(res_bt.status_code, 200)
        run_data = res_bt.get_json()['backtest_run']
        run_id = run_data['id']

        # 3. GET /api/rules/TX-001/backtest
        res_list = self.client.get("/api/rules/TX-001/backtest", headers=headers_analyst)
        self.assertEqual(res_list.status_code, 200)
        self.assertGreaterEqual(res_list.get_json()['total_runs'], 1)

        # 4. GET /api/rules/backtests/<run_id>
        res_get_run = self.client.get(f"/api/rules/backtests/{run_id}", headers=headers_analyst)
        self.assertEqual(res_get_run.status_code, 200)

        # 5. POST /api/rules/TX-001/lifecycle (Transition to shadow)
        trans_payload = {
            "to_state": "shadow",
            "reason": "Test transition via API",
            "backtest_run_id": run_id
        }
        res_trans = self.client.post("/api/rules/TX-001/lifecycle", json=trans_payload, headers=headers_admin)
        self.assertEqual(res_trans.status_code, 200)
        self.assertEqual(res_trans.get_json()['to_state'], "shadow")

        # 6. GET /api/rules/TX-001/lifecycle (Audit trail)
        res_hist = self.client.get("/api/rules/TX-001/lifecycle", headers=headers_analyst)
        self.assertEqual(res_hist.status_code, 200)
        self.assertGreaterEqual(res_hist.get_json()['total_transitions'], 1)

        # 7. POST /api/rules/TX-001/feedback (Record feedback)
        fb_payload = {
            "verdict": "true_positive",
            "analyst_notes": "Valid test hit"
        }
        res_fb = self.client.post("/api/rules/TX-001/feedback", json=fb_payload, headers=headers_analyst)
        self.assertEqual(res_fb.status_code, 201)

        # 8. GET /api/rules/TX-001/metrics
        res_metrics = self.client.get("/api/rules/TX-001/metrics", headers=headers_analyst)
        self.assertEqual(res_metrics.status_code, 200)
        self.assertEqual(res_metrics.get_json()['true_positives'], 1)

        # 9. GET /api/rules/metrics/summary
        res_sum = self.client.get("/api/rules/metrics/summary", headers=headers_analyst)
        self.assertEqual(res_sum.status_code, 200)
        self.assertIn("total_rules", res_sum.get_json())


if __name__ == '__main__':
    unittest.main()
