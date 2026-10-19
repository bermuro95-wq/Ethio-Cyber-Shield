"""
Test Suite: Part 22 — Explainable Behavioral Baselines (Phase 3.4).

Verifies:
1. Statistical baseline calculation over sliding lookback window (amount median/mean/std_dev, operating hours EAT, devices, channels).
2. Deterministic fallback when history is thin (< 5 events).
3. Plain-language explainability for amount multipliers (e.g., 'amount is 9.0× this account's 90-day median (20,000 ETB)').
4. Temporal off-hours deviation in Addis Ababa timezone (Africa/Addis_Ababa, UTC+3).
5. Unfamiliar client device and unprecedented channel detection.
6. Multi-tenant isolation (Tenant A baselines strictly isolated from Tenant B).
7. End-to-end integration with evaluate_event_stream synthesizing rules + baselines.
8. REST API endpoints: GET /api/baselines/*, POST /evaluate, /recalculate, /summary.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.behavioral_baseline_service import (
    BehavioralBaselineService,
    clear_baseline_caches,
    EAT_TZ
)
from app.services.detection_engine import evaluate_event_stream


class TestBehavioralBaselines(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())
        cls.user_admin_a = str(uuid.uuid4())
        cls.user_analyst_a = str(uuid.uuid4())
        cls.user_viewer_a = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_analyst_a = create_token(cls.user_analyst_a, "analyst@bank-a.et", "analyst", organization_id=cls.org_a)
        cls.token_viewer_a = create_token(cls.user_viewer_a, "viewer@bank-a.et", "viewer", organization_id=cls.org_a)
        cls.token_admin_b = create_token(str(uuid.uuid4()), "admin@bank-b.et", "admin", organization_id=cls.org_b)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_baseline_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_statistical_baseline_calculation(self):
        """Test statistical metrics calculation: amounts, operating hours (EAT), devices, and channels."""
        acc_id = f"ACC_BEKELE_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        # Seed 6 historical events during daytime (10:00 - 15:00 EAT) with amounts: 10k, 15k, 20k, 25k, 30k, 35k ETB
        # Median of [10k, 15k, 20k, 25k, 30k, 35k] is (20k + 25k) / 2 = 22,500 ETB
        for i, amt in enumerate([10000.0, 15000.0, 20000.0, 25000.0, 30000.0, 35000.0]):
            ev_dt = now - timedelta(days=i + 1)
            # 10:00 UTC is 13:00 EAT
            ev_dt = ev_dt.replace(hour=10, minute=0, second=0, microsecond=0)
            BehavioralBaselineService.record_event_for_baseline({
                'event_id': f"ev-hist-{i}",
                'organization_id': self.org_a,
                'account_id': acc_id,
                'amount': amt,
                'currency': 'ETB',
                'occurred_at': ev_dt.isoformat(),
                'device_id': 'dev_trusted_phone_01',
                'channel': 'mobile_app',
                'source_ip': '196.188.10.15'
            }, org_id=self.org_a)

        baseline = BehavioralBaselineService.calculate_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            lookback_days=90,
            save=False
        )

        self.assertEqual(baseline['status'], 'sufficient')
        self.assertEqual(baseline['sample_count'], 6)

        amt_stats = baseline['amount_stats']
        self.assertEqual(amt_stats['count'], 6)
        self.assertEqual(amt_stats['min'], 10000.0)
        self.assertEqual(amt_stats['max'], 35000.0)
        self.assertEqual(amt_stats['median'], 22500.0)
        self.assertEqual(amt_stats['mean'], 22500.0)
        self.assertGreater(amt_stats['std_dev'], 0)

        # Operating hours in EAT: 10:00 UTC = 13:00 EAT
        temporal = baseline['temporal_profile']
        self.assertIn(13, temporal['active_hours'])
        self.assertEqual(temporal['typical_window']['start_hour'], 13)
        self.assertEqual(temporal['typical_window']['end_hour'], 13)

        self.assertEqual(baseline['known_devices'], ['dev_trusted_phone_01'])
        self.assertEqual(baseline['known_channels'], ['mobile_app'])
        self.assertIn('196.188.10.15', baseline['known_locations'])

    def test_02_deterministic_fallback_when_history_is_thin(self):
        """Test deterministic fallback when history is thin (< 5 events)."""
        acc_new = f"ACC_NEW_{uuid.uuid4().hex[:6]}"

        # Only 2 events recorded
        for i in range(2):
            BehavioralBaselineService.record_event_for_baseline({
                'event_id': f"ev-thin-{i}",
                'organization_id': self.org_a,
                'account_id': acc_new,
                'amount': 5000.0,
                'currency': 'ETB'
            }, org_id=self.org_a)

        baseline = BehavioralBaselineService.calculate_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_new,
            save=False
        )
        self.assertEqual(baseline['status'], 'insufficient_data')
        self.assertEqual(baseline['sample_count'], 2)

        # Evaluate transaction
        test_event = {
            'event_id': 'ev-test-fallback',
            'organization_id': self.org_a,
            'account_id': acc_new,
            'amount': 45000.0,
            'currency': 'ETB'
        }
        res = BehavioralBaselineService.evaluate_event_against_baseline(test_event, org_id=self.org_a)

        self.assertFalse(res['is_anomalous'])
        self.assertEqual(res['anomaly_score'], 0)
        self.assertTrue(res['deterministic_fallback'])
        self.assertEqual(res['data_sufficiency'], 'insufficient')
        self.assertTrue(any('Insufficient historical baseline' in exp for exp in res['explanations']))
        self.assertTrue(any('fallback to platform policy defaults' in exp for exp in res['explanations']))

    def test_03_amount_multiplier_deviation_with_plain_explanation(self):
        """Test plain explanation for amount deviation: 'amount is 9.0× this account's 90-day median (20,000 ETB)'."""
        acc_id = f"ACC_EXP_{uuid.uuid4().hex[:6]}"

        # Seed baseline with median = 20,000 ETB
        BehavioralBaselineService.seed_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            baseline_data={
                'status': 'sufficient',
                'sample_count': 15,
                'lookback_days': 90,
                'amount_stats': {
                    'count': 15,
                    'median': 20000.0,
                    'mean': 21000.0,
                    'min': 5000.0,
                    'max': 35000.0
                },
                'temporal_profile': {'active_hours': [9, 10, 11, 12, 13, 14, 15, 16], 'typical_window': {'start_hour': 9, 'end_hour': 16}},
                'known_devices': ['dev-laptop-01']
            }
        )

        # Incoming event of 180,000 ETB (exactly 9.0x median)
        event_9x = {
            'event_id': 'ev-9x',
            'organization_id': self.org_a,
            'account_id': acc_id,
            'amount': 180000.0,
            'currency': 'ETB',
            'device_id': 'dev-laptop-01',
            'attributes': {'local_hour': 11}
        }
        eval_res = BehavioralBaselineService.evaluate_event_against_baseline(event_9x, org_id=self.org_a)

        self.assertTrue(eval_res['is_anomalous'])
        self.assertFalse(eval_res['deterministic_fallback'])
        self.assertGreaterEqual(eval_res['anomaly_score'], 35)

        amount_signals = [s for s in eval_res['signals'] if s['dimension'] == 'amount']
        self.assertEqual(len(amount_signals), 1)
        self.assertEqual(amount_signals[0]['ratio'], 9.0)
        self.assertEqual(amount_signals[0]['metric_value'], 180000.0)
        self.assertEqual(amount_signals[0]['baseline_value'], 20000.0)

        expected_explanation = "amount is 9.0× this account's 90-day median (20,000 ETB)"
        self.assertIn(expected_explanation, amount_signals[0]['explanation'])

    def test_04_temporal_off_hours_deviation_in_addis_ababa_tz(self):
        """Test off-hours temporal deviation in East Africa Time (UTC+3)."""
        acc_id = f"ACC_NIGHT_{uuid.uuid4().hex[:6]}"

        BehavioralBaselineService.seed_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            baseline_data={
                'status': 'sufficient',
                'sample_count': 20,
                'lookback_days': 90,
                'amount_stats': {'median': 10000.0},
                'temporal_profile': {
                    'active_hours': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    'typical_window': {'start_hour': 8, 'end_hour': 17}
                },
                'known_devices': ['dev-mobile-01']
            }
        )

        # Event at 00:00 UTC = 03:00 EAT (Addis Ababa)
        event_3am = {
            'event_id': 'ev-3am',
            'organization_id': self.org_a,
            'account_id': acc_id,
            'amount': 10000.0,
            'currency': 'ETB',
            'occurred_at': '2026-10-19T00:00:00Z',  # 03:00 EAT
            'device_id': 'dev-mobile-01'
        }
        eval_res = BehavioralBaselineService.evaluate_event_against_baseline(event_3am, org_id=self.org_a)

        self.assertTrue(eval_res['is_anomalous'])
        time_signals = [s for s in eval_res['signals'] if s['dimension'] == 'temporal']
        self.assertEqual(len(time_signals), 1)
        self.assertEqual(time_signals[0]['metric_value'], 3)
        self.assertIn("Activity at 03:00 EAT is outside typical operating window (08:00 - 17:00 EAT)", time_signals[0]['explanation'])

    def test_05_unfamiliar_device_and_channel_deviations(self):
        """Test unfamiliar client device and unprecedented payment channel deviations."""
        acc_id = f"ACC_DEV_{uuid.uuid4().hex[:6]}"

        BehavioralBaselineService.seed_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            baseline_data={
                'status': 'sufficient',
                'sample_count': 10,
                'lookback_days': 90,
                'amount_stats': {'median': 15000.0},
                'temporal_profile': {'active_hours': [10], 'typical_window': {'start_hour': 10, 'end_hour': 10}},
                'known_devices': ['dev_primary_samsung_s21'],
                'known_channels': ['mobile_app']
            }
        )

        # Event with new unknown device and USSD channel
        event_dev_ch = {
            'event_id': 'ev-dev-ch',
            'organization_id': self.org_a,
            'account_id': acc_id,
            'amount': 15000.0,
            'currency': 'ETB',
            'attributes': {'local_hour': 10},
            'device_id': 'dev_unrecognized_iphone_15',
            'channel': 'ussd'
        }
        eval_res = BehavioralBaselineService.evaluate_event_against_baseline(event_dev_ch, org_id=self.org_a)

        self.assertTrue(eval_res['is_anomalous'])
        dimensions = {s['dimension'] for s in eval_res['signals']}
        self.assertIn('device', dimensions)
        self.assertIn('channel', dimensions)

        dev_sig = next(s for s in eval_res['signals'] if s['dimension'] == 'device')
        self.assertIn("Device 'dev_unrecognized_iphone_15' has never been observed", dev_sig['explanation'])

        ch_sig = next(s for s in eval_res['signals'] if s['dimension'] == 'channel')
        self.assertIn("Transaction via channel 'ussd' is unprecedented", ch_sig['explanation'])

    def test_06_multi_tenant_isolation(self):
        """Verify strict multi-tenant isolation: Tenant A baselines cannot be viewed or leaked to Tenant B."""
        shared_acc_id = "ACC_SHARED_IDENTITY_01"

        # Seed baseline for Tenant A
        BehavioralBaselineService.seed_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=shared_acc_id,
            baseline_data={
                'status': 'sufficient',
                'sample_count': 25,
                'amount_stats': {'median': 50000.0}
            }
        )

        # Tenant A sees sufficient baseline with median 50,000 ETB
        base_a = BehavioralBaselineService.get_baseline(self.org_a, 'account', shared_acc_id)
        self.assertEqual(base_a['status'], 'sufficient')
        self.assertEqual(base_a['amount_stats']['median'], 50000.0)

        # Tenant B has no history for this account -> falls back to insufficient_data
        base_b = BehavioralBaselineService.get_baseline(self.org_b, 'account', shared_acc_id)
        self.assertEqual(base_b['status'], 'insufficient_data')
        self.assertEqual(base_b['sample_count'], 0)

        # REST API Isolation Test
        headers_b = {"Authorization": f"Bearer {self.token_admin_b}"}
        res_api_b = self.client.get(f"/api/baselines/account/{shared_acc_id}", headers=headers_b)
        self.assertEqual(res_api_b.status_code, 200)
        self.assertEqual(res_api_b.get_json()['baseline']['organization_id'], self.org_b)
        self.assertEqual(res_api_b.get_json()['baseline']['sample_count'], 0)

    @patch("app.services.response_policy.evaluate_and_execute_containment")
    @patch("app.services.incident_service.promote_alert_to_incident")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_07_detection_engine_stream_behavioral_synthesis(self, mock_sb, mock_inc, mock_cont):
        """Test evaluate_event_stream synthesizing rules + behavioral baseline anomalies."""
        acc_id = f"ACC_STREAM_{uuid.uuid4().hex[:6]}"

        # Seed account baseline with median 10,000 ETB and daytime hours 9-17 EAT
        BehavioralBaselineService.seed_baseline(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            baseline_data={
                'status': 'sufficient',
                'sample_count': 12,
                'lookback_days': 90,
                'amount_stats': {'median': 10000.0, 'count': 12},
                'temporal_profile': {'active_hours': [9, 10, 11, 12, 13, 14, 15, 16, 17], 'typical_window': {'start_hour': 9, 'end_hour': 17}},
                'known_devices': ['trusted_phone']
            }
        )

        # Event: 120,000 ETB (fires TX-001 +20 pts) + 12x median (fires baseline amount anomaly +45 pts)
        stream_event = {
            'event_id': f"ev-stream-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc_id,
            'amount': 120000.0,
            'currency': 'ETB',
            'attributes': {'local_hour': 12},
            'device_id': 'trusted_phone'
        }

        eval_res = evaluate_event_stream(stream_event)

        # Rules fired: TX-001
        self.assertIn("TX-001", eval_res['rules_fired'])
        # Behavioral baseline metadata present
        self.assertIn('behavioral_baseline', eval_res)
        self.assertTrue(eval_res['behavioral_baseline']['is_anomalous'])
        self.assertFalse(eval_res['deterministic_fallback'])

        # Score synthesis: 20 (TX-001) + 45 (12x median) = 65
        self.assertGreaterEqual(eval_res['risk_score'], 60)
        self.assertEqual(eval_res['severity'], 'high')

        # Explainable breakdown contains BASE-AMOUNT
        breakdown_rules = [b['rule_id'] for b in eval_res['breakdown']]
        self.assertIn('TX-001', breakdown_rules)
        self.assertIn('BASE-AMOUNT', breakdown_rules)

        # Plain explanation in reasons
        self.assertTrue(any('amount is 12.0× this account\'s 90-day median' in r for r in eval_res['reasons']))

    def test_08_rest_api_endpoints_and_rbac(self):
        """Test REST API endpoints: GET /api/baselines/*, POST /evaluate, /recalculate, and RBAC."""
        acc_api = f"ACC_API_{uuid.uuid4().hex[:6]}"
        headers_analyst = {"Authorization": f"Bearer {self.token_analyst_a}"}
        headers_admin = {"Authorization": f"Bearer {self.token_admin_a}"}
        headers_viewer = {"Authorization": f"Bearer {self.token_viewer_a}"}

        # 1. Admin seeds baseline: POST /api/baselines/<entity_type>/<entity_id>/seed
        seed_payload = {
            'status': 'sufficient',
            'sample_count': 18,
            'amount_stats': {'median': 25000.0, 'mean': 24000.0, 'count': 18},
            'known_devices': ['dev_sec_01']
        }
        res_seed = self.client.post(
            f"/api/baselines/account/{acc_api}/seed",
            json=seed_payload,
            headers=headers_admin
        )
        self.assertEqual(res_seed.status_code, 201)
        self.assertEqual(res_seed.get_json()['baseline']['sample_count'], 18)

        # 2. Viewer attempts recalculate -> 403 Forbidden (RBAC enforces analyst/admin)
        acc_recalc = f"ACC_RECALC_{uuid.uuid4().hex[:6]}"
        res_recalc_viewer = self.client.post(
            f"/api/baselines/account/{acc_recalc}/recalculate",
            json={'lookback_days': 60},
            headers=headers_viewer
        )
        self.assertEqual(res_recalc_viewer.status_code, 403)

        # 3. Analyst recalculates -> 200 OK
        res_recalc_analyst = self.client.post(
            f"/api/baselines/account/{acc_recalc}/recalculate",
            json={'lookback_days': 60},
            headers=headers_analyst
        )
        self.assertEqual(res_recalc_analyst.status_code, 200)

        # 4. Get baseline detail: GET /api/baselines/account/<id>
        res_get = self.client.get(f"/api/baselines/account/{acc_api}", headers=headers_viewer)
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.get_json()['baseline']['entity_id'], acc_api)

        # 5. Evaluate event: POST /api/baselines/evaluate
        eval_payload = {
            'account_id': acc_api,
            'amount': 225000.0,  # 9x median of 25k
            'currency': 'ETB',
            'device_id': 'dev_sec_01'
        }
        res_eval = self.client.post("/api/baselines/evaluate", json=eval_payload, headers=headers_viewer)
        self.assertEqual(res_eval.status_code, 200)
        eval_data = res_eval.get_json()['evaluation']
        self.assertTrue(eval_data['is_anomalous'])
        self.assertTrue(any('amount is 9.0×' in exp for exp in eval_data['explanations']))

        # 6. Baseline Summary: GET /api/baselines/summary
        res_summary = self.client.get("/api/baselines/summary", headers=headers_viewer)
        self.assertEqual(res_summary.status_code, 200)
        summary_data = res_summary.get_json()
        self.assertGreaterEqual(summary_data['total_baselines'], 1)
        self.assertEqual(summary_data['organization_id'], self.org_a)


if __name__ == '__main__':
    unittest.main()
