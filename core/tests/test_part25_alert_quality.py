"""
Test Suite: Part 25 — Alert Quality, Deduplication, Suppression Windows & Fatigue Reduction (Phase 3.7).

Verifies:
1. Deterministic alert fingerprinting based on invariant attributes (org, rule, entity, type).
2. Alert deduplication within sliding window (absorbing bursts, incrementing duplicate_count and updating last_seen_at).
3. Risk score escalation during deduplication (escalating severity when duplicate events carry higher risk).
4. Time-based suppression windows (suppressing alerts during maintenance, pentests, or tuning).
5. Automatic expiration of suppression windows.
6. Entity alert grouping / attack-chain correlation across multiple rules.
7. Alert fatigue reduction metrics (reduction rate, dedupe counts, fatigue grade).
8. Multi-tenant isolation for suppression rules and deduplication state.
9. End-to-end integration with evaluate_event_stream.
10. Full REST API coverage: /api/alerts/quality/metrics, /suppressions, /evaluate.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.alert_quality_service import (
    AlertQualityService,
    clear_alert_quality_caches
)
from app.services.detection_engine import evaluate_event_stream


class TestAlertQuality(unittest.TestCase):
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
        clear_alert_quality_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_alert_fingerprinting(self):
        """Test deterministic alert fingerprinting produces invariant hashes for identical incident attributes."""
        fp1 = AlertQualityService.generate_fingerprint(
            org_id=self.org_a,
            rule_id="AUTH-001",
            entity_type="account",
            entity_id="ACC_BEKELE_101",
            alert_type="high_risk"
        )
        fp2 = AlertQualityService.generate_fingerprint(
            org_id=self.org_a,
            rule_id="AUTH-001",
            entity_type="account",
            entity_id="ACC_BEKELE_101",
            alert_type="high_risk"
        )
        fp_diff = AlertQualityService.generate_fingerprint(
            org_id=self.org_a,
            rule_id="AUTH-001",
            entity_type="account",
            entity_id="ACC_AMINA_999",  # Different entity
            alert_type="high_risk"
        )

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp_diff)
        self.assertEqual(len(fp1), 64, "SHA-256 fingerprint must be 64 hex characters")

    def test_02_alert_deduplication_within_window(self):
        """Test a rapid burst of 5 identical candidate alerts creates 1 alert and increments duplicate_count to 5."""
        acc_id = f"ACC_DEDUPE_{uuid.uuid4().hex[:6]}"
        candidate = {
            'title': 'High Risk Login Failure Burst',
            'severity': 'medium',
            'alert_type': 'high_risk',
            'risk_score': 35,
            'primary_rule_id': 'AUTH-001',
            'entity_type': 'account',
            'entity_id': acc_id,
            'description': 'Repeated failed logins',
            'trigger_event_id': str(uuid.uuid4())
        }

        # 1st candidate -> Created
        res1 = AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)
        self.assertEqual(res1['action'], 'created')
        self.assertEqual(res1['alert']['duplicate_count'], 1)
        created_id = res1['alert']['id']

        # 4 subsequent candidates -> Deduplicated
        for i in range(2, 6):
            cand_next = dict(candidate)
            cand_next['trigger_event_id'] = str(uuid.uuid4())
            res_next = AlertQualityService.process_candidate_alert(cand_next, org_id=self.org_a)
            self.assertEqual(res_next['action'], 'deduplicated')
            self.assertEqual(res_next['alert']['id'], created_id)
            self.assertEqual(res_next['alert']['duplicate_count'], i)

    def test_03_risk_score_escalation_on_deduplication(self):
        """Test that duplicate events with higher risk scores escalate the parent alert's severity and score."""
        acc_id = f"ACC_ESCALATE_{uuid.uuid4().hex[:6]}"
        cand1 = {
            'title': 'Suspicious Activity',
            'severity': 'medium',
            'alert_type': 'suspicious_transaction',
            'risk_score': 30,
            'primary_rule_id': 'TX-001',
            'entity_type': 'account',
            'entity_id': acc_id,
            'trigger_event_id': 'evt_01'
        }
        res1 = AlertQualityService.process_candidate_alert(cand1, org_id=self.org_a)
        self.assertEqual(res1['alert']['risk_score'], 30)
        self.assertEqual(res1['alert']['severity'], 'medium')

        # Duplicate event with escalated risk score (75, critical)
        cand2 = dict(cand1)
        cand2['risk_score'] = 75
        cand2['severity'] = 'critical'
        cand2['trigger_event_id'] = 'evt_02'

        res2 = AlertQualityService.process_candidate_alert(cand2, org_id=self.org_a)
        self.assertEqual(res2['action'], 'deduplicated')
        self.assertEqual(res2['alert']['risk_score'], 75)
        self.assertEqual(res2['alert']['severity'], 'critical')
        self.assertEqual(res2['alert']['duplicate_count'], 2)

    def test_04_time_based_suppression_windows(self):
        """Test suppression rules suppress candidate alerts on targeted entities or rules."""
        target_ip = "196.188.50.25"
        
        # Create 1-hour suppression rule on this IP (e.g. penetration test or scheduled maintenance)
        rule = AlertQualityService.create_suppression_rule(
            org_id=self.org_a,
            entity_type='ip',
            entity_id=target_ip,
            rule_id='*',
            reason='Authorized Penetration Testing Window',
            duration_minutes=60,
            created_by=self.user_admin_a
        )
        self.assertIsNotNone(rule['id'])
        self.assertTrue(rule['is_active'])

        candidate = {
            'title': 'Port Scan / API Abuse',
            'severity': 'high',
            'alert_type': 'high_risk',
            'risk_score': 60,
            'primary_rule_id': 'API-001',
            'entity_type': 'ip',
            'entity_id': target_ip,
            'trigger_event_id': str(uuid.uuid4())
        }

        res = AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)
        self.assertEqual(res['action'], 'suppressed')
        self.assertIsNone(res['alert'])
        self.assertIn('Penetration Testing', res['reason'])

    def test_05_suppression_window_expiry(self):
        """Test that expired suppression rules allow alerts to be created normally."""
        target_acc = f"ACC_EXPIRED_SUPPRESS_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        # Create already-expired suppression rule (-10 minutes)
        AlertQualityService.create_suppression_rule(
            org_id=self.org_a,
            entity_type='account',
            entity_id=target_acc,
            rule_id='*',
            reason='Past maintenance window',
            duration_minutes=-10,
            created_by=self.user_admin_a
        )

        candidate = {
            'title': 'Unusual Activity Post Maintenance',
            'severity': 'medium',
            'alert_type': 'high_risk',
            'risk_score': 40,
            'primary_rule_id': 'TX-001',
            'entity_type': 'account',
            'entity_id': target_acc,
            'trigger_event_id': str(uuid.uuid4())
        }

        # Suppression expired, so alert must be created
        res = AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)
        self.assertEqual(res['action'], 'created')
        self.assertIsNotNone(res['alert'])

    def test_06_entity_alert_grouping(self):
        """Test multiple distinct alerts on the same entity within correlation window are assigned the same group_id."""
        acc_id = f"ACC_CLUSTER_{uuid.uuid4().hex[:6]}"

        cand_auth = {
            'title': 'AUTH-001 Login Failure Burst',
            'severity': 'medium',
            'alert_type': 'high_risk',
            'risk_score': 35,
            'primary_rule_id': 'AUTH-001',
            'entity_type': 'account',
            'entity_id': acc_id,
            'trigger_event_id': 'evt_auth'
        }
        res_auth = AlertQualityService.process_candidate_alert(cand_auth, org_id=self.org_a)
        group_id = res_auth['alert']['group_id']
        self.assertIsNotNone(group_id)

        # Second alert with different rule on the same account
        cand_tx = {
            'title': 'TX-001 High Value Transfer',
            'severity': 'high',
            'alert_type': 'suspicious_transaction',
            'risk_score': 55,
            'primary_rule_id': 'TX-001',
            'entity_type': 'account',
            'entity_id': acc_id,
            'trigger_event_id': 'evt_tx'
        }
        res_tx = AlertQualityService.process_candidate_alert(cand_tx, org_id=self.org_a)
        self.assertEqual(res_tx['action'], 'created')
        # Correlated group_id must match
        self.assertEqual(res_tx['alert']['group_id'], group_id)

    def test_07_alert_fatigue_reduction_metrics(self):
        """Test alert fatigue metrics: reduction rate calculation and fatigue grade."""
        acc_id = f"ACC_METRICS_{uuid.uuid4().hex[:6]}"
        
        # Feed 1 created alert + 9 duplicates = 10 total evaluated, 1 created, 9 deduplicated
        candidate = {
            'title': 'High Frequency Telemetry',
            'severity': 'medium',
            'alert_type': 'high_risk',
            'risk_score': 30,
            'primary_rule_id': 'AUTH-001',
            'entity_type': 'account',
            'entity_id': acc_id,
            'trigger_event_id': 'evt_init'
        }
        AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)
        for i in range(9):
            AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)

        metrics = AlertQualityService.get_fatigue_metrics(org_id=self.org_a)
        
        self.assertGreaterEqual(metrics['total_alerts_evaluated'], 10)
        self.assertEqual(metrics['alerts_deduplicated'], 9)
        # 9 deduplicated out of 10 evaluated = 90% reduction rate!
        self.assertGreaterEqual(metrics['alert_reduction_rate'], 0.85)
        self.assertEqual(metrics['fatigue_grade'], 'Optimal')

    def test_08_multi_tenancy_isolation(self):
        """Test Tenant A suppression rules and deduplication state do not affect Tenant B."""
        shared_acc = "ACC_SHARED_TENANT_ID_88"

        # Tenant A sets suppression rule
        AlertQualityService.create_suppression_rule(
            org_id=self.org_a,
            entity_type='account',
            entity_id=shared_acc,
            reason='Tenant A VIP suppression'
        )

        candidate = {
            'title': 'Suspicious Probe',
            'severity': 'high',
            'alert_type': 'high_risk',
            'risk_score': 60,
            'primary_rule_id': 'TX-001',
            'entity_type': 'account',
            'entity_id': shared_acc,
            'trigger_event_id': 'evt_probe'
        }

        # Tenant A is suppressed
        res_a = AlertQualityService.process_candidate_alert(candidate, org_id=self.org_a)
        self.assertEqual(res_a['action'], 'suppressed')

        # Tenant B receives alert normally (not suppressed)
        res_b = AlertQualityService.process_candidate_alert(candidate, org_id=self.org_b)
        self.assertEqual(res_b['action'], 'created')
        self.assertIsNotNone(res_b['alert'])

    def test_09_evaluate_event_stream_deduplication_integration(self):
        """Test evaluate_event_stream absorbs duplicate bursts into a single alert with incremented count."""
        acc_id = f"ACC_E2E_STREAM_{uuid.uuid4().hex[:6]}"
        event_sample = {
            'event_id': str(uuid.uuid4()),
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc_id,
            'amount_etb': 120000,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'attributes': {'amount_etb': 120000, 'off_hours': True}
        }

        # Event 1: Creates alert
        res1 = evaluate_event_stream(event_sample)
        self.assertIsNotNone(res1['alert_id'])
        alert_id = res1['alert_id']

        # Event 2: Immediate identical event should deduplicate into existing alert
        event_sample_2 = dict(event_sample)
        event_sample_2['event_id'] = str(uuid.uuid4())
        res2 = evaluate_event_stream(event_sample_2)
        
        self.assertEqual(res2['alert_id'], alert_id)
        if res2.get('alert_quality'):
            self.assertEqual(res2['alert_quality']['action'], 'deduplicated')
            self.assertEqual(res2['alert_quality']['duplicate_count'], 2)

    def test_10_rest_api_endpoints(self):
        """Test REST API routes: /api/alerts/quality/metrics, /suppressions, /evaluate."""
        headers_viewer = {'Authorization': f'Bearer {self.token_viewer_a}', 'Content-Type': 'application/json'}
        headers_analyst = {'Authorization': f'Bearer {self.token_analyst_a}', 'Content-Type': 'application/json'}

        # 1. GET /api/alerts/quality/metrics
        resp_met = self.client.get('/api/alerts/quality/metrics', headers=headers_viewer)
        self.assertEqual(resp_met.status_code, 200)
        self.assertIn('alert_reduction_rate', resp_met.get_json()['data'])

        # 2. POST /api/alerts/quality/suppressions (Create suppression window)
        supp_payload = {
            'entity_type': 'ip',
            'entity_id': '196.188.99.1',
            'rule_id': '*',
            'reason': 'API Load Testing',
            'duration_minutes': 30
        }
        resp_create = self.client.post('/api/alerts/quality/suppressions', json=supp_payload, headers=headers_analyst)
        self.assertEqual(resp_create.status_code, 201)
        supp_id = resp_create.get_json()['data']['id']

        # 3. GET /api/alerts/quality/suppressions (List active)
        resp_list = self.client.get('/api/alerts/quality/suppressions', headers=headers_viewer)
        self.assertEqual(resp_list.status_code, 200)
        items = resp_list.get_json()['data']
        self.assertTrue(any(s['id'] == supp_id for s in items))

        # 4. POST /api/alerts/quality/evaluate (Dry run decision)
        eval_payload = {
            'primary_rule_id': 'API-001',
            'entity_type': 'ip',
            'entity_id': '196.188.99.1',
            'alert_type': 'high_risk',
            'risk_score': 50
        }
        resp_eval = self.client.post('/api/alerts/quality/evaluate', json=eval_payload, headers=headers_viewer)
        self.assertEqual(resp_eval.status_code, 200)
        # Must be suppressed because of active suppression rule created above
        self.assertEqual(resp_eval.get_json()['data']['action'], 'suppressed')

        # 5. DELETE /api/alerts/quality/suppressions/<id> (Revoke)
        resp_del = self.client.delete(f'/api/alerts/quality/suppressions/{supp_id}', headers=headers_analyst)
        self.assertEqual(resp_del.status_code, 200)

        # After revocation, evaluate returns candidate action 'created'
        resp_eval_after = self.client.post('/api/alerts/quality/evaluate', json=eval_payload, headers=headers_viewer)
        self.assertEqual(resp_eval_after.get_json()['data']['action'], 'created')


if __name__ == '__main__':
    unittest.main()
