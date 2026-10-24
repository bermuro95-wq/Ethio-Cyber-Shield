"""
Test Suite: Part 23 — Risk Model v2 (Phase 3.5).

Verifies:
1. Additive 0-100 model with rule confidence factors (high=1.0, medium=0.85, low=0.70).
2. Entity Criticality tiers (critical, high, medium, low) with multipliers and score boosts.
3. Automatic criticality inference for critical Ethiopian infrastructure (Core Banking, EthSwitch, Treasury).
4. Zero-baseline protection: Benign events on critical systems do not fire false alarms (boost only applies when pre_score > 0).
5. Recency decay calculation over temporal windows (<=15m, <=60m, <=6h, <=24h, >24h).
6. Non-probability declaration and explainable severity rationales.
7. Multi-tenant isolation for entity criticality configurations (Tenant A vs Tenant B).
8. Composite decayed entity risk profile calculation.
9. Integration with evaluate_event_stream synthesizing rules + baselines + Risk Model v2.
10. Full REST API coverage: /api/risk/model/spec, /evaluate, /criticality, /entities/<type>/<id>.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.detection_engine import evaluate_event_stream
from app.services.risk_model_service import (
    RiskModelV2Service,
    clear_risk_model_caches,
    CRITICALITY_TIERS,
    CONFIDENCE_FACTORS,
    RECENCY_DECAY_TIERS,
)


class TestRiskModelV2(unittest.TestCase):
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
        clear_risk_model_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_rule_confidence_weighting(self):
        """Test rule confidence factors (high=1.0, medium=0.85, low=0.70) adjust rule score contributions."""
        fired_rules = [
            {'rule_id': 'RULE-HIGH', 'name': 'High Conf Rule', 'weight': 30, 'confidence': 'high'},
            {'rule_id': 'RULE-MED', 'name': 'Medium Conf Rule', 'weight': 30, 'confidence': 'medium'},
            {'rule_id': 'RULE-LOW', 'name': 'Low Conf Rule', 'weight': 30, 'confidence': 'low'},
        ]
        
        # Medium entity (1.0x, 0 boost)
        eval_result = RiskModelV2Service.calculate_risk(
            fired_rules=fired_rules,
            entity_type='account',
            entity_id='ACC_123',
            org_id=self.org_a
        )

        breakdown = {r['rule_id']: r for r in eval_result['rules_breakdown']}
        
        # High: 30 * 1.0 = 30
        self.assertEqual(breakdown['RULE-HIGH']['confidence_factor'], 1.0)
        self.assertEqual(breakdown['RULE-HIGH']['effective_contribution'], 30)

        # Medium: round(30 * 0.85) = 26 (or 25.5 -> 26)
        self.assertEqual(breakdown['RULE-MED']['confidence_factor'], 0.85)
        self.assertEqual(breakdown['RULE-MED']['effective_contribution'], round(30 * 0.85))

        # Low: round(30 * 0.70) = 21
        self.assertEqual(breakdown['RULE-LOW']['confidence_factor'], 0.70)
        self.assertEqual(breakdown['RULE-LOW']['effective_contribution'], round(30 * 0.70))

        expected_rules_sum = 30 + round(30 * 0.85) + round(30 * 0.70)
        self.assertEqual(eval_result['components']['confidence_adjusted_rules_score'], expected_rules_sum)

    def test_02_entity_criticality_tiers_and_multipliers(self):
        """Test entity criticality tiers (critical, high, medium, low) adjust scores accurately."""
        # 1. Critical tier: 1.4x + 15 pts boost
        RiskModelV2Service.set_entity_criticality(
            org_id=self.org_a,
            entity_type='system',
            entity_id='ETHSWITCH_CORE_GW',
            tier='critical',
            owner_unit='National Switch Rails',
            notes='Primary EthSwitch interbank settlement node'
        )

        rules = [{'rule_id': 'TEST-01', 'name': 'Suspicious Probe', 'weight': 30, 'confidence': 'high'}]
        res_crit = RiskModelV2Service.calculate_risk(
            fired_rules=rules,
            entity_type='system',
            entity_id='ETHSWITCH_CORE_GW',
            org_id=self.org_a
        )

        # pre_score = 30. adjusted = round(30 * 1.4) + 15 = 42 + 15 = 57 (High severity)
        self.assertEqual(res_crit['components']['entity_criticality']['tier'], 'critical')
        self.assertEqual(res_crit['components']['entity_criticality']['multiplier'], 1.4)
        self.assertEqual(res_crit['components']['entity_criticality']['boost'], 15)
        self.assertEqual(res_crit['risk_score'], 57)
        self.assertEqual(res_crit['severity'], 'high')

        # 2. Low tier: 0.9x + 0 boost
        RiskModelV2Service.set_entity_criticality(
            org_id=self.org_a,
            entity_type='account',
            entity_id='ACC_TEST_SANDBOX',
            tier='low',
            owner_unit='QA Lab'
        )
        res_low = RiskModelV2Service.calculate_risk(
            fired_rules=rules,
            entity_type='account',
            entity_id='ACC_TEST_SANDBOX',
            org_id=self.org_a
        )
        # pre_score = 30. adjusted = round(30 * 0.9) + 0 = 27
        self.assertEqual(res_low['components']['entity_criticality']['tier'], 'low')
        self.assertEqual(res_low['risk_score'], 27)

    def test_03_zero_baseline_protection(self):
        """Test zero-baseline protection: benign events on critical entities do NOT get boosted to positive risk."""
        RiskModelV2Service.set_entity_criticality(
            org_id=self.org_a,
            entity_type='system',
            entity_id='CBE_CORE_BANKING_PROD',
            tier='critical'
        )

        res = RiskModelV2Service.calculate_risk(
            fired_rules=[],
            baseline_score=0,
            entity_type='system',
            entity_id='CBE_CORE_BANKING_PROD',
            org_id=self.org_a
        )

        # Base is 0, so risk score must remain 0 and NOT jump to 15
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['severity'], 'low')
        self.assertFalse(res['is_threat'])

    def test_04_automatic_criticality_inference(self):
        """Test automatic inference of critical/high tier based on Ethiopian infrastructure and role keywords."""
        # EthSwitch keyword in entity_id
        res_switch = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Anomaly', 'weight': 20}],
            entity_type='system',
            entity_id='ethswitch-clearing-node-01',
            org_id=self.org_a
        )
        self.assertEqual(res_switch['components']['entity_criticality']['tier'], 'critical')
        self.assertEqual(res_switch['components']['entity_criticality']['multiplier'], 1.4)

        # Treasury keyword in account
        res_treasury = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Anomaly', 'weight': 20}],
            entity_type='account',
            entity_id='ACC_TREASURY_RESERVE_ETB',
            org_id=self.org_a
        )
        self.assertEqual(res_treasury['components']['entity_criticality']['tier'], 'critical')

        # Admin role keyword in user
        res_admin = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Anomaly', 'weight': 20}],
            entity_type='user',
            entity_id='soc-admin-user-01',
            org_id=self.org_a
        )
        self.assertEqual(res_admin['components']['entity_criticality']['tier'], 'high')

    def test_05_recency_decay_calculation(self):
        """Test recency decay factors over sliding time windows."""
        now = datetime.now(timezone.utc)

        # 10 minutes ago -> 1.0 (Acute)
        t_10m = (now - timedelta(minutes=10)).isoformat()
        decay_10m, delta_10m = RiskModelV2Service.calculate_recency_decay(t_10m, now)
        self.assertEqual(decay_10m, 1.0)

        # 45 minutes ago -> 0.85
        t_45m = (now - timedelta(minutes=45)).isoformat()
        decay_45m, _ = RiskModelV2Service.calculate_recency_decay(t_45m, now)
        self.assertEqual(decay_45m, 0.85)

        # 3 hours ago -> 0.65
        t_3h = (now - timedelta(hours=3)).isoformat()
        decay_3h, _ = RiskModelV2Service.calculate_recency_decay(t_3h, now)
        self.assertEqual(decay_3h, 0.65)

        # 12 hours ago -> 0.40
        t_12h = (now - timedelta(hours=12)).isoformat()
        decay_12h, _ = RiskModelV2Service.calculate_recency_decay(t_12h, now)
        self.assertEqual(decay_12h, 0.40)

        # 48 hours ago -> 0.20
        t_48h = (now - timedelta(hours=48)).isoformat()
        decay_48h, _ = RiskModelV2Service.calculate_recency_decay(t_48h, now)
        self.assertEqual(decay_48h, 0.20)

    def test_06_additive_capping_and_non_probability_declaration(self):
        """Test strict [0, 100] capping and non-probability legal disclaimer."""
        heavy_rules = [
            {'rule_id': 'R1', 'name': 'R1', 'weight': 50, 'confidence': 'high'},
            {'rule_id': 'R2', 'name': 'R2', 'weight': 50, 'confidence': 'high'},
            {'rule_id': 'R3', 'name': 'R3', 'weight': 40, 'confidence': 'high'},
        ]
        
        # Raw is 140, on critical system (1.4x + 15) -> mathematically 211
        res = RiskModelV2Service.calculate_risk(
            fired_rules=heavy_rules,
            entity_type='system',
            entity_id='core-banking-host',
            org_id=self.org_a
        )

        self.assertEqual(res['risk_score'], 100)
        self.assertEqual(res['severity'], 'critical')
        self.assertIn("NOT a statistical probability", res['non_probability_declaration'])
        self.assertIn("operational risk", res['non_probability_declaration'].lower())

    def test_07_severity_tiers_and_rationale(self):
        """Test deterministic severity mapping and explanatory rationale."""
        # 1. Low: score 15
        r_low = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Minor', 'weight': 15, 'confidence': 'high'}],
            entity_type='account', entity_id='ACC_PLAIN', org_id=self.org_a
        )
        self.assertEqual(r_low['severity'], 'low')
        self.assertIn("Sub-threshold", r_low['severity_rationale'])

        # 2. Medium: score 30
        r_med = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Noticeable', 'weight': 30, 'confidence': 'high'}],
            entity_type='account', entity_id='ACC_PLAIN', org_id=self.org_a
        )
        self.assertEqual(r_med['severity'], 'medium')
        self.assertIn("monitoring", r_med['severity_rationale'].lower())

        # 3. High: score 60
        r_high = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Severe', 'weight': 60, 'confidence': 'high'}],
            entity_type='account', entity_id='ACC_PLAIN', org_id=self.org_a
        )
        self.assertEqual(r_high['severity'], 'high')
        self.assertIn("Significant", r_high['severity_rationale'])

        # 4. Critical: score 85
        r_crit = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'Extreme', 'weight': 85, 'confidence': 'high'}],
            entity_type='account', entity_id='ACC_PLAIN', org_id=self.org_a
        )
        self.assertEqual(r_crit['severity'], 'critical')
        self.assertIn("Acute threat", r_crit['severity_rationale'])

    def test_08_multi_tenancy_isolation(self):
        """Test Tenant A entity criticality configurations are completely isolated from Tenant B."""
        target_account = "ACC_SHARED_ID_9999"

        # Tenant A sets target_account as 'critical'
        RiskModelV2Service.set_entity_criticality(
            org_id=self.org_a,
            entity_type='account',
            entity_id=target_account,
            tier='critical',
            owner_unit='Tenant A VIP'
        )

        # Tenant B evaluates same account identifier
        eval_b = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'R1', 'weight': 20, 'confidence': 'high'}],
            entity_type='account',
            entity_id=target_account,
            org_id=self.org_b
        )

        # Tenant B must NOT see Tenant A's 'critical' tier; defaults to 'medium' (1.0x, 0 boost)
        self.assertEqual(eval_b['components']['entity_criticality']['tier'], 'medium')
        self.assertEqual(eval_b['risk_score'], 20)

        # Tenant A sees 'critical' (1.4x + 15 boost) -> round(20 * 1.4) + 15 = 28 + 15 = 43
        eval_a = RiskModelV2Service.calculate_risk(
            fired_rules=[{'rule_id': 'R1', 'name': 'R1', 'weight': 20, 'confidence': 'high'}],
            entity_type='account',
            entity_id=target_account,
            org_id=self.org_a
        )
        self.assertEqual(eval_a['components']['entity_criticality']['tier'], 'critical')
        self.assertEqual(eval_a['risk_score'], 43)

    def test_09_entity_composite_risk_posture(self):
        """Test composite entity risk profile calculated with recency decay from past detections."""
        entity_id = f"ACC_MULE_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        # Record 2 past detections:
        # Detection 1: 30 minutes ago, score 50 (decay 0.85 -> 42.5)
        # Detection 2: 5 hours ago, score 40 (decay 0.65 -> 26.0)
        RiskModelV2Service.record_entity_detection(
            org_id=self.org_a,
            entity_type='account',
            entity_id=entity_id,
            detection_id=str(uuid.uuid4()),
            rule_id='FRAUD-MULE-01',
            score=50,
            timestamp=(now - timedelta(minutes=30)).isoformat()
        )
        RiskModelV2Service.record_entity_detection(
            org_id=self.org_a,
            entity_type='account',
            entity_id=entity_id,
            detection_id=str(uuid.uuid4()),
            rule_id='FRAUD-STRUCTURING-01',
            score=40,
            timestamp=(now - timedelta(hours=5)).isoformat()
        )

        profile = RiskModelV2Service.get_entity_risk_profile(
            org_id=self.org_a,
            entity_type='account',
            entity_id=entity_id,
            reference_time=now
        )

        self.assertEqual(profile['entity_id'], entity_id)
        self.assertEqual(profile['detection_count'], 2)
        # Active decayed score = max or composite decayed contribution
        self.assertGreater(profile['active_decayed_risk'], 0)
        self.assertLessEqual(profile['active_decayed_risk'], 100)
        self.assertEqual(len(profile['recent_detections']), 2)

    def test_10_end_to_end_evaluate_event_stream_integration(self):
        """Test evaluate_event_stream integrates Risk Model v2 with rules and baselines."""
        acc_id = f"ACC_CRIT_E2E_{uuid.uuid4().hex[:6]}"
        
        # Configure as high criticality
        RiskModelV2Service.set_entity_criticality(
            org_id=self.org_a,
            entity_type='account',
            entity_id=acc_id,
            tier='high',
            owner_unit='Branch Operations'
        )

        sample_event = {
            'event_id': str(uuid.uuid4()),
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_INITIATED',
            'account_id': acc_id,
            'source_account': acc_id,
            'user_id': 'USR_E2E_01',
            'amount_etb': 85000,
            'currency': 'ETB',
            'channel': 'USSD',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'attributes': {
                'channel': 'USSD',
                'amount_etb': 85000,
            }
        }

        result = evaluate_event_stream(sample_event)

        self.assertIn('risk_model_v2', result)
        v2_meta = result['risk_model_v2']
        self.assertEqual(v2_meta['components']['entity_criticality']['tier'], 'high')
        self.assertIn("NOT a statistical probability", result['risk_model_v2']['non_probability_declaration'])
        self.assertEqual(result['risk_score'], v2_meta['risk_score'])
        self.assertEqual(result['severity'], v2_meta['severity'])

    def test_11_rest_api_endpoints(self):
        """Test REST API routes: /api/risk/model/spec, /evaluate, /criticality, /entities/<type>/<id>."""
        headers_admin = {'Authorization': f'Bearer {self.token_admin_a}', 'Content-Type': 'application/json'}
        headers_viewer = {'Authorization': f'Bearer {self.token_viewer_a}', 'Content-Type': 'application/json'}

        # 1. GET /api/risk/model/spec
        resp_spec = self.client.get('/api/risk/model/spec', headers=headers_viewer)
        self.assertEqual(resp_spec.status_code, 200)
        spec_data = resp_spec.get_json()['data']
        self.assertEqual(spec_data['model_version'], '2.0')
        self.assertIn('criticality_tiers', spec_data)
        self.assertIn('confidence_factors', spec_data)
        self.assertIn('recency_decay_tiers', spec_data)
        self.assertIn("NOT a statistical probability", spec_data['non_probability_notice'])

        # 2. POST /api/risk/criticality (Admin only)
        crit_payload = {
            'entity_type': 'system',
            'entity_id': 'REST_API_CORE_SWITCH',
            'criticality_tier': 'critical',
            'owner_unit': 'Switch Ops',
            'notes': 'Provisioned via REST API'
        }
        resp_set = self.client.post('/api/risk/criticality', json=crit_payload, headers=headers_admin)
        self.assertEqual(resp_set.status_code, 201)
        created_id = resp_set.get_json()['data']['id']

        # Viewer cannot mutate criticality (Forbidden)
        resp_viewer_mut = self.client.post('/api/risk/criticality', json=crit_payload, headers=headers_viewer)
        self.assertEqual(resp_viewer_mut.status_code, 403)

        # 3. GET /api/risk/criticality
        resp_list = self.client.get('/api/risk/criticality', headers=headers_viewer)
        self.assertEqual(resp_list.status_code, 200)
        items = resp_list.get_json()['data']
        self.assertTrue(any(i['entity_id'] == 'REST_API_CORE_SWITCH' for i in items))

        # 4. POST /api/risk/evaluate (Dry-run evaluation)
        eval_payload = {
            'entity_type': 'system',
            'entity_id': 'REST_API_CORE_SWITCH',
            'fired_rules': [
                {'rule_id': 'API-RULE-01', 'name': 'API Abuse', 'weight': 30, 'confidence': 'high'}
            ]
        }
        resp_eval = self.client.post('/api/risk/evaluate', json=eval_payload, headers=headers_viewer)
        self.assertEqual(resp_eval.status_code, 200)
        eval_res = resp_eval.get_json()['data']
        self.assertEqual(eval_res['components']['entity_criticality']['tier'], 'critical')
        self.assertEqual(eval_res['risk_score'], 57)  # round(30 * 1.4) + 15 = 57

        # 5. GET /api/risk/entities/system/REST_API_CORE_SWITCH
        resp_entity = self.client.get('/api/risk/entities/system/REST_API_CORE_SWITCH', headers=headers_viewer)
        self.assertEqual(resp_entity.status_code, 200)
        entity_res = resp_entity.get_json()['data']
        self.assertEqual(entity_res['criticality_tier'], 'critical')

        # 6. DELETE /api/risk/criticality/<id>
        resp_del = self.client.delete(f'/api/risk/criticality/{created_id}', headers=headers_admin)
        self.assertEqual(resp_del.status_code, 200)

        # Verify deletion
        resp_after_del = self.client.get('/api/risk/entities/system/REST_API_CORE_SWITCH', headers=headers_viewer)
        self.assertEqual(resp_after_del.get_json()['data']['criticality_tier'], 'medium')


if __name__ == '__main__':
    unittest.main()
