"""
Test Suite: Part 21 — Specialized Detection Rule Packs (Phase 3.3).

Verifies:
1. Complete rule pack inventory (>= 25 rules across 3 packs: fraud_payments, web_api, insider_admin).
2. Fraud & Payments Pack:
   - FRAUD-001: Rapid Beneficiary Add and Transfer
   - FRAUD-002: Mule Pass-Through Account Pattern
   - FRAUD-003: SIM-Swap or Credential Reset Prior to Transfer
   - FRAUD-004: Transaction Structuring Under Reporting Threshold
   - FRAUD-005: USSD and Agent Cash-Out Burst
   - FRAUD-006: Authorized Push Payment (APP) Coached Transfer
   - FRAUD-007: Impossible Geolocation Travel Velocity
3. Web & API Pack:
   - API-003: Bearer Token Misuse and Replay
   - API-004: Automated Bot and Security Tool Scanning
   - API-005: Distributed Rate Limit Evasion Probing
   - AUTH-004: Password Spraying Campaign
4. Insider & Admin Pack:
   - ADMIN-001: Mass Customer Data Export Anomaly
   - ADMIN-002: Dormant Admin Account Activation
   - ADMIN-003: Off-Hours Privileged Configuration Action
   - ADMIN-004: Unauthorized Role Elevation Attempt
   - ADMIN-005: Audit Trail Tampering Attempt
5. Multi-tenant threshold overrides and filtering across packs via REST API.
6. End-to-end risk synthesis in evaluate_event_stream.
"""
import unittest
from unittest.mock import patch
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.rule_engine_service import (
    get_rule_engine,
    clear_rule_engine_caches
)
from app.services.detection_engine import evaluate_event_stream


class TestRulePacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())
        cls.user_admin_a = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_rule_engine_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_rule_packs_inventory_and_counts(self):
        """Test that >= 25 declarative rules are loaded across fraud_payments, web_api, and insider_admin packs."""
        engine = get_rule_engine()
        all_rules = engine.list_rules(org_id=self.org_a)

        self.assertGreaterEqual(len(all_rules), 25)

        fraud_rules = [r for r in all_rules if r.get('pack') == 'fraud_payments']
        web_rules = [r for r in all_rules if r.get('pack') == 'web_api']
        insider_rules = [r for r in all_rules if r.get('pack') == 'insider_admin']

        self.assertGreaterEqual(len(fraud_rules), 10)
        self.assertGreaterEqual(len(web_rules), 9)
        self.assertGreaterEqual(len(insider_rules), 6)

        # Verify REST API filtering
        headers = {"Authorization": f"Bearer {self.token_admin_a}"}
        res_fraud = self.client.get("/api/rules?pack=fraud_payments", headers=headers)
        self.assertEqual(res_fraud.status_code, 200)
        self.assertGreaterEqual(len(res_fraud.get_json()['rules']), 10)

        res_insider = self.client.get("/api/rules?pack=insider_admin", headers=headers)
        self.assertEqual(res_insider.status_code, 200)
        self.assertGreaterEqual(len(res_insider.get_json()['rules']), 6)

    def test_02_fraud_pack_rapid_beneficiary_and_mule_passthrough(self):
        """Test FRAUD-001 (Rapid Beneficiary Transfer) and FRAUD-002 (Mule Pass-Through)."""
        engine = get_rule_engine()
        account_id = f"ACC_MULE_{uuid.uuid4().hex[:6]}"

        # 1. FRAUD-001
        ev_beneficiary_transfer = {
            'event_id': f"ev-fb-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': account_id,
            'amount': 35000.0,
            'currency': 'ETB',
            'attributes': {'rapid_beneficiary_transfer': True}
        }
        res_f1 = engine.evaluate_event(ev_beneficiary_transfer, org_id=self.org_a)
        matched_f1 = [r for r in res_f1 if r['rule_id'] == 'FRAUD-001']
        self.assertEqual(len(matched_f1), 1)
        self.assertEqual(matched_f1[0]['severity'], 'high')
        self.assertEqual(matched_f1[0]['weight'], 35)

        # 2. FRAUD-002
        ev_mule = {
            'event_id': f"ev-mule-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': account_id,
            'amount': 85000.0,
            'currency': 'ETB',
            'attributes': {'mule_passthrough': True}
        }
        res_f2 = engine.evaluate_event(ev_mule, org_id=self.org_a)
        matched_f2 = [r for r in res_f2 if r['rule_id'] == 'FRAUD-002']
        self.assertEqual(len(matched_f2), 1)
        self.assertEqual(matched_f2[0]['weight'], 35)

    def test_03_fraud_pack_sim_swap_and_structuring(self):
        """Test FRAUD-003 (SIM-Swap Prior to Transfer) and FRAUD-004 (Transaction Structuring)."""
        engine = get_rule_engine()
        acc = f"ACC_SIM_{uuid.uuid4().hex[:6]}"

        # 1. FRAUD-003
        ev_sim = {
            'event_id': f"ev-sim-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 30000.0,
            'currency': 'ETB',
            'attributes': {'sim_swap_recent': True}
        }
        res_sim = engine.evaluate_event(ev_sim, org_id=self.org_a)
        matched_sim = [r for r in res_sim if r['rule_id'] == 'FRAUD-003']
        self.assertEqual(len(matched_sim), 1)
        self.assertEqual(matched_sim[0]['severity'], 'critical')

        # 2. FRAUD-004 Structuring
        ev_struct = {
            'event_id': f"ev-struct-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 48000.0,
            'currency': 'ETB',
            'attributes': {'structuring_detected': True}
        }
        res_struct = engine.evaluate_event(ev_struct, org_id=self.org_a)
        matched_struct = [r for r in res_struct if r['rule_id'] == 'FRAUD-004']
        self.assertEqual(len(matched_struct), 1)
        self.assertEqual(matched_struct[0]['weight'], 30)

    def test_04_fraud_pack_ussd_app_scam_and_impossible_travel(self):
        """Test FRAUD-005 (USSD Abuse), FRAUD-006 (APP Coached Transfer), and FRAUD-007 (Impossible Travel)."""
        engine = get_rule_engine()

        # 1. FRAUD-005
        ev_ussd = {
            'event_id': f"ev-ussd-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'channel': 'ussd',
            'account_id': "ACC_USSD",
            'attributes': {'ussd_abuse_burst': True}
        }
        res_ussd = engine.evaluate_event(ev_ussd, org_id=self.org_a)
        matched_ussd = [r for r in res_ussd if r['rule_id'] == 'FRAUD-005']
        self.assertEqual(len(matched_ussd), 1)

        # 2. FRAUD-006
        ev_app = {
            'event_id': f"ev-app-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': "ACC_APP",
            'amount': 65000.0,
            'currency': 'ETB',
            'attributes': {'coached_session': True}
        }
        res_app = engine.evaluate_event(ev_app, org_id=self.org_a)
        matched_app = [r for r in res_app if r['rule_id'] == 'FRAUD-006']
        self.assertEqual(len(matched_app), 1)
        self.assertEqual(matched_app[0]['severity'], 'critical')

        # 3. FRAUD-007
        ev_travel = {
            'event_id': f"ev-travel-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'account_id': "ACC_TRAVEL",
            'attributes': {'impossible_travel': True}
        }
        res_travel = engine.evaluate_event(ev_travel, org_id=self.org_a)
        matched_travel = [r for r in res_travel if r['rule_id'] == 'FRAUD-007']
        self.assertEqual(len(matched_travel), 1)

    def test_05_web_api_pack_evaluations(self):
        """Test API-003, API-004, API-005, and AUTH-004."""
        engine = get_rule_engine()

        # 1. API-003 Token Misuse
        ev_token = {
            'event_id': f"ev-tok-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TOKEN_REPLAYED',
            'attributes': {'token_replayed': True}
        }
        res_tok = engine.evaluate_event(ev_token, org_id=self.org_a)
        self.assertTrue(any(r['rule_id'] == 'API-003' for r in res_tok))

        # 2. API-004 Scanner bot
        ev_scanner = {
            'event_id': f"ev-scan-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'source_ip': '198.51.100.99',
            'attributes': {'user_agent': 'sqlmap/1.6#stable (https://sqlmap.org)'}
        }
        res_scan = engine.evaluate_event(ev_scanner, org_id=self.org_a)
        matched_scan = [r for r in res_scan if r['rule_id'] == 'API-004']
        self.assertEqual(len(matched_scan), 1)
        self.assertIn('sqlmap', matched_scan[0]['summary'])

        # 3. API-005 Rate Limit Evasion
        ev_evasion = {
            'event_id': f"ev-evade-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'source_ip': '196.188.10.45',
            'attributes': {'rate_limit_evasion': True}
        }
        res_evade = engine.evaluate_event(ev_evasion, org_id=self.org_a)
        self.assertTrue(any(r['rule_id'] == 'API-005' for r in res_evade))

        # 4. AUTH-004 Password Spray
        ev_spray = {
            'event_id': f"ev-spray-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'source_ip': '198.51.100.22',
            'attributes': {'password_spray': True}
        }
        res_spray = engine.evaluate_event(ev_spray, org_id=self.org_a)
        self.assertTrue(any(r['rule_id'] == 'AUTH-004' for r in res_spray))

    def test_06_insider_admin_pack_evaluations(self):
        """Test ADMIN-001 through ADMIN-005."""
        engine = get_rule_engine()

        # 1. ADMIN-001 Mass Export
        ev_export = {
            'event_id': f"ev-exp-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'ADMIN_ACTION',
            'account_id': 'admin_bekele',
            'attributes': {'record_count': 1500}
        }
        res_exp = engine.evaluate_event(ev_export, org_id=self.org_a)
        matched_exp = [r for r in res_exp if r['rule_id'] == 'ADMIN-001']
        self.assertEqual(len(matched_exp), 1)
        self.assertEqual(matched_exp[0]['severity'], 'critical')

        # 2. ADMIN-002 Dormant Admin
        ev_dormant = {
            'event_id': f"ev-dorm-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'LOGIN_SUCCESS',
            'account_id': 'admin_dormant_01',
            'attributes': {'days_inactive': 60}
        }
        res_dorm = engine.evaluate_event(ev_dormant, org_id=self.org_a)
        self.assertTrue(any(r['rule_id'] == 'ADMIN-002' for r in res_dorm))

        # 3. ADMIN-003 Off-Hours Admin
        ev_off_hours = {
            'event_id': f"ev-offadmin-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'ADMIN_ACTION',
            'account_id': 'admin_night',
            'attributes': {'local_hour': 2}  # 02:00 Addis Ababa
        }
        res_off = engine.evaluate_event(ev_off_hours, org_id=self.org_a)
        self.assertTrue(any(r['rule_id'] == 'ADMIN-003' for r in res_off))

        # 4. ADMIN-004 Role Elevation
        ev_elev = {
            'event_id': f"ev-elev-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'ROLE_ASSIGNED',
            'account_id': 'admin_rogue',
            'attributes': {'attempted_role': 'superuser', 'dual_approval': False}
        }
        res_elev = engine.evaluate_event(ev_elev, org_id=self.org_a)
        matched_elev = [r for r in res_elev if r['rule_id'] == 'ADMIN-004']
        self.assertEqual(len(matched_elev), 1)

        # 5. ADMIN-005 Audit Tamper
        ev_tamper = {
            'event_id': f"ev-tamper-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'AUDIT_TAMPER_DETECTED',
            'attributes': {'query': 'TRUNCATE TABLE audit_logs;'}
        }
        res_tamper = engine.evaluate_event(ev_tamper, org_id=self.org_a)
        matched_tamper = [r for r in res_tamper if r['rule_id'] == 'ADMIN-005']
        self.assertEqual(len(matched_tamper), 1)
        self.assertEqual(matched_tamper[0]['weight'], 50)

    def test_07_tenant_custom_overrides_across_packs(self):
        """Test tenant threshold overrides on new rules (e.g. FRAUD-001 threshold tuned to 50k ETB)."""
        engine = get_rule_engine()

        # Set Tenant A override for FRAUD-001 to 50,000 ETB
        engine.set_tenant_override(
            org_id=self.org_a,
            rule_id="FRAUD-001",
            is_enabled=True,
            threshold_overrides={'min_amount_etb': 50000.0}
        )

        event_25k = {
            'event_id': 'ev-override-test',
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_TEST_OVERRIDE',
            'amount': 25000.0,
            'currency': 'ETB',
            'attributes': {'rapid_beneficiary_transfer': True}
        }

        # Tenant A: 25k is below 50k threshold -> Should NOT fire
        res_a = engine.evaluate_event(event_25k, org_id=self.org_a)
        self.assertFalse(any(r['rule_id'] == 'FRAUD-001' for r in res_a))

        # Tenant B: Default threshold is 10k -> Should fire
        event_25k_b = dict(event_25k, organization_id=self.org_b)
        res_b = engine.evaluate_event(event_25k_b, org_id=self.org_b)
        self.assertTrue(any(r['rule_id'] == 'FRAUD-001' for r in res_b))

    @patch("app.services.response_policy.evaluate_and_execute_containment")
    @patch("app.services.incident_service.promote_alert_to_incident")
    @patch("app.services.detection_engine.get_service_supabase")
    def test_08_detection_engine_stream_multi_pack_synthesis(self, mock_sb, mock_incident, mock_containment):
        """Test evaluate_event_stream synthesizing multiple rules across packs into an explainable score."""
        event_multi = {
            'event_id': f"ev-multi-{uuid.uuid4().hex[:6]}",
            'organization_id': self.org_a,
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_CRITICAL_CORRELATION',
            'amount': 150000.0,
            'currency': 'ETB',
            'attributes': {
                'rapid_beneficiary_transfer': True,  # FRAUD-001 (+35)
                'sim_swap_recent': True,             # FRAUD-003 (+40)
                # TX-001 fires on 150,000 ETB        # TX-001 (+20)
            }
        }

        eval_res = evaluate_event_stream(event_multi)
        self.assertIn("TX-001", eval_res['rules_fired'])
        self.assertIn("FRAUD-001", eval_res['rules_fired'])
        self.assertIn("FRAUD-003", eval_res['rules_fired'])
        # Total score: 20 + 35 + 40 = 95
        self.assertGreaterEqual(eval_res['risk_score'], 90)
        self.assertEqual(eval_res['severity'], 'critical')
        self.assertTrue(eval_res['is_threat'])


if __name__ == '__main__':
    unittest.main()
