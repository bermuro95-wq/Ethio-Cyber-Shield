"""
Test Suite: Part 19 — Rules as Data, Declarative Engine & Tenant Overrides (Phase 3.1).
Verifies:
1. Declarative Sigma-inspired rule definition parsing (YAML/JSON) with metadata and thresholds.
2. Migration of L1-L3 rules (AUTH-001, AUTH-002, TX-001, IOC-001, AUTH-003, TX-003, ATO-001) into declarative data.
3. Dynamic rule evaluation against event streams and sliding windows.
4. Per-tenant rule overrides (enable/disable, custom thresholds, weight/severity overrides).
5. Rule lifecycle states: 'live' (normal detection), 'shadow' (audit-only without alerting), 'draft'/'backtest' (dormant).
6. Strict multi-tenant isolation across rule configuration and overrides.
7. REST API endpoints for rule management and tenant overrides under /api/rules/*.
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.rule_engine_service import (
    DetectionRule,
    RuleEngine,
    get_rule_engine,
    clear_rule_engine_caches
)
from app.services.event_service import ingest_event


class TestRulesAsData(unittest.TestCase):
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
        clear_rule_engine_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_declarative_rule_loading_and_metadata(self):
        """Test that built-in declarative rules are loaded correctly with Sigma-inspired metadata."""
        engine = get_rule_engine()
        rules = engine.list_rules()
        self.assertGreaterEqual(len(rules), 8)

        rule_ids = [r['id'] for r in rules]
        self.assertIn("AUTH-001", rule_ids)
        self.assertIn("AUTH-002", rule_ids)
        self.assertIn("TX-001", rule_ids)
        self.assertIn("IOC-001", rule_ids)
        self.assertIn("AUTH-003", rule_ids)
        self.assertIn("TX-003", rule_ids)
        self.assertIn("ATO-001", rule_ids)

        # Inspect AUTH-001 metadata
        auth_rule = engine.get_rule("AUTH-001")
        self.assertIsNotNone(auth_rule)
        self.assertEqual(auth_rule['layer'], 'L1')
        self.assertEqual(auth_rule['severity'], 'medium')
        self.assertIn('attack.t1110', auth_rule['tags'])
        self.assertIn('burst_count', auth_rule['thresholds'])

    def test_02_evaluate_l1_auth_001_login_failure_burst(self):
        """Test declarative evaluation of AUTH-001 (Login Failure Burst)."""
        engine = get_rule_engine()
        account_id = f"ACC_TEST_L1_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        # Feed 4 failures -> Should NOT fire yet (threshold is 5)
        for i in range(4):
            fired = engine.evaluate_event({
                'event_id': f"ev-fail-{i}",
                'event_type': 'LOGIN_FAILED',
                'account_id': account_id,
                'occurred_at': now.isoformat(),
                'organization_id': self.org_a,
                'attributes': {'consecutive_failures_for_identifier': i + 1}
            }, org_id=self.org_a)
            self.assertFalse(any(r['rule_id'] == 'AUTH-001' for r in fired))

        # 5th failure -> Should fire AUTH-001
        fired_5th = engine.evaluate_event({
            'event_id': "ev-fail-5",
            'event_type': 'LOGIN_FAILED',
            'account_id': account_id,
            'occurred_at': now.isoformat(),
            'organization_id': self.org_a,
            'attributes': {'consecutive_failures_for_identifier': 5}
        }, org_id=self.org_a)

        matched = [r for r in fired_5th if r['rule_id'] == 'AUTH-001']
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]['severity'], 'medium')
        self.assertEqual(matched[0]['weight'], 25)

    def test_03_evaluate_l1_tx_001_high_value_transfer(self):
        """Test declarative evaluation of TX-001 (High-Value Transfer Anomaly)."""
        engine = get_rule_engine()

        # Transfer under 100,000 ETB -> No detection
        low_transfer = {
            'event_id': 'ev-tx-low',
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_123',
            'amount': 45000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {}
        }
        res_low = engine.evaluate_event(low_transfer, org_id=self.org_a)
        self.assertFalse(any(r['rule_id'] == 'TX-001' for r in res_low))

        # Transfer >= 100,000 ETB -> Fires TX-001
        high_transfer = {
            'event_id': 'ev-tx-high',
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_123',
            'amount': 150000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {}
        }
        res_high = engine.evaluate_event(high_transfer, org_id=self.org_a)
        matched = [r for r in res_high if r['rule_id'] == 'TX-001']
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]['weight'], 20)

    def test_04_tenant_override_disable_rule(self):
        """Test that Tenant A can disable a rule without affecting Tenant B."""
        engine = get_rule_engine()

        # Disable TX-001 for Tenant A
        engine.set_tenant_override(
            org_id=self.org_a,
            rule_id="TX-001",
            is_enabled=False
        )

        test_event = {
            'event_id': 'ev-tx-200k',
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_TX_DISABLE',
            'amount': 200000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {}
        }

        # Evaluate for Tenant A -> Suppressed
        res_a = engine.evaluate_event(test_event, org_id=self.org_a)
        self.assertFalse(any(r['rule_id'] == 'TX-001' for r in res_a))

        # Evaluate same event for Tenant B -> Fires normally
        test_event_b = dict(test_event, organization_id=self.org_b)
        res_b = engine.evaluate_event(test_event_b, org_id=self.org_b)
        self.assertTrue(any(r['rule_id'] == 'TX-001' for r in res_b))

    def test_05_tenant_override_custom_thresholds_and_weights(self):
        """Test that Tenant A can override threshold (e.g. 500k ETB) and weight (+40 pts)."""
        engine = get_rule_engine()

        # Set threshold to 500,000 ETB and weight to 40 for Tenant A
        engine.set_tenant_override(
            org_id=self.org_a,
            rule_id="TX-001",
            is_enabled=True,
            threshold_overrides={'amount_threshold_etb': 500000.0},
            weight_override=40
        )

        # 250,000 ETB transfer -> Under Tenant A's 500k threshold, but over Tenant B's 100k threshold
        event_250k = {
            'event_id': 'ev-tx-250k',
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_THRESH_TEST',
            'amount': 250000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {}
        }

        # Tenant A: should NOT fire
        res_a = engine.evaluate_event(event_250k, org_id=self.org_a)
        self.assertFalse(any(r['rule_id'] == 'TX-001' for r in res_a))

        # 600,000 ETB transfer -> Over Tenant A's threshold
        event_600k = dict(event_250k, amount=600000.0)
        res_a_600k = engine.evaluate_event(event_600k, org_id=self.org_a)
        matched_a = [r for r in res_a_600k if r['rule_id'] == 'TX-001']
        self.assertEqual(len(matched_a), 1)
        # Verify overridden weight of 40 is used
        self.assertEqual(matched_a[0]['weight'], 40)

        # Tenant B: 250k fires with default weight of 20
        event_250k_b = dict(event_250k, organization_id=self.org_b)
        res_b = engine.evaluate_event(event_250k_b, org_id=self.org_b)
        matched_b = [r for r in res_b if r['rule_id'] == 'TX-001']
        self.assertEqual(len(matched_b), 1)
        self.assertEqual(matched_b[0]['weight'], 20)

    def test_06_rule_lifecycle_shadow_mode(self):
        """Test that a rule in shadow mode produces shadow detections without contributing to active containment."""
        engine = get_rule_engine()

        # Set TX-001 to shadow mode for Tenant A
        engine.set_tenant_override(
            org_id=self.org_a,
            rule_id="TX-001",
            lifecycle_state_override="shadow"
        )

        event = {
            'event_id': 'ev-tx-shadow',
            'event_type': 'TRANSFER_CREATED',
            'account_id': 'ACC_SHADOW',
            'amount': 150000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {}
        }

        res = engine.evaluate_event(event, org_id=self.org_a)
        matched = [r for r in res if r['rule_id'] == 'TX-001']
        self.assertEqual(len(matched), 1)
        self.assertTrue(matched[0]['is_shadow'])
        self.assertEqual(matched[0]['lifecycle_state'], 'shadow')

    def test_07_evaluate_l3_ato_001_account_takeover_chain(self):
        """Test declarative evaluation of ATO-001 (Account Takeover Chain)."""
        engine = get_rule_engine()
        account_id = f"ACC_ATO_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        ato_event = {
            'event_id': 'ev-ato-final',
            'event_type': 'TRANSFER_CREATED',
            'account_id': account_id,
            'amount': 250000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': now.isoformat(),
            'attributes': {
                'lab_scenario_id': 'account_takeover',
                'held_for_review': True
            }
        }

        res = engine.evaluate_event(ato_event, org_id=self.org_a)
        matched = [r for r in res if r['rule_id'] == 'ATO-001']
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]['layer'], 'L3')
        self.assertEqual(matched[0]['severity'], 'critical')
        self.assertEqual(matched[0]['weight'], 80)

    def test_08_rest_api_endpoints_and_tenant_isolation(self):
        """Test REST API endpoints for listing rules and configuring per-tenant overrides."""
        headers_a = {"Authorization": f"Bearer {self.token_admin_a}"}
        headers_b = {"Authorization": f"Bearer {self.token_admin_b}"}

        # 1. GET /api/rules (List all rules with effective tenant config)
        resp = self.client.get("/api/rules", headers=headers_a)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(len(data['rules']), 8)

        # 2. GET /api/rules/TX-001
        rule_resp = self.client.get("/api/rules/TX-001", headers=headers_a)
        self.assertEqual(rule_resp.status_code, 200)
        self.assertEqual(rule_resp.get_json()['rule']['id'], "TX-001")

        # 3. PUT /api/rules/TX-001/override (Set tenant override)
        override_payload = {
            "is_enabled": True,
            "threshold_overrides": {"amount_threshold_etb": 350000.0},
            "weight_override": 45,
            "lifecycle_state_override": "live"
        }
        put_resp = self.client.put("/api/rules/TX-001/override", json=override_payload, headers=headers_a)
        self.assertEqual(put_resp.status_code, 200)
        self.assertEqual(put_resp.get_json()['override']['weight_override'], 45)

        # 4. GET /api/rules/TX-001/override
        get_override = self.client.get("/api/rules/TX-001/override", headers=headers_a)
        self.assertEqual(get_override.status_code, 200)
        self.assertEqual(get_override.get_json()['override']['weight_override'], 45)

        # 5. Verify Tenant B sees no override for TX-001
        get_override_b = self.client.get("/api/rules/TX-001/override", headers=headers_b)
        self.assertEqual(get_override_b.status_code, 200)
        self.assertIsNone(get_override_b.get_json()['override'])

        # 6. DELETE /api/rules/TX-001/override (Reset to default)
        del_resp = self.client.delete("/api/rules/TX-001/override", headers=headers_a)
        self.assertEqual(del_resp.status_code, 200)
        get_after_del = self.client.get("/api/rules/TX-001/override", headers=headers_a)
        self.assertIsNone(get_after_del.get_json()['override'])

    def test_09_evaluate_event_stream_integration_with_overrides_and_shadow(self):
        """Test evaluate_event_stream end-to-end integration with tenant overrides and shadow mode."""
        from app.services.detection_engine import evaluate_event_stream
        engine = get_rule_engine()

        # 1. Normal transfer of 150,000 ETB on Tenant A -> fires TX-001, score 20
        event_150k = {
            'event_id': f'ev-stream-150k-{uuid.uuid4().hex[:6]}',
            'event_type': 'TRANSFER_CREATED',
            'account_id': f'ACC_{uuid.uuid4().hex[:6]}',
            'amount': 150000.0,
            'currency': 'ETB',
            'organization_id': self.org_a,
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'attributes': {'local_hour': 12}
        }
        res_live = evaluate_event_stream(event_150k)
        self.assertIn("TX-001", res_live["rules_fired"])
        self.assertEqual(res_live["risk_score"], 20)
        self.assertTrue(res_live["is_threat"])

        # 2. Put TX-001 in shadow mode for Tenant A
        engine.set_tenant_override(
            org_id=self.org_a,
            rule_id="TX-001",
            lifecycle_state_override="shadow"
        )
        res_shadow = evaluate_event_stream(dict(event_150k, event_id=f'ev-stream-shadow-{uuid.uuid4().hex[:6]}'))
        # Appears in fired rules and breakdown as shadow
        self.assertIn("TX-001", res_shadow["rules_fired"])
        self.assertTrue(res_shadow["breakdown"][0]["is_shadow"])
        # But active risk score is 0 and no alert was dispatched
        self.assertEqual(res_shadow["risk_score"], 0)
        self.assertIsNone(res_shadow["alert_id"])
        self.assertFalse(res_shadow["is_threat"])

        # 3. Meanwhile for Tenant B, TX-001 is still live
        event_b = dict(event_150k, organization_id=self.org_b, event_id=f'ev-stream-b-{uuid.uuid4().hex[:6]}')
        res_b = evaluate_event_stream(event_b)
        self.assertIn("TX-001", res_b["rules_fired"])
        self.assertEqual(res_b["risk_score"], 20)
        self.assertFalse(res_b["breakdown"][0]["is_shadow"])
        self.assertTrue(res_b["is_threat"])


if __name__ == '__main__':
    unittest.main()
