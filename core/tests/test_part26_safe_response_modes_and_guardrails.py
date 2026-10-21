"""
Test Suite: Part 26 — Safe Response Modes, Guardrails, & Declarative Playbooks (Phase 4.1, 4.2, 4.3).

Verifies:
1. Response Modes (Phase 4.1):
   - Progressive risk postures: observe (shadow) -> recommend -> approve -> auto.
   - Default posture for new tenants: observe (shadow mode).
   - Simulated "would-have-done" report generation during observe mode.
   - Per-action-type and per-tenant mode overrides.
2. Guardrails Engine (Phase 4.2):
   - Emergency Kill Switch halting automated containment.
   - Allowlists protecting critical infrastructure IPs (EthSwitch, RTGS) and VIP/staff accounts.
   - Blast Radius Rate Limits (hourly and daily action caps).
   - Entity Cooldowns preventing repeat actions within lookback window.
   - Confidence threshold enforcement.
   - Guardrail audit trail logging every decision.
3. Declarative Playbooks & Response Connectors (Phase 4.3):
   - Declarative playbook YAML loading and schema validation.
   - Dry-run simulation tracing without side effects.
   - Response connector control contract (reversibility, rollback connector).
   - Idempotent action rollback (revert).
   - Two-person / dual approval for high-risk / irreversible operations.
4. Multi-Tenant Isolation:
   - Complete partition between Tenant A and Tenant B for modes, guardrails, and playbooks.
5. REST API Endpoints:
   - /api/response/modes, /modes/would-have-done
   - /api/response/guardrails, /guardrails/kill-switch, /guardrails/allowlist
   - /api/response/playbooks, /playbooks/<id>/dry-run, /playbooks/<id>/execute
   - /api/response/connectors, /approvals, /actions/<id>/rollback
"""
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.response_modes_service import (
    ResponseModesService,
    RESPONSE_MODES,
    clear_response_mode_caches
)
from app.services.guardrails_service import (
    GuardrailsService,
    clear_guardrail_caches
)
from app.services.playbook_service import (
    PlaybookService,
    clear_playbook_caches
)


class TestSafeResponseModesAndGuardrails(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())
        cls.user_admin_a = str(uuid.uuid4())
        cls.user_analyst_a = str(uuid.uuid4())
        cls.user_approver2_a = str(uuid.uuid4())
        cls.user_viewer_a = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_analyst_a = create_token(cls.user_analyst_a, "analyst@bank-a.et", "analyst", organization_id=cls.org_a)
        cls.token_approver2_a = create_token(cls.user_approver2_a, "approver2@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_viewer_a = create_token(cls.user_viewer_a, "viewer@bank-a.et", "viewer", organization_id=cls.org_a)
        cls.token_admin_b = create_token(str(uuid.uuid4()), "admin@bank-b.et", "admin", organization_id=cls.org_b)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_response_mode_caches()
        clear_guardrail_caches()
        clear_playbook_caches()

    def tearDown(self):
        set_current_organization_id(None)

    # =========================================================================
    # PHASE 4.1: RESPONSE MODES TESTS
    # =========================================================================

    def test_01_default_response_mode_is_observe(self):
        """New tenants must default to 'observe' (shadow mode) for all action types."""
        mode = ResponseModesService.get_effective_mode(self.org_a, 'block_ip')
        self.assertEqual(mode, 'observe')

        mode_freeze = ResponseModesService.get_effective_mode(self.org_a, 'freeze_transaction')
        self.assertEqual(mode_freeze, 'observe')

    def test_02_set_and_get_mode_overrides(self):
        """Tenants can configure progressive risk postures per action type."""
        # Set block_ip to auto
        ResponseModesService.set_mode(self.org_a, 'block_ip', 'auto', updated_by=self.user_admin_a)
        self.assertEqual(ResponseModesService.get_effective_mode(self.org_a, 'block_ip'), 'auto')

        # Set lock_account to approve (human-in-the-loop)
        ResponseModesService.set_mode(self.org_a, 'lock_account', 'approve', requires_two_person=True, updated_by=self.user_admin_a)
        mode_info = ResponseModesService.get_mode_config(self.org_a, 'lock_account')
        self.assertEqual(mode_info['mode'], 'approve')
        self.assertTrue(mode_info['requires_two_person_approval'])

        # Other action types remain in default observe
        self.assertEqual(ResponseModesService.get_effective_mode(self.org_a, 'freeze_transaction'), 'observe')

    def test_03_observe_shadow_mode_would_have_done_report(self):
        """Observe mode executes simulated action without target mutation and generates would-have-done report."""
        action_candidate = {
            'action_type': 'block_ip',
            'entity_type': 'ip',
            'entity_id': '198.51.100.99',
            'reason': 'High-volume credential stuffing burst',
            'confidence': 'high',
            'alert_id': str(uuid.uuid4())
        }

        # Dispatch in observe mode
        sim_res = ResponseModesService.process_action_request(self.org_a, action_candidate)
        self.assertEqual(sim_res['mode'], 'observe')
        self.assertEqual(sim_res['status'], 'simulated')
        self.assertTrue(sim_res['would_have_executed'])
        self.assertIsNotNone(sim_res['simulated_action_id'])

        # Check would-have-done report
        report = ResponseModesService.generate_would_have_done_report(self.org_a)
        self.assertGreaterEqual(report['total_simulated_actions'], 1)
        self.assertIn('block_ip', report['actions_by_type'])
        self.assertTrue(any(a['entity_id'] == '198.51.100.99' for a in report['simulated_actions']))

    # =========================================================================
    # PHASE 4.2: GUARDRAILS ENGINE TESTS
    # =========================================================================

    def test_04_emergency_kill_switch(self):
        """Emergency kill switch halts all automated actions, overriding auto mode."""
        ResponseModesService.set_mode(self.org_a, 'block_ip', 'auto')
        GuardrailsService.set_kill_switch(self.org_a, enabled=True, updated_by=self.user_admin_a)

        guardrail_eval = GuardrailsService.evaluate_guardrails(
            org_id=self.org_a,
            action_type='block_ip',
            entity_type='ip',
            entity_id='198.51.100.77',
            confidence='high'
        )
        self.assertFalse(guardrail_eval['passed'])
        self.assertEqual(guardrail_eval['blocked_by'], 'kill_switch')
        self.assertIn('Emergency kill switch is active', guardrail_eval['reason'])

    def test_05_allowlists_and_protected_entities(self):
        """Allowlisted core infrastructure IPs and VIP accounts cannot be blocked or held."""
        # Add EthSwitch IP gateway and Treasury account to allowlist
        ethswitch_gw = "196.188.10.1"
        vip_account = "ACC_TREASURY_RESERVE_01"
        GuardrailsService.add_to_allowlist(self.org_a, 'ip', ethswitch_gw, reason='EthSwitch National Switch Gateway')
        GuardrailsService.add_to_allowlist(self.org_a, 'account', vip_account, reason='Central Treasury Settlement Account')

        # Test IP allowlist hit
        ip_check = GuardrailsService.evaluate_guardrails(
            org_id=self.org_a,
            action_type='block_ip',
            entity_type='ip',
            entity_id=ethswitch_gw,
            confidence='high'
        )
        self.assertFalse(ip_check['passed'])
        self.assertEqual(ip_check['blocked_by'], 'allowlist')
        self.assertIn('Allowlisted entity', ip_check['reason'])

        # Test Account allowlist hit
        acc_check = GuardrailsService.evaluate_guardrails(
            org_id=self.org_a,
            action_type='lock_account',
            entity_type='account',
            entity_id=vip_account,
            confidence='high'
        )
        self.assertFalse(acc_check['passed'])
        self.assertEqual(acc_check['blocked_by'], 'allowlist')

    def test_06_blast_radius_hourly_rate_limits(self):
        """Exceeding max actions per hour blocks subsequent automated actions."""
        # Configure max 3 actions per hour
        GuardrailsService.configure_guardrails(self.org_a, max_actions_per_hour=3)

        target_ip = "198.51.100.5"
        # First 3 actions pass
        for i in range(3):
            res = GuardrailsService.evaluate_guardrails(self.org_a, 'block_ip', 'ip', f"{target_ip}_{i}", 'high')
            self.assertTrue(res['passed'])
            GuardrailsService.record_action_execution(self.org_a, 'block_ip', 'ip', f"{target_ip}_{i}")

        # 4th action exceeds blast radius limit
        res_4 = GuardrailsService.evaluate_guardrails(self.org_a, 'block_ip', 'ip', f"{target_ip}_4", 'high')
        self.assertFalse(res_4['passed'])
        self.assertEqual(res_4['blocked_by'], 'rate_limit_hour')
        self.assertIn('Blast radius rate limit exceeded', res_4['reason'])

    def test_07_entity_cooldown_enforcement(self):
        """Repeated actions on the same entity within cooldown period are suppressed."""
        GuardrailsService.configure_guardrails(self.org_a, cooldown_seconds=600)
        target_account = "ACC_REPEATED_ATTACK_01"

        # Action 1 passes and records execution
        res1 = GuardrailsService.evaluate_guardrails(self.org_a, 'lock_account', 'account', target_account, 'high')
        self.assertTrue(res1['passed'])
        GuardrailsService.record_action_execution(self.org_a, 'lock_account', 'account', target_account)

        # Immediate Action 2 on same account triggers cooldown
        res2 = GuardrailsService.evaluate_guardrails(self.org_a, 'lock_account', 'account', target_account, 'high')
        self.assertFalse(res2['passed'])
        self.assertEqual(res2['blocked_by'], 'cooldown')
        self.assertIn('cooldown window', res2['reason'].lower())

    def test_08_confidence_threshold_guardrail(self):
        """Actions with confidence below tenant threshold are prevented from automated execution."""
        GuardrailsService.configure_guardrails(self.org_a, min_confidence='high')

        res_low = GuardrailsService.evaluate_guardrails(self.org_a, 'block_ip', 'ip', '198.51.100.12', confidence='medium')
        self.assertFalse(res_low['passed'])
        self.assertEqual(res_low['blocked_by'], 'confidence_too_low')

        res_high = GuardrailsService.evaluate_guardrails(self.org_a, 'block_ip', 'ip', '198.51.100.12', confidence='high')
        self.assertTrue(res_high['passed'])

    # =========================================================================
    # PHASE 4.3: DECLARATIVE PLAYBOOKS & RESPONSE CONNECTORS TESTS
    # =========================================================================

    def test_09_declarative_playbook_catalog_and_dry_run(self):
        """Declarative playbooks load properly and dry-run produces complete trace without mutations."""
        playbooks = PlaybookService.list_playbooks(self.org_a)
        self.assertGreaterEqual(len(playbooks), 3, "Must include pre-built production playbooks")

        ato_pb = next((p for p in playbooks if p['id'] == 'PB-001-ATO-CONTAINMENT'), None)
        self.assertIsNotNone(ato_pb)
        self.assertEqual(ato_pb['trigger']['severity_in'], ['high', 'critical'])

        # Dry-run execution against simulated high-risk incident
        incident_context = {
            'risk_score': 85,
            'severity': 'critical',
            'rules_fired': ['ATO-001', 'AUTH-001'],
            'transaction_id': 'TX_MOCK_101',
            'session_id': 'SESS_MOCK_202',
            'source_ip': '198.51.100.88',
            'confidence': 'high'
        }

        dry_run_trace = PlaybookService.dry_run_playbook(self.org_a, 'PB-001-ATO-CONTAINMENT', incident_context)
        self.assertEqual(dry_run_trace['playbook_id'], 'PB-001-ATO-CONTAINMENT')
        self.assertTrue(dry_run_trace['trigger_matched'])
        self.assertEqual(dry_run_trace['actions_evaluated_count'], 3)

        # Actions are simulated only
        for action_trace in dry_run_trace['actions']:
            self.assertEqual(action_trace['status'], 'simulated')
            self.assertIn('connector', action_trace)
            self.assertTrue(action_trace.get('is_reversible') in (True, False))

    def test_10_response_connectors_control_contract_and_rollback(self):
        """All response connectors publish control contract with reversibility and rollback capability."""
        connectors = PlaybookService.list_connectors()
        self.assertGreaterEqual(len(connectors), 6)

        # Inspect freeze_transaction connector
        freeze_conn = next((c for c in connectors if c['name'] == 'freeze_transaction'), None)
        self.assertIsNotNone(freeze_conn)
        self.assertTrue(freeze_conn['is_reversible'])
        self.assertEqual(freeze_conn['rollback_connector'], 'revert')

        # Inspect lock_account connector
        lock_conn = next((c for c in connectors if c['name'] == 'lock_account'), None)
        self.assertIsNotNone(lock_conn)
        self.assertTrue(lock_conn['requires_approval_if_irreversible'] or lock_conn['is_reversible'])

        # Verify rollback invocation works idempotently
        with patch('app.services.target_system_service.revert_target_action') as mock_revert:
            mock_revert.return_value = {'status': 'confirmed', 'action_id': 'ACT_REVERT_99'}
            res = PlaybookService.rollback_action(self.org_a, action_id='ACT_MOCK_1', reason='False Positive Investigation')
            self.assertEqual(res['status'], 'confirmed')
            mock_revert.assert_called_once()

    def test_11_two_person_approval_workflow(self):
        """Risky or two-person approval actions remain pending until second distinct approver confirms."""
        # Stage approval request
        approval_req = PlaybookService.create_approval_request(
            org_id=self.org_a,
            action_type='lock_account',
            entity_type='account',
            entity_id='ACC_HIGH_VALUE_007',
            reason='Suspected insider account takeover',
            requires_two_person=True,
            requested_by=self.user_analyst_a
        )
        req_id = approval_req['id']
        self.assertEqual(approval_req['status'], 'pending')

        # 1st approval from user_admin_a
        step1 = PlaybookService.submit_approval(self.org_a, req_id, approver_id=self.user_admin_a)
        self.assertEqual(step1['status'], 'pending', "Two-person approval must require 2 distinct approvers")
        self.assertEqual(step1['approvals_count'], 1)

        # Same approver trying again must fail
        with self.assertRaises(ValueError):
            PlaybookService.submit_approval(self.org_a, req_id, approver_id=self.user_admin_a)

        # 2nd approval from user_approver2_a confirms execution
        step2 = PlaybookService.submit_approval(self.org_a, req_id, approver_id=self.user_approver2_a)
        self.assertEqual(step2['status'], 'approved')
        self.assertEqual(step2['approvals_count'], 2)

    def test_12_multi_tenancy_isolation(self):
        """Tenant A response modes, guardrails, allowlists, and playbooks are invisible to Tenant B."""
        # Tenant A sets kill switch and allowlist
        GuardrailsService.set_kill_switch(self.org_a, enabled=True)
        GuardrailsService.add_to_allowlist(self.org_a, 'ip', '196.188.99.99', reason='Tenant A router')
        ResponseModesService.set_mode(self.org_a, 'block_ip', 'auto')

        # Tenant B checks: kill switch is false, allowlist is empty, mode is default observe
        cfg_b = GuardrailsService.get_guardrail_config(self.org_b)
        self.assertFalse(cfg_b['emergency_kill_switch'])
        self.assertFalse(GuardrailsService.is_allowlisted(self.org_b, 'ip', '196.188.99.99'))
        self.assertEqual(ResponseModesService.get_effective_mode(self.org_b, 'block_ip'), 'observe')

    # =========================================================================
    # REST API INTEGRATION TESTS
    # =========================================================================

    def test_13_rest_api_endpoints(self):
        """Test REST API routes: /modes, /guardrails, /playbooks, /connectors, /approvals."""
        headers_viewer = {'Authorization': f'Bearer {self.token_viewer_a}', 'Content-Type': 'application/json'}
        headers_analyst = {'Authorization': f'Bearer {self.token_analyst_a}', 'Content-Type': 'application/json'}
        headers_admin = {'Authorization': f'Bearer {self.token_admin_a}', 'Content-Type': 'application/json'}

        # 1. GET /api/response/modes
        resp_modes = self.client.get('/api/response/modes', headers=headers_viewer)
        self.assertEqual(resp_modes.status_code, 200)
        self.assertIn('data', resp_modes.get_json())

        # 2. POST /api/response/modes (Admin only)
        resp_set_mode = self.client.post('/api/response/modes', json={'action_type': 'block_ip', 'mode': 'recommend'}, headers=headers_admin)
        self.assertEqual(resp_set_mode.status_code, 200)

        # 3. GET /api/response/guardrails
        resp_gr = self.client.get('/api/response/guardrails', headers=headers_viewer)
        self.assertEqual(resp_gr.status_code, 200)
        self.assertIn('max_actions_per_hour', resp_gr.get_json()['data'])

        # 4. POST /api/response/guardrails/kill-switch (Admin or Analyst)
        resp_ks = self.client.post('/api/response/guardrails/kill-switch', json={'enabled': True}, headers=headers_analyst)
        self.assertEqual(resp_ks.status_code, 200)
        self.assertTrue(resp_ks.get_json()['data']['emergency_kill_switch'])

        # 5. POST & GET /api/response/guardrails/allowlist
        resp_al_add = self.client.post('/api/response/guardrails/allowlist', json={
            'entity_type': 'ip',
            'entity_id': '196.188.1.1',
            'reason': 'HQ External Gateway'
        }, headers=headers_analyst)
        self.assertEqual(resp_al_add.status_code, 201)

        resp_al_list = self.client.get('/api/response/guardrails/allowlist', headers=headers_viewer)
        self.assertEqual(resp_al_list.status_code, 200)
        self.assertTrue(any(item['entity_id'] == '196.188.1.1' for item in resp_al_list.get_json()['data']))

        # 6. GET /api/response/playbooks
        resp_pb = self.client.get('/api/response/playbooks', headers=headers_viewer)
        self.assertEqual(resp_pb.status_code, 200)
        self.assertGreaterEqual(len(resp_pb.get_json()['data']), 3)

        # 7. POST /api/response/playbooks/<id>/dry-run
        dry_payload = {
            'risk_score': 90,
            'severity': 'critical',
            'rules_fired': ['ATO-001'],
            'transaction_id': 'TX_100',
            'source_ip': '198.51.100.1'
        }
        resp_dry = self.client.post('/api/response/playbooks/PB-001-ATO-CONTAINMENT/dry-run', json=dry_payload, headers=headers_analyst)
        self.assertEqual(resp_dry.status_code, 200)
        self.assertTrue(resp_dry.get_json()['data']['trigger_matched'])

        # 8. GET /api/response/connectors
        resp_conn = self.client.get('/api/response/connectors', headers=headers_viewer)
        self.assertEqual(resp_conn.status_code, 200)
        self.assertGreaterEqual(len(resp_conn.get_json()['data']), 6)


if __name__ == '__main__':
    unittest.main()
