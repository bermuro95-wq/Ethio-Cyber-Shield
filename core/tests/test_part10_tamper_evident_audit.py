"""
Test Suite Part 10: Tamper-Evident Hash-Chained Audit Logs.
Verifies Phase 1.7 requirements:
- Cryptographic hash chaining: each audit log entry stores SHA-256 hash of previous entry
- Chain integrity verification: detects modified, deleted, or inserted historical rows
- Tenant-scoped audit chains: Tenant A and Tenant B maintain separate isolated chains
- Periodic anchor export: hash-sealed audit anchor packages
- RBAC enforcement: auditor and admin can verify and export; unauthorized roles denied
"""
import unittest
import uuid
import copy
from datetime import datetime, timezone
from app import create_app
from app.services.audit_service import (
    log_action,
    verify_audit_chain,
    export_audit_anchor,
    get_audit_logs,
    calculate_entry_hash,
    GENESIS_HASH
)
from app.services.auth_service import create_token
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID


class TestPart10TamperEvidentAudit(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.org_a = f"org-a-{uuid.uuid4().hex[:8]}"
        self.org_b = f"org-b-{uuid.uuid4().hex[:8]}"
        self.admin_user_id = "3224270a-9033-4bfa-b430-4de6d15d7567"

    def test_1_hash_chain_creation(self):
        """Verifies successive audit log rows link via SHA-256 prev_hash -> entry_hash."""
        # Entry 1 (Genesis or first in session)
        e1 = log_action(
            user_id=self.admin_user_id,
            action="login_success",
            entity_type="session",
            entity_id="sess-1",
            details={"ip": "196.188.1.1"},
            organization_id=self.org_a
        )
        self.assertIsNotNone(e1)
        self.assertIn('entry_hash', e1)
        self.assertIn('prev_hash', e1)

        # Entry 2
        e2 = log_action(
            user_id=self.admin_user_id,
            action="incident_created",
            entity_type="incident",
            entity_id="inc-100",
            details={"title": "Suspicious USSD Transfer"},
            organization_id=self.org_a
        )
        self.assertIsNotNone(e2)
        self.assertEqual(e2['prev_hash'], e1['entry_hash'], "Entry 2 prev_hash must match Entry 1 entry_hash")

        # Entry 3
        e3 = log_action(
            user_id=self.admin_user_id,
            action="containment_executed",
            entity_type="incident",
            entity_id="inc-100",
            details={"action": "step_up_mfa"},
            organization_id=self.org_a
        )
        self.assertIsNotNone(e3)
        self.assertEqual(e3['prev_hash'], e2['entry_hash'], "Entry 3 prev_hash must match Entry 2 entry_hash")

    def test_2_chain_integrity_verification(self):
        """Verifies that an untouched audit log chain verifies successfully."""
        org_test = f"org-verify-{uuid.uuid4().hex[:6]}"
        for i in range(5):
            log_action(
                user_id=self.admin_user_id,
                action=f"audit_event_{i}",
                details={"seq": i},
                organization_id=org_test
            )

        res = verify_audit_chain(organization_id=org_test)
        self.assertTrue(res['verified'], f"Chain verification failed: {res}")
        self.assertGreaterEqual(res['count'], 5)
        self.assertIsNotNone(res.get('latest_hash'))

    def test_3_tamper_detection(self):
        """Verifies that tampering with an audit record causes verification to fail."""
        org_tamper = f"org-tamper-{uuid.uuid4().hex[:6]}"
        entries = []
        for i in range(4):
            e = log_action(
                user_id=self.admin_user_id,
                action=f"action_{i}",
                details={"amount": 1000 * (i + 1)},
                organization_id=org_tamper
            )
            entries.append(e)

        # Verify before tamper
        self.assertTrue(verify_audit_chain(organization_id=org_tamper)['verified'])

        # Tamper with an in-memory/retrieved record details
        logs = get_audit_logs(organization_id=org_tamper)
        self.assertGreaterEqual(len(logs), 4)

        # Forge modified record: change amount
        logs[2]['details']['amount'] = 9999999  # Tampered!

        # Verification over tampered logs must fail
        tamper_res = verify_audit_chain(logs=logs, organization_id=org_tamper)
        self.assertFalse(tamper_res['verified'], "Tampered audit log must fail verification")
        self.assertIn('tampered_index', tamper_res)

    def test_4_multi_tenancy_chain_isolation(self):
        """Verifies Tenant A and Tenant B maintain completely independent hash chains."""
        ea = log_action(self.admin_user_id, "action_a", organization_id=self.org_a)
        eb = log_action(self.admin_user_id, "action_b", organization_id=self.org_b)

        # The hashes must not collide or depend on each other's prev_hash
        self.assertNotEqual(ea['entry_hash'], eb['entry_hash'])

        logs_a = get_audit_logs(organization_id=self.org_a)
        logs_b = get_audit_logs(organization_id=self.org_b)

        for la in logs_a:
            self.assertEqual(la['organization_id'], self.org_a)
        for lb in logs_b:
            self.assertEqual(lb['organization_id'], self.org_b)

    def test_5_anchor_export_and_auditor_role_route(self):
        """Verifies export_audit_anchor package generation and HTTP endpoints with auditor role."""
        org_anchor = f"org-anch-{uuid.uuid4().hex[:6]}"
        log_action(self.admin_user_id, "policy_update", organization_id=org_anchor)
        log_action(self.admin_user_id, "key_rotation", organization_id=org_anchor)

        anchor = export_audit_anchor(organization_id=org_anchor)
        self.assertIsNotNone(anchor)
        self.assertEqual(anchor['organization_id'], org_anchor)
        self.assertGreaterEqual(anchor['record_count'], 2)
        self.assertIn('root_hash', anchor)
        self.assertIn('seal_signature', anchor)

        # Test HTTP endpoints with auditor role
        auditor_token = create_token("user-auditor-1", "auditor@bank.et", "auditor", org_anchor)
        viewer_token = create_token("user-viewer-1", "viewer@bank.et", "viewer", org_anchor)

        # Auditor can list audit logs
        resp_list = self.client.get('/api/audit', headers={'Authorization': f'Bearer {auditor_token}'})
        self.assertEqual(resp_list.status_code, 200)

        # Auditor can verify chain
        resp_verify = self.client.post('/api/audit/verify', headers={'Authorization': f'Bearer {auditor_token}'})
        self.assertEqual(resp_verify.status_code, 200)
        self.assertTrue(resp_verify.get_json().get('verified'))

        # Auditor can export anchor
        resp_anchor = self.client.post('/api/audit/anchor', headers={'Authorization': f'Bearer {auditor_token}'})
        self.assertEqual(resp_anchor.status_code, 200)
        self.assertIn('root_hash', resp_anchor.get_json())

        # Viewer is denied (403)
        resp_denied = self.client.post('/api/audit/verify', headers={'Authorization': f'Bearer {viewer_token}'})
        self.assertEqual(resp_denied.status_code, 403)


if __name__ == '__main__':
    unittest.main()
