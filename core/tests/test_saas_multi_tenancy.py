"""
Unit tests for SaaS Multi-Tenancy Platform Governance in Ethio-Cyber-Shield (ECS).
Validates Superadmin role resolution, tenant provisioning, cross-tenant user CRUD,
target credentials issuance, and tenant-scoped alert boundaries.
"""
import unittest
from unittest.mock import patch, MagicMock
import uuid

from app import create_app
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID
from app.services.tenant_mgmt_service import (
    is_superadmin,
    list_tenants_summary,
    create_tenant,
    update_tenant,
    delete_tenant,
    generate_sdk_snippets,
    slugify
)


class TestSaaSMultiTenancy(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_superadmin_resolution(self):
        # 1. Platform Root Superadmin via email
        self.assertTrue(is_superadmin({'email': 'admin@ethiocybershield.et', 'role': 'admin'}))
        self.assertTrue(is_superadmin({'email': 'admin', 'role': 'admin'}))

        # 2. Superadmin via explicit role
        self.assertTrue(is_superadmin({'email': 'secops@anybank.et', 'role': 'superadmin'}))

        # 3. Superadmin via root tenant admin
        self.assertTrue(is_superadmin({'email': 'ops@cbe.et', 'role': 'admin', 'organization_id': DEFAULT_ORGANIZATION_ID}))

        # 4. Regular Tenant Admin is NOT Superadmin
        tenant_id = str(uuid.uuid4())
        self.assertFalse(is_superadmin({'email': 'admin@awashbank.et', 'role': 'admin', 'organization_id': tenant_id}))

        # 5. Regular Analyst or Viewer is NOT Superadmin
        self.assertFalse(is_superadmin({'email': 'analyst@ethiocybershield.et', 'role': 'analyst', 'organization_id': DEFAULT_ORGANIZATION_ID}))
        self.assertFalse(is_superadmin(None))

    def test_slugify(self):
        self.assertEqual(slugify("Awash Bank SC"), "awash-bank-sc")
        self.assertEqual(slugify("Dashen_Bank #1"), "dashen-bank-1")
        self.assertTrue(len(slugify("")) > 0)

    def test_create_tenant_lifecycle(self):
        tenant_payload = {
            'name': 'Dashen Bank Test',
            'slug': 'dashen-bank-test',
            'sector': 'Finance - Commercial Bank',
            'license_reference': 'NBE/CB/2026/09',
            'admin_email': 'admin@dashenbank-test.et',
            'admin_full_name': 'Dashen SOC Admin',
            'admin_password': 'SecureDashenPassword2026!',
            'target_name': 'Dashen Core Switch',
            'target_base_url': 'https://dashen.bank.et'
        }

        res = create_tenant(tenant_payload, creator_id='00000000-0000-0000-0000-000000000002')
        self.assertIn('tenant', res)
        self.assertIn('admin_user', res)
        self.assertIn('target_system', res)
        self.assertIn('sdk_integration', res)

        tenant = res['tenant']
        self.assertEqual(tenant['name'], 'Dashen Bank Test')
        self.assertEqual(tenant['slug'], 'dashen-bank-test')
        self.assertTrue(tenant['is_active'])

        admin = res['admin_user']
        self.assertEqual(admin['email'], 'admin@dashenbank-test.et')
        self.assertEqual(admin['role'], 'admin')

        target = res['target_system']
        self.assertTrue(target['key_id'].startswith('ecs_dashen-b'))
        self.assertTrue(target['secret_key'].startswith('ecs_sec_'))

        sdk = res['sdk_integration']
        self.assertIn('typescript', sdk)
        self.assertIn('python', sdk)
        self.assertIn('curl', sdk)
        self.assertIn(target['key_id'], sdk['typescript'])
        self.assertIn(target['secret_key'], sdk['typescript'])

    def test_generate_sdk_snippets(self):
        org = {'id': 'test-org-123', 'slug': 'test-bank', 'name': 'Test Bank'}
        target = {'name': 'Test CBS', 'key_id': 'ecs_test_1234'}
        secret = 'ecs_sec_supersecretkey123'

        snippets = generate_sdk_snippets(org, target, secret)
        self.assertIn('typescript', snippets)
        self.assertIn('python', snippets)
        self.assertIn('curl', snippets)
        self.assertIn('ecs_test_1234', snippets['python'])
        self.assertIn('ecs_sec_supersecretkey123', snippets['python'])
        self.assertIn('test-org-123', snippets['typescript'])

    def test_list_tenants_summary_structure(self):
        summaries = list_tenants_summary()
        self.assertIsInstance(summaries, list)
        self.assertTrue(len(summaries) >= 1)

        # Check root tenant structure
        root = summaries[0]
        self.assertIn('id', root)
        self.assertIn('name', root)
        self.assertIn('slug', root)
        self.assertIn('target_systems_count', root)
        self.assertIn('users_count', root)
        self.assertIn('alert_counts', root)
        self.assertIn('health_status', root)

    def test_update_and_delete_tenant(self):
        tenant_payload = {
            'name': 'Wegagen Bank Test',
            'slug': 'wegagen-test',
            'admin_email': 'admin@wegagen-test.et',
            'admin_password': 'WegagenPassword2026!'
        }
        res = create_tenant(tenant_payload)
        tid = res['tenant']['id']

        # Update
        updated = update_tenant(tid, {'name': 'Wegagen Bank Renamed', 'license_reference': 'NBE/WG/01'})
        self.assertEqual(updated['name'], 'Wegagen Bank Renamed')

        # Deactivate
        ok = delete_tenant(tid)
        self.assertTrue(ok)


if __name__ == '__main__':
    unittest.main()
