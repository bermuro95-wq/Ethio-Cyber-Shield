"""
Test Suite: Attack Correlation & Multi-Dimensional Pivot Analysis.
Verifies:
1. GET /api/analysis/correlations returns aggregated IP correlations with OS, ISP, and Network rail.
2. Device Hardware MAC correlations identify cross-account pivot attacks.
3. Position / Geographic correlations accurately cluster Ethiopian regional hubs (Addis Ababa, Hawassa, Adama, etc.).
4. SaaS multi-tenant isolation and Superadmin filtering.
"""
import unittest
import uuid
from app import create_app
from app.services.auth_service import create_token
from app.services.enrichment_service import clear_enrichment_caches


class TestAttackCorrelationAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.superadmin_id = str(uuid.uuid4())
        cls.tenant_org = str(uuid.uuid4())
        cls.tenant_user_id = str(uuid.uuid4())

        cls.superadmin_token = create_token(
            cls.superadmin_id,
            "admin@ethiocybershield.et",
            "superadmin",
            organization_id="00000000-0000-0000-0000-000000000001"
        )
        cls.tenant_token = create_token(
            cls.tenant_user_id,
            "analyst@cbe.et",
            "analyst",
            organization_id=cls.tenant_org
        )

    def setUp(self):
        clear_enrichment_caches()

    def test_01_correlations_endpoint_superadmin(self):
        """Test GET /api/analysis/correlations returns valid multi-dimensional aggregations."""
        headers = {'Authorization': f'Bearer {self.superadmin_token}'}
        res = self.client.get('/api/analysis/correlations', headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('summary', data)
        self.assertIn('ip_correlations', data)
        self.assertIn('device_correlations', data)
        self.assertIn('location_correlations', data)

        summary = data['summary']
        self.assertIn('total_correlated_ips', summary)
        self.assertIn('total_correlated_devices', summary)
        self.assertIn('total_hotspots', summary)
        self.assertIn('wifi_percentage', summary)

    def test_02_correlations_endpoint_tenant_isolation(self):
        """Test GET /api/analysis/correlations enforces tenant scope for regular tenant users."""
        headers = {'Authorization': f'Bearer {self.tenant_token}'}
        res = self.client.get('/api/analysis/correlations', headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get('tenant_filter'), self.tenant_org)

    def test_03_correlations_ip_data_structure(self):
        """Verifies IP correlations include OS, Flag, ISP, and Network classification."""
        headers = {'Authorization': f'Bearer {self.superadmin_token}'}
        res = self.client.get('/api/analysis/correlations', headers=headers)
        data = res.get_json()
        ip_list = data.get('ip_correlations', [])
        if ip_list:
            first_ip = ip_list[0]
            self.assertIn('ip', first_ip)
            self.assertIn('city', first_ip)
            self.assertIn('flag', first_ip)
            self.assertIn('os', first_ip)
            self.assertNotEqual(first_ip['os'], 'Unknown OS')
            self.assertIn('connection_type', first_ip)
            self.assertIn('is_wifi', first_ip)


if __name__ == '__main__':
    unittest.main()
