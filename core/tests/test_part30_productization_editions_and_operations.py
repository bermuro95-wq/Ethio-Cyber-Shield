"""
Test Suite: Part 30 — Productization, Packaging, Executive Metrics, and Operations (Phase 7).

Verifies:
1. Product Editions & Feature Entitlements (Phase 7.1):
   - 4 distinct tiers: Community, Pro / Financial Operator, Managed, Sector Hub.
   - Feature gating (is_feature_enabled) accurately isolates Community vs Pro/Managed/Hub.
   - REST endpoints: GET /api/settings/editions, PUT /api/settings/editions.
2. Executive & Operational Metrics (Phase 7.3):
   - MTTD, MTTA, MTTC, MTTR computation.
   - Total ETB volume protected calculation.
   - 48-Hour Statutory Compliance adherence rate under Proclamation No. 1426/2026.
   - Alert fatigue & noise reduction ratio.
   - Low-Bandwidth Mode optimization (<1 KB compact representation) for rural branches.
   - REST endpoint: GET /api/dashboard/executive (standard and low_bandwidth).
3. Multilingual Terminology Service (Phase 7.4):
   - Localized cybersecurity terms across English ('en'), Amharic ('am'), and Afaan Oromo ('om').
   - REST endpoint: GET /api/settings/i18n.
4. Governance, Open-Source & Operational Assets (Phase 7.2 & 7.5):
   - Verification of LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md.
   - Verification of docs/ROADMAP.md, docs/SUPPORT_MODEL.md, docs/OPERATIONS_RUNBOOK.md, docs/PILOT_ONBOARDING.md.
   - Strict enforcement of Rule #6: Disclaimers and "supports evidence for" language.
5. Multi-Tenancy Isolation:
   - Tenant A edition and metrics cannot leak into or mutate Tenant B.
"""
import os
import unittest
import json
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.editions_service import (
    EditionsService,
    clear_editions_caches,
    EDITIONS
)
from app.services.metrics_service import (
    MetricsService,
    clear_metrics_caches
)
from app.services.i18n_service import (
    I18nService,
    SUPPORTED_LANGUAGES,
    GLOSSARY
)
from app.services.case_service import clear_case_caches, _LOCAL_INCIDENTS


class TestProductizationEditionsAndOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.tenant_a = "11111111-1111-1111-1111-111111111111"  # Commercial Bank of Ethiopia
        cls.tenant_b = "22222222-2222-2222-2222-222222222222"  # Dashen Bank

        cls.user_a_admin = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        cls.token_a_admin = create_token(
            cls.user_a_admin,
            'admin@cbe.com.et',
            'admin',
            organization_id=cls.tenant_a
        )

        cls.user_a_analyst = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        cls.token_a_analyst = create_token(
            cls.user_a_analyst,
            'analyst@cbe.com.et',
            'analyst',
            organization_id=cls.tenant_a
        )

        cls.user_b_admin = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        cls.token_b_admin = create_token(
            cls.user_b_admin,
            'admin@dashenbanksc.com',
            'admin',
            organization_id=cls.tenant_b
        )

    def setUp(self):
        clear_editions_caches()
        clear_metrics_caches()
        clear_case_caches()
        set_current_organization_id(self.tenant_a)

    # =========================================================================
    # 1. EDITIONS & FEATURE ENTITLEMENTS (PHASE 7.1)
    # =========================================================================

    def test_01_list_editions_and_structure(self):
        """Verifies all four distinct editions are defined with correct feature sets."""
        editions = EditionsService.list_editions()
        self.assertEqual(len(editions), 4)

        edition_ids = [e['id'] for e in editions]
        self.assertIn('community', edition_ids)
        self.assertIn('pro', edition_ids)
        self.assertIn('managed', edition_ids)
        self.assertIn('sector_hub', edition_ids)

        comm = EditionsService.get_edition_details('community')
        self.assertIn('core_detection_engine', comm['features'])
        self.assertIn('basic_payment_fraud_pack', comm['features'])
        self.assertNotIn('evidence_vault_sha256', comm['features'])
        self.assertNotIn('readiness_engine_48h_clock', comm['features'])

        pro = EditionsService.get_edition_details('pro')
        self.assertIn('evidence_vault_sha256', pro['features'])
        self.assertIn('readiness_engine_48h_clock', pro['features'])
        self.assertIn('advanced_ethiopian_fraud_pack', pro['features'])

    def test_02_feature_entitlement_gating(self):
        """Verifies feature gating accurately allows/denies features based on tenant edition."""
        # Tenant A set to community
        EditionsService.set_tenant_edition(self.tenant_a, 'community')
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'core_detection_engine'))
        self.assertFalse(EditionsService.is_feature_enabled(self.tenant_a, 'evidence_vault_sha256'))
        self.assertFalse(EditionsService.is_feature_enabled(self.tenant_a, 'readiness_engine_48h_clock'))

        # Upgrade Tenant A to pro
        EditionsService.set_tenant_edition(self.tenant_a, 'pro')
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'evidence_vault_sha256'))
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'readiness_engine_48h_clock'))
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'safe_response_modes'))

        # Managed and Sector Hub inherit pro features
        EditionsService.set_tenant_edition(self.tenant_a, 'managed')
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'evidence_vault_sha256'))
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'managed_rule_tuning'))

        EditionsService.set_tenant_edition(self.tenant_a, 'sector_hub')
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'evidence_vault_sha256'))
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'signal_exchange_hub'))

    def test_03_editions_rest_api(self):
        """Verifies GET /api/settings/editions and PUT /api/settings/editions endpoints."""
        # GET editions
        res = self.client.get(
            '/api/settings/editions',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('available_editions', data)
        self.assertIn('current_edition', data)
        self.assertEqual(data['organization_id'], self.tenant_a)

        # PUT edition change (as admin)
        res = self.client.put(
            '/api/settings/editions',
            headers={'Authorization': f'Bearer {self.token_a_admin}'},
            json={'edition': 'sector_hub'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['edition']['id'], 'sector_hub')

        # Verify invalid edition rejected
        res = self.client.put(
            '/api/settings/editions',
            headers={'Authorization': f'Bearer {self.token_a_admin}'},
            json={'edition': 'enterprise_ultra_invalid'}
        )
        self.assertEqual(res.status_code, 400)

    # =========================================================================
    # 2. EXECUTIVE METRICS & LOW-BANDWIDTH MODE (PHASE 7.3)
    # =========================================================================

    def test_04_executive_metrics_computation(self):
        """Verifies MTTD, MTTA, MTTC, MTTR, and ETB financial volume protected calculations."""
        now = datetime.now(timezone.utc)

        # Seed test incidents for Tenant A
        _LOCAL_INCIDENTS['inc-101'] = {
            'id': 'inc-101',
            'organization_id': self.tenant_a,
            'incident_date': (now - timedelta(minutes=45)).isoformat(),
            'created_at': (now - timedelta(minutes=43)).isoformat(),
            'detection_date': (now - timedelta(minutes=42)).isoformat(),
            'acknowledged_at': (now - timedelta(minutes=35)).isoformat(),
            'contained_at': (now - timedelta(minutes=20)).isoformat(),
            'resolved_at': (now - timedelta(minutes=5)).isoformat(),
            'status': 'resolved',
            'severity': 'high',
            'financial_impact_etb': 2500000.0,
            'is_reportable_48h': True,
            'reported_to_cert_at': (now - timedelta(minutes=10)).isoformat()
        }

        # Seed additional financial protection volume
        MetricsService.record_financial_protection(
            self.tenant_a,
            amount_etb=15000000.0,
            reason="Blocked automated USSD mule drain"
        )

        metrics = MetricsService.get_executive_metrics(self.tenant_a, low_bandwidth=False, now=now)
        self.assertEqual(metrics['mode'], 'standard_executive')
        self.assertEqual(metrics['organization_id'], self.tenant_a)

        # Verify time metrics
        kpis = metrics['kpis']
        self.assertGreater(kpis['mttd_minutes'], 0)
        self.assertGreater(kpis['mtta_minutes'], 0)
        self.assertGreater(kpis['mttc_minutes'], 0)
        self.assertGreater(kpis['mttr_minutes'], 0)

        # Total ETB protected (2.5M + 15M = 17.5M)
        self.assertEqual(kpis['financial_volume_protected_etb'], 17500000.0)
        self.assertIn("ETB 17,500,000.00", kpis['financial_volume_protected_formatted'])

        # 48h statutory compliance rate
        self.assertEqual(kpis['statutory_48h_compliance_pct'], 100.0)
        self.assertEqual(metrics['statutory_compliance']['total_reportable_cases'], 1)
        self.assertEqual(metrics['statutory_compliance']['submitted_on_time'], 1)

    def test_05_low_bandwidth_mode_payload_size(self):
        """Verifies low-bandwidth mode strips verbose fields and returns compact payload < 1KB."""
        # Record some metrics
        MetricsService.record_financial_protection(self.tenant_a, amount_etb=500000.0)

        # Request low-bandwidth via service
        compact = MetricsService.get_executive_metrics(self.tenant_a, low_bandwidth=True)
        self.assertEqual(compact['mode'], 'compact_low_bandwidth')
        self.assertIn('kpis', compact)
        self.assertIn('counts', compact)
        self.assertNotIn('noise_suppression', compact)
        self.assertNotIn('operational_context', compact)

        payload_bytes = json.dumps(compact).encode('utf-8')
        # Hard constraint: Payload must be under 1,024 bytes
        self.assertLess(len(payload_bytes), 1024, f"Payload size {len(payload_bytes)} bytes exceeds 1KB limit")

        # Request low-bandwidth via REST API endpoint
        res = self.client.get(
            '/api/dashboard/executive?low_bandwidth=true',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        api_data = res.get_json()
        self.assertEqual(api_data['mode'], 'compact_low_bandwidth')
        self.assertIn('mttd_min', api_data['kpis'])
        self.assertIn('etb_protected', api_data['kpis'])

    def test_06_statutory_compliance_rate_with_breach(self):
        """Verifies compliance rate drops when an unsubmitted incident exceeds 48 hours."""
        now = datetime.now(timezone.utc)

        # Incident 1: Reported on time
        _LOCAL_INCIDENTS['inc-ontime'] = {
            'id': 'inc-ontime',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=30)).isoformat(),
            'reported_to_cert_at': (now - timedelta(hours=5)).isoformat(),
            'is_reportable_48h': True,
            'status': 'contained'
        }

        # Incident 2: Breached (55 hours elapsed, not reported)
        _LOCAL_INCIDENTS['inc-breached'] = {
            'id': 'inc-breached',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=55)).isoformat(),
            'reported_to_cert_at': None,
            'is_reportable_48h': True,
            'status': 'investigating'
        }

        metrics = MetricsService.get_executive_metrics(self.tenant_a, low_bandwidth=False, now=now)
        compliance = metrics['statutory_compliance']
        self.assertEqual(compliance['total_reportable_cases'], 2)
        self.assertEqual(compliance['submitted_on_time'], 1)
        self.assertEqual(compliance['breached'], 1)
        # 1 out of 2 compliant = 50.0%
        self.assertEqual(compliance['adherence_rate_pct'], 50.0)

    # =========================================================================
    # 3. MULTILINGUAL CONTEXT (i18n) (PHASE 7.4)
    # =========================================================================

    def test_07_multilingual_glossary_and_translations(self):
        """Verifies translations across English, Amharic, and Afaan Oromo."""
        languages = I18nService.list_languages()
        self.assertEqual(len(languages), 3)
        lang_codes = [l['code'] for l in languages]
        self.assertIn('en', lang_codes)
        self.assertIn('am', lang_codes)
        self.assertIn('om', lang_codes)

        # Account Takeover
        self.assertEqual(I18nService.translate('account_takeover', 'en'), 'Account Takeover')
        self.assertEqual(I18nService.translate('account_takeover', 'am'), 'የሂሳብ ቁጥጥር ስርቆት')
        self.assertEqual(I18nService.translate('account_takeover', 'om'), 'Herrega Dhuunfaa Qabachuu')

        # Evidence Vault
        self.assertEqual(I18nService.translate('evidence_vault', 'en'), 'Evidence Vault')
        self.assertEqual(I18nService.translate('evidence_vault', 'am'), 'የማስረጃ ማከማቻ')
        self.assertEqual(I18nService.translate('evidence_vault', 'om'), 'Kuusaa Ragaa')

        # Emergency Kill Switch
        self.assertEqual(I18nService.translate('emergency_kill_switch', 'en'), 'Emergency Kill Switch')
        self.assertEqual(I18nService.translate('emergency_kill_switch', 'am'), 'የአደጋ ጊዜ ድንገተኛ ማቆሚያ')
        self.assertEqual(I18nService.translate('emergency_kill_switch', 'om'), 'Cufaa Balaa Hatattamaa')

        # Localize incident card summary
        summary_am = I18nService.localize_incident_summary(
            incident_type='account_takeover',
            severity='critical',
            status='contained',
            lang='am'
        )
        self.assertEqual(summary_am['incident_type'], 'የሂሳብ ቁጥጥር ስርቆት')
        self.assertEqual(summary_am['severity'], 'እጅግ አሳሳቢ ክብደት')
        self.assertEqual(summary_am['status'], 'ቁጥጥር ስር የዋለ')

    def test_08_i18n_rest_api(self):
        """Verifies GET /api/settings/i18n returns translations accurately."""
        # Query Amharic
        res = self.client.get(
            '/api/settings/i18n?lang=am',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['active_language'], 'am')
        self.assertEqual(data['translations']['account_takeover'], 'የሂሳብ ቁጥጥር ስርቆት')

        # Query Afaan Oromo
        res = self.client.get(
            '/api/settings/i18n?lang=om',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['active_language'], 'om')
        self.assertEqual(data['translations']['account_takeover'], 'Herrega Dhuunfaa Qabachuu')

    # =========================================================================
    # 4. GOVERNANCE & OPERATIONAL ASSETS (PHASE 7.2 & 7.5)
    # =========================================================================

    def test_09_governance_and_runbook_files_exist(self):
        """Verifies existence, content, and Rule #6 compliance of governance assets."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

        required_files = [
            'LICENSE',
            'CONTRIBUTING.md',
            'CODE_OF_CONDUCT.md',
            'docs/ROADMAP.md',
            'docs/SUPPORT_MODEL.md',
            'docs/OPERATIONS_RUNBOOK.md',
            'docs/PILOT_ONBOARDING.md'
        ]

        for rel_path in required_files:
            full_path = os.path.join(repo_root, rel_path)
            self.assertTrue(os.path.exists(full_path), f"File {rel_path} does not exist")
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertGreater(len(content), 100, f"File {rel_path} is unexpectedly small")

        # Verify Apache-2.0 in LICENSE
        with open(os.path.join(repo_root, 'LICENSE'), 'r') as f:
            lic = f.read()
        self.assertIn("Apache License", lic)
        self.assertIn("Version 2.0", lic)

        # Verify Rule #6 disclaimer in SUPPORT_MODEL.md
        with open(os.path.join(repo_root, 'docs/SUPPORT_MODEL.md'), 'r') as f:
            sup = f.read()
        self.assertIn("supports evidence for", sup)
        self.assertIn("guarantee", sup)

    # =========================================================================
    # 5. MULTI-TENANT ISOLATION
    # =========================================================================

    def test_10_multitenant_edition_and_metrics_isolation(self):
        """Ensures Tenant A settings and financial metrics do not leak into Tenant B."""
        # Tenant A is Managed, Tenant B is Community
        EditionsService.set_tenant_edition(self.tenant_a, 'managed')
        EditionsService.set_tenant_edition(self.tenant_b, 'community')

        self.assertEqual(EditionsService.get_tenant_edition(self.tenant_a)['id'], 'managed')
        self.assertEqual(EditionsService.get_tenant_edition(self.tenant_b)['id'], 'community')
        self.assertTrue(EditionsService.is_feature_enabled(self.tenant_a, 'managed_rule_tuning'))
        self.assertFalse(EditionsService.is_feature_enabled(self.tenant_b, 'managed_rule_tuning'))

        # Record financial protection only for Tenant A
        MetricsService.record_financial_protection(self.tenant_a, amount_etb=99000000.0)

        metrics_a = MetricsService.get_executive_metrics(self.tenant_a)
        metrics_b = MetricsService.get_executive_metrics(self.tenant_b)

        self.assertEqual(metrics_a['kpis']['financial_volume_protected_etb'], 99000000.0)
        self.assertEqual(metrics_b['kpis']['financial_volume_protected_etb'], 0.0)


if __name__ == '__main__':
    unittest.main()
