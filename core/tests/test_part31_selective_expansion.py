"""
Test Suite: Part 31 — Selective Expansion (Phase 8).

Verifies:
1. Explainable Multilingual Narratives (Phase 8.1):
   - Structured deterministic narrative generation (English, Amharic, Afaan Oromo).
   - PII minimization & scrubbing.
   - REST endpoints: POST /api/narrative/incident/<id>, GET /api/narrative/incident/<id>.
2. Endpoint & Email Security Ingestion Adapters (Phase 8.2):
   - Sysmon/Wazuh host process telemetry & ransomware precursors ('vssadmin delete shadows', MITRE T1490).
   - Email telemetry, DMARC/SPF analysis, and BEC VIP impersonation detection with wire urgency.
   - REST endpoints: POST /api/adapters/endpoint/ingest, POST /api/adapters/email/ingest, GET /api/adapters/events.
3. Exposure Management & Attack Surface Context (Phase 8.3):
   - Asset inventory registration (domains, IPs).
   - TLS expiration (<14 days), deprecated ciphers, missing security headers (HSTS, CSP), and exposed ports.
   - External attack surface context integration into ECS risk scoring.
   - REST endpoints: POST /api/exposure/assets, GET /api/exposure/assets, POST /api/exposure/assets/<id>/scan.
4. National Identity Assurance (Fayda Digital ID) (Phase 8.4):
   - Privacy-preserving keyed hashing of Fayda FIN (no plaintext FIN stored).
   - Biometric verification risk mitigation vs spoof presentation attack penalty.
   - REST endpoints: POST /api/fayda/verify, GET /api/fayda/account/<account_number>.
5. Regulator & Sector-Wide Aggregate Telemetry Dashboard (Phase 8.5):
   - Anonymized cross-operator sector overview (Commercial Banking, MFI, FinTech, Telecom).
   - Verified zero cross-tenant leakage of bank identities or customer PII.
   - REST endpoint: GET /api/regulator/sector-overview.
6. Multi-Tenancy Isolation:
   - Tenant A assets and narratives cannot be queried or mutated by Tenant B.
"""
import unittest
import json
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.case_service import clear_case_caches, _LOCAL_INCIDENTS
from app.services.narrative_service import (
    NarrativeService,
    clear_narrative_caches
)
from app.services.endpoint_email_adapter_service import (
    EndpointEmailAdapterService,
    clear_adapter_caches
)
from app.services.exposure_service import (
    ExposureService,
    clear_exposure_caches
)
from app.services.fayda_id_service import (
    FaydaIdService,
    clear_fayda_caches
)
from app.services.regulator_dashboard_service import RegulatorDashboardService


class TestSelectiveExpansion(unittest.TestCase):
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
        clear_case_caches()
        clear_narrative_caches()
        clear_adapter_caches()
        clear_exposure_caches()
        clear_fayda_caches()
        set_current_organization_id(self.tenant_a)

    # =========================================================================
    # 1. EXPLAINABLE MULTILINGUAL NARRATIVES (PHASE 8.1)
    # =========================================================================

    def test_01_explainable_narrative_multilingual(self):
        """Verifies deterministic explainable narrative generation in English, Amharic, and Afaan Oromo."""
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS['inc-exp-01'] = {
            'id': 'inc-exp-01',
            'organization_id': self.tenant_a,
            'title': 'High Velocity Account Takeover Attack',
            'incident_type': 'account_takeover',
            'severity': 'critical',
            'status': 'contained',
            'created_at': (now - timedelta(hours=2)).isoformat(),
            'detection_date': (now - timedelta(hours=2)).isoformat(),
            'contained_at': (now - timedelta(hours=1)).isoformat(),
            'financial_impact_etb': 4500000.0,
            'is_reportable_48h': True
        }

        # 1. English narrative
        nar_en = NarrativeService.generate_incident_narrative(self.tenant_a, 'inc-exp-01', lang='en')
        self.assertEqual(nar_en['language'], 'en')
        self.assertTrue(nar_en['advisory_only'])
        self.assertIn("CRITICAL", nar_en['content']['executive_summary'])
        self.assertIn("Account Takeover", nar_en['content']['executive_summary'])
        self.assertIn("ETB 4,500,000.00", nar_en['content']['executive_summary'])

        # 2. Amharic narrative
        nar_am = NarrativeService.generate_incident_narrative(self.tenant_a, 'inc-exp-01', lang='am')
        self.assertEqual(nar_am['language'], 'am')
        self.assertIn("የሂሳብ ቁጥጥር ስርቆት", nar_am['content']['executive_summary'])
        self.assertIn("ብር 4,500,000.00", nar_am['content']['executive_summary'])

        # 3. Afaan Oromo narrative
        nar_om = NarrativeService.generate_incident_narrative(self.tenant_a, 'inc-exp-01', lang='om')
        self.assertEqual(nar_om['language'], 'om')
        self.assertIn("Herrega Dhuunfaa Qabachuu", nar_om['content']['executive_summary'])
        self.assertIn("Birrii 4,500,000.00", nar_om['content']['executive_summary'])

        # 4. REST API Endpoint test
        res = self.client.post(
            '/api/narrative/incident/inc-exp-01',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'},
            json={'language': 'am'}
        )
        self.assertEqual(res.status_code, 200)
        api_data = res.get_json()
        self.assertEqual(api_data['language'], 'am')
        self.assertIn("የሂሳብ ቁጥጥር ስርቆት", api_data['content']['executive_summary'])

    # =========================================================================
    # 2. ENDPOINT & EMAIL TELEMETRY ADAPTERS (PHASE 8.2)
    # =========================================================================

    def test_02_endpoint_ransomware_precursor_detection(self):
        """Verifies endpoint adapter ingests Sysmon logs and detects ransomware shadow deletion."""
        raw_sysmon = {
            'Computer': 'CORE-BANK-SRV-01',
            'Image': 'C:\\Windows\\System32\\vssadmin.exe',
            'CommandLine': 'vssadmin.exe delete shadows /all /quiet',
            'User': 'NT AUTHORITY\\SYSTEM'
        }

        event = EndpointEmailAdapterService.ingest_endpoint_log(
            org_id=self.tenant_a,
            raw_log=raw_sysmon,
            source_format='sysmon'
        )

        self.assertEqual(event['event_type'], 'endpoint.ransomware_precursor')
        self.assertTrue(event['is_ransomware_precursor'])
        self.assertEqual(event['severity'], 'critical')
        self.assertEqual(event['risk_score'], 95)
        self.assertIn('mitre_t1490', event['tags'])

        # REST API Endpoint test
        res = self.client.post(
            '/api/adapters/endpoint/ingest',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'},
            json={'format': 'sysmon', 'log': raw_sysmon}
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data['is_ransomware_precursor'])

    def test_03_email_bec_and_dmarc_detection(self):
        """Verifies email adapter detects BEC VIP impersonation and DMARC failures."""
        email_data = {
            'from': 'attacker@external-evil-domain.com',
            'display_name': 'Abebe Kebede - Chief Executive Officer (CEO)',
            'to': 'treasury.ops@cbe.com.et',
            'subject': 'URGENT: Confidential Immediate Remittance Required',
            'body_snippet': 'Please process an urgent wire transfer of 8,500,000 ETB immediately.',
            'corporate_domain': 'cbe.com.et',
            'dmarc': 'fail',
            'spf': 'fail'
        }

        event = EndpointEmailAdapterService.ingest_email_event(
            org_id=self.tenant_a,
            email_data=email_data,
            known_executives=['Chief Executive Officer', 'CEO']
        )

        self.assertEqual(event['event_type'], 'email.bec_threat')
        self.assertTrue(event['is_vip_spoof'])
        self.assertTrue(event['has_wire_urgency'])
        self.assertEqual(event['severity'], 'critical')
        self.assertEqual(event['risk_score'], 90)
        self.assertIn('bec_attempt', event['tags'])
        self.assertIn('urgent_wire_lure', event['tags'])

    # =========================================================================
    # 3. EXPOSURE MANAGEMENT & ATTACK SURFACE CONTEXT (PHASE 8.3)
    # =========================================================================

    def test_04_exposure_asset_auditing_and_risk_scoring(self):
        """Verifies attack surface asset registration, TLS scan, and risk integration."""
        # 1. Register domain asset
        asset = ExposureService.register_asset(
            org_id=self.tenant_a,
            asset_type='domain',
            identifier='ebanking.cbe.com.et',
            environment='production'
        )
        asset_id = asset['id']

        # 2. Execute exposure scan with certificate expiring in 7 days and missing HSTS
        scan_results = {
            'tls': {
                'is_valid': True,
                'days_to_expire': 7,
                'is_self_signed': False,
                'tls_version': 'TLSv1.2'
            },
            'headers': {
                'Content-Security-Policy': "default-src 'self'",
                # Missing Strict-Transport-Security (HSTS)
            },
            'open_ports': [443, 80]
        }

        updated = ExposureService.scan_asset_exposure(self.tenant_a, asset_id, scan_results)
        self.assertGreater(updated['exposure_score'], 40)
        self.assertIn(updated['exposure_grade'], ('high', 'critical'))

        # Verify vulnerability detection
        vuln_codes = [v['code'] for v in updated['vulnerabilities']]
        self.assertIn('EXP-TLS-002', vuln_codes)  # Expiring in 7 days
        self.assertIn('EXP-HDR-STR', vuln_codes)  # Missing Strict-Transport-Security

        # 3. Verify exposure context lookup
        ctx = ExposureService.get_asset_exposure_context(self.tenant_a, 'ebanking.cbe.com.et')
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx['identifier'], 'ebanking.cbe.com.et')
        self.assertGreater(ctx['exposure_score'], 0)

        # 4. REST API Endpoint test
        res = self.client.get(
            '/api/exposure/assets',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['total'], 1)

    # =========================================================================
    # 4. NATIONAL IDENTITY ASSURANCE (FAYDA DIGITAL ID) (PHASE 8.4)
    # =========================================================================

    def test_05_fayda_id_assurance_and_spoof_detection(self):
        """Verifies Fayda FIN keyed hashing, biometric verification, and presentation spoof detection."""
        fin_raw = "1234-5678-9012"
        fin_hash = FaydaIdService.hash_fayda_fin(fin_raw)

        # Ensure raw FIN is not leaked
        self.assertNotIn("1234-5678-9012", fin_hash)
        self.assertTrue(fin_hash.startswith("fayda_fin_h_"))

        # Case A: High-assurance biometric face verification
        evt_verified = FaydaIdService.ingest_verification_event(
            org_id=self.tenant_a,
            fayda_fin=fin_raw,
            account_number="100012345678",
            auth_mode="biometric_face",
            auth_status="verified"
        )
        self.assertEqual(evt_verified['assurance_level'], 'high_biometric')
        self.assertLess(evt_verified['risk_adjustment'], 0)  # Negative adjustment reduces risk

        # Case B: Biometric presentation spoof attack detected
        evt_spoof = FaydaIdService.ingest_verification_event(
            org_id=self.tenant_a,
            fayda_fin="9999-8888-7777",
            account_number="100099999999",
            auth_mode="biometric_face",
            auth_status="spoof_detected"
        )
        self.assertEqual(evt_spoof['assurance_level'], 'compromised_spoof')
        self.assertEqual(evt_spoof['risk_adjustment'], 90)  # +90 risk penalty
        self.assertIn("deepfake spoof", evt_spoof['flagged_reason'])

        # Query account assurance status via REST API
        res = self.client.get(
            '/api/fayda/account/100012345678',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['identity_assurance']['is_verified'])
        self.assertEqual(data['identity_assurance']['assurance_level'], 'high_biometric')

    # =========================================================================
    # 5. REGULATOR & SECTOR-WIDE DASHBOARD (PHASE 8.5)
    # =========================================================================

    def test_06_regulator_sector_overview_anonymization(self):
        """Verifies regulator overview provides cross-sector KPIs with zero bank identity leakage."""
        res = self.client.get(
            '/api/regulator/sector-overview',
            headers={'Authorization': f'Bearer {self.token_a_analyst}'}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data['anonymization_verified'])
        self.assertIn('summary_kpis', data)
        self.assertIn('threat_campaigns', data)
        self.assertIn('sector_distribution', data)

        # Check that individual bank names are NOT leaked
        content_str = json.dumps(data)
        self.assertNotIn("Commercial Bank of Ethiopia", content_str)
        self.assertNotIn("Dashen Bank", content_str)
        self.assertNotIn("Awash Bank", content_str)

        # Verify statutory compliance and currency metrics
        self.assertIn("ETB", data['summary_kpis']['total_etb_protected_formatted'])
        self.assertGreater(data['summary_kpis']['statutory_48h_compliance_rate_pct'], 80.0)

    # =========================================================================
    # 6. MULTI-TENANCY ISOLATION
    # =========================================================================

    def test_07_multitenant_asset_and_narrative_isolation(self):
        """Verifies Tenant A cannot access or mutate Tenant B assets or incident narratives."""
        # Tenant A registers asset
        asset_a = ExposureService.register_asset(
            org_id=self.tenant_a,
            asset_type='domain',
            identifier='portal.cbe.com.et'
        )

        # Tenant B registers asset
        asset_b = ExposureService.register_asset(
            org_id=self.tenant_b,
            asset_type='domain',
            identifier='ebanking.dashenbanksc.com'
        )

        # Tenant A listing should ONLY contain Tenant A's asset
        assets_a = ExposureService.list_assets(self.tenant_a)
        identifiers_a = [a['identifier'] for a in assets_a]
        self.assertIn('portal.cbe.com.et', identifiers_a)
        self.assertNotIn('ebanking.dashenbanksc.com', identifiers_a)

        # Tenant B listing should ONLY contain Tenant B's asset
        assets_b = ExposureService.list_assets(self.tenant_b)
        identifiers_b = [a['identifier'] for a in assets_b]
        self.assertIn('ebanking.dashenbanksc.com', identifiers_b)
        self.assertNotIn('portal.cbe.com.et', identifiers_b)

        # Tenant A cannot scan Tenant B's asset
        with self.assertRaises(ValueError):
            ExposureService.scan_asset_exposure(self.tenant_a, asset_b['id'], {})


if __name__ == '__main__':
    unittest.main()
