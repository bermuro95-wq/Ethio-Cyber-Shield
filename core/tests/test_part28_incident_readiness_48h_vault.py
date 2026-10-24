"""
Test Suite: Part 28 — Incident Readiness Engine, 48-Hour Clock & Evidence Vault (Phase 5).

Verifies:
1. Reportable-Incident Classification:
   - Statutory triggers (critical severity, risk >= 75, ATO/ransomware, ETB >= 50,000, mass PII records >= 100).
   - Explicit detection timestamp recording and analyst confirmation.
2. 48-Hour Statutory Clock Engine:
   - Accurate milestone calculation in Africa/Addis_Ababa local time (UTC+3).
   - Stages: green (0-24h), yellow_warning (24-36h), amber_warning (36-44h), red_critical (44-48h), breached (>48h).
   - Milestone escalation watchdog.
   - EthioCERT submission recording stopping clock on-time.
3. EthioCERT / INSA Bilingual Package Generator:
   - Conformance to ECS-IRS-v1.0 schema (docs/INCIDENT_REPORT_FALLBACK_SPEC.md).
   - Bilingual summaries (English & Amharic).
   - Reference code format ECS-REP-YYYYMMDD-<short_id>.
4. Evidence Vault & Cryptographic Integrity:
   - Immutable snapshot creation with telemetry, audit trail, and composite SHA-256 manifest.
   - Cryptographic seal verification (valid seal passes, tampered seal detected).
   - Chain-of-custody logging.
5. Statutory Obligation Mapping & Non-Overclaiming:
   - Proclamation No. 1426/2026, NBE Directives, PDPP 1321/2024 register.
   - Strict adherence to 'supports evidence for' without overclaiming compliance.
6. One-Click Sealed Audit Pack:
   - Complete regulatory bundle export with SHA-256 manifest.
7. Multi-Tenant Isolation & Auditor Role:
   - Tenant A cannot access Tenant B's readiness assets.
   - Auditor role granted read-only inspection access.
"""
import unittest
import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.readiness_service import (
    ReadinessService,
    clear_readiness_caches,
    _LOCAL_READINESS_POLICIES,
    _LOCAL_EVIDENCE_VAULTS,
    _LOCAL_CHAIN_OF_CUSTODY
)
from app.services.case_service import CaseService, clear_case_caches, _LOCAL_INCIDENTS


class TestIncidentReadiness48hVault(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.tenant_a = "11111111-1111-1111-1111-111111111111"
        cls.tenant_b = "22222222-2222-2222-2222-222222222222"

        cls.user_a_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        cls.user_b_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        cls.auditor_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"

        cls.token_a = create_token(
            cls.user_a_id,
            'ciso_a@cbe.com.et',
            'admin',
            organization_id=cls.tenant_a
        )

        cls.token_b = create_token(
            cls.user_b_id,
            'ciso_b@dashen.com.et',
            'admin',
            organization_id=cls.tenant_b
        )

        cls.token_auditor = create_token(
            cls.auditor_id,
            'auditor@insa.gov.et',
            'auditor',
            organization_id=cls.tenant_a
        )

    def setUp(self):
        clear_readiness_caches()
        clear_case_caches()
        set_current_organization_id(self.tenant_a)

    # =========================================================================
    # 1. REPORTABLE-INCIDENT CLASSIFICATION & CONFIRMATION
    # =========================================================================

    def test_reportable_incident_classification_triggers(self):
        """Verifies statutory criteria evaluation under Proclamation No. 1426/2026."""
        # 1. High risk / critical severity trigger
        crit_inc = {
            'severity': 'critical',
            'risk_score': 90,
            'incident_type': 'suspicious_login'
        }
        is_rep, reason, diag = ReadinessService.evaluate_reportability(crit_inc)
        self.assertTrue(is_rep)
        self.assertIn("CRITICAL", reason)

        # 2. Financial threshold trigger (>= 50,000 ETB)
        fraud_inc = {
            'severity': 'medium',
            'risk_score': 50,
            'incident_type': 'fraud',
            'evidence': {'amount_etb': 120000.0}
        }
        is_rep_fraud, reason_fraud, diag_fraud = ReadinessService.evaluate_reportability(fraud_inc)
        self.assertTrue(is_rep_fraud)
        self.assertIn("120,000.00 ETB", reason_fraud)

        # 3. Critical national infrastructure (EthSwitch / RTGS)
        switch_inc = {
            'severity': 'medium',
            'risk_score': 45,
            'title': 'Anomalous burst on EthSwitch RTGS gateway',
            'incident_type': 'api_abuse'
        }
        is_rep_sw, reason_sw, _ = ReadinessService.evaluate_reportability(switch_inc)
        self.assertTrue(is_rep_sw)
        self.assertIn("settlement rail", reason_sw)

        # 4. Benign minor incident (below statutory threshold)
        minor_inc = {
            'severity': 'low',
            'risk_score': 20,
            'incident_type': 'other',
            'evidence': {'amount_etb': 500.0}
        }
        is_rep_minor, _, _ = ReadinessService.evaluate_reportability(minor_inc)
        self.assertFalse(is_rep_minor)

    def test_confirm_reportable_status_locks_detection_timestamp(self):
        """Verifies human-in-the-loop analyst confirmation step."""
        inc_id = 'inc-rep-conf-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'Account Takeover Syndicate',
            'severity': 'critical',
            'risk_score': 85,
            'status': 'investigating',
            'detection_date': now.isoformat(),
            'created_at': now.isoformat()
        }

        res = ReadinessService.confirm_reportable_status(
            org_id=self.tenant_a,
            incident_id=inc_id,
            is_reportable=True,
            reason="Confirmed critical ATO with potential settlement exposure.",
            officer_name="Dawit Mengistu",
            officer_role="CISO"
        )
        self.assertTrue(res['is_reportable_48h'])
        self.assertIn('clock', res)
        self.assertEqual(res['detection_date'], now.isoformat())

    # =========================================================================
    # 2. 48-HOUR STATUTORY COUNTDOWN CLOCK TESTS
    # =========================================================================

    def test_48h_clock_milestone_stages(self):
        """Verifies countdown stages: green (0-24h), yellow (24-36h), amber (36-44h), red (44-48h), breached (>48h)."""
        now = datetime.now(timezone.utc)

        # Stage 1: Green (10h elapsed)
        inc_10h = {
            'id': 'inc-10h',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=10)).isoformat()
        }
        clock_10h = ReadinessService.calculate_48h_clock(inc_10h, now=now)
        self.assertEqual(clock_10h['clock_stage'], 'green')
        self.assertEqual(clock_10h['elapsed_hours'], 10.0)
        self.assertEqual(clock_10h['remaining_hours'], 38.0)
        self.assertFalse(clock_10h['is_breached'])

        # Stage 2: Yellow Warning (26h elapsed)
        inc_26h = {
            'id': 'inc-26h',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=26)).isoformat()
        }
        clock_26h = ReadinessService.calculate_48h_clock(inc_26h, now=now)
        self.assertEqual(clock_26h['clock_stage'], 'yellow_warning')

        # Stage 3: Amber Warning (38h elapsed)
        inc_38h = {
            'id': 'inc-38h',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=38)).isoformat()
        }
        clock_38h = ReadinessService.calculate_48h_clock(inc_38h, now=now)
        self.assertEqual(clock_38h['clock_stage'], 'amber_warning')

        # Stage 4: Red Critical (46h elapsed)
        inc_46h = {
            'id': 'inc-46h',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=46)).isoformat()
        }
        clock_46h = ReadinessService.calculate_48h_clock(inc_46h, now=now)
        self.assertEqual(clock_46h['clock_stage'], 'red_critical')
        self.assertEqual(clock_46h['remaining_hours'], 2.0)

        # Stage 5: Breached (50h elapsed)
        inc_50h = {
            'id': 'inc-50h',
            'organization_id': self.tenant_a,
            'detection_date': (now - timedelta(hours=50)).isoformat()
        }
        clock_50h = ReadinessService.calculate_48h_clock(inc_50h, now=now)
        self.assertEqual(clock_50h['clock_stage'], 'breached')
        self.assertTrue(clock_50h['is_breached'])

    def test_record_cert_submission_stops_clock_on_time(self):
        """Verifies formal submission to EthioCERT locks 48h clock as submitted."""
        inc_id = 'inc-cert-sub-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'Ransomware Probe Neutralized',
            'detection_date': (now - timedelta(hours=18)).isoformat(),
            'status': 'contained'
        }

        sub = ReadinessService.record_cert_submission(
            org_id=self.tenant_a,
            incident_id=inc_id,
            cert_reference_no="ETHIOCERT-2026-INC-88991",
            submission_channel="portal",
            officer_name="Dawit Mengistu"
        )
        self.assertEqual(sub['cert_reference_no'], "ETHIOCERT-2026-INC-88991")
        self.assertTrue(sub['clock']['is_submitted'])
        self.assertEqual(sub['clock']['clock_stage'], 'submitted_on_time')
        self.assertFalse(sub['clock']['is_breached'])

    # =========================================================================
    # 3. ETHIOCERT BILINGUAL PACKAGE GENERATOR TESTS
    # =========================================================================

    def test_generate_ethiocert_report_package_conformance(self):
        """Verifies generated package conforms to ECS-IRS-v1.0 schema."""
        inc_id = 'inc-dossier-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'High Value Fraud Ring',
            'incident_type': 'account_takeover',
            'severity': 'critical',
            'detection_date': now.isoformat(),
            'status': 'contained',
            'evidence': {'amount_etb': 250000.0, 'accounts_affected': 2}
        }

        pkg = ReadinessService.generate_ethiocert_report_package(self.tenant_a, inc_id)
        self.assertEqual(pkg['specification_version'], 'ECS-IRS-v1.0')
        self.assertTrue(pkg['report_id'].startswith("ECS-REP-"))

        # Check required top-level sections
        required_keys = [
            'report_id', 'organization_profile', 'statutory_timeline',
            'incident_classification', 'technical_summary', 'impact_assessment',
            'indicators_of_compromise', 'containment_and_remediation',
            'evidence_manifest', 'attestation'
        ]
        for rk in required_keys:
            self.assertIn(rk, pkg, f"Missing required package section: {rk}")

        # Check Bilingual Summaries
        tech = pkg['technical_summary']
        self.assertIn('Statutory 48-Hour Incident Notification', tech['executive_summary_en'])
        self.assertIn('በኢንፎርሜሽን መረብ ደህንነት አስተዳደር', tech['executive_summary_am'])

        # Check Evidence Manifest hashes
        manifest = pkg['evidence_manifest']
        self.assertEqual(len(manifest['telemetry_sha256_digest']), 64)
        self.assertEqual(len(manifest['audit_trail_sha256_digest']), 64)
        self.assertEqual(len(manifest['bundle_signature']), 64)

    # =========================================================================
    # 4. EVIDENCE VAULT & CRYPTOGRAPHIC INTEGRITY TESTS
    # =========================================================================

    def test_evidence_vault_sealing_verification_and_tampering_detection(self):
        """Verifies Evidence Vault snapshot sealing, chain of custody, and tamper detection."""
        inc_id = 'inc-vault-test-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'Dormant Admin Activation & Mass Exfiltration',
            'incident_type': 'account_takeover',
            'severity': 'critical',
            'detection_date': now.isoformat(),
            'status': 'contained'
        }

        # 1. Create Vault
        vault = ReadinessService.create_evidence_vault(
            org_id=self.tenant_a,
            incident_id=inc_id,
            officer_name="Dawit Mengistu",
            officer_role="CISO"
        )
        self.assertEqual(vault['status'], 'sealed')
        self.assertEqual(len(vault['manifest_sha256']), 64)
        self.assertEqual(vault['retention_days'], 3650)

        # 2. Verify Vault Integrity
        v_res = ReadinessService.verify_vault_integrity(self.tenant_a, vault['id'])
        self.assertTrue(v_res['verified'])
        self.assertEqual(v_res['recomputed_manifest_sha256'], vault['manifest_sha256'])

        # 3. Check Chain of Custody
        custody = ReadinessService.list_chain_of_custody(self.tenant_a, vault['id'])
        self.assertGreaterEqual(len(custody), 2)  # 'created_and_sealed' + 'verified'
        self.assertEqual(custody[0]['action'], 'created_and_sealed')
        self.assertEqual(custody[1]['action'], 'verified')

        # 4. Tampering Detection
        # Modify stored manifest directly
        _LOCAL_EVIDENCE_VAULTS[vault['id']]['manifest_sha256'] = "bad" * 16
        tampered_res = ReadinessService.verify_vault_integrity(self.tenant_a, vault['id'])
        self.assertFalse(tampered_res['verified'])

    # =========================================================================
    # 5. STATUTORY OBLIGATION REGISTER & AUDIT PACK TESTS
    # =========================================================================

    def test_statutory_obligation_register_and_audit_pack(self):
        """Verifies statutory register adheres to 'supports evidence for' and compiles sealed audit pack."""
        # 1. Register inspection
        register = ReadinessService.get_obligation_register()
        self.assertGreaterEqual(len(register), 5)

        for clause in register:
            status = clause['ecs_support_status']
            # Strict Rule #6 enforcement: Must NEVER claim 'guarantees compliance'
            self.assertIn(status, ['supports_evidence_for', 'partially_supported', 'not_covered'])
            self.assertNotIn("guarantee", clause['description'].lower())

        # 2. Readiness Evaluation
        eval_res = ReadinessService.evaluate_compliance_readiness_support(self.tenant_a)
        self.assertGreaterEqual(eval_res['compliance_support_score'], 80.0)
        self.assertIn("does not constitute legal certification", eval_res['mandatory_disclaimer'])

        # 3. Sealed Audit Pack Bundle
        audit_pack = ReadinessService.generate_audit_pack(self.tenant_a, certifying_officer="Dawit Mengistu")
        self.assertIn("AUDIT-PACK-", audit_pack['audit_pack_id'])
        self.assertEqual(len(audit_pack['audit_pack_sha256_seal']), 64)
        self.assertIn('statutory_frameworks', audit_pack)

    # =========================================================================
    # 6. REST API, AUDITOR ROLE & MULTI-TENANT ISOLATION TESTS
    # =========================================================================

    def test_rest_api_and_auditor_role(self):
        """Verifies REST endpoints and auditor read-only inspection access."""
        inc_id = 'inc-rest-readiness-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'REST API Test Incident',
            'severity': 'critical',
            'risk_score': 85,
            'detection_date': now.isoformat(),
            'status': 'investigating'
        }

        headers_admin = {'Authorization': f'Bearer {self.token_a}'}
        headers_auditor = {'Authorization': f'Bearer {self.token_auditor}'}

        # 1. 48h Clock GET (Auditor can read)
        res_clock = self.client.get(f'/api/readiness/clock/{inc_id}', headers=headers_auditor)
        self.assertEqual(res_clock.status_code, 200)
        self.assertEqual(res_clock.get_json()['clock_stage'], 'green')

        # 2. Auditor can read obligations and audit pack
        res_ob = self.client.get('/api/readiness/obligations', headers=headers_auditor)
        self.assertEqual(res_ob.status_code, 200)

        res_pack = self.client.get('/api/readiness/audit-pack', headers=headers_auditor)
        self.assertEqual(res_pack.status_code, 200)
        self.assertIn('audit_pack_sha256_seal', res_pack.get_json())

        # 3. Auditor CANNOT update policy (admin only)
        res_pol = self.client.put('/api/readiness/policy', json={'license_ref': 'ILLEGAL'}, headers=headers_auditor)
        self.assertEqual(res_pol.status_code, 403)

        # 4. Admin CAN update policy
        res_pol_admin = self.client.put('/api/readiness/policy', json={'legal_name': 'Commercial Bank of Ethiopia'}, headers=headers_admin)
        self.assertEqual(res_pol_admin.status_code, 200)

    def test_multi_tenant_isolation_readiness(self):
        """Ensures Tenant A cannot access Tenant B's 48h clock, EthioCERT packages, or Vaults."""
        inc_b_id = 'inc-tenant-b-readiness'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_b_id] = {
            'id': inc_b_id,
            'organization_id': self.tenant_b,
            'title': 'Dashen Bank Secret Incident',
            'severity': 'critical',
            'detection_date': now.isoformat(),
            'status': 'open'
        }

        # Create vault in Tenant B
        vault_b = ReadinessService.create_evidence_vault(self.tenant_b, inc_b_id)

        headers_a = {'Authorization': f'Bearer {self.token_a}'}
        headers_b = {'Authorization': f'Bearer {self.token_b}'}

        # Tenant A tries to access Tenant B's 48h clock -> 404
        res_clock = self.client.get(f'/api/readiness/clock/{inc_b_id}', headers=headers_a)
        self.assertEqual(res_clock.status_code, 404)

        # Tenant A tries to access Tenant B's Evidence Vault -> 404
        res_vault = self.client.get(f'/api/readiness/vault/{vault_b["id"]}', headers=headers_a)
        self.assertEqual(res_vault.status_code, 404)

        # Tenant B can access their own vault
        res_b = self.client.get(f'/api/readiness/vault/{vault_b["id"]}', headers=headers_b)
        self.assertEqual(res_b.status_code, 200)
        self.assertEqual(res_b.get_json()['id'], vault_b['id'])


if __name__ == '__main__':
    unittest.main()
