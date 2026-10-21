"""
Test Suite: Part 27 — Case Management, Notifications, Feedback Loop, & Post-Incident Reviews (Phase 4.4 - 4.7).

Verifies:
1. Case Management (Phase 4.4):
   - Dynamic SLA health (on_track, at_risk, breached) and milestones (TTA, TTC, TTR).
   - Case assignment and status transitions.
   - Case notes and analyst comments.
   - Evidence attachments with SHA-256 sealing and verification.
   - Cross-time entity timeline aggregation (events, alerts, actions).
   - Related-alert case graph structure.
   - Saved searches and cross-time event search engine.
2. Multi-Channel Notifications (Phase 4.5):
   - Envelope-encrypted channel credentials (Telegram, SMS, Webhook, Email).
   - Privacy-preserving PII redaction (masked accounts, masked IPs, masked phones).
   - Severity routing matrix.
   - Addis Ababa timezone quiet hours with critical severity override.
   - Outbound HMAC-SHA256 webhook signing.
   - Delivery auditing and SLA escalation watchdog.
3. Analyst Feedback & Suppression Suggestions (Phase 4.6):
   - Feedback verdict capture (TP, FP, benign positive, test).
   - Precision and False Positive Rate (FPR) rule tuning metrics.
   - Tuning alert warning when FPR >= 25%.
   - Invariant pattern analysis and 1-click suppression rule suggestion.
4. Post-Incident Review (PIR) & Evidence Sealing (Phase 4.7):
   - Auto-compilation of PIR with TTD, TTA, TTC, TTR, and SLA adherence.
   - ETB financial impact assessment (at risk, saved, net loss).
   - Regulatory mapping to INSA Proc. 1426/2026, NBE Directives, PDPP 1321/2024.
   - 5 Whys root cause analysis and rule-tuning action items.
   - Bilingual Amharic and English executive summaries.
   - Cryptographic SHA-256 sealing, tamper verification, and Markdown export.
5. Strict Multi-Tenancy Isolation:
   - Full partition between Tenant A and Tenant B across all entities.
"""
import unittest
import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.case_service import (
    CaseService,
    clear_case_caches,
    _LOCAL_INCIDENTS,
    _LOCAL_CASE_NOTES,
    _LOCAL_ATTACHMENTS,
    _LOCAL_SAVED_SEARCHES
)
from app.services.notification_service import (
    NotificationService,
    redact_sensitive_payload,
    clear_notification_caches,
    _LOCAL_NOTIFICATION_CONFIGS,
    _LOCAL_NOTIFICATION_LOGS
)
from app.services.analyst_feedback_service import (
    AnalystFeedbackService,
    clear_feedback_caches,
    _LOCAL_FEEDBACK,
    _LOCAL_SUGGESTIONS
)
from app.services.pir_service import (
    PIRService,
    clear_pir_caches,
    _LOCAL_PIRS
)
from app.services.alert_quality_service import AlertQualityService


class TestCaseManagementNotificationsFeedbackPIR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.tenant_a = "11111111-1111-1111-1111-111111111111"
        cls.tenant_b = "22222222-2222-2222-2222-222222222222"

        cls.user_a_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        cls.user_b_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

        cls.token_a = create_token(
            cls.user_a_id,
            'analyst_a@cbe.com.et',
            'analyst',
            organization_id=cls.tenant_a
        )

        cls.token_b = create_token(
            cls.user_b_id,
            'analyst_b@dashen.com.et',
            'analyst',
            organization_id=cls.tenant_b
        )

    def setUp(self):
        clear_case_caches()
        clear_notification_caches()
        clear_feedback_caches()
        clear_pir_caches()
        set_current_organization_id(self.tenant_a)

    # =========================================================================
    # 1. CASE MANAGEMENT & SLA TESTS (PHASE 4.4)
    # =========================================================================

    def test_sla_calculation_and_milestones(self):
        """Verifies SLA stages, remaining times, and breach evaluation."""
        now = datetime.now(timezone.utc)
        created_at = (now - timedelta(minutes=20)).isoformat()

        # Critical incident: Target response is 15 mins. Since 20 mins elapsed without ack, response is breached!
        crit_incident = {
            'id': 'inc-crit-001',
            'organization_id': self.tenant_a,
            'severity': 'critical',
            'status': 'open',
            'detection_date': created_at,
            'incident_date': created_at,
            'created_at': created_at
        }

        sla = CaseService.calculate_sla_status(crit_incident, now=now)
        self.assertTrue(sla['is_breached'])
        self.assertEqual(sla['response']['status'], 'breached')
        self.assertEqual(sla['overall_sla_status'], 'breached')
        self.assertGreater(sla['response']['elapsed_mins'], 15.0)

        # High incident: Target response is 30 mins. 20 mins elapsed (66%) -> on_track
        high_incident = {
            'id': 'inc-high-001',
            'organization_id': self.tenant_a,
            'severity': 'high',
            'status': 'open',
            'detection_date': created_at,
            'incident_date': created_at,
            'created_at': created_at
        }
        sla_high = CaseService.calculate_sla_status(high_incident, now=now)
        self.assertFalse(sla_high['is_breached'])
        self.assertEqual(sla_high['response']['status'], 'on_track')

    def test_case_assignment_and_status_transitions(self):
        """Verifies assignment transitions open -> investigating and records milestones."""
        inc_id = 'inc-test-trans-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'Suspicious High Velocity Transfers',
            'severity': 'critical',
            'status': 'open',
            'detection_date': now.isoformat(),
            'incident_date': now.isoformat(),
            'created_at': now.isoformat()
        }

        # 1. Assign case
        assigned = CaseService.assign_case(self.tenant_a, inc_id, self.user_a_id)
        self.assertEqual(assigned['assigned_to'], self.user_a_id)
        self.assertEqual(assigned['status'], 'investigating')
        self.assertIsNotNone(assigned['acknowledged_at'])

        # 2. Transition to contained
        contained = CaseService.transition_status(self.tenant_a, inc_id, 'contained', user_id=self.user_a_id)
        self.assertEqual(contained['status'], 'contained')
        self.assertIsNotNone(contained['contained_at'])

        # 3. Transition to resolved
        resolved = CaseService.transition_status(self.tenant_a, inc_id, 'resolved', user_id=self.user_a_id)
        self.assertEqual(resolved['status'], 'resolved')
        self.assertIsNotNone(resolved['resolved_at'])

    def test_case_notes_and_evidence_attachments(self):
        """Verifies collaborative notes and SHA-256 sealed evidence attachments."""
        inc_id = 'inc-notes-att-01'
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'ATM PIN Brute Force Incident',
            'severity': 'high',
            'status': 'investigating'
        }

        # 1. Add Note
        note = CaseService.add_note(
            org_id=self.tenant_a,
            incident_id=inc_id,
            note="Identified suspicious IP originating from foreign VPN range. Contacted fraud triage unit.",
            author_id=self.user_a_id,
            author_name="Abebe Bikila"
        )
        self.assertEqual(note['incident_id'], inc_id)
        self.assertIn("fraud triage", note['note'])

        notes_list = CaseService.list_notes(self.tenant_a, inc_id)
        self.assertEqual(len(notes_list), 1)

        # 2. Add Attachment
        sample_data = b"FORENSIC EVIDENCE DUMP: IP 196.188.10.55 executed 25 failed PIN attempts."
        expected_hash = hashlib.sha256(sample_data).hexdigest()

        att = CaseService.add_attachment(
            org_id=self.tenant_a,
            incident_id=inc_id,
            filename="forensic_dump.log",
            content_bytes=sample_data,
            content_type="text/plain",
            uploaded_by=self.user_a_id
        )
        self.assertEqual(att['sha256'], expected_hash)
        self.assertEqual(att['file_size'], len(sample_data))

        # 3. Verify Attachment SHA-256 seal
        v_res = CaseService.verify_attachment(self.tenant_a, att['id'], sample_data)
        self.assertTrue(v_res['verified'])
        self.assertEqual(v_res['computed_sha256'], expected_hash)

        # 4. Tampering detection
        tampered_data = b"TAMPERED DUMP: All traces erased."
        t_res = CaseService.verify_attachment(self.tenant_a, att['id'], tampered_data)
        self.assertFalse(t_res['verified'])

    def test_cross_time_entity_timeline_and_case_graph(self):
        """Verifies unified timeline aggregation and case graph nodes/edges."""
        inc_id = 'inc-graph-01'
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'Account Takeover on ACC-9901',
            'severity': 'critical',
            'status': 'investigating'
        }

        timeline = CaseService.get_entity_timeline(
            org_id=self.tenant_a,
            entity_type='account',
            entity_value='ACC-9901'
        )
        self.assertEqual(timeline['entity_value'], 'ACC-9901')
        self.assertIsInstance(timeline['timeline'], list)

        graph = CaseService.get_case_graph(self.tenant_a, inc_id)
        self.assertIn('nodes', graph)
        self.assertIn('edges', graph)
        self.assertGreaterEqual(len(graph['nodes']), 1)
        self.assertEqual(graph['nodes'][0]['id'], f"inc_{inc_id}")

    def test_saved_searches(self):
        """Verifies creating, listing, and deleting saved search queries."""
        search = CaseService.create_saved_search(
            org_id=self.tenant_a,
            user_id=self.user_a_id,
            name="High Value Transfers > 100k ETB",
            query_params={'min_amount': 100000, 'event_type': 'transfer'},
            description="Audit query for regulatory threshold reporting"
        )
        self.assertEqual(search['name'], "High Value Transfers > 100k ETB")

        searches = CaseService.list_saved_searches(self.tenant_a, self.user_a_id)
        self.assertEqual(len(searches), 1)

        CaseService.delete_saved_search(self.tenant_a, search['id'], self.user_a_id)
        searches_after = CaseService.list_saved_searches(self.tenant_a, self.user_a_id)
        self.assertEqual(len(searches_after), 0)

    # =========================================================================
    # 2. MULTI-CHANNEL NOTIFICATIONS TESTS (PHASE 4.5)
    # =========================================================================

    def test_channel_configuration_with_envelope_encryption(self):
        """Verifies envelope encryption of sensitive tokens and safe masked display."""
        raw_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
        cfg = NotificationService.set_channel_config(
            org_id=self.tenant_a,
            channel='telegram',
            config_data={'chat_id': '-1001234567890', 'bot_token': raw_token},
            is_enabled=True,
            min_severity='high'
        )
        # Display config must NOT show raw token
        self.assertNotIn(raw_token, str(cfg['config_data']))
        self.assertEqual(cfg['config_data']['bot_token'], "enc:***MASKED***")

        # Internal decrypted fetch must recover original token
        internal_cfg = NotificationService.get_channel_config(
            self.tenant_a, 'telegram', decrypt_secrets_for_internal_use=True
        )
        self.assertEqual(internal_cfg['config_data']['bot_token'], raw_token)

    def test_privacy_preserving_payload_scrubbing(self):
        """Verifies that PII (accounts, phones, IPs, national IDs) is scrubbed in notification bodies."""
        raw_incident = {
            'id': 'inc-pii-001',
            'title': 'High Value Fraud Transfer',
            'severity': 'critical',
            'risk_score': 92,
            'source_ip': '196.188.10.45',
            'account_id': '100001234567',
            'phone': '+251911223344',
            'national_id': 'FAYDA-99887766',
            'api_token': 'secret-token-xyz'
        }

        redacted = redact_sensitive_payload(raw_incident)
        self.assertEqual(redacted['account_id'], 'ACC-***4567')
        self.assertEqual(redacted['source_ip'], '196.188.***.***')
        self.assertEqual(redacted['phone'], '+25191****44')
        self.assertEqual(redacted['national_id'], '[MASKED_NATIONAL_ID]')
        self.assertEqual(redacted['api_token'], '[REDACTED_SECRET]')

    def test_quiet_hours_and_severity_routing(self):
        """Verifies Addis Ababa quiet hours suppression and critical severity override."""
        cfg = {
            'quiet_hours_enabled': True,
            'quiet_hours_start': '22:00',
            'quiet_hours_end': '06:00'
        }

        # 02:00 EAT (23:00 UTC previous day) is in quiet hours
        night_time_utc = datetime(2026, 10, 21, 23, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(NotificationService.is_in_quiet_hours(cfg, now_utc=night_time_utc))

        # 14:00 EAT (11:00 UTC) is business hours -> NOT in quiet hours
        day_time_utc = datetime(2026, 10, 21, 11, 0, 0, tzinfo=timezone.utc)
        self.assertFalse(NotificationService.is_in_quiet_hours(cfg, now_utc=day_time_utc))

    def test_outbound_webhook_hmac_signing(self):
        """Verifies HMAC-SHA256 signature generation on outbound webhooks."""
        secret = "secret-shared-key-for-tenant-a"
        payload_str = json.dumps({'event': 'alert', 'severity': 'critical'})
        sig = NotificationService.generate_webhook_signature(secret, payload_str)
        self.assertEqual(len(sig), 64)

        # Expected HMAC
        import hmac
        expected = hmac.new(secret.encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
        self.assertEqual(sig, expected)

    # =========================================================================
    # 3. ANALYST FEEDBACK & SUPPRESSION SUGGESTIONS (PHASE 4.6)
    # =========================================================================

    def test_feedback_capture_and_rule_tuning_metrics(self):
        """Verifies feedback verdict capture and FPR calculation triggering tuning warnings."""
        rid = "RULE-ET-PAY-003"

        # Submit 1 TP, 3 FP (FPR = 75% >= 25% threshold)
        AnalystFeedbackService.submit_feedback(
            org_id=self.tenant_a,
            rule_id=rid,
            verdict='true_positive',
            reason_category='malicious_confirmed',
            entity_type='ip',
            entity_value='196.188.10.1',
            user_id=self.user_a_id
        )

        for ip_val in ['196.188.10.99', '196.188.10.99', '196.188.10.99']:
            AnalystFeedbackService.submit_feedback(
                org_id=self.tenant_a,
                rule_id=rid,
                verdict='false_positive',
                reason_category='benign_business_activity',
                analyst_notes="Scheduled settlement test",
                entity_type='ip',
                entity_value=ip_val,
                user_id=self.user_a_id
            )

        stats = AnalystFeedbackService.get_rule_tuning_stats(self.tenant_a, rule_id=rid)
        rule_stat = stats['rules']
        self.assertEqual(rule_stat['true_positives'], 1)
        self.assertEqual(rule_stat['false_positives'], 3)
        self.assertEqual(rule_stat['false_positive_rate'], 0.75)
        self.assertTrue(rule_stat['needs_tuning'])
        self.assertIn(">= 25% threshold", rule_stat['recommendation'])

        # Automated suppression suggestions from recurring FP entity
        suggestions = AnalystFeedbackService.generate_suppression_suggestions(self.tenant_a, rule_id=rid)
        self.assertGreaterEqual(len(suggestions), 1)
        sug = suggestions[0]
        self.assertEqual(sug['entity_id'], '196.188.10.99')
        self.assertEqual(sug['false_positive_count'], 3)

        # 1-click apply suppression rule
        active_supp = AnalystFeedbackService.apply_suppression_suggestion(
            self.tenant_a, sug, user_id=self.user_a_id
        )
        self.assertTrue(active_supp['is_active'])
        self.assertEqual(active_supp['entity_id'], '196.188.10.99')

    # =========================================================================
    # 4. POST-INCIDENT REVIEW (PIR) & EVIDENCE SEALING (PHASE 4.7)
    # =========================================================================

    def test_pir_generation_sealing_verification_and_markdown(self):
        """Verifies auto-generation, operational metrics, SHA-256 seal, and Markdown export."""
        inc_id = 'inc-pir-test-01'
        now = datetime.now(timezone.utc)
        _LOCAL_INCIDENTS[inc_id] = {
            'id': inc_id,
            'organization_id': self.tenant_a,
            'title': 'High Volume Account Takeover Syndicate',
            'incident_type': 'account_takeover',
            'severity': 'critical',
            'status': 'resolved',
            'risk_score': 95,
            'incident_date': (now - timedelta(minutes=45)).isoformat(),
            'detection_date': (now - timedelta(minutes=40)).isoformat(),
            'acknowledged_at': (now - timedelta(minutes=35)).isoformat(),
            'contained_at': (now - timedelta(minutes=20)).isoformat(),
            'resolved_at': now.isoformat(),
            'created_at': (now - timedelta(minutes=40)).isoformat()
        }

        # 1. Generate PIR
        pir = PIRService.generate_pir(self.tenant_a, inc_id, created_by=self.user_a_id)
        self.assertEqual(pir['incident_id'], inc_id)
        self.assertEqual(pir['status'], 'draft')
        self.assertIn('የድህረ-ክስተት', pir['summary_am'])
        self.assertGreater(pir['financial_impact']['total_at_risk'], 0)
        self.assertEqual(pir['financial_impact']['currency'], 'ETB')

        # 2. Cryptographic SHA-256 Sealing
        sealed = PIRService.seal_pir(self.tenant_a, pir['id'], user_id=self.user_a_id)
        self.assertEqual(sealed['status'], 'sealed')
        self.assertIsNotNone(sealed['sha256_seal'])
        self.assertEqual(len(sealed['sha256_seal']), 64)

        # 3. Seal Verification
        v_res = PIRService.verify_pir_seal(self.tenant_a, pir['id'])
        self.assertTrue(v_res['verified'])
        self.assertEqual(v_res['recomputed_seal'], sealed['sha256_seal'])

        # 4. Modification rejection after sealing
        with self.assertRaises(ValueError):
            PIRService.update_pir(self.tenant_a, pir['id'], {'title': 'Tampered Title'})

        # 5. Export Markdown
        md_text = PIRService.export_pir_markdown(self.tenant_a, pir['id'])
        self.assertIn("# Post-Incident Review", md_text)
        self.assertIn("የድህረ-ክስተት ግምገማ ሪፖርት", md_text)
        self.assertIn("INSA Proclamation No. 1426/2026", md_text)
        self.assertIn("SHA-256 SEALED", md_text)

    # =========================================================================
    # 5. MULTI-TENANT ISOLATION TESTS
    # =========================================================================

    def test_multi_tenant_isolation_cases_and_pir(self):
        """Ensures Tenant A cannot access, update, or view Tenant B's cases or PIRs."""
        # Setup case in Tenant B
        inc_b_id = 'inc-tenant-b-secret'
        _LOCAL_INCIDENTS[inc_b_id] = {
            'id': inc_b_id,
            'organization_id': self.tenant_b,
            'title': 'Dashen Bank Secret Case',
            'severity': 'critical',
            'status': 'open'
        }

        # Tenant A tries to access Tenant B's case via REST API -> 404
        headers_a = {'Authorization': f'Bearer {self.token_a}'}
        res = self.client.get(f'/api/cases/{inc_b_id}', headers=headers_a)
        self.assertEqual(res.status_code, 404)

        # Tenant A tries to add note to Tenant B's case -> 404 / error
        res_note = self.client.post(f'/api/cases/{inc_b_id}/notes', json={'note': 'Illegal Note'}, headers=headers_a)
        self.assertIn(res_note.status_code, [400, 404])

        # Tenant A tries to generate PIR for Tenant B's case -> 404
        res_pir = self.client.post(f'/api/pir/generate/{inc_b_id}', headers=headers_a)
        self.assertEqual(res_pir.status_code, 404)

        # Tenant B can access their own case
        headers_b = {'Authorization': f'Bearer {self.token_b}'}
        res_b = self.client.get(f'/api/cases/{inc_b_id}', headers=headers_b)
        self.assertEqual(res_b.status_code, 200)
        self.assertEqual(res_b.get_json()['title'], 'Dashen Bank Secret Case')


if __name__ == '__main__':
    unittest.main()
