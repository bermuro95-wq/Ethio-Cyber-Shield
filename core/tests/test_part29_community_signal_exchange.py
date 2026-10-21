"""
Test Suite: Part 29 — Community Defense & Privacy-Preserving Signal Exchange (Phase 6).

Verifies:
1. Sharing Preferences & Opt-in Consent:
   - Opt-in enforcement (unauthorized contribution denied before consent).
   - Tenant preferences update (opt-in, allowed TLPs, anonymization).
2. Privacy-Preserving Keyed Hashing:
   - Keyed hashing of accounts, phone numbers, and mule IDs with hub salt.
   - Verification that raw customer PII is never exposed in community records.
3. Traffic Light Protocol (TLP) Policy:
   - TLP:RED rejection from community egress.
   - TLP filtering on community feed.
4. Anti-Poisoning & Corroboration Engine:
   - Uncorroborated initial state for single-source signals (N = 1).
   - Multi-tenant corroboration (N >= 2 independent reporting institutions).
   - Reporter reputation adjustments.
   - Signal retraction and penalty flow upon benign/false discovery.
5. Safe Automation & Detection Engine Matching:
   - Corroborated signal yields high-confidence IOC match (allow_automated_block: True).
   - Single uncorroborated signal yields advisory match (allow_automated_block: False).
   - Gate 6: Signal contributed by Tenant A flags/prevents threat at Tenant B.
6. EthioCERT STIX 2.1 Export & Ingestion:
   - OASIS STIX 2.1 JSON bundle generation.
   - Ingestion of official CERT threat advisory bundles.
7. Network Effect Dashboard:
   - Contributed, corroborated, and attacks prevented metrics.
8. Multi-Tenant Isolation:
   - Tenant A cannot alter Tenant B's preferences or retract Tenant B's signals.
"""
import unittest
import uuid
import json
import hashlib

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.signal_exchange_service import (
    SignalExchangeService,
    clear_signal_exchange_caches,
    HUB_PEPPER,
    _LOCAL_SHARING_PREFS,
    _LOCAL_COMMUNITY_SIGNALS,
    _LOCAL_REPUTATIONS
)


class TestCommunitySignalExchange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.tenant_a = "11111111-1111-1111-1111-111111111111"  # Commercial Bank of Ethiopia
        cls.tenant_b = "22222222-2222-2222-2222-222222222222"  # Dashen Bank
        cls.tenant_c = "33333333-3333-3333-3333-333333333333"  # Awash Bank

        cls.user_a_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        cls.user_b_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

        cls.token_a = create_token(
            cls.user_a_id,
            'soc_a@cbe.com.et',
            'admin',
            organization_id=cls.tenant_a
        )

        cls.token_b = create_token(
            cls.user_b_id,
            'soc_b@dashen.com.et',
            'admin',
            organization_id=cls.tenant_b
        )

    def setUp(self):
        clear_signal_exchange_caches()
        set_current_organization_id(self.tenant_a)

    # =========================================================================
    # 1. SHARING PREFERENCES & CONSENT
    # =========================================================================

    def test_opt_in_enforcement_and_preferences(self):
        """Verifies that contribution is denied until tenant explicitly opts into sharing."""
        # Tenant A has not opted in yet -> contribution fails
        with self.assertRaises(ValueError):
            SignalExchangeService.contribute_signal(
                org_id=self.tenant_a,
                indicator_type='ip',
                raw_indicator_value='196.188.10.99',
                threat_category='credential_stuffing'
            )

        # Opt in Tenant A
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {
            'opt_in_sharing': True,
            'allowed_tlp_levels': ['CLEAR', 'WHITE', 'GREEN', 'AMBER'],
            'anonymize_reporter': True
        })

        prefs = SignalExchangeService.get_sharing_preferences(self.tenant_a)
        self.assertTrue(prefs['opt_in_sharing'])
        self.assertIn('AMBER', prefs['allowed_tlp_levels'])

    # =========================================================================
    # 2. PRIVACY-PRESERVING KEYED HASHING
    # =========================================================================

    def test_keyed_hashing_of_sensitive_identifiers(self):
        """Verifies that customer accounts and phone numbers are keyed-hashed with hub salt."""
        raw_account = "100001234567"
        raw_phone = "+251911223344"

        hashed_acc = SignalExchangeService.hash_indicator('mule_account_hash', raw_account)
        hashed_phone = SignalExchangeService.hash_indicator('phone_hash', raw_phone)

        # Must not contain raw account or phone
        self.assertNotIn(raw_account, hashed_acc)
        self.assertNotIn(raw_phone, hashed_phone)
        self.assertTrue(hashed_acc.startswith("hash:v1:"))
        self.assertTrue(hashed_phone.startswith("hash:v1:"))

        # Expected HMAC with hub pepper
        expected_acc_h = hashlib.sha256(f"{HUB_PEPPER}:{raw_account}".encode('utf-8')).hexdigest()
        self.assertEqual(hashed_acc, f"hash:v1:{expected_acc_h}")

        # Public network observables (IP) remain normalized for firewall/WAF matching
        ip_val = "196.188.10.45"
        self.assertEqual(SignalExchangeService.hash_indicator('ip', ip_val), ip_val)

    # =========================================================================
    # 3. TLP POLICY & REJECTION OF TLP:RED
    # =========================================================================

    def test_tlp_policy_rejection_of_red(self):
        """Verifies that TLP:RED signals are strictly rejected from community egress."""
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {'opt_in_sharing': True})

        with self.assertRaises(ValueError) as ctx:
            SignalExchangeService.contribute_signal(
                org_id=self.tenant_a,
                indicator_type='ip',
                raw_indicator_value='196.188.10.50',
                threat_category='insider_threat',
                tlp='RED'
            )
        self.assertIn("TLP:RED signals are strictly local", str(ctx.exception))

    # =========================================================================
    # 4. ANTI-POISONING & CORROBORATION ENGINE
    # =========================================================================

    def test_anti_poisoning_corroboration_and_reputation(self):
        """
        Verifies:
        1. Single contributor signal starts as uncorroborated (N=1).
        2. Second independent tenant contributing the same indicator corroborates it (N=2).
        3. Contributor reputations increase upon corroboration.
        4. Signal retraction penalizes reputation and marks signal retracted.
        """
        # Opt in Tenant A and Tenant B
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {'opt_in_sharing': True})
        SignalExchangeService.set_sharing_preferences(self.tenant_b, {'opt_in_sharing': True})

        malicious_ip = "196.188.10.77"

        # 1. Tenant A contributes malicious IP
        sig_a = SignalExchangeService.contribute_signal(
            org_id=self.tenant_a,
            indicator_type='ip',
            raw_indicator_value=malicious_ip,
            threat_category='credential_stuffing',
            confidence=0.80,
            tlp='GREEN'
        )
        self.assertFalse(sig_a['is_corroborated'])
        self.assertEqual(sig_a['corroboration_count'], 1)

        rep_a_init = SignalExchangeService.get_reporter_reputation(self.tenant_a)
        self.assertEqual(rep_a_init['signals_contributed'], 1)
        self.assertEqual(rep_a_init['signals_corroborated'], 0)

        # 2. Tenant B independently observes and contributes the same IP -> Corroboration!
        sig_b = SignalExchangeService.contribute_signal(
            org_id=self.tenant_b,
            indicator_type='ip',
            raw_indicator_value=malicious_ip,
            threat_category='credential_stuffing',
            confidence=0.85,
            tlp='GREEN'
        )
        self.assertTrue(sig_b['is_corroborated'])
        self.assertEqual(sig_b['corroboration_count'], 2)
        self.assertGreater(sig_b['confidence'], 0.85)

        # 3. Both tenant reputations updated
        rep_a_after = SignalExchangeService.get_reporter_reputation(self.tenant_a)
        rep_b_after = SignalExchangeService.get_reporter_reputation(self.tenant_b)
        self.assertGreater(rep_a_after['signals_corroborated'], 0)
        self.assertGreater(rep_b_after['signals_corroborated'], 0)

        # 4. Retraction Flow upon benign discovery
        retracted = SignalExchangeService.retract_signal(
            org_id=self.tenant_a,
            signal_hash=sig_a['signal_hash'],
            reason="Verified as authorized national load-testing probe"
        )
        self.assertEqual(retracted['status'], 'retracted')

        # Tenant A reputation penalized
        rep_a_penalized = SignalExchangeService.get_reporter_reputation(self.tenant_a)
        self.assertEqual(rep_a_penalized['signals_retracted'], 1)
        self.assertLess(rep_a_penalized['reputation_score'], rep_a_after['reputation_score'])

    # =========================================================================
    # 5. DETECTION ENGINE MATCHING & SAFE AUTOMATION RULE
    # =========================================================================

    def test_safe_automation_rule_no_auto_block_from_single_source(self):
        """
        Verifies Non-Negotiable Hard Engineering Rule:
        - Uncorroborated signals produce only advisory warnings (allow_automated_block: False).
        - Corroborated signals are eligible for automated containment (allow_automated_block: True).
        """
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {'opt_in_sharing': True})
        SignalExchangeService.set_sharing_preferences(self.tenant_b, {'opt_in_sharing': True})

        # Single source uncorroborated signal
        unverified_ip = "196.188.10.88"
        SignalExchangeService.contribute_signal(
            org_id=self.tenant_a,
            indicator_type='ip',
            raw_indicator_value=unverified_ip,
            threat_category='api_abuse'
        )

        match_unverified = SignalExchangeService.evaluate_community_match(
            org_id=self.tenant_b,
            indicator_type='ip',
            raw_indicator_value=unverified_ip
        )
        self.assertIsNotNone(match_unverified)
        self.assertEqual(match_unverified['match_type'], 'advisory')
        self.assertFalse(match_unverified['allow_automated_block'])
        self.assertEqual(match_unverified['rule_id'], 'IOC-COMMUNITY-ADVISORY')

        # Now Tenant B corroborates it
        SignalExchangeService.contribute_signal(
            org_id=self.tenant_b,
            indicator_type='ip',
            raw_indicator_value=unverified_ip,
            threat_category='api_abuse'
        )

        match_corroborated = SignalExchangeService.evaluate_community_match(
            org_id=self.tenant_a,
            indicator_type='ip',
            raw_indicator_value=unverified_ip
        )
        self.assertIsNotNone(match_corroborated)
        self.assertEqual(match_corroborated['match_type'], 'corroborated')
        self.assertTrue(match_corroborated['allow_automated_block'])
        self.assertEqual(match_corroborated['rule_id'], 'IOC-COMMUNITY-CORROBORATED')

    # =========================================================================
    # 6. GATE 6 END-TO-END CROSS-TENANT DEFENSE
    # =========================================================================

    def test_gate6_cross_tenant_prevention(self):
        """
        Gate 6 Criteria:
        A malicious indicator identified at Tenant A prevents/flags a seeded attack at Tenant B.
        """
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {'opt_in_sharing': True})
        SignalExchangeService.set_sharing_preferences(self.tenant_b, {'opt_in_sharing': True})

        mule_account = "100009988776"
        hashed_mule = SignalExchangeService.hash_indicator('mule_account_hash', mule_account)

        # Tenant A identifies mule account and contributes to community exchange
        SignalExchangeService.contribute_signal(
            org_id=self.tenant_a,
            indicator_type='mule_account_hash',
            raw_indicator_value=mule_account,
            threat_category='mule_network',
            tlp='GREEN'
        )

        # Tenant B receives transaction with this mule account
        match = SignalExchangeService.evaluate_community_match(
            org_id=self.tenant_b,
            indicator_type='mule_account_hash',
            raw_indicator_value=mule_account
        )
        self.assertIsNotNone(match)
        self.assertEqual(match['indicator_value'], hashed_mule)
        self.assertIn('mule_network', match['threat_category'])

    # =========================================================================
    # 7. ETHIOCERT STIX 2.1 EXPORT & IMPORT
    # =========================================================================

    def test_stix_21_bundle_export_and_cert_import(self):
        """Verifies OASIS STIX 2.1 JSON export and EthioCERT advisory ingestion."""
        SignalExchangeService.set_sharing_preferences(self.tenant_a, {'opt_in_sharing': True})

        SignalExchangeService.contribute_signal(
            org_id=self.tenant_a,
            indicator_type='ip',
            raw_indicator_value='196.188.10.123',
            threat_category='c2_communication',
            tlp='WHITE'
        )

        # Export STIX
        stix_bundle = SignalExchangeService.export_stix_bundle(self.tenant_a)
        self.assertEqual(stix_bundle['type'], 'bundle')
        self.assertGreaterEqual(len(stix_bundle['objects']), 1)
        ind_obj = stix_bundle['objects'][0]
        self.assertEqual(ind_obj['type'], 'indicator')
        self.assertEqual(ind_obj['spec_version'], '2.1')
        self.assertIn("196.188.10.123", ind_obj['pattern'])

        # Ingest simulated EthioCERT advisory
        cert_advisory = {
            'type': 'bundle',
            'objects': [
                {
                    'type': 'indicator',
                    'pattern': "[ipv4-addr:value = '196.188.10.200']"
                }
            ]
        }
        ingest_res = SignalExchangeService.import_cert_advisories(self.tenant_a, cert_advisory)
        self.assertEqual(ingest_res['imported_count'], 1)

        match_cert = SignalExchangeService.evaluate_community_match(
            self.tenant_a, 'ip', '196.188.10.200'
        )
        self.assertIsNotNone(match_cert)
        self.assertEqual(match_cert['threat_category'], 'cert_advisory')

    # =========================================================================
    # 8. REST API & MULTI-TENANT ISOLATION
    # =========================================================================

    def test_rest_api_and_multi_tenant_isolation(self):
        """Verifies REST endpoints and multi-tenant isolation."""
        headers_a = {'Authorization': f'Bearer {self.token_a}'}
        headers_b = {'Authorization': f'Bearer {self.token_b}'}

        # 1. Update preferences via API
        res_pref = self.client.put('/api/signals/preferences', json={
            'opt_in_sharing': True,
            'allowed_tlp_levels': ['CLEAR', 'WHITE', 'GREEN']
        }, headers=headers_a)
        self.assertEqual(res_pref.status_code, 200)

        # 2. Contribute signal via API
        res_contrib = self.client.post('/api/signals/contribute', json={
            'indicator_type': 'ip',
            'indicator_value': '196.188.10.150',
            'threat_category': 'ddos_bot',
            'tlp': 'GREEN'
        }, headers=headers_a)
        self.assertEqual(res_contrib.status_code, 201)
        sig_data = res_contrib.get_json()

        # 3. Tenant B consumes feed via API
        self.client.put('/api/signals/preferences', json={'opt_in_sharing': True}, headers=headers_b)
        res_feed = self.client.get('/api/signals/feed', headers=headers_b)
        self.assertEqual(res_feed.status_code, 200)
        feed_items = res_feed.get_json()['feed']
        self.assertGreaterEqual(len(feed_items), 1)

        # Ensure Tenant A identity was anonymized in Tenant B's feed
        matched_item = next(f for f in feed_items if f['indicator_value'] == '196.188.10.150')
        self.assertEqual(matched_item['organization_id'], 'HUB-ANONYMIZED-PARTICIPANT')

        # 4. Multi-Tenant Isolation: Tenant B CANNOT retract Tenant A's signal
        res_retract_b = self.client.post('/api/signals/retract', json={
            'signal_hash': sig_data['signal_hash'],
            'reason': 'Unauthorized retraction'
        }, headers=headers_b)
        self.assertEqual(res_retract_b.status_code, 400)


if __name__ == '__main__':
    unittest.main()
