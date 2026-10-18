"""
Test Suite: Part 15 — Offline GeoIP/ASN, Tor/VPN/Hosting Detection,
Threat Intelligence Caching, and Internal Device Reputation Engine.
Verifies:
1. Offline GeoIP and ASN resolution for Ethiopian networks (Ethio Telecom, Safaricom Ethiopia) and private RFC1918 ranges.
2. Cloud hosting (AWS, DO, Hetzner) and foreign IP detection.
3. Tor exit node and anonymizing proxy flag detection.
4. Threat intelligence feed matching with cache layer.
5. Explainable device reputation engine based on internal telemetry history.
6. Multi-tenant isolation in device reputation scoring.
7. Full canonical event enrichment and REST API endpoints.
"""
import unittest
import uuid
from datetime import datetime, timezone

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.event_service import ingest_event
from app.services.enrichment_service import (
    lookup_ip_enrichment,
    calculate_device_reputation,
    enrich_canonical_event,
    add_threat_indicator,
    clear_enrichment_caches
)


class TestEnrichmentService(unittest.TestCase):
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
        clear_enrichment_caches()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_offline_geoip_ethiopian_ranges(self):
        """Test offline resolution of Ethiopian telecom ranges (Ethio Telecom, Safaricom) and RFC1918."""
        # 1. Ethio Telecom IP (196.188.12.34)
        info_ethio = lookup_ip_enrichment("196.188.12.34")
        self.assertEqual(info_ethio["country"], "ET")
        self.assertEqual(info_ethio["country_name"], "Ethiopia")
        self.assertEqual(info_ethio["asn"], "AS24757")
        self.assertIn("Ethio Telecom", info_ethio["as_org"])
        self.assertTrue(info_ethio["is_local_ethiopian"])
        self.assertFalse(info_ethio["is_hosting"])

        # 2. Safaricom Ethiopia IP (102.218.41.10)
        info_saf = lookup_ip_enrichment("102.218.41.10")
        self.assertEqual(info_saf["country"], "ET")
        self.assertEqual(info_saf["asn"], "AS329340")
        self.assertIn("Safaricom", info_saf["as_org"])
        self.assertTrue(info_saf["is_local_ethiopian"])

        # 3. Private RFC1918 (192.168.1.100 and 10.0.0.5)
        info_priv = lookup_ip_enrichment("192.168.1.100")
        self.assertEqual(info_priv["country"], "INTERNAL")
        self.assertTrue(info_priv["is_private"])
        self.assertFalse(info_priv["is_hosting"])

    def test_02_foreign_and_cloud_hosting_detection(self):
        """Test identification of cloud datacenter / VPS hosting providers."""
        # AWS IP
        info_aws = lookup_ip_enrichment("3.5.10.20")
        self.assertEqual(info_aws["country"], "US")
        self.assertTrue(info_aws["is_hosting"])
        self.assertFalse(info_aws["is_local_ethiopian"])

        # DigitalOcean IP
        info_do = lookup_ip_enrichment("167.99.1.5")
        self.assertTrue(info_do["is_hosting"])
        self.assertIn("DigitalOcean", info_do["as_org"])

    def test_03_tor_and_vpn_detection(self):
        """Test Tor exit node and commercial VPN / proxy identification."""
        # Known Tor Exit Node in test registry
        info_tor = lookup_ip_enrichment("185.220.101.5")
        self.assertTrue(info_tor["is_tor"])
        self.assertTrue(info_tor["is_vpn"] or info_tor["is_proxy"])

    def test_04_threat_intel_feed_caching(self):
        """Test matching against local/cached Threat Intelligence indicators."""
        test_ip = "198.51.100.77"
        add_threat_indicator(
            indicator_type="ip",
            value=test_ip,
            severity="critical",
            confidence=95,
            category="botnet_c2",
            description="Active C2 server targeting financial portals"
        )

        res = lookup_ip_enrichment(test_ip)
        ti = res.get("threat_intel") or {}
        self.assertEqual(ti.get("status"), "malicious")
        self.assertEqual(ti.get("category"), "botnet_c2")
        self.assertGreaterEqual(ti.get("score", 0), 80)

    def test_05_device_reputation_from_internal_history(self):
        """Test device reputation scoring from historical telemetry for an organization."""
        device_id = f"dev-test-{uuid.uuid4().hex[:8]}"

        # 1. Ingest events linking this device to multiple accounts and failures
        for i in range(4):
            ingest_event({
                "event_id": f"dev_ev_succ_{i}_{uuid.uuid4().hex[:6]}",
                "event_type": "LOGIN_SUCCESS",
                "organization_id": self.org_a,
                "user_id_pub": f"USR_MULE_{i}",
                "account_id_pub": f"ACC_MULE_{i}",
                "device_fingerprint": device_id,
                "source_ip": "196.188.12.34",
                "channel": "mobile",
                "result": "SUCCESS"
            })

        for j in range(3):
            ingest_event({
                "event_id": f"dev_ev_fail_{j}_{uuid.uuid4().hex[:6]}",
                "event_type": "LOGIN_FAILED",
                "organization_id": self.org_a,
                "user_id_pub": f"USR_VICTIM_{j}",
                "account_id_pub": f"ACC_VICTIM_{j}",
                "device_fingerprint": device_id,
                "source_ip": "196.188.12.34",
                "channel": "mobile",
                "result": "FAILURE"
            })

        # Calculate reputation for Tenant A
        rep_a = calculate_device_reputation(device_id, organization_id=self.org_a)
        self.assertGreaterEqual(rep_a["risk_score"], 60)
        self.assertIn(rep_a["reputation"], ("suspicious", "high_risk"))
        self.assertGreaterEqual(rep_a["accounts_seen_24h"], 4)
        self.assertGreaterEqual(rep_a["failed_logins_24h"], 3)
        self.assertTrue(len(rep_a["reasons"]) > 0)

        # 2. Strict Tenancy Isolation: Tenant B querying the same device sees clean baseline
        rep_b = calculate_device_reputation(device_id, organization_id=self.org_b)
        self.assertEqual(rep_b["accounts_seen_24h"], 0)
        self.assertEqual(rep_b["failed_logins_24h"], 0)
        self.assertEqual(rep_b["risk_score"], 0)
        self.assertEqual(rep_b["reputation"], "trusted")

    def test_06_enrich_canonical_event(self):
        """Test full enrichment of a canonical event dictionary."""
        event = {
            "event_id": f"ev_{uuid.uuid4().hex[:8]}",
            "organization_id": self.org_a,
            "event_type": "TRANSACTION",
            "source_ip": "196.188.12.34",
            "device_fingerprint": "dfp_android_102",
            "channel": "mobile",
            "amount": 5000.0,
            "currency": "ETB",
            "attributes": {"client": "Telebirr App"}
        }

        enriched = enrich_canonical_event(event)
        attrs = enriched.get("attributes", {})
        self.assertIn("enrichment", attrs)
        geo = attrs["enrichment"].get("geo", {})
        self.assertEqual(geo.get("country"), "ET")
        self.assertEqual(geo.get("asn"), "AS24757")
        self.assertTrue(geo.get("is_local_ethiopian"))

    def test_07_api_enrichment_endpoints(self):
        """Test REST API endpoints for IP and Device enrichment."""
        # 1. IP enrichment endpoint
        res_ip = self.client.get(
            "/api/enrichment/ip/196.188.12.34",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_ip.status_code, 200)
        data_ip = res_ip.get_json()
        self.assertEqual(data_ip["country"], "ET")
        self.assertEqual(data_ip["asn"], "AS24757")

        # 2. Device enrichment endpoint
        res_dev = self.client.get(
            "/api/enrichment/device/dfp_clean_001",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_dev.status_code, 200)
        data_dev = res_dev.get_json()
        self.assertIn("risk_score", data_dev)
        self.assertIn("reputation", data_dev)


if __name__ == '__main__':
    unittest.main()
