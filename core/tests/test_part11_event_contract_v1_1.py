"""
Test Suite: Part 11 — ECS Canonical Event Contract v1.1 Validation, Channel Normalization,
Privacy-Preserving PII Hashing, and Multi-Tenant Telemetry Ingestion.
"""
import unittest
import uuid
import hashlib
from datetime import datetime, timezone
from app import create_app
from app.schemas.event_contract import validate_and_normalize_event
from app.services.event_service import ingest_event, query_events
from app.services.tenant_service import set_current_organization_id


class TestEventContractV11(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.org_a = str(uuid.uuid4())
        self.org_b = str(uuid.uuid4())
        set_current_organization_id(self.org_a)

    def tearDown(self):
        set_current_organization_id(None)

    def test_schema_validator_valid_v11_event(self):
        """Test validate_and_normalize_event accepts full valid v1.1 event."""
        payload = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.created",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source_system": "cbe-mobile-backend",
            "channel": "mobile",
            "payment_rail": "wallet",
            "amount_minor": 250000,
            "currency": "ETB",
            "user_id_pub": "USR_1001",
            "account_id_pub": "ACC_2002",
            "counterparty_ref_hash": hashlib.sha256(b"DEST_9988").hexdigest(),
            "msisdn_hash": hashlib.sha256(b"+251911223344").hexdigest(),
            "national_id_hash": hashlib.sha256(b"FAYDA-123456").hexdigest(),
            "device_fingerprint": "dfp_android_samsung_a12",
            "locale_tz": "Africa/Addis_Ababa",
            "result": "SUCCESS",
            "attributes": {"carrier": "Ethio Telecom"}
        }
        is_valid, norm, errors = validate_and_normalize_event(payload, default_org_id=self.org_a)
        self.assertTrue(is_valid, f"Validation failed with: {errors}")
        self.assertEqual(len(errors), 0)
        self.assertEqual(norm["channel"], "mobile")
        self.assertEqual(norm["payment_rail"], "wallet")
        self.assertEqual(norm["amount_minor"], 250000)
        self.assertEqual(norm["amount"], 2500.0)
        self.assertEqual(norm["locale_tz"], "Africa/Addis_Ababa")
        self.assertEqual(norm["organization_id"], self.org_a)

    def test_channel_and_brand_mapping_normalization(self):
        """Test that local Ethiopian brands and channel aliases normalize to generic types."""
        # 1. Telebirr -> wallet
        payload = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.created",
            "source_system": "telebirr-gateway",
            "channel": "app",
            "payment_rail": "Telebirr",
            "amount": 1000.0,
        }
        is_valid, norm, errors = validate_and_normalize_event(payload)
        self.assertTrue(is_valid, f"Failed: {errors}")
        self.assertEqual(norm["channel"], "mobile")
        self.assertEqual(norm["payment_rail"], "wallet")
        self.assertEqual(norm["amount_minor"], 100000)

        # 2. EthSwitch -> interbank
        payload2 = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.created",
            "channel": "ussd_session",
            "payment_rail": "EthSwitch",
        }
        is_valid2, norm2, _ = validate_and_normalize_event(payload2)
        self.assertTrue(is_valid2)
        self.assertEqual(norm2["channel"], "ussd")
        self.assertEqual(norm2["payment_rail"], "interbank")

        # 3. CBE Birr -> wallet
        payload3 = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.created",
            "payment_rail": "cbe birr",
        }
        is_valid3, norm3, _ = validate_and_normalize_event(payload3)
        self.assertTrue(is_valid3)
        self.assertEqual(norm3["payment_rail"], "wallet")

    def test_privacy_preserving_auto_hashing_and_scrubbing(self):
        """Test that raw PII (phone, Fayda ID, counterparty) is scrubbed and hashed."""
        raw_phone = "+251911223344"
        raw_fayda = "FAYDA-9876543210"
        raw_dest_acc = "1000123456789"

        payload = {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": "transaction.transfer.created",
            "phone": raw_phone,
            "national_id": raw_fayda,
            "counterparty_ref": raw_dest_acc,
            "attributes": {
                "msisdn": raw_phone,
                "fayda_id": raw_fayda,
                "notes": "Remittance for family"
            }
        }
        is_valid, norm, errors = validate_and_normalize_event(payload)
        self.assertTrue(is_valid, f"Failed: {errors}")

        # Check raw values are removed from top-level and attributes
        self.assertNotIn("phone", norm)
        self.assertNotIn("national_id", norm)
        self.assertNotIn("counterparty_ref", norm)
        self.assertNotIn("msisdn", norm["attributes"])
        self.assertNotIn("phone", norm["attributes"])
        self.assertNotIn("fayda_id", norm["attributes"])

        # Check SHA-256 hashes are properly calculated
        expected_phone_hash = hashlib.sha256(raw_phone.encode('utf-8')).hexdigest()
        expected_fayda_hash = hashlib.sha256(raw_fayda.encode('utf-8')).hexdigest()
        expected_dest_hash = hashlib.sha256(raw_dest_acc.encode('utf-8')).hexdigest()

        self.assertEqual(norm["msisdn_hash"], expected_phone_hash)
        self.assertEqual(norm["national_id_hash"], expected_fayda_hash)
        self.assertEqual(norm["counterparty_ref_hash"], expected_dest_hash)

    def test_backward_compatibility_v10_events(self):
        """Test v1.0 canonical events pass validation and adopt sensible v1.1 defaults."""
        v10_payload = {
            "event_id": f"evt-legacy-{uuid.uuid4().hex[:8]}",
            "event_type": "auth.login.failed",
            "source_ip": "196.188.10.22",
            "user_id_pub": "USR_LEGACY_1",
            "account_id_pub": "ACC_LEGACY_1",
            "result": "FAILURE"
        }
        is_valid, norm, errors = validate_and_normalize_event(v10_payload, default_org_id=self.org_a)
        self.assertTrue(is_valid, f"Legacy payload failed: {errors}")
        self.assertEqual(norm["channel"], "web")
        self.assertEqual(norm["locale_tz"], "Africa/Addis_Ababa")
        self.assertEqual(norm["currency"], "ETB")
        self.assertIsNone(norm["payment_rail"])

    def test_invalid_schema_rejection(self):
        """Test invalid events are rejected with specific errors."""
        # Missing event_id
        is_valid, _, errors = validate_and_normalize_event({"event_type": "login"})
        self.assertFalse(is_valid)
        self.assertTrue(any("event_id" in e for e in errors))

        # Missing event_type
        is_valid, _, errors = validate_and_normalize_event({"event_id": "evt-1"})
        self.assertFalse(is_valid)
        self.assertTrue(any("event_type" in e for e in errors))

        # Invalid channel
        is_valid, _, errors = validate_and_normalize_event({
            "event_id": "evt-2",
            "event_type": "test",
            "channel": "satellite_radio"
        })
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid channel" in e for e in errors))

        # Invalid payment rail
        is_valid, _, errors = validate_and_normalize_event({
            "event_id": "evt-3",
            "event_type": "test",
            "payment_rail": "crypto_dogecoin"
        })
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid payment_rail" in e for e in errors))

        # Malformed msisdn_hash (not 64-char hex)
        is_valid, _, errors = validate_and_normalize_event({
            "event_id": "evt-4",
            "event_type": "test",
            "msisdn_hash": "not-a-valid-sha256"
        })
        self.assertFalse(is_valid)
        self.assertTrue(any("msisdn_hash" in e for e in errors))

    def test_end_to_end_ingest_and_query_v11(self):
        """Test full ingestion service flow with v1.1 channel and rail fields."""
        evt_id = f"evt-e2e-{uuid.uuid4().hex[:10]}"
        payload = {
            "event_id": evt_id,
            "organization_id": self.org_a,
            "event_type": "transaction.transfer.created",
            "channel": "ussd",
            "payment_rail": "wallet",
            "source_system": "ussd-core",
            "account_id": "ACC_USSD_99",
            "amount": 450.0,
            "msisdn_hash": hashlib.sha256(b"+251922334455").hexdigest(),
            "counterparty_ref_hash": hashlib.sha256(b"BEN_USSD_11").hexdigest(),
            "attributes": {"shortcode": "*990#"}
        }
        res = ingest_event(payload)
        self.assertEqual(res["status"], "received")
        self.assertEqual(res["event_id"], evt_id)

        # Query events by channel
        results = query_events(channel="ussd", account="ACC_USSD_99")
        self.assertTrue(any(r["event_id"] == evt_id for r in results))

    def test_contract_schema_api_route(self):
        """Test that /api/events/contract serves the canonical contract specification."""
        res = self.client.get('/api/events/contract')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["version"], "1.1.0")
        self.assertEqual(data["standard"], "ECS Event Contract v1.1")
        self.assertIn("schema", data)
        self.assertIn("properties", data["schema"])
        self.assertIn("channel", data["schema"]["properties"])
        self.assertIn("payment_rail", data["schema"]["properties"])

    def test_multi_tenancy_isolation_v11(self):
        """Test that Tenant A cannot query Tenant B's v1.1 events."""
        evt_a = f"evt-org-a-{uuid.uuid4().hex[:8]}"
        evt_b = f"evt-org-b-{uuid.uuid4().hex[:8]}"

        # Ingest for Org A
        set_current_organization_id(self.org_a)
        ingest_event({
            "event_id": evt_a,
            "organization_id": self.org_a,
            "event_type": "transaction.transfer.created",
            "channel": "mobile",
            "source_system": "tenant-a-sys"
        })

        # Ingest for Org B
        set_current_organization_id(self.org_b)
        ingest_event({
            "event_id": evt_b,
            "organization_id": self.org_b,
            "event_type": "transaction.transfer.created",
            "channel": "mobile",
            "source_system": "tenant-b-sys"
        })

        # Query as Org A
        set_current_organization_id(self.org_a)
        events_a = query_events(channel="mobile")
        ids_a = [e["event_id"] for e in events_a]
        self.assertIn(evt_a, ids_a)
        self.assertNotIn(evt_b, ids_a)

        # Query as Org B
        set_current_organization_id(self.org_b)
        events_b = query_events(channel="mobile")
        ids_b = [e["event_id"] for e in events_b]
        self.assertIn(evt_b, ids_b)
        self.assertNotIn(evt_a, ids_b)


if __name__ == '__main__':
    unittest.main()
