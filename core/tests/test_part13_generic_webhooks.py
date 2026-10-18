"""
Test Suite: Part 13 — Generic Inbound Webhook Receiver & Configurable Field Mapper Engine.
Verifies:
1. JSONPath extraction and value transformations (amount_to_minor, timestamp_iso, value_map, phone normalization).
2. Third-party webhook mapping into canonical ECS Event Contract v1.1.
3. Test-with-sample diagnostic runner.
4. Webhook sources CRUD with envelope encryption of secret tokens and strict multi-tenancy isolation.
5. Inbound receiver authentication (Token and HMAC-SHA256 signatures).
6. End-to-end ingestion pipeline integration for mapped webhook events.
"""
import unittest
import json
import uuid
import hmac
import hashlib
from datetime import datetime, timezone

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.crypto_service import decrypt_secret
from app.services.field_mapper import (
    extract_jsonpath,
    apply_transforms,
    apply_mapping,
    test_mapping
)
from app.services.webhook_service import (
    create_webhook_source,
    get_webhook_source,
    list_webhook_sources,
    delete_webhook_source,
    verify_webhook_auth,
    _LOCAL_WEBHOOK_SOURCES
)


class TestGenericWebhooks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())

        cls.user_admin_a = str(uuid.uuid4())
        cls.user_admin_b = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@tenant-a.et", "admin", organization_id=cls.org_a)
        cls.token_admin_b = create_token(cls.user_admin_b, "admin@tenant-b.et", "admin", organization_id=cls.org_b)

    def setUp(self):
        set_current_organization_id(self.org_a)

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_jsonpath_extraction(self):
        """Test extraction of values from nested JSON structures using JSONPath notation."""
        sample = {
            "event": "charge.completed",
            "data": {
                "id": "tx_998877",
                "customer": {
                    "name": "Almaz Kebede",
                    "phones": ["+251911223344", "+251922334455"]
                },
                "items": [
                    {"code": "AIRTIME_01", "price": 100},
                    {"code": "FEES", "price": 2.5}
                ]
            },
            "meta": {
                "ip": "196.188.12.34"
            }
        }

        # 1. Direct and nested dot notation
        self.assertEqual(extract_jsonpath(sample, "$.event"), "charge.completed")
        self.assertEqual(extract_jsonpath(sample, "event"), "charge.completed")
        self.assertEqual(extract_jsonpath(sample, "$.data.id"), "tx_998877")
        self.assertEqual(extract_jsonpath(sample, "data.customer.name"), "Almaz Kebede")

        # 2. Array index notation
        self.assertEqual(extract_jsonpath(sample, "$.data.customer.phones[0]"), "+251911223344")
        self.assertEqual(extract_jsonpath(sample, "$.data.items[0].code"), "AIRTIME_01")
        self.assertEqual(extract_jsonpath(sample, "data.items[1].price"), 2.5)

        # 3. Missing keys return default
        self.assertIsNone(extract_jsonpath(sample, "$.data.non_existent"))
        self.assertEqual(extract_jsonpath(sample, "$.data.non_existent", default="FALLBACK"), "FALLBACK")
        self.assertIsNone(extract_jsonpath(sample, "$.data.items[99].code"))

    def test_02_value_transforms(self):
        """Test value transformation functions."""
        # 1. amount_to_minor
        self.assertEqual(apply_transforms(250.50, transform="amount_to_minor"), 25050)
        self.assertEqual(apply_transforms("100.00", transform="amount_to_minor"), 10000)

        # 2. minor_to_amount
        self.assertEqual(apply_transforms(50000, transform="minor_to_amount"), 500.0)

        # 3. value_map
        status_map = {"charge.success": "SUCCESS", "charge.failed": "FAILURE"}
        self.assertEqual(apply_transforms("charge.success", value_map=status_map), "SUCCESS")
        self.assertEqual(apply_transforms("charge.failed", value_map=status_map), "FAILURE")
        self.assertEqual(apply_transforms("charge.unknown", value_map=status_map, default="HELD"), "HELD")

        # 4. timestamp_iso
        epoch_sec = 1776510000
        iso_res = apply_transforms(epoch_sec, transform="timestamp_iso")
        self.assertTrue("T" in iso_res and "+00:00" in iso_res or iso_res.endswith("Z"))

    def test_03_field_mapper_full_event(self):
        """Test full mapping of a third-party payment gateway payload to canonical Event Contract v1.1."""
        raw_gateway_webhook = {
            "event": "transaction.success",
            "reference": "CHAPA_REF_102938",
            "amount": 4500.00,
            "currency": "ETB",
            "method": "telebirr",
            "timestamp": "2026-10-18T10:30:00Z",
            "payer": {
                "phone_number": "0911223344",
                "account_id": "ACC_SENDER_01",
                "client_ip": "197.156.104.22"
            },
            "receiver": {
                "account_number": "ACC_RECEIVER_99",
                "name": "Ethiopian Electric Power"
            }
        }

        mapping_rules = {
            "event_id": {"path": "$.reference"},
            "event_type": {"default": "TRANSACTION"},
            "channel": {"default": "mobile"},
            "payment_rail": {"path": "$.method"},
            "action": {"default": "transfer"},
            "result": {
                "path": "$.event",
                "value_map": {"transaction.success": "SUCCESS", "transaction.failed": "FAILURE"}
            },
            "amount": {"path": "$.amount", "transform": "to_float"},
            "currency": {"path": "$.currency", "default": "ETB"},
            "occurred_at": {"path": "$.timestamp"},
            "actor": {
                "actor_id": {"path": "$.payer.account_id"},
                "account_number": {"path": "$.payer.account_id"},
                "phone": {"path": "$.payer.phone_number"},
                "ip": {"path": "$.payer.client_ip"}
            },
            "target": {
                "counterparty_ref": {"path": "$.receiver.account_number"},
                "counterparty_name": {"path": "$.receiver.name"}
            }
        }

        is_valid, norm_event, errors = apply_mapping(
            raw_gateway_webhook,
            mapping_rules,
            default_org_id=self.org_a,
            source_name="Chapa Gateway"
        )

        self.assertTrue(is_valid, f"Mapping failed with errors: {errors}")
        self.assertEqual(norm_event["event_id"], "CHAPA_REF_102938")
        self.assertEqual(norm_event["organization_id"], self.org_a)
        self.assertEqual(norm_event["channel"], "mobile")
        self.assertEqual(norm_event["payment_rail"], "wallet")  # telebirr normalized to wallet
        self.assertEqual(norm_event["amount"], 4500.0)
        self.assertEqual(norm_event["amount_minor"], 450000)
        self.assertEqual(norm_event["currency"], "ETB")
        self.assertEqual(norm_event["result"], "SUCCESS")
        self.assertEqual(norm_event["source_ip"], "197.156.104.22")

        # Privacy hashes
        expected_msisdn_hash = hashlib.sha256(b"+251911223344").hexdigest()
        self.assertEqual(norm_event["msisdn_hash"], expected_msisdn_hash)
        expected_counterparty_hash = hashlib.sha256(b"ACC_RECEIVER_99").hexdigest()
        self.assertEqual(norm_event["counterparty_ref_hash"], expected_counterparty_hash)

    def test_04_test_mapping_diagnostics(self):
        """Test test_mapping runner diagnostics endpoint functionality."""
        sample_payload = {
            "tradeNo": "TB_998811",
            "totalAmount": 1250.75,
            "payer": "+251912345678"
        }
        rules = {
            "event_id": {"path": "$.tradeNo"},
            "event_type": {"default": "TRANSACTION"},
            "amount": {"path": "$.totalAmount"},
            "payment_rail": {"default": "telebirr"},
            "actor": {
                "phone": {"path": "$.payer"}
            }
        }

        diagnostics = test_mapping(sample_payload, rules, default_org_id=self.org_a)
        self.assertTrue(diagnostics["success"])
        self.assertTrue(diagnostics["is_valid"])
        self.assertGreater(diagnostics["fields_mapped_count"], 3)
        self.assertEqual(diagnostics["normalized_event"]["payment_rail"], "wallet")
        self.assertEqual(diagnostics["normalized_event"]["amount_minor"], 125075)

    def test_05_webhook_source_crud_and_tenancy(self):
        """Test creating, listing, and isolating webhook sources between tenants."""
        source_data = {
            "source_id": f"src-{uuid.uuid4().hex[:8]}",
            "name": "Telebirr Merchant Callback",
            "auth_type": "token",
            "secret_token": "secret-token-telebirr-xyz",
            "signature_header": "X-Webhook-Secret",
            "mapping_rules": {
                "event_id": {"path": "$.tx_id"},
                "amount": {"path": "$.amount"}
            }
        }

        # 1. Register as Tenant A
        res = self.client.post(
            "/api/webhooks/sources",
            headers={"Authorization": f"Bearer {self.token_admin_a}"},
            json=source_data
        )
        self.assertIn(res.status_code, (200, 201))
        created = res.get_json()
        self.assertEqual(created["source_id"], source_data["source_id"])
        self.assertEqual(created["organization_id"], self.org_a)
        # Secret must be masked in API output
        self.assertNotIn("secret-token-telebirr-xyz", created.get("secret_token_masked", ""))
        self.assertNotIn("secret_token", created)

        # 2. Verify stored secret is encrypted at rest
        stored = get_webhook_source(source_data["source_id"], org_id=self.org_a)
        self.assertIsNotNone(stored)
        raw_stored_sec = stored.get("secret_token")
        self.assertTrue(raw_stored_sec.startswith("enc:v1:"), "Secret must be envelope encrypted with enc:v1: prefix")
        self.assertEqual(decrypt_secret(raw_stored_sec), "secret-token-telebirr-xyz")

        # 3. Tenant B cannot list or access Tenant A's webhook source
        res_b = self.client.get(
            f"/api/webhooks/sources/{source_data['source_id']}",
            headers={"Authorization": f"Bearer {self.token_admin_b}"}
        )
        self.assertEqual(res_b.status_code, 404, "Tenant B must not access Tenant A's webhook source")

        list_b = self.client.get(
            "/api/webhooks/sources",
            headers={"Authorization": f"Bearer {self.token_admin_b}"}
        )
        sources_b = list_b.get_json() or []
        self.assertFalse(any(s["source_id"] == source_data["source_id"] for s in sources_b))

    def test_06_inbound_webhook_token_auth(self):
        """Test inbound webhook receiver with token authentication."""
        src_id = f"token-src-{uuid.uuid4().hex[:8]}"
        secret = "auth-token-cbe-birr-999"
        create_webhook_source({
            "source_id": src_id,
            "name": "CBE Birr Inbound",
            "auth_type": "token",
            "secret_token": secret,
            "signature_header": "X-Webhook-Secret",
            "mapping_rules": {
                "event_id": {"path": "$.referenceId"},
                "event_type": {"default": "TRANSACTION"},
                "amount": {"path": "$.transAmount"},
                "payment_rail": {"default": "cbe_birr"},
                "result": {"default": "SUCCESS"}
            }
        }, org_id=self.org_a)

        payload = {
            "referenceId": f"CBE_{uuid.uuid4().hex[:10]}",
            "transAmount": 8900.00
        }

        # 1. Valid token in header
        res_ok = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={"X-Webhook-Secret": secret, "Content-Type": "application/json"},
            json=payload
        )
        self.assertIn(res_ok.status_code, (200, 202))
        data_ok = res_ok.get_json()
        self.assertEqual(data_ok["status"], "accepted")
        self.assertEqual(data_ok["event_id"], payload["referenceId"])

        # 2. Missing token
        res_no_tok = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        self.assertEqual(res_no_tok.status_code, 401)

        # 3. Invalid token
        res_bad_tok = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={"X-Webhook-Secret": "wrong-secret", "Content-Type": "application/json"},
            json=payload
        )
        self.assertEqual(res_bad_tok.status_code, 401)

    def test_07_inbound_webhook_hmac_sha256_auth(self):
        """Test inbound webhook receiver with HMAC-SHA256 signature verification."""
        src_id = f"hmac-src-{uuid.uuid4().hex[:8]}"
        secret = "super-secret-hmac-key-256"
        create_webhook_source({
            "source_id": src_id,
            "name": "Signed Gateway Webhook",
            "auth_type": "hmac_sha256",
            "secret_token": secret,
            "signature_header": "X-Signature-SHA256",
            "mapping_rules": {
                "event_id": {"path": "$.tx_id"},
                "event_type": {"default": "TRANSACTION"},
                "amount": {"path": "$.amount"},
                "payment_rail": {"default": "interbank"},
                "result": {"default": "SUCCESS"}
            }
        }, org_id=self.org_a)

        body_dict = {
            "tx_id": f"ETH_{uuid.uuid4().hex[:8]}",
            "amount": 150000.00
        }
        body_bytes = json.dumps(body_dict).encode("utf-8")
        valid_signature = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

        # 1. Valid HMAC signature
        res_ok = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={
                "X-Signature-SHA256": valid_signature,
                "Content-Type": "application/json"
            },
            data=body_bytes
        )
        self.assertIn(res_ok.status_code, (200, 202))

        # 2. Tampered body with original signature
        tampered_bytes = json.dumps({"tx_id": body_dict["tx_id"], "amount": 999999.00}).encode("utf-8")
        res_tampered = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={
                "X-Signature-SHA256": valid_signature,
                "Content-Type": "application/json"
            },
            data=tampered_bytes
        )
        self.assertEqual(res_tampered.status_code, 401)

    def test_08_inbound_webhook_pipeline_integration(self):
        """Test that accepted webhook events seamlessly feed into the ECS event stream and queries."""
        src_id = f"pipe-src-{uuid.uuid4().hex[:8]}"
        create_webhook_source({
            "source_id": src_id,
            "name": "Pipeline Integration Webhook",
            "auth_type": "none",
            "mapping_rules": {
                "event_id": {"path": "$.id"},
                "event_type": {"default": "TRANSACTION"},
                "amount": {"path": "$.val"},
                "currency": {"default": "ETB"},
                "payment_rail": {"default": "p2p"},
                "actor": {
                    "account_number": {"path": "$.sender"}
                }
            }
        }, org_id=self.org_a)

        evt_id = f"pipe_evt_{uuid.uuid4().hex[:10]}"
        res = self.client.post(
            f"/api/webhooks/inbound/{src_id}",
            headers={"Content-Type": "application/json"},
            json={"id": evt_id, "val": 350.0, "sender": "ACC_PIPE_001"}
        )
        self.assertIn(res.status_code, (200, 202))

        # Query events via API for Tenant A
        res_query = self.client.get(
            f"/api/events?account=ACC_PIPE_001",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_query.status_code, 200)
        events = res_query.get_json() or []
        matched = [e for e in events if e.get("event_id") == evt_id]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["payment_rail"], "p2p")
        self.assertEqual(matched[0]["organization_id"], self.org_a)


if __name__ == '__main__':
    unittest.main()
