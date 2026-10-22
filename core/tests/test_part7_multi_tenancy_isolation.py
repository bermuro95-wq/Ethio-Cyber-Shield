"""
Comprehensive Multi-Tenancy Isolation & Cryptographic Hardening Test Suite for ECS v3.0.
Verifies strict mathematical separation between organizations (reads and writes denied across boundaries)
and envelope encryption of target system credentials at rest.
"""
import unittest
import json
import uuid
from flask import Flask
from app import create_app
from app.services.tenant_service import (
    DEFAULT_ORGANIZATION_ID,
    get_current_organization_id,
    set_current_organization_id,
    resolve_tenant_from_request
)
from app.services.crypto_service import encrypt_secret, decrypt_secret
from app.services.auth_service import create_token
from app.services.db import get_service_supabase
from app.routes.alerts import _ALERT_ORGS


class TestMultiTenancyIsolation(unittest.TestCase):
    """Test suite for Tenant data boundaries and credential security."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())

        # Valid database user id for foreign key constraints
        valid_user_id = "3224270a-9033-4bfa-b430-4de6d15d7567"
        try:
            sb = get_service_supabase()
            u_res = sb.table('users').select('id').limit(1).execute()
            if u_res.data:
                valid_user_id = u_res.data[0]['id']
        except Exception:
            pass

        cls.user_admin_a = str(uuid.uuid4())
        cls.user_analyst_a = str(uuid.uuid4())
        cls.user_admin_b = str(uuid.uuid4())
        cls.user_analyst_b = str(uuid.uuid4())

        # Tokens for distinct organizations
        cls.token_admin_a = create_token(cls.user_admin_a, "admin@orga.et", "admin", organization_id=cls.org_a)
        cls.token_analyst_a = create_token(cls.user_analyst_a, "analyst@orga.et", "analyst", organization_id=cls.org_a)
        cls.token_admin_b = create_token(cls.user_admin_b, "admin@orgb.et", "admin", organization_id=cls.org_b)
        cls.token_analyst_b = create_token(cls.user_analyst_b, "analyst@orgb.et", "analyst", organization_id=cls.org_b)

    def test_tenant_context_resolution(self):
        """Verifies X-ECS-Tenant header parsing and fallback resolution."""
        test_org = str(uuid.uuid4())
        with self.app.test_request_context(headers={"X-ECS-Tenant": test_org}):
            resolved = resolve_tenant_from_request()
            self.assertEqual(resolved, test_org)
            self.assertEqual(get_current_organization_id(), test_org)

        # Fallback without header
        with self.app.test_request_context():
            resolved_default = resolve_tenant_from_request()
            self.assertEqual(resolved_default, DEFAULT_ORGANIZATION_ID)

    def test_envelope_encryption_at_rest(self):
        """Verifies AES-256-GCM envelope encryption and decryption."""
        raw_secret = "super-confidential-banking-api-secret-key-2026"
        encrypted = encrypt_secret(raw_secret)

        # 1. Format check
        self.assertTrue(encrypted.startswith("enc:v1:"))
        parts = encrypted.split(":")
        self.assertEqual(len(parts), 4)

        # 2. Decryption round-trip
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, raw_secret)

        # 3. Transparent backward compatibility with plaintext
        legacy_plain = "legacy-plain-key"
        self.assertEqual(decrypt_secret(legacy_plain), legacy_plain)

        # 4. Tampered ciphertext rejection
        tampered = f"{parts[0]}:{parts[1]}:{parts[2]}:AAAA{parts[3][4:]}"
        with self.assertRaises(ValueError):
            decrypt_secret(tampered)

    def test_cross_tenant_reads_denied_on_incidents(self):
        """Ensures Tenant B cannot view incidents belonging to Tenant A."""
        # 1. Create incident under Tenant A
        headers_a = {
            "Authorization": f"Bearer {self.token_admin_a}",
            "Content-Type": "application/json"
        }
        res_create = self.client.post("/api/incidents", headers=headers_a, json={
            "title": f"Incident Org A - {uuid.uuid4().hex[:6]}",
            "description": "Sensitive security incident details for Organization A only",
            "incident_type": "fraud",
            "severity": "high"
        })
        self.assertIn(res_create.status_code, (200, 201))
        incident_a = res_create.get_json()
        incident_a_id = incident_a.get("id")

        # 2. Query as Tenant B (listing)
        headers_b = {
            "Authorization": f"Bearer {self.token_admin_b}",
            "Content-Type": "application/json"
        }
        res_list_b = self.client.get("/api/incidents", headers=headers_b)
        self.assertEqual(res_list_b.status_code, 200)
        incidents_b = res_list_b.get_json()
        found_in_list = any(inc.get("id") == incident_a_id for inc in incidents_b)
        self.assertFalse(found_in_list, "CRITICAL LEAK: Tenant B can see Tenant A's incident in list query!")

        # 3. Query direct ID as Tenant B
        res_get_b = self.client.get(f"/api/incidents/{incident_a_id}", headers=headers_b)
        self.assertEqual(res_get_b.status_code, 404, "CRITICAL LEAK: Tenant B can fetch Tenant A's incident directly!")

    def test_cross_tenant_writes_denied_on_incidents(self):
        """Ensures Tenant B cannot update or modify Tenant A's incidents."""
        # 1. Create incident under Tenant A
        headers_a = {
            "Authorization": f"Bearer {self.token_admin_a}",
            "Content-Type": "application/json"
        }
        res_create = self.client.post("/api/incidents", headers=headers_a, json={
            "title": f"Immutable Incident Org A - {uuid.uuid4().hex[:6]}",
            "incident_type": "account_takeover",
            "severity": "critical"
        })
        incident_a = res_create.get_json()
        incident_a_id = incident_a.get("id")

        # 2. Tenant B attempts unauthorized update
        headers_b = {
            "Authorization": f"Bearer {self.token_admin_b}",
            "Content-Type": "application/json"
        }
        res_update_b = self.client.put(f"/api/incidents/{incident_a_id}", headers=headers_b, json={
            "title": "Hacked Title by Unauthorized Tenant",
            "status": "closed"
        })
        self.assertEqual(res_update_b.status_code, 404, "SECURITY VIOLATION: Tenant B updated Tenant A's incident!")

    def test_cross_tenant_alerts_isolation(self):
        """Ensures Tenant B cannot acknowledge or resolve Tenant A's alerts."""
        sb = get_service_supabase()
        alert_row = {
            "title": f"Alert Org A {uuid.uuid4().hex[:6]}",
            "alert_type": "suspicious_transaction",
            "severity": "high",
            "status": "open",
            "organization_id": self.org_a
        }
        res_alert = None
        try:
            res_alert = sb.table("alerts").insert(alert_row).execute()
        except Exception:
            alert_row.pop("organization_id", None)
            res_alert = sb.table("alerts").insert(alert_row).execute()

        if res_alert and res_alert.data:
            alert_id = res_alert.data[0]["id"]
            _ALERT_ORGS[str(alert_id)] = self.org_a

            headers_b = {"Authorization": f"Bearer {self.token_analyst_b}"}

            # Tenant B cannot view alert
            res_get = self.client.get(f"/api/alerts/{alert_id}", headers=headers_b)
            self.assertEqual(res_get.status_code, 404)

            # Tenant B cannot acknowledge alert
            res_ack = self.client.post(f"/api/alerts/{alert_id}/acknowledge", headers=headers_b)
            self.assertEqual(res_ack.status_code, 404)

            # Tenant B cannot resolve alert
            res_res = self.client.post(f"/api/alerts/{alert_id}/resolve", headers=headers_b, json={"status": "resolved"})
            self.assertEqual(res_res.status_code, 404)

    def test_target_systems_tenant_isolation(self):
        """Ensures Target systems registered under Org A are never visible to Org B."""
        headers_a = {
            "Authorization": f"Bearer {self.token_admin_a}",
            "Content-Type": "application/json"
        }
        unique_key = f"key_orga_{uuid.uuid4().hex[:8]}"
        res_reg = self.client.post("/api/targets", headers=headers_a, json={
            "name": "Org A Private Target Banking Switch",
            "base_url": "http://127.0.0.1:8888",
            "key_id": unique_key,
            "secret_key": "private-secret-32b-org-a-strictly",
            "sync_mode": "push"
        })
        self.assertIn(res_reg.status_code, (200, 201))

        # Listing targets under Org B
        headers_b = {"Authorization": f"Bearer {self.token_admin_b}"}
        res_list_b = self.client.get("/api/targets", headers=headers_b)
        self.assertEqual(res_list_b.status_code, 200)
        targets_b = res_list_b.get_json()
        self.assertFalse(any(t.get("key_id") == unique_key for t in targets_b),
                         "CRITICAL LEAK: Tenant B can see Tenant A's private target system credentials!")


if __name__ == "__main__":
    unittest.main()
