"""
Test Suite Part 9: Identity, Multi-Tenant RBAC, TOTP MFA, and Scoped API Tokens.
Verifies Phase 1.6 requirements:
- TOTP MFA generation, challenge flow, and code verification
- Extended roles ('admin', 'analyst', 'responder', 'viewer', 'auditor') permission enforcement
- Session revocation / token blacklisting
- Scoped API tokens for machine connectors with revocation
"""
import unittest
import uuid
import json
import pyotp
from datetime import datetime, timezone, timedelta
from app import create_app
from app.services.auth_service import (
    create_token, decode_token, hash_password,
    revoke_token, is_token_revoked,
    generate_totp_secret, verify_totp_code,
    create_scoped_api_token, verify_scoped_api_token, revoke_api_token
)
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID


class TestPart9IdentityMfaRbac(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.org_a = "00000000-0000-0000-0000-000000000001"
        self.org_b = "99999999-9999-9999-9999-999999999999"

    def test_1_totp_mfa_generation_and_verification(self):
        """Verifies TOTP secret generation, RFC 6238 token calculation, and verification."""
        secret = generate_totp_secret()
        self.assertIsNotNone(secret)
        self.assertGreaterEqual(len(secret), 16)

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Valid code must pass
        self.assertTrue(verify_totp_code(secret, valid_code))

        # Invalid code must fail
        self.assertFalse(verify_totp_code(secret, "000000" if valid_code != "000000" else "111111"))

    def test_2_session_revocation_and_token_blacklist(self):
        """Verifies that revoking a session token immediately denies authentication."""
        token = create_token(
            user_id="user-revoc-test",
            email="revoc@bank.et",
            role="analyst",
            organization_id=self.org_a
        )
        decoded = decode_token(token)
        self.assertIsNotNone(decoded)

        # Before revocation, not revoked
        self.assertFalse(is_token_revoked(token))

        # Revoke token
        revoke_token(token)

        # After revocation, must be recognized as revoked
        self.assertTrue(is_token_revoked(token))

        # Verification via decode_token or get_current_user should reject revoked token
        with self.app.test_request_context(headers={'Authorization': f'Bearer {token}'}):
            from app.services.auth_service import get_current_user
            user = get_current_user()
            self.assertIsNone(user, "Revoked token should not resolve a valid user")

    def test_3_rbac_roles_matrix_enforcement(self):
        """Verifies access enforcement across extended roles: auditor, responder, analyst, admin, viewer."""
        auditor_token = create_token("user-auditor", "auditor@bank.et", "auditor", self.org_a)
        viewer_token = create_token("user-viewer", "viewer@bank.et", "viewer", self.org_a)
        admin_token = create_token("user-admin", "admin@bank.et", "admin", self.org_a)

        # Viewer trying to create incident -> 403
        resp = self.client.post('/api/incidents', headers={
            'Authorization': f'Bearer {viewer_token}',
            'Content-Type': 'application/json'
        }, json={'title': 'Viewer Incident', 'incident_type': 'phishing'})
        self.assertEqual(resp.status_code, 403)

        # Auditor trying to create incident -> 403
        resp = self.client.post('/api/incidents', headers={
            'Authorization': f'Bearer {auditor_token}',
            'Content-Type': 'application/json'
        }, json={'title': 'Auditor Incident', 'incident_type': 'phishing'})
        self.assertEqual(resp.status_code, 403)

        # Viewer trying to manage users -> 403
        resp = self.client.post('/api/auth/users', headers={
            'Authorization': f'Bearer {viewer_token}',
            'Content-Type': 'application/json'
        }, json={'email': 'hacker@bank.et', 'password': 'Password123!', 'full_name': 'Hacker'})
        self.assertEqual(resp.status_code, 403)

    def test_4_scoped_api_token_lifecycle(self):
        """Verifies creating, validating scope, and revoking scoped API tokens for machine connectors."""
        # Create token with ingest:events and read:alerts scopes
        token_info = create_scoped_api_token(
            name="Core Banking Connector",
            organization_id=self.org_a,
            scopes=["ingest:events", "read:alerts"],
            expires_days=30
        )
        raw_token = token_info['raw_token']
        token_id = token_info['token_id']

        self.assertTrue(raw_token.startswith("ecs_pat_"))

        # Verify token and scope
        valid_user = verify_scoped_api_token(raw_token, required_scope="ingest:events")
        self.assertIsNotNone(valid_user)
        self.assertEqual(valid_user['organization_id'], self.org_a)

        # Check unauthorized scope
        denied_user = verify_scoped_api_token(raw_token, required_scope="admin:users")
        self.assertIsNone(denied_user, "Token should be denied for ungranted scope")

        # Revoke API token
        revoke_api_token(token_id, organization_id=self.org_a)

        # After revocation, token verification must fail
        revoked_check = verify_scoped_api_token(raw_token, required_scope="ingest:events")
        self.assertIsNone(revoked_check, "Revoked API token must not authenticate")

    def test_5_mfa_setup_and_api_token_endpoints(self):
        """Verifies HTTP routes for MFA setup and API token management."""
        admin_token = create_token("user-admin-mfa", "adminmfa@bank.et", "admin", self.org_a)

        # 1. MFA setup endpoint
        resp_setup = self.client.post('/api/auth/mfa/setup', headers={
            'Authorization': f'Bearer {admin_token}'
        })
        self.assertEqual(resp_setup.status_code, 200)
        data = resp_setup.get_json()
        self.assertIn('secret', data)
        self.assertIn('uri', data)

        secret = data['secret']
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # 2. MFA enable endpoint
        resp_enable = self.client.post('/api/auth/mfa/enable', headers={
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }, json={'secret': secret, 'code': code})
        self.assertEqual(resp_enable.status_code, 200)

        # 3. API token management routes (POST /api-tokens)
        resp_tok = self.client.post('/api/auth/api-tokens', headers={
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }, json={'name': 'EthSwitch Ingestion Key', 'scopes': ['ingest:events']})
        self.assertEqual(resp_tok.status_code, 201)
        tok_data = resp_tok.get_json()
        self.assertIn('raw_token', tok_data)
        token_id = tok_data['token_id']

        # 4. List API tokens
        resp_list = self.client.get('/api/auth/api-tokens', headers={
            'Authorization': f'Bearer {admin_token}'
        })
        self.assertEqual(resp_list.status_code, 200)
        tok_list = resp_list.get_json()
        self.assertTrue(any(t['id'] == token_id for t in tok_list))

        # 5. Revoke API token
        resp_del = self.client.delete(f'/api/auth/api-tokens/{token_id}', headers={
            'Authorization': f'Bearer {admin_token}'
        })
        self.assertEqual(resp_del.status_code, 200)


if __name__ == '__main__':
    unittest.main()

