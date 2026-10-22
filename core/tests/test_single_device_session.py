import unittest
from app.services.auth_service import create_token, decode_token, clear_user_active_session

class TestSingleDeviceAdminSession(unittest.TestCase):
    def test_single_device_admin_concurrency(self):
        admin_user_id = 'test-admin-uuid-12345'
        clear_user_active_session(admin_user_id)
        
        # 1. Device A creates token
        token_a = create_token(
            user_id=admin_user_id,
            email='admin@test.et',
            role='admin'
        )
        self.assertIsNotNone(token_a)
        
        # Device A token should be valid
        payload_a = decode_token(token_a)
        self.assertIsNotNone(payload_a)
        self.assertEqual(payload_a['sub'], admin_user_id)
        
        # 2. Device B creates token for same admin
        token_b = create_token(
            user_id=admin_user_id,
            email='admin@test.et',
            role='admin'
        )
        self.assertIsNotNone(token_b)
        
        # Device B token should be valid
        payload_b = decode_token(token_b)
        self.assertIsNotNone(payload_b)
        self.assertEqual(payload_b['sub'], admin_user_id)
        
        # 3. Device A token must now be REJECTED (superseded)
        payload_a_superseded = decode_token(token_a)
        self.assertIsNone(payload_a_superseded, "Superseded Device A token must be rejected")
        
        # 4. Device B token remains valid
        payload_b_recheck = decode_token(token_b)
        self.assertIsNotNone(payload_b_recheck, "Active Device B token must remain valid")
        self.assertEqual(payload_b_recheck['jti'], payload_b['jti'])

if __name__ == '__main__':
    unittest.main()
