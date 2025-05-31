import unittest
from unittest.mock import patch, MagicMock, PropertyMock

import ldap # Import ldap directly for ldap.LDAPError and other constants
from ldap import LDAPError, INVALID_CREDENTIALS, SERVER_DOWN

# Assuming ADConfiguration and ADAuthService are structured as previously defined
# Need to ensure paths are correct for your project structure
from models.ad import ADConfiguration
from services.auth.ad_auth_service import ADAuthService


class TestADAuthService(unittest.TestCase):

    def _create_mock_config(
        self,
        is_enabled=True,
        server_url="ldap://testserver:389",
        bind_dn="cn=admin,dc=example,dc=com",
        encrypted_password=b"cGFzc3dvcmQ=", # "password" base64 encoded
        tenant_id="test_tenant_id",
        user_search_base="ou=users,dc=example,dc=com",
        user_search_filter="(&(objectClass=user)(sAMAccountName=%(username)s))",
        attr_username="sAMAccountName",
        attr_email="mail",
        attr_display_name="displayName"
    ):
        config = ADConfiguration()
        config.id = "test_config_id"
        config.tenant_id = tenant_id
        config.is_enabled = is_enabled
        config.server_url = server_url
        config.bind_dn = bind_dn
        config.encrypted_bind_password = encrypted_password
        config.user_search_base = user_search_base
        config.user_search_filter = user_search_filter
        config.attribute_mapping_username = attr_username
        config.attribute_mapping_email = attr_email
        config.attribute_mapping_display_name = attr_display_name
        return config

    @patch('services.auth.ad_auth_service.decrypt_token')
    @patch('services.auth.ad_auth_service.ldap.initialize')
    def test_get_ldap_connection_success_with_bind_dn(self, mock_ldap_initialize, mock_decrypt_token):
        mock_conn = MagicMock()
        mock_ldap_initialize.return_value = mock_conn
        mock_decrypt_token.return_value = "decrypted_password"

        config = self._create_mock_config()
        service = ADAuthService(config)

        returned_conn = service._get_ldap_connection()

        mock_ldap_initialize.assert_called_once_with(config.server_url)
        mock_conn.set_option.assert_called_once_with(ldap.OPT_REFERRALS, 0)
        mock_decrypt_token.assert_called_once_with(str(config.tenant_id), config.encrypted_bind_password.decode('utf-8'))
        mock_conn.simple_bind_s.assert_called_once_with(config.bind_dn, "decrypted_password")
        self.assertEqual(returned_conn, mock_conn)
        # Ensure unbind is not called here, it's up to the caller of _get_ldap_connection
        mock_conn.unbind_s.assert_not_called()


    @patch('services.auth.ad_auth_service.ldap.initialize')
    def test_get_ldap_connection_success_anonymous_bind(self, mock_ldap_initialize):
        mock_conn = MagicMock()
        mock_ldap_initialize.return_value = mock_conn

        config = self._create_mock_config(bind_dn=None, encrypted_password=None)
        service = ADAuthService(config)

        returned_conn = service._get_ldap_connection()

        mock_ldap_initialize.assert_called_once_with(config.server_url)
        mock_conn.set_option.assert_called_once_with(ldap.OPT_REFERRALS, 0)
        mock_conn.simple_bind_s.assert_called_once_with("", "") # Anonymous bind
        self.assertEqual(returned_conn, mock_conn)


    @patch('services.auth.ad_auth_service.decrypt_token')
    @patch('services.auth.ad_auth_service.ldap.initialize')
    def test_get_ldap_connection_bind_failure(self, mock_ldap_initialize, mock_decrypt_token):
        mock_conn = MagicMock()
        mock_ldap_initialize.return_value = mock_conn
        mock_decrypt_token.return_value = "decrypted_password"
        mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS("Bind failed")

        config = self._create_mock_config()
        service = ADAuthService(config)

        with self.assertRaises(LDAPError) as context:
            service._get_ldap_connection()

        self.assertIn("LDAP bind failed", str(context.exception))
        mock_conn.unbind_s.assert_called_once() # Should unbind on failure


    @patch('services.auth.ad_auth_service.decrypt_token')
    @patch('services.auth.ad_auth_service.ldap.initialize')
    def test_get_ldap_connection_decryption_failure(self, mock_ldap_initialize, mock_decrypt_token):
        mock_ldap_initialize.return_value = MagicMock() # Don't need conn if decryption fails first
        mock_decrypt_token.side_effect = Exception("Decryption error")

        config = self._create_mock_config()
        service = ADAuthService(config)

        with self.assertRaises(LDAPError) as context:
            service._get_ldap_connection()
        self.assertIn("Password decryption failed", str(context.exception))


    def test_get_ldap_connection_not_enabled(self):
        config = self._create_mock_config(is_enabled=False)
        service = ADAuthService(config)
        with self.assertRaises(LDAPError) as context:
            service._get_ldap_connection()
        self.assertIn("AD authentication is not enabled", str(context.exception))


    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_test_connection_success(self, mock_get_ldap_conn):
        mock_ldap_conn_instance = MagicMock()
        mock_get_ldap_conn.return_value = mock_ldap_conn_instance

        config = self._create_mock_config()
        service = ADAuthService(config)

        success, error = service.test_connection()

        self.assertTrue(success)
        self.assertIsNone(error)
        mock_get_ldap_conn.assert_called_once()
        mock_ldap_conn_instance.unbind_s.assert_called_once()


    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_test_connection_failure_ldap_error(self, mock_get_ldap_conn):
        mock_get_ldap_conn.side_effect = ldap.SERVER_DOWN("Server is down")

        config = self._create_mock_config()
        service = ADAuthService(config)

        success, error = service.test_connection()

        self.assertFalse(success)
        self.assertIn("Server is down", error)


    def test_test_connection_not_enabled(self):
        config = self._create_mock_config(is_enabled=False)
        service = ADAuthService(config)
        success, error = service.test_connection()
        self.assertFalse(success)
        self.assertEqual(error, "AD authentication is not enabled in the configuration.")


    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_authenticate_success(self, mock_get_ldap_conn_outer):
        # Mock for the initial _get_ldap_connection (service account bind or anonymous)
        mock_service_conn = MagicMock()
        mock_get_ldap_conn_outer.return_value = mock_service_conn

        # Mock for ldap.initialize called inside authenticate for user bind
        with patch('services.auth.ad_auth_service.ldap.initialize') as mock_ldap_initialize_user:
            mock_user_auth_conn = MagicMock()
            mock_ldap_initialize_user.return_value = mock_user_auth_conn

            user_dn = "uid=testuser,ou=users,dc=example,dc=com"
            user_attributes = {
                'sAMAccountName': [b'testuser'],
                'mail': [b'testuser@example.com'],
                'displayName': [b'Test User']
            }
            mock_service_conn.search_s.return_value = [(user_dn, user_attributes)]

            config = self._create_mock_config()
            service = ADAuthService(config)

            result = service.authenticate("testuser", "password")

            mock_get_ldap_conn_outer.assert_called_once()
            mock_service_conn.search_s.assert_called_once_with(
                config.user_search_base,
                ldap.SCOPE_SUBTREE,
                config.user_search_filter % {'username': 'testuser'},
                attrlist=['sAMAccountName', 'mail', 'displayName']
            )

            mock_ldap_initialize_user.assert_called_once_with(config.server_url)
            mock_user_auth_conn.set_option.assert_called_once_with(ldap.OPT_REFERRALS, 0)
            mock_user_auth_conn.simple_bind_s.assert_called_once_with(user_dn, "password")

            self.assertIsNotNone(result)
            self.assertEqual(result['dn'], user_dn)
            self.assertEqual(result['username'], 'testuser')
            self.assertEqual(result['email'], 'testuser@example.com')
            self.assertEqual(result['display_name'], 'Test User')

            mock_service_conn.unbind_s.assert_called_once() # Service connection should be unbound
            mock_user_auth_conn.unbind_s.assert_called_once() # User auth connection unbound


    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_authenticate_user_not_found(self, mock_get_ldap_conn):
        mock_service_conn = MagicMock()
        mock_get_ldap_conn.return_value = mock_service_conn
        mock_service_conn.search_s.return_value = [] # No user found

        config = self._create_mock_config()
        service = ADAuthService(config)

        result = service.authenticate("unknownuser", "password")

        self.assertIsNone(result)
        mock_service_conn.unbind_s.assert_called_once()


    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_authenticate_invalid_password(self, mock_get_ldap_conn_outer):
        mock_service_conn = MagicMock()
        mock_get_ldap_conn_outer.return_value = mock_service_conn

        with patch('services.auth.ad_auth_service.ldap.initialize') as mock_ldap_initialize_user:
            mock_user_auth_conn = MagicMock()
            mock_ldap_initialize_user.return_value = mock_user_auth_conn
            mock_user_auth_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS

            user_dn = "uid=testuser,ou=users,dc=example,dc=com"
            user_attributes = {'sAMAccountName': [b'testuser']} # Dummy attributes
            mock_service_conn.search_s.return_value = [(user_dn, user_attributes)]

            config = self._create_mock_config()
            service = ADAuthService(config)

            result = service.authenticate("testuser", "wrongpassword")

            self.assertIsNone(result)
            mock_service_conn.unbind_s.assert_called_once()
            mock_user_auth_conn.unbind_s.assert_called_once()


    def test_authenticate_ad_disabled(self):
        config = self._create_mock_config(is_enabled=False)
        service = ADAuthService(config)
        result = service.authenticate("testuser", "password")
        self.assertIsNone(result)

    @patch.object(ADAuthService, '_get_ldap_connection')
    def test_authenticate_empty_password_string(self, mock_get_ldap_conn):
        config = self._create_mock_config()
        service = ADAuthService(config)
        result = service.authenticate("testuser", "") # Empty password string
        self.assertIsNone(result)
        mock_get_ldap_conn.assert_not_called() # Should not proceed to LDAP calls

if __name__ == '__main__':
    unittest.main()
