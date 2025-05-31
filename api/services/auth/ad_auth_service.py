import ldap
from ldap import LDAPError

from models.ad import ADConfiguration
from core.helper.encrypter import decrypt_token # Import for decryption
from typing import Optional # For type hinting

class ADAuthService:
    def __init__(self, ad_configuration: ADConfiguration):
        self.config = ad_configuration

    def _decrypt_password(self, encrypted_password_bytes: bytes) -> str:
        """
        Decrypts the encrypted password.
        """
        if not encrypted_password_bytes:
            return ""

        # encrypted_password_bytes is LargeBinary, so it's already bytes.
        # decrypt_token expects a base64 encoded string.
        # The encrypt_token function base64 encodes AFTER encryption.
        # So, we need to ensure the bytes from DB are treated as the raw encrypted bytes,
        # then base64 encode them if decrypt_token expects that, or pass raw if it handles bytes.
        # encrypt_token returns base64.b64encode(encrypted_token).decode()
        # decrypt_token does rsa.decrypt(base64.b64decode(token), tenant_id)
        # So the stored encrypted_bind_password should be base64 string stored as bytes in DB.

        try:
            # Assuming encrypted_bind_password stored in DB is the direct output of encrypt_token (a b64 encoded string, stored as bytes)
            base64_encoded_password_str = encrypted_password_bytes.decode('utf-8')
            # TODO: Ensure tenant_id is valid and corresponds to the key used for encryption.
            # If tenant_id is not available or encryption was done with a global key, this needs adjustment.
            # For now, using self.config.tenant_id as passed to encrypt_token.
            if not self.config.tenant_id:
                raise ValueError("Tenant ID is missing in ADConfiguration, cannot decrypt password.")
            return decrypt_token(str(self.config.tenant_id), base64_encoded_password_str)
        except Exception as e:
            # Log the error appropriately
            raise LDAPError(f"Failed to decrypt bind password: {e}")


    def _get_ldap_connection(self):
        """
        Establishes and returns an LDAP connection.
        Performs a simple bind if bind_dn and password are configured.
        """
        if not self.config.is_enabled:
            raise LDAPError("AD authentication is not enabled.")

        conn = ldap.initialize(self.config.server_url)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        # Optionally set other options like OPT_PROTOCOL_VERSION
        # conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)

        if self.config.bind_dn and self.config.encrypted_bind_password:
            try:
                bind_password = self._decrypt_password(self.config.encrypted_bind_password)
            except LDAPError as e: # Catch decryption specific errors
                raise LDAPError(f"Configuration error for Bind DN '{self.config.bind_dn}': {e}")

            if not bind_password: # Treat empty string password as None if bind_dn is present
                 # Some LDAP servers might allow bind with empty password if anonymous bind is not desired for search
                 # but specific user context is needed. However, typically this means no password.
                 # For simplicity, if there's a bind_dn, we expect a password.
                 # If anonymous bind is intended for search, bind_dn should be None/empty.
                pass # Allow to proceed to simple_bind_s, it will likely fail if password is required by server

            try:
                # Using simple_bind_s for synchronous operation
                conn.simple_bind_s(self.config.bind_dn, bind_password)
            except LDAPError as e:
                # Clean up connection if bind fails
                conn.unbind_s()
                raise LDAPError(f"LDAP bind failed for Bind DN '{self.config.bind_dn}': {e}")
        else:
            # Attempt anonymous bind if no bind_dn is provided, some servers allow this for searches
            try:
                conn.simple_bind_s("", "")
            except LDAPError as e:
                # Some servers might reject anonymous bind explicitly
                conn.unbind_s()
                raise LDAPError(f"LDAP anonymous bind failed: {e}")
        return conn

    def test_connection(self) -> tuple[bool, Optional[str]]:
        """
        Tests the LDAP connection and bind credentials.
        Returns a tuple (bool, Optional[str]) indicating success and error message.
        """
        if not self.config.is_enabled:
            return False, "AD authentication is not enabled in the configuration."
        try:
            conn = self._get_ldap_connection()
            conn.unbind_s() # Close the connection
            return True, None
        except LDAPError as e:
            return False, str(e)
        except Exception as e: # Catch any other unexpected errors
            return False, f"An unexpected error occurred: {str(e)}"

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """
        Authenticates a user against the LDAP server.
        Returns a dictionary with user attributes upon successful authentication, else None.
        """
        if not self.config.is_enabled:
            return None

        if not password: # LDAP typically doesn't allow empty passwords for user bind
            return None

        ldap_conn = None
        try:
            ldap_conn = self._get_ldap_connection()

            search_filter = self.config.user_search_filter % {'username': ldap.filter.escape_filter_chars(username)}

            attributes_to_fetch = [
                self.config.attribute_mapping_username,
                self.config.attribute_mapping_email,
                self.config.attribute_mapping_display_name,
                # 'dn' is not an attribute, but useful for getting the DN directly if needed
                # However, search_s returns DN as part of the result tuple
            ]
            # Filter out any None or empty string attributes if they are optional and not set
            attributes_to_fetch = [attr for attr in attributes_to_fetch if attr]

            #ldap.SCOPE_SUBTREE, search_filter, attributes_to_fetch
            results = ldap_conn.search_s(
                self.config.user_search_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                attrlist=attributes_to_fetch if attributes_to_fetch else None # Pass None if no attributes are mapped
            )

            if not results:
                return None  # User not found
            if len(results) > 1:
                # Log this event? Multiple users found, which shouldn't happen for a unique identifier.
                return None

            user_dn, user_attributes_ldap = results[0]

            if not user_dn: # Should not happen if results contains an entry
                return None

            # Now attempt to bind as the user to verify the password
            # Create a new connection for this specific user bind is safer
            auth_conn = ldap.initialize(self.config.server_url)
            auth_conn.set_option(ldap.OPT_REFERRALS, 0)
            try:
                auth_conn.simple_bind_s(user_dn, password)
            except ldap.INVALID_CREDENTIALS:
                return None # Authentication failed (wrong password)
            except LDAPError:
                # Other LDAP error during user bind
                return None
            finally:
                if auth_conn:
                    auth_conn.unbind_s()

            # Extract attributes, handling potential missing keys if attributes were not found
            user_info = {
                'dn': user_dn,
                'username': user_attributes_ldap.get(self.config.attribute_mapping_username, [b''])[0].decode('utf-8')
                            if self.config.attribute_mapping_username and self.config.attribute_mapping_username in user_attributes_ldap else None,
                'email': user_attributes_ldap.get(self.config.attribute_mapping_email, [b''])[0].decode('utf-8')
                         if self.config.attribute_mapping_email and self.config.attribute_mapping_email in user_attributes_ldap else None,
                'display_name': user_attributes_ldap.get(self.config.attribute_mapping_display_name, [b''])[0].decode('utf-8')
                                if self.config.attribute_mapping_display_name and self.config.attribute_mapping_display_name in user_attributes_ldap else None,
            }

            # If mapped username is not found, it's problematic. Fallback or error?
            # For now, if the core username attribute is missing, consider it a failure.
            if not user_info['username']:
                 # Try to use the originally provided username if the mapped one isn't found or is empty
                 # This might happen if attribute_mapping_username is misconfigured or the LDAP entry is incomplete
                 user_info['username'] = username


            return user_info

        except LDAPError as e:
            # Log the LDAP error
            # print(f"LDAP Error: {e}") # Replace with actual logging
            return None
        except Exception as e:
            # Log other errors
            # print(f"Generic Error in authenticate: {e}") # Replace with actual logging
            return None
        finally:
            if ldap_conn:
                ldap_conn.unbind_s()

# Example Usage (for testing purposes, not part of the actual service file usually)
if __name__ == '__main__':
    # This is a mock configuration. Replace with actual test details if running standalone.
    class MockADConfiguration:
        def __init__(self, server_url, bind_dn=None, bind_password=None,
                     user_search_base=None, user_search_filter=None,
                     attr_user='uid', attr_email='mail', attr_name='cn', is_enabled=True):
            self.is_enabled = is_enabled
            self.server_url = server_url
            self.bind_dn = bind_dn
            # Store password as bytes to mimic LargeBinary
            self.encrypted_bind_password = bind_password.encode('utf-8') if bind_password else None
            self.user_search_base = user_search_base
            self.user_search_filter = user_search_filter
            self.attribute_mapping_username = attr_user
            self.attribute_mapping_email = attr_email
            self.attribute_mapping_display_name = attr_name
            self.group_search_base = None # Not used in this example
            self.group_search_filter = None # Not used in this example

    # --- Test Connection ---
    # Replace with your LDAP server details for testing
    # Test 1: Successful connection (e.g., to a public test LDAP server or your own)
    # config_ok = MockADConfiguration(server_url="ldap://ldap.forumsys.com:389",
    #                                 bind_dn="cn=read-only-admin,dc=example,dc=com",
    #                                 bind_password="password",
    #                                 user_search_base="dc=example,dc=com")
    # service_ok = ADAuthService(config_ok)
    # connected, error = service_ok.test_connection()
    # print(f"Test Connection OK: Connected={connected}, Error='{error}'") # Expected: True, None

    # Test 2: Failed connection (e.g., wrong server_url)
    # config_fail_url = MockADConfiguration(server_url="ldap://nonexistentldapserver:12345")
    # service_fail_url = ADAuthService(config_fail_url)
    # connected, error = service_fail_url.test_connection()
    # print(f"Test Connection Fail URL: Connected={connected}, Error='{error}'") # Expected: False, Error message

    # Test 3: Failed bind (e.g., wrong bind credentials)
    # config_fail_bind = MockADConfiguration(server_url="ldap://ldap.forumsys.com:389",
    #                                      bind_dn="cn=wrong-admin,dc=example,dc=com",
    #                                      bind_password="wrongpassword",
    #                                      user_search_base="dc=example,dc=com")
    # service_fail_bind = ADAuthService(config_fail_bind)
    # connected, error = service_fail_bind.test_connection()
    # print(f"Test Connection Fail Bind: Connected={connected}, Error='{error}'") # Expected: False, Bind error message

    # --- Test Authentication ---
    # auth_config = MockADConfiguration(server_url="ldap://ldap.forumsys.com:389",
    #                                 bind_dn="cn=read-only-admin,dc=example,dc=com",
    #                                 bind_password="password",
    #                                 user_search_base="dc=example,dc=com",
    #                                 user_search_filter="(&(objectClass=inetOrgPerson)(uid=%(username)s))",
    #                                 attr_user='uid', attr_email='mail', attr_name='cn')
    # auth_service = ADAuthService(auth_config)

    # Test 4: Successful authentication
    # user_attrs = auth_service.authenticate(username="einstein", password="password")
    # print(f"Auth Success: User Info={user_attrs}") # Expected: {'dn': 'uid=einstein,dc=example,dc=com', 'username': 'einstein', ...}

    # Test 5: Failed authentication (wrong password)
    # user_attrs_fail_pass = auth_service.authenticate(username="einstein", password="wrongpassword")
    # print(f"Auth Fail (Wrong Pass): User Info={user_attrs_fail_pass}") # Expected: None

    # Test 6: Failed authentication (user not found)
    # user_attrs_fail_user = auth_service.authenticate(username="nonexistentuser", password="password")
    # print(f"Auth Fail (User Not Found): User Info={user_attrs_fail_user}") # Expected: None

    # Test 7: AD disabled
    # config_disabled = MockADConfiguration(server_url="ldap://ldap.forumsys.com:389", is_enabled=False)
    # service_disabled = ADAuthService(config_disabled)
    # connected, error = service_disabled.test_connection()
    # print(f"Test Disabled Connection: Connected={connected}, Error='{error}'") # Expected: False, "AD authentication is not enabled..."
    # user_attrs_disabled = service_disabled.authenticate("einstein", "password")
    # print(f"Test Disabled Auth: User Info={user_attrs_disabled}") # Expected: None

    pass
