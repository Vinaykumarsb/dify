import pytest
from unittest.mock import patch, MagicMock
import json
import uuid

from extensions.ext_database import db
from models.ad import ADConfiguration
from models.account import Tenant # Needed for creating a tenant for encryption

# Assuming conftest.py provides console_client and sets up the app context
# Helper function to get admin headers (adapt if your conftest has a different way)
def get_admin_headers(api_key):
    return {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

@pytest.fixture(scope="function", autouse=True)
def setup_database(app):
    with app.app_context():
        # Clean ADConfiguration before each test
        ADConfiguration.query.delete()
        # Create a dummy tenant for encryption/decryption if it doesn't exist
        # encrypt_token and decrypt_token in the actual code rely on Tenant.encrypt_public_key
        tenant = db.session.query(Tenant).filter_by(id='_ad_test_tenant_').first()
        if not tenant:
            tenant = Tenant(id='_ad_test_tenant_', name='AD Test Tenant')
            # In a real scenario, public/private keys would be generated for the tenant.
            # For testing, encrypt_token/decrypt_token might be mocked or use a fixed key if not hitting RSA.
            # For these tests, we'll mostly mock encrypt_token.
            db.session.add(tenant)
        db.session.commit()

# Mock the ADMIN_API_KEY used by the @admin_required decorator
MOCK_ADMIN_API_KEY = "test_admin_api_key"

@pytest.fixture
def admin_api_key_mock(monkeypatch):
    monkeypatch.setattr('configs.dify_config.ADMIN_API_KEY', MOCK_ADMIN_API_KEY)


# ==== ADConfigurationResource Tests ====

def test_get_ad_configuration_empty(console_client, admin_api_key_mock):
    response = console_client.get('/console/admin/ad/configuration', headers=get_admin_headers(MOCK_ADMIN_API_KEY))
    assert response.status_code == 200
    data = response.json
    # Based on current controller logic, it returns ADConfigurationResponseSchema().model_dump(exclude_none=True)
    # which would be an empty dict if all fields are optional or have defaults that are None.
    # If it populates with defaults from schema, assert those defaults.
    # For now, assuming it returns a structure with default/null values for an empty config.
    assert data['is_enabled'] == False # Default from Pydantic schema if not found
    assert data['server_url'] is None or data['server_url'] == '' # Depends on schema default for HttpUrl


@patch('api.controllers.console.ad_admin_controller.encrypt_token')
def test_put_ad_configuration_create_and_get(mock_encrypt_token, console_client, admin_api_key_mock, app):
    mock_encrypt_token.return_value = "encrypted_password_mock" # Base64 encoded string

    tenant_id_for_test = '_ad_test_tenant_' # Must match the one in setup_database or be created

    initial_payload = {
        "tenant_id": tenant_id_for_test, # Required by schema and for encryption
        "is_enabled": True,
        "server_url": "ldap://ldap.example.com",
        "bind_dn": "cn=admin,dc=example,dc=com",
        "bind_password": "password123",
        "user_search_base": "ou=users,dc=example,dc=com",
        "user_search_filter": "(&(objectClass=user)(uid=%(username)s))",
        "attribute_mapping_username": "uid",
        "attribute_mapping_email": "mail",
        "attribute_mapping_display_name": "cn"
    }

    # Create
    response_put = console_client.put('/console/admin/ad/configuration',
                                   headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                   json=initial_payload)
    assert response_put.status_code == 200
    created_data = response_put.json
    assert created_data['is_enabled'] == True
    assert created_data['server_url'] == "ldap://ldap.example.com"
    assert created_data['bind_dn'] == "cn=admin,dc=example,dc=com"
    assert 'bind_password' not in created_data # Password should not be returned

    mock_encrypt_token.assert_called_once_with(tenant_id_for_test, "password123")

    # Verify DB content
    with app.app_context():
        ad_config_db = db.session.query(ADConfiguration).first()
        assert ad_config_db is not None
        assert ad_config_db.is_enabled == True
        assert ad_config_db.server_url == "ldap://ldap.example.com"
        assert ad_config_db.encrypted_bind_password == "encrypted_password_mock".encode('utf-8')
        assert ad_config_db.tenant_id == uuid.UUID(tenant_id_for_test)


    # GET the config
    response_get = console_client.get('/console/admin/ad/configuration', headers=get_admin_headers(MOCK_ADMIN_API_KEY))
    assert response_get.status_code == 200
    retrieved_data = response_get.json
    assert retrieved_data['is_enabled'] == True
    assert retrieved_data['server_url'] == "ldap://ldap.example.com"
    assert retrieved_data['bind_dn'] == "cn=admin,dc=example,dc=com"
    assert 'bind_password' not in retrieved_data


@patch('api.controllers.console.ad_admin_controller.encrypt_token')
def test_put_ad_configuration_update(mock_encrypt_token, console_client, admin_api_key_mock, app):
    mock_encrypt_token.return_value = "new_encrypted_password_mock"
    tenant_id_for_test = '_ad_test_tenant_'

    # Initial create
    initial_payload = {
        "tenant_id": tenant_id_for_test,
        "is_enabled": True, "server_url": "ldap://old.example.com", "bind_password": "old_password"
    }
    console_client.put('/console/admin/ad/configuration', headers=get_admin_headers(MOCK_ADMIN_API_KEY), json=initial_payload)

    with app.app_context(): # Get the ID of the created record
        ad_config_initial = db.session.query(ADConfiguration).first()
        assert ad_config_initial is not None
        config_id = str(ad_config_initial.id)

    # Update
    update_payload = {
        "id": config_id, # Include ID for update
        "tenant_id": tenant_id_for_test, # Required by schema
        "is_enabled": True, # Must pass all required fields for Pydantic schema
        "server_url": "ldap://new.example.com",
        "bind_dn": "cn=updater,dc=example,dc=com",
        "bind_password": "new_password123", # New password
        "user_search_base": "ou=people,dc=example,dc=com", # Required by schema
         # Provide other required fields as per schema if not optional
        "user_search_filter": "(&(objectClass=posixAccount)(uid=%(username)s))",
        "attribute_mapping_username": "uid",
        "attribute_mapping_email": "mail",
        "attribute_mapping_display_name": "cn"
    }
    response_update = console_client.put('/console/admin/ad/configuration',
                                     headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                     json=update_payload)
    assert response_update.status_code == 200
    updated_data = response_update.json
    assert updated_data['server_url'] == "ldap://new.example.com"
    assert updated_data['bind_dn'] == "cn=updater,dc=example,dc=com"

    mock_encrypt_token.assert_called_with(tenant_id_for_test, "new_password123")

    with app.app_context():
        ad_config_db = db.session.query(ADConfiguration).filter_by(id=uuid.UUID(config_id)).first()
        assert ad_config_db is not None
        assert ad_config_db.server_url == "ldap://new.example.com"
        assert ad_config_db.encrypted_bind_password == "new_encrypted_password_mock".encode('utf-8')


def test_put_ad_configuration_invalid_payload(console_client, admin_api_key_mock):
    # Missing required server_url
    invalid_payload = {"is_enabled": True, "tenant_id": "_ad_test_tenant_"}
    response = console_client.put('/console/admin/ad/configuration',
                                headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                json=invalid_payload)
    assert response.status_code == 400 # Bad Request due to Pydantic validation

    # Invalid server_url format
    invalid_payload_url = {
        "tenant_id": "_ad_test_tenant_", "is_enabled": True, "server_url": "not_a_url",
        "user_search_base": "dc=test", "attribute_mapping_username": "uid",
        "attribute_mapping_email": "mail", "attribute_mapping_display_name": "cn"
    }
    response_url = console_client.put('/console/admin/ad/configuration',
                                headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                json=invalid_payload_url)
    assert response_url.status_code == 400


def test_get_ad_configuration_unauthorized(console_client):
    response = console_client.get('/console/admin/ad/configuration', headers={'Content-Type': 'application/json'})
    assert response.status_code == 401


def test_put_ad_configuration_unauthorized(console_client):
    payload = {"is_enabled": True, "server_url": "ldap://test.com"}
    response = console_client.put('/console/admin/ad/configuration',
                                headers={'Content-Type': 'application/json'},
                                json=payload)
    assert response.status_code == 401


# ==== ADTestConnectionResource Tests ====

# Patch where ADAuthService is instantiated or imported in the controller
@patch('api.controllers.console.ad_admin_controller.ADAuthService')
def test_test_ad_connection_success(mock_ad_auth_service_constructor, console_client, admin_api_key_mock):
    mock_service_instance = MagicMock()
    mock_service_instance.test_connection.return_value = (True, None)
    mock_ad_auth_service_constructor.return_value = mock_service_instance

    test_payload = {
        "server_url": "ldap://test.com",
        "bind_dn": "cn=test",
        "bind_password": "password"
    }
    response = console_client.post('/console/admin/ad/test-connection',
                                 headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                 json=test_payload)
    assert response.status_code == 200
    assert response.json == {'status': 'success'}
    # Check that ADAuthService was called with a config object matching test_payload
    args, kwargs = mock_ad_auth_service_constructor.call_args
    called_with_config = args[0] # The ADConfiguration instance
    assert called_with_config.server_url == test_payload['server_url']
    assert called_with_config.bind_dn == test_payload['bind_dn']
    # Password check is tricky as it's on encrypted_bind_password attribute after encoding
    assert called_with_config.encrypted_bind_password == test_payload['bind_password'].encode('utf-8')


@patch('api.controllers.console.ad_admin_controller.ADAuthService')
def test_test_ad_connection_failure(mock_ad_auth_service_constructor, console_client, admin_api_key_mock):
    mock_service_instance = MagicMock()
    mock_service_instance.test_connection.return_value = (False, "Mocked LDAP Error")
    mock_ad_auth_service_constructor.return_value = mock_service_instance

    test_payload = {"server_url": "ldap://fail.com"}
    response = console_client.post('/console/admin/ad/test-connection',
                                 headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                 json=test_payload)
    assert response.status_code == 400 # Adjusted expectation based on controller logic
    assert response.json == {'status': 'failure', 'error': 'Mocked LDAP Error'}


def test_test_ad_connection_bad_payload(console_client, admin_api_key_mock):
    # Missing server_url
    response = console_client.post('/console/admin/ad/test-connection',
                                 headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                 json={})
    assert response.status_code == 400 # Bad Request due to Pydantic validation

    # Invalid URL format
    response_invalid_url = console_client.post('/console/admin/ad/test-connection',
                                               headers=get_admin_headers(MOCK_ADMIN_API_KEY),
                                               json={"server_url": "not_a_valid_url"})
    assert response_invalid_url.status_code == 400


def test_test_ad_connection_unauthorized(console_client):
    response = console_client.post('/console/admin/ad/test-connection',
                                  headers={'Content-Type': 'application/json'},
                                  json={"server_url": "ldap://test.com"})
    assert response.status_code == 401
