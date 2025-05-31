import pytest
from unittest.mock import patch, MagicMock
import uuid

from extensions.ext_database import db
from models.ad import ADConfiguration
from models.account import Account, AccountStatus, Tenant, TenantAccountJoin, TenantAccountRole
from services.account_service import AccountService # For password hashing if needed, or direct Account creation

# Helper function to get headers (can be shared or defined per test file)
def get_login_headers():
    return {
        'Content-Type': 'application/json'
    }

@pytest.fixture(scope="function", autouse=True)
def setup_database(app):
    with app.app_context():
        # Clean ADConfiguration and relevant Accounts before each test
        ADConfiguration.query.delete()
        # Be careful with Account.query.delete() if other tests rely on existing accounts.
        # For these specific login tests, it's safer to control account creation.
        # However, if AccountService.authenticate relies on other tables, they might need setup/cleanup.

        # Ensure a default tenant exists for user creation, similar to ad_admin_controller tests
        tenant = db.session.query(Tenant).filter_by(id='_login_test_tenant_').first()
        if not tenant:
            tenant = Tenant(id='_login_test_tenant_', name='Login Test Tenant')
            db.session.add(tenant)

        # Clean up accounts potentially created by these tests to avoid interference
        # This is a bit broad; ideally, track and delete only accounts created by these tests.
        # For now, deleting accounts that might match test data emails.
        # accounts_to_delete = Account.query.filter(Account.email.like('%@adtest.example.com')).all()
        # for acc in accounts_to_delete:
        #     TenantAccountJoin.query.filter_by(account_id=acc.id).delete()
        #     db.session.delete(acc)

        db.session.commit()

def create_local_account(email, password, name="Test User", tenant_id='_login_test_tenant_'):
    # Use AccountService to create user with hashed password if possible,
    # or set password directly if hashing is handled by AccountService.authenticate
    # For testing fallback, we need a user that AccountService.authenticate can find.

    # Simplified: create account directly. AccountService.authenticate will handle it.
    # Hashing of password needs to match what AccountService.authenticate expects.
    # Let's assume AccountService.create_account_and_tenant or similar would normally do this.
    # For now, we'll use AccountService to set the password to ensure it's hashed.

    account = Account(email=email, name=name, status=AccountStatus.ACTIVE.value)
    db.session.add(account)
    db.session.commit() # Commit to get ID

    # Set password using AccountService logic (or a simplified hash if that's too complex to call here)
    # This is a bit of a workaround. Ideally, a test helper fixture would create users properly.
    # For now, let's assume AccountService.authenticate can handle plain text for test hashes,
    # or we set a known hashed value if the hashing mechanism is simple.
    # The actual AccountService.authenticate will hash the input password and compare.
    # So, we need to store a password that, when hashed, matches.
    # Or, mock the part of AccountService that does password verification for local users if too complex.

    # Let's create an account and then use AccountService to "reset" password to a known one
    # This is indirect. A direct way to set a hashed password would be better.
    # For integration tests, we often test the service layer as is.
    AccountService.update_user_password(account, password) # This should hash and save

    # Add user to the default tenant
    if not TenantAccountJoin.query.filter_by(tenant_id=tenant_id, account_id=account.id).first():
        join = TenantAccountJoin(tenant_id=tenant_id, account_id=account.id, role=TenantAccountRole.NORMAL)
        db.session.add(join)

    db.session.commit()
    return account


def create_ad_configuration(is_enabled=True, tenant_id='_login_test_tenant_'):
    # Ensure the tenant for AD config exists if it's different or specific
    tenant = db.session.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        tenant = Tenant(id=tenant_id, name='AD Config Tenant')
        db.session.add(tenant)
        db.session.commit()

    ad_config = ADConfiguration(
        tenant_id=tenant_id,
        is_enabled=is_enabled,
        server_url="ldap://fake-ldap.example.com",
        bind_dn="cn=admin",
        encrypted_bind_password=b"testpassword", # Assume already "encrypted" for service layer test
        user_search_base="ou=users,dc=example,dc=com",
        user_search_filter="(&(objectClass=user)(mail=%(username)s))", # Using mail as username for these tests
        attribute_mapping_username="uid", # This is what ADAuthService returns as 'username'
        attribute_mapping_email="mail",
        attribute_mapping_display_name="cn"
    )
    db.session.add(ad_config)
    db.session.commit()
    return ad_config

# Patch the ADAuthService within the login controller's scope
LOGIN_CONTROLLER_PATH = 'controllers.console.auth.login'

@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_with_ad_success_new_user_provisioning(mock_ad_auth_service_constructor, console_client, app):
    create_ad_configuration(is_enabled=True)

    mock_auth_service_instance = MagicMock()
    ad_user_attributes = {
        'dn': 'uid=newuser,ou=users,dc=example,dc=com',
        'username': 'ad_newuser_uid', # From attribute_mapping_username
        'email': 'newuser@adtest.example.com',    # From attribute_mapping_email
        'display_name': 'New AD User CN' # From attribute_mapping_display_name
    }
    mock_auth_service_instance.authenticate.return_value = ad_user_attributes
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "newuser@adtest.example.com", "password": "adpassword"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    assert 'access_token' in response.json['data']

    mock_ad_auth_service_constructor.assert_called_once()
    mock_auth_service_instance.authenticate.assert_called_once_with(username="newuser@adtest.example.com", password="adpassword")

    with app.app_context():
        account_db = Account.query.filter_by(email="newuser@adtest.example.com").first()
        assert account_db is not None
        assert account_db.name == "New AD User CN"
        assert account_db.ad_user_dn == 'uid=newuser,ou=users,dc=example,dc=com'
        assert account_db.password is not None # Should be a random, unusable password
        assert account_db.password != "adpassword"


@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_with_ad_success_existing_user_by_dn(mock_ad_auth_service_constructor, console_client, app):
    create_ad_configuration(is_enabled=True)
    with app.app_context():
        existing_account = Account(
            email="existing@example.com",
            name="Old Name",
            ad_user_dn='uid=aduser,ou=users,dc=example,dc=com',
            status=AccountStatus.ACTIVE.value
        )
        db.session.add(existing_account)
        # Add to tenant
        join = TenantAccountJoin(tenant_id='_login_test_tenant_', account_id=existing_account.id, role=TenantAccountRole.NORMAL)
        db.session.add(join)
        db.session.commit()
        existing_account_id = existing_account.id

    mock_auth_service_instance = MagicMock()
    ad_user_attributes = {
        'dn': 'uid=aduser,ou=users,dc=example,dc=com', # This DN exists locally
        'username': 'aduser_uid',
        'email': 'updated_email@adtest.example.com', # Email might change in AD
        'display_name': 'Updated AD Name'
    }
    mock_auth_service_instance.authenticate.return_value = ad_user_attributes
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "any_email_for_ad_user", "password": "adpassword"} # Login email might not matter if AD uses another ID
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    assert 'access_token' in response.json['data']

    with app.app_context():
        account_db = Account.query.filter_by(id=existing_account_id).first()
        assert account_db is not None
        assert account_db.name == "Updated AD Name" # Name updated
        assert account_db.email == "existing@example.com" # Email should not change if found by DN, unless explicitly coded
        # The current login logic updates email if found by DN. Let's assume this behavior.
        # No, the code implies email from AD is primarily for finding or new user creation.
        # Let's verify current code: it finds by DN, then updates name, dn. Email is not updated if found by DN.

@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_with_ad_success_existing_user_by_email_if_no_dn_match(mock_ad_auth_service_constructor, console_client, app):
    create_ad_configuration(is_enabled=True)
    with app.app_context():
        existing_account = Account(
            email="user@adtest.example.com",
            name="Existing Name",
            ad_user_dn=None, # No DN initially
            status=AccountStatus.ACTIVE.value
        )
        db.session.add(existing_account)
        join = TenantAccountJoin(tenant_id='_login_test_tenant_', account_id=existing_account.id, role=TenantAccountRole.NORMAL)
        db.session.add(join)
        db.session.commit()
        existing_account_id = existing_account.id

    mock_auth_service_instance = MagicMock()
    ad_user_attributes = {
        'dn': 'uid=newdn,ou=users,dc=example,dc=com',
        'username': 'user_uid',
        'email': 'user@adtest.example.com', # Matches existing email
        'display_name': 'Name From AD'
    }
    mock_auth_service_instance.authenticate.return_value = ad_user_attributes
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "user@adtest.example.com", "password": "adpassword"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    with app.app_context():
        account_db = Account.query.filter_by(id=existing_account_id).first()
        assert account_db is not None
        assert account_db.name == "Name From AD"
        assert account_db.ad_user_dn == 'uid=newdn,ou=users,dc=example,dc=com' # DN should be updated


@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_ad_auth_fails_fallback_to_local_auth_success(mock_ad_auth_service_constructor, console_client, app):
    create_ad_configuration(is_enabled=True)
    with app.app_context():
        create_local_account("localuser@example.com", "localpassword123", tenant_id='_login_test_tenant_')

    mock_auth_service_instance = MagicMock()
    mock_auth_service_instance.authenticate.return_value = None # AD auth fails
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "localuser@example.com", "password": "localpassword123"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    assert 'access_token' in response.json['data']
    assert response.json['data']['token_type'].lower() == 'bearer' # Assuming local auth returns this
    mock_auth_service_instance.authenticate.assert_called_once_with(username="localuser@example.com", password="localpassword123")


@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_ad_auth_fails_fallback_to_local_auth_failure(mock_ad_auth_service_constructor, console_client):
    create_ad_configuration(is_enabled=True)
    # No local user created for this email, or wrong password

    mock_auth_service_instance = MagicMock()
    mock_auth_service_instance.authenticate.return_value = None # AD auth fails
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "localuser@example.com", "password": "wronglocalpassword"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    # Expects AccountNotFoundError which translates to a specific JSON response or 404/401
    # Based on login.py, it's EmailOrPasswordMismatchError (401) or AccountNotFound (custom response with code)
    assert response.status_code == 401 # Assuming AccountPasswordError or similar maps to 401
    # Or if it's AccountNotFound and registration is allowed:
    # assert response.json['code'] == "account_not_found"


@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_when_ad_is_disabled_uses_local_auth(mock_ad_auth_service_constructor, console_client, app):
    create_ad_configuration(is_enabled=False) # AD is configured but disabled
    with app.app_context():
        create_local_account("localuser@example.com", "localpassword123", tenant_id='_login_test_tenant_')

    mock_auth_service_instance = MagicMock() # Should not be called
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "localuser@example.com", "password": "localpassword123"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    assert 'access_token' in response.json['data']
    mock_ad_auth_service_constructor.assert_not_called() # ADAuthService should not be instantiated
    mock_auth_service_instance.authenticate.assert_not_called()


@patch(f'{LOGIN_CONTROLLER_PATH}.ADAuthService')
def test_login_no_ad_config_uses_local_auth(mock_ad_auth_service_constructor, console_client, app):
    # No ADConfiguration in DB for this test
    with app.app_context():
        create_local_account("localuser@example.com", "localpassword123", tenant_id='_login_test_tenant_')

    mock_auth_service_instance = MagicMock()
    mock_ad_auth_service_constructor.return_value = mock_auth_service_instance

    login_payload = {"email": "localuser@example.com", "password": "localpassword123"}
    response = console_client.post('/console/api/login', headers=get_login_headers(), json=login_payload)

    assert response.status_code == 200
    assert 'access_token' in response.json['data']
    mock_ad_auth_service_constructor.assert_not_called()
    mock_auth_service_instance.authenticate.assert_not_called()

# TODO: Test case for when AD user's email is missing from AD attributes (should not create account or fail gracefully)
# TODO: Test case for tenant assignment logic for new AD users, especially if multiple tenants exist or default tenant logic.
# For now, the tenant assignment is very basic in the login controller.
# TODO: Add test for `auth_method` claim in token if `AccountService.login` is modified to support it.
# Currently, the `AccountService.login` in the provided code doesn't show explicit handling for `auth_method` param to add to token.
# This test suite assumes it's either passed through or gracefully ignored.
# If it's added to the token, token decoding and claim assertion would be needed.
