import uuid
from datetime import datetime, timezone
from flask import Blueprint, current_app, make_response, redirect, request, session, url_for, jsonify
from flask_login import login_user, logout_user

from api.configs import saml_config
from api.extensions.ext_database import db
from api.extensions.ext_saml import saml_client
from api.models.account import Account, AccountIntegrate, AccountStatus
from api.models.model import Tenant, TenantAccountJoin, TenantAccountRole
from api.services.account_service import AccountService
from api.services.enterprise.tenant_service import TenantService
from api.services.web_app_auth_service import WebAppAuthService # For login
import logging

logger = logging.getLogger(__name__)

# Define constants for SAML attribute names (Ideally, these should be in SAMLConfig)
SAML_ATTR_EMAIL = 'urn:oid:0.9.2342.19200300.100.1.3' # Common OID for email
SAML_ATTR_GIVEN_NAME = 'urn:oid:2.5.4.42' # Common OID for givenName
SAML_ATTR_SURNAME = 'urn:oid:2.5.4.4' # Common OID for sn (surname)
SAML_ATTR_NAMEID = 'nameid' # Often 'nameid' or a specific URN like 'urn:oasis:names:tc:SAML:1.1:nameid-format:persistent'
# Fallback email attributes
SAML_ATTR_EMAIL_FALLBACKS = [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'email', # Common fallback
]
SAML_ATTR_GIVEN_NAME_FALLBACKS = [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'firstName', 'givenName',
]
SAML_ATTR_SURNAME_FALLBACKS = [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'lastName', 'sn',
]

saml_sso_bp = Blueprint('saml_sso', __name__, url_prefix='/sso/saml')

@saml_sso_bp.before_request
def check_saml_enabled():
    if not saml_config.SAML_ENABLED:
        return jsonify({"status": "error", "message": "SAML is not enabled."}), 403

# Metadata Endpoint
@saml_sso_bp.route('/metadata', methods=['GET'])
def metadata():
    try:
        provider_name = saml_config.SAML_PROVIDER_NAME
        metadata_xml = saml_client.create_metadata_response(provider_name)
        response = make_response(metadata_xml)
        response.headers['Content-Type'] = 'application/samlmetadata+xml'
        return response
    except Exception as e:
        logger.error(f"Error generating SAML metadata: {e}")
        return jsonify({"status": "error", "message": "Failed to generate SAML metadata."}), 500

# Login Initiation Endpoint - Note: This URL is different from the one in web/service/sso.ts
# The blueprint prefix /sso/saml makes the final URL /sso/saml/login
# The frontend expects /enterprise/sso/saml/login. This will be handled by registering another blueprint later for /enterprise prefix
@saml_sso_bp.route('/login', methods=['GET'])
def login():
    try:
        provider_name = saml_config.SAML_PROVIDER_NAME
        
        # Construct ACS URL dynamically
        # Scheme needs to be determined based on deployment (http vs https)
        # SERVER_NAME should also be correctly configured in Flask
        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
        server_name = current_app.config.get('SERVER_NAME') or request.host
        
        application_root = current_app.config.get('APPLICATION_ROOT') or '/'
        if not application_root.startswith('/'):
            application_root = '/' + application_root
        if application_root.endswith('/'):
            application_root = application_root[:-1]

        base_url = f"{scheme}://{server_name}{application_root}"
        redirect_uri = f"{base_url}{saml_config.SAML_ACS_URL_PATH}"

        invite_token = request.args.get('invite_token')
        if invite_token:
            session['saml_invite_token'] = invite_token
            # Authlib typically uses 'state' for OAuth2, for SAML, if we need to pass
            # custom parameters, it might need to be part of the relay_state or handled via session.
            # For now, storing in session is the most straightforward.

        auth_url_resp = saml_client.create_authorization_url(provider_name, redirect_uri=redirect_uri)
        return redirect(auth_url_resp['url'])
    except Exception as e:
        logger.error(f"Error initiating SAML login: {e}")
        return jsonify({"status": "error", "message": "Failed to initiate SAML login."}), 500


# Assertion Consumer Service (ACS) Endpoint
@saml_sso_bp.route(saml_config.SAML_ACS_URL_PATH.replace('/sso/saml', ''), methods=['POST'])
def acs():
    try:
        provider_name = saml_config.SAML_PROVIDER_NAME
        # The method to parse the response might be different in newer Authlib versions
        # or specific to the SAML part of Authlib.
        # Common methods are parse_idp_response or through authorize_access_token which internally handles it.
        # Assuming a method like 'fetch_user_profile' or 'parse_idp_response' exists and works with request.form
        
        # For SAML, the IdP response is typically in request.form['SAMLResponse']
        # Authlib's Flask integration should handle this automatically when calling a processing method.
        token = saml_client.fetch_access_token(provider_name, request_data=request.form)
        
        # Authlib typically returns SAML attributes directly in the token object for SAML.
        # For example, if 'claims' is how Authlib exposes them, or directly on token.
        # The structure can vary, so we need to be flexible.
        # Let's assume attributes are under a 'attributes' key or directly in 'userinfo' / 'claims'
        
        saml_attributes = {}
        if 'attributes' in token: # Common for some SAML parsing libraries
            saml_attributes = token['attributes']
        elif 'userinfo' in token: # Common for OIDC, but Authlib might use it for SAML claims too
            saml_attributes = token['userinfo']
        elif 'claims' in token: # Another common key
            saml_attributes = token['claims']
        else: # Fallback: assume attributes are at the root of the token object
            saml_attributes = token

        logger.info(f"SAML ACS received. Raw SAML attributes/token: {saml_attributes}")

        def get_attribute(attrs, primary_key, fallbacks=None):
            if primary_key in attrs:
                value = attrs[primary_key]
                return value[0] if isinstance(value, list) and len(value) > 0 else value
            if fallbacks:
                for key in fallbacks:
                    if key in attrs:
                        value = attrs[key]
                        return value[0] if isinstance(value, list) and len(value) > 0 else value
            return None

        email = get_attribute(saml_attributes, SAML_ATTR_EMAIL, SAML_ATTR_EMAIL_FALLBACKS)
        # NameID is crucial, Authlib might expose it as 'sub' (subject) or a specific claim.
        # Often it's available via token.get_nameid() or similar if Authlib parses it specially.
        # For now, let's assume it's in the attributes map or a dedicated field in token.
        name_id_val = get_attribute(saml_attributes, SAML_ATTR_NAMEID)
        if not name_id_val and 'sub' in saml_attributes : # 'sub' is often used for NameID in OIDC-like structures
             name_id_val = saml_attributes['sub']
        if not name_id_val and hasattr(token, 'get_nameid') and callable(token.get_nameid):
             name_id_val = token.get_nameid() # Ideal if Authlib provides this for SAML

        if not name_id_val: # If still not found, check common NameID URNs
            name_id_val = get_attribute(saml_attributes, 'urn:oasis:names:tc:SAML:1.1:nameid-format:persistent') or \
                          get_attribute(saml_attributes, 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')


        given_name = get_attribute(saml_attributes, SAML_ATTR_GIVEN_NAME, SAML_ATTR_GIVEN_NAME_FALLBACKS)
        surname = get_attribute(saml_attributes, SAML_ATTR_SURNAME, SAML_ATTR_SURNAME_FALLBACKS)

        if not email or not name_id_val:
            logger.error(f"Missing required SAML attributes. Email: {email}, NameID: {name_id_val}")
            return jsonify({"status": "error", "message": "Missing required SAML attributes (email or NameID)."}), 400

        account = None
        try:
            # 1. Check AccountIntegrate
            account_integrate = db.session.query(AccountIntegrate).filter(
                AccountIntegrate.provider_name == provider_name,
                AccountIntegrate.provider_id == name_id_val
            ).first()

            if account_integrate:
                account = db.session.query(Account).filter(Account.id == account_integrate.account_id).first()
                if not account: # Should not happen if data is consistent
                     logger.error(f"AccountIntegrate found for NameID {name_id_val} but corresponding Account {account_integrate.account_id} missing.")
                     db.session.delete(account_integrate) # Clean up orphan
                     db.session.commit()
                     account_integrate = None # Treat as not found

            # 2. Find by Email if not found by AccountIntegrate
            if not account:
                account = db.session.query(Account).filter(Account.email == email).first()

            invite_token = session.pop('saml_invite_token', None)
            tenant_id_from_invite = None
            role_from_invite = None

            if invite_token:
                try:
                    tenant_from_invite = AccountService.get_tenant_by_invite_token(invite_token)
                    if tenant_from_invite:
                        tenant_id_from_invite = tenant_from_invite.id
                        # Assuming AccountService.get_tenant_by_invite_token also gives role or we fetch it
                        # For now, let's assume a default role if invite token is valid
                        role_from_invite = saml_config.SAML_DEFAULT_USER_ROLE 
                        logger.info(f"Valid invite token processed for tenant {tenant_id_from_invite}")
                    else:
                        logger.warning(f"SAML ACS: Invalid or expired invite_token: {invite_token}")
                except Exception as e_invite:
                    logger.warning(f"SAML ACS: Error processing invite_token '{invite_token}': {e_invite}")


            # 3. Just-In-Time (JIT) Provisioning
            if not account:
                logger.info(f"JIT Provisioning: No existing account found for email {email} or NameID {name_id_val}. Creating new user.")
                
                user_name = f"{given_name} {surname}".strip() if given_name or surname else email.split('@')[0]
                
                account = Account(
                    id=str(uuid.uuid4()),
                    email=email,
                    name=user_name,
                    password=None, # No password for SSO users initially
                    status=AccountStatus.ACTIVE.value,
                    initialized_at=datetime.now(timezone.utc)
                )
                db.session.add(account)
                
                # Tenant Assignment
                target_tenant_id = tenant_id_from_invite
                target_role = role_from_invite or saml_config.SAML_DEFAULT_USER_ROLE

                if not target_tenant_id:
                    # Fallback to a default tenant strategy
                    # Option 1: Use a globally configured default tenant ID (if any)
                    # Option 2: Find the first available tenant (simplistic, might not be suitable for all setups)
                    default_tenant = db.session.query(Tenant).first() # Example: Get first tenant
                    if not default_tenant:
                        logger.error("JIT Provisioning: No default tenant found and no valid invite token. Cannot assign user.")
                        db.session.rollback()
                        return jsonify({"status": "error", "message": "User provisioning failed: No tenant available."}), 500
                    target_tenant_id = default_tenant.id
                    logger.info(f"JIT Provisioning: Assigning new user to default tenant {target_tenant_id} with role {target_role}")

                tenant_account_join = TenantAccountJoin(
                    id=str(uuid.uuid4()),
                    tenant_id=target_tenant_id,
                    account_id=account.id,
                    role=TenantAccountRole.get_member_role_by_value(target_role).value, # Ensure valid role
                    invited_by=None, # Can be set if tracking SAML as inviter
                    created_at=datetime.now(timezone.utc)
                )
                db.session.add(tenant_account_join)
                account.current_tenant_id = target_tenant_id # Set current tenant for the new user

            # 4. Update/Create AccountIntegrate
            if not account_integrate:
                account_integrate = AccountIntegrate(
                    id=str(uuid.uuid4()),
                    account_id=account.id,
                    provider_name=provider_name,
                    provider_id=name_id_val, # Store the persistent NameID
                    encrypted_credentials=None, # Not storing SAML assertion here
                    created_at=datetime.now(timezone.utc)
                )
                db.session.add(account_integrate)
            
            # Ensure current_tenant_id is set for existing users if not already set or if invite token overrides
            if account.current_tenant_id is None or (tenant_id_from_invite and account.current_tenant_id != tenant_id_from_invite):
                if tenant_id_from_invite:
                    # Check if user is already part of this tenant from invite
                    existing_join = db.session.query(TenantAccountJoin).filter_by(account_id=account.id, tenant_id=tenant_id_from_invite).first()
                    if not existing_join:
                         # If invite token specified a tenant and user is not part of it, add them (or error based on policy)
                         logger.info(f"User {account.email} invited to tenant {tenant_id_from_invite}. Adding.")
                         new_join = TenantAccountJoin(
                            id=str(uuid.uuid4()),
                            tenant_id=tenant_id_from_invite,
                            account_id=account.id,
                            role=TenantAccountRole.get_member_role_by_value(role_from_invite or saml_config.SAML_DEFAULT_USER_ROLE).value,
                            created_at=datetime.now(timezone.utc)
                         )
                         db.session.add(new_join)
                    account.current_tenant_id = tenant_id_from_invite
                elif not account.current_tenant_id:
                    # If no current tenant, try to set one from existing joins or default
                    first_join = db.session.query(TenantAccountJoin).filter_by(account_id=account.id).first()
                    if first_join:
                        account.current_tenant_id = first_join.tenant_id
                    else:
                        # This case should ideally not happen if user was provisioned correctly or already existed
                        logger.error(f"User {account.email} has no tenant memberships. This is an inconsistent state.")
                        db.session.rollback()
                        return jsonify({"status": "error", "message": "User has no tenant assignment."}), 500
            
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during SAML user provisioning/linking: {e}", exc_info=True)
            return jsonify({"status": "error", "message": f"Failed to process SAML login: {str(e)}"}), 500

        # 5. Log In User
        # WebAppAuthService.login expects an Account object.
        # It handles flask_login.login_user and session management.
        # The method might also return a JWT if the frontend expects it,
        # but for web flow, session cookie set by flask_login is standard.
        
        # Ensure the account object is fully loaded and associated with the session
        # This might require merging or refreshing if changes were made.
        db.session.refresh(account)
        if account.current_tenant_id: # Ensure current_tenant is loaded for the session
             account.current_tenant # Accessing this loads the relationship if not already loaded
        
        # Use WebAppAuthService to perform login, which handles flask_login.login_user
        # and potentially other session setup.
        # For console login, app_code and end_user_id are typically None.
        auth_token_response = WebAppAuthService.login(account=account, app_code=None, end_user_id=None)
        
        # `WebAppAuthService.login` should call `flask_login.login_user(account)`
        # and set up the session correctly.
        
        logger.info(f"User {account.email} (ID: {account.id}) logged in successfully via SAML from provider {provider_name}.")

        # 6. Redirect User
        # Redirect to a sensible frontend page, e.g., /apps or a configured URL.
        # The session cookie set by flask_login should handle authentication for subsequent requests.
        # If the frontend expects a token in the URL (less common for web flows),
        # it would be part of auth_token_response.
        
        # Default redirect URL, can be made configurable
        redirect_url_after_login = url_for('web.index', _external=True) # Assuming 'web.index' is the main app page
        
        # If invite_token was used, maybe redirect to a specific part of the app
        # For example, if invite_token was for a workspace, redirect to that workspace.
        # This logic can be added later if needed.

        return redirect(redirect_url_after_login)

    except Exception as e:
        logger.error(f"Error processing SAML assertion (ACS outer try-except): {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to process SAML assertion: {str(e)}"}), 500

# Single Logout (SLO) Endpoint
@saml_sso_bp.route(saml_config.SAML_SLO_URL_PATH.replace('/sso/saml', ''), methods=['GET', 'POST']) # SLO can be GET or POST
def slo():
    try:
        provider_name = saml_config.SAML_PROVIDER_NAME
        # Authlib's handling of SAML SLO might require specific request parsing.
        # The method could be something like 'parse_logout_request' or part of a more general SLO handler.
        # We need to check how Authlib expects to receive and process SLO requests.
        # Assuming there's a method that can determine if it's a valid SLO request
        # and provide a URL to redirect back to the IdP if necessary.

        # This is a placeholder for actual SLO processing logic with Authlib
        # For example, it might be:
        # slo_info = saml_client.parse_logout_request(provider_name, request_data=request.form or request.args)
        # if slo_info and slo_info.is_valid():
        # logout_user()
        # return redirect(slo_info.redirect_url or url_for('web.login')) # Or IdP's provided URL
        
        # For now, just log out the user and redirect to login.
        # Actual SAML LogoutResponse generation and IdP interaction would be more complex.
        logout_user()
        logger.info("User logged out via SAML SLO.")
        # The redirect URL after logout should ideally be configurable or determined from SAML request
        return redirect(url_for('web.login')) # Assuming 'web.login' is the Dify login page
    except Exception as e:
        logger.error(f"Error processing SAML SLO request: {e}")
        return jsonify({"status": "error", "message": "Failed to process SAML SLO request."}), 500

# This blueprint will be registered with /sso/saml prefix.
# We need another blueprint for the /enterprise/sso/saml/login route.
enterprise_saml_sso_bp = Blueprint('enterprise_saml_sso', __name__, url_prefix='/enterprise/sso/saml')

@enterprise_saml_sso_bp.before_request
def check_saml_enabled_enterprise():
    if not saml_config.SAML_ENABLED:
        return jsonify({"status": "error", "message": "SAML is not enabled."}), 403

@enterprise_saml_sso_bp.route('/login', methods=['GET'])
def enterprise_login():
    # This just forwards to the actual login handler in the other blueprint
    # to keep the login logic centralized but provide the desired URL.
    # It copies query parameters like invite_token.
    
    # Reconstruct the URL for the actual SAML login endpoint
    # The actual login endpoint is at /sso/saml/login
    # We need to ensure query parameters are preserved.
    
    actual_login_url = url_for('saml_sso.login', _external=False)
    
    # Preserve query parameters
    args = request.args.to_dict()
    if args:
        return redirect(actual_login_url + '?' + '&'.join([f'{k}={v}' for k, v in args.items()]))
    else:
        return redirect(actual_login_url)
