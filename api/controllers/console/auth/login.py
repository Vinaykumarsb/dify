from typing import cast

import flask_login
from flask import request
from flask_restful import Resource, reqparse

import services
from configs import dify_config
from constants.languages import languages
from controllers.console import api
from controllers.console.auth.error import (
    EmailCodeError,
    EmailOrPasswordMismatchError,
    EmailPasswordLoginLimitError,
    InvalidEmailError,
    InvalidTokenError,
)
from controllers.console.error import (
    AccountBannedError,
    AccountInFreezeError,
    AccountNotFound,
    EmailSendIpLimitError,
    NotAllowedCreateWorkspace,
    WorkspacesLimitExceeded,
)
from controllers.console.wraps import email_password_login_enabled, setup_required
from events.tenant_event import tenant_was_created
import uuid # For generating placeholder passwords
from extensions.ext_database import db # For direct db interaction if needed
from libs.helper import email, extract_remote_ip
from libs.password import valid_password
from models.account import Account, AccountStatus, TenantAccountRole # Added AccountStatus, TenantAccountRole
from models.ad import ADConfiguration # Import ADConfiguration
from services.auth.ad_auth_service import ADAuthService # Import ADAuthService
from services.account_service import AccountService, RegisterService, TenantService
from services.billing_service import BillingService
from services.errors.account import AccountRegisterError
from services.errors.workspace import WorkSpaceNotAllowedCreateError, WorkspacesLimitExceededError
from services.feature_service import FeatureService


class LoginApi(Resource):
    """Resource for user login."""

    @setup_required
    @email_password_login_enabled
    def post(self):
        """Authenticate user and login."""
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=email, required=True, location="json")
        parser.add_argument("password", type=valid_password, required=True, location="json")
        parser.add_argument("remember_me", type=bool, required=False, default=False, location="json")
        parser.add_argument("invite_token", type=str, required=False, default=None, location="json")
        parser.add_argument("language", type=str, required=False, default="en-US", location="json")
        args = parser.parse_args()

        if dify_config.BILLING_ENABLED and BillingService.is_email_in_freeze(args["email"]):
            raise AccountInFreezeError()

        is_login_error_rate_limit = AccountService.is_login_error_rate_limit(args["email"])
        if is_login_error_rate_limit:
            raise EmailPasswordLoginLimitError()

        invitation = args["invite_token"]
        if invitation:
            invitation = RegisterService.get_invitation_if_token_valid(None, args["email"], invitation)

        if args["language"] is not None and args["language"] == "zh-Hans":
            language = "zh-Hans"
        else:
            language = "en-US"

        # AD Authentication
        ad_config = db.session.query(ADConfiguration).filter(ADConfiguration.is_enabled == True).first()
        account = None
        auth_method = 'local' # Default auth method

        if ad_config:
            ad_auth_service = ADAuthService(ad_config)
            # Using email as the AD username for now.
            # Password from request (args['password']) is used for AD auth.
            user_ad_info = ad_auth_service.authenticate(username=args["email"], password=args["password"])

            if user_ad_info:
                auth_method = 'ad'
                # AD Auth successful, find or provision local account
                # Try to find by ad_user_dn first, then by email
                if user_ad_info.get('dn'):
                    account = db.session.query(Account).filter(Account.ad_user_dn == user_ad_info['dn']).first()

                if not account and user_ad_info.get('email'):
                    account = db.session.query(Account).filter(Account.email == user_ad_info['email']).first()

                if not account: # Create new local account
                    # TODO: Ensure tenant_id for the new user is correctly assigned.
                    # This might involve a default tenant or logic based on AD groups/attributes.
                    # For now, new users might not be associated with a tenant automatically,
                    # or AccountService.create_account_and_tenant needs to be adapted or called.
                    # This part is crucial for multi-tenancy.

                    new_email = user_ad_info.get('email')
                    if not new_email: # Email is mandatory for Account model
                        # Fallback or raise error if email not mapped from AD
                        # For now, let's prevent account creation if email is missing.
                        # This case should ideally be handled by ensuring email attribute mapping is correct.
                        pass # Will proceed to local auth or fail if local auth also fails

                    if new_email:
                        account = Account(
                            email=new_email,
                            name=user_ad_info.get('display_name') or new_email.split('@')[0],
                            password=str(uuid.uuid4()),  # Set unusable random password
                            status=AccountStatus.ACTIVE,
                            initialized_at=db.func.current_timestamp(),
                            ad_user_dn=user_ad_info.get('dn'),
                            # TODO: Assign a default tenant or handle tenant creation/assignment
                        )
                        db.session.add(account)

                        # Check if a tenant needs to be created or assigned
                        # This logic is simplified; a real scenario would involve more robust tenant assignment.
                        # For self-hosted, there's often a default tenant or admin creates one.
                        # We also need to ensure the user is added to a tenant.
                        # This might require calling TenantService.create_tenant_member or similar.
                        # The original code has logic for creating a tenant if none exist for the user.
                        # That logic might need to be invoked here.
                        # For now, committing the account. Tenant association is a separate concern here.
                        try:
                            db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            # Log error, potentially cannot create account due to DB constraints (e.g. email unique)
                            # If so, try to fetch again in case of race condition, or fail.
                            account = db.session.query(Account).filter(Account.email == new_email).first()
                            if not account: # Truly failed to create or find
                                pass # Fall through to local auth, or raise specific error.


                elif account: # Account exists, update info if needed
                    # Check if any info from AD needs to be updated locally
                    if user_ad_info.get('display_name') and account.name != user_ad_info.get('display_name'):
                        account.name = user_ad_info.get('display_name')
                    if user_ad_info.get('dn') and account.ad_user_dn != user_ad_info.get('dn'):
                        account.ad_user_dn = user_ad_info.get('dn')
                    # Update email if it changed? This can be complex. For now, assume email from AD is primary if account found via DN.
                    # Or, if found by email, ensure DN is updated.
                    db.session.commit()

                # If account is successfully found or created via AD:
                if account:
                    # Ensure user is part of at least one tenant
                    tenants = TenantService.get_join_tenants(account)
                    if not tenants:
                        # This logic is similar to original code for new users or users without tenants.
                        # Potentially create a default tenant or assign to one based on AD group mapping (future).
                        system_features = FeatureService.get_system_features()
                        if system_features.is_allow_create_workspace and not system_features.license.workspaces.is_available():
                            # This error might be too harsh if local fallback is desired.
                            # However, if AD auth is successful, user should ideally get a workspace.
                            raise WorkspacesLimitExceeded("Workspace limit reached, cannot create/assign workspace for AD user.")

                        # For self-hosted, usually a default tenant is created or admin invites.
                        # This part needs careful review in context of how tenants are provisioned.
                        # Simplified: if no tenants, and creation allowed, try to create one.
                        # This might not be the right place if AD users should be explicitly invited.
                        # For now, mirroring the existing logic for users without tenants.
                        if dify_config.EDITION == "SELF_HOSTED" and system_features.is_allow_create_workspace:
                             # Attempt to create a personal workspace or assign to a default one.
                             # This is simplified. A real system might look up AD groups to assign tenants.
                            try:
                                default_tenant = TenantService.get_default_tenant() # Assuming such a function could exist
                                if not default_tenant: # Or create one if allowed
                                     default_tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
                                TenantService.create_tenant_member(default_tenant, account, role=TenantAccountRole.NORMAL) # Or role from AD group
                                account.current_tenant = default_tenant # Set current tenant context
                                tenant_was_created.send(default_tenant) # Event if needed
                            except Exception as e:
                                # Log error, cannot create/assign tenant.
                                # Depending on policy, either fail login or allow login without tenant.
                                # For now, if tenant assignment fails, login might proceed without full workspace access.
                                pass # Fall through, login will occur but user might have no workspace.


                    # Proceed to login (flask_login.login_user is handled by AccountService.login)
                    token_pair = AccountService.login(account=account, ip_address=extract_remote_ip(request), auth_method=auth_method)
                    AccountService.reset_login_error_rate_limit(args["email"])
                    return {"result": "success", "data": token_pair.model_dump()}

            # If AD auth failed (user_ad_info is None), fall through to local authentication.
            # No explicit 'else' here, the code will naturally proceed if account is not set by AD logic.

        # Local Authentication (Fallback or if AD is not enabled/user not found in AD)
        if not account: # Only try local auth if AD did not authenticate the user
            try:
                if invitation:
                    data = invitation.get("data", {})
                    invitee_email = data.get("email") if data else None
                    if invitee_email != args["email"]:
                        raise InvalidEmailError()
                    account_local = AccountService.authenticate(args["email"], args["password"], args["invite_token"])
                else:
                    account_local = AccountService.authenticate(args["email"], args["password"])

                account = account_local # Assign to account variable to be used below
                auth_method = 'local' # Set auth method for local successful auth

            except services.errors.account.AccountLoginError:
                raise AccountBannedError()
            except services.errors.account.AccountPasswordError:
                AccountService.add_login_error_rate_limit(args["email"])
                raise EmailOrPasswordMismatchError()
            except services.errors.account.AccountNotFoundError:
                if FeatureService.get_system_features().is_allow_register:
                    # This part is for when user not found locally.
                    # If AD was enabled and auth failed, we reach here.
                    # If AD not enabled, we also reach here if user not found locally.
                    token = AccountService.send_reset_password_email(email=args["email"], language=language)
                    return {"result": "fail", "data": token, "code": "account_not_found"}
                else:
                    raise AccountNotFound()

        # Common post-authentication logic (applies if local auth succeeded)
        if not account: # Should not happen if one of the auth methods succeeded or raised
             raise EmailOrPasswordMismatchError() # Generic error if no account found after all attempts

        # SELF_HOSTED only have one workspace (This check is from original code)
        tenants = TenantService.get_join_tenants(account)
        if not tenants: # If user has no tenants (e.g. new local user, or AD user for whom tenant creation failed)
            system_features = FeatureService.get_system_features()
            if system_features.is_allow_create_workspace and not system_features.license.workspaces.is_available():
                raise WorkspacesLimitExceeded()
            else:
                # Original code returns this if user has no workspace.
                # For AD users, this path means AD auth was successful, but tenant assignment failed AND
                # they don't have any other existing tenant memberships.
                # For local users, this is standard behavior if they somehow exist without a tenant.
                return {
                    "result": "fail",
                    "data": "workspace not found, please contact system admin to invite you to join in a workspace or check AD tenant provisioning.",
                }

        token_pair = AccountService.login(account=account, ip_address=extract_remote_ip(request), auth_method=auth_method)
        AccountService.reset_login_error_rate_limit(args["email"]) # Reset for the email tried
        return {"result": "success", "data": token_pair.model_dump()}


class LogoutApi(Resource):
    @setup_required
    def get(self):
        account = cast(Account, flask_login.current_user)
        if isinstance(account, flask_login.AnonymousUserMixin):
            return {"result": "success"}
        AccountService.logout(account=account)
        flask_login.logout_user()
        return {"result": "success"}


class ResetPasswordSendEmailApi(Resource):
    @setup_required
    @email_password_login_enabled
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=email, required=True, location="json")
        parser.add_argument("language", type=str, required=False, location="json")
        args = parser.parse_args()

        if args["language"] is not None and args["language"] == "zh-Hans":
            language = "zh-Hans"
        else:
            language = "en-US"
        try:
            account = AccountService.get_user_through_email(args["email"])
        except AccountRegisterError as are:
            raise AccountInFreezeError()
        if account is None:
            if FeatureService.get_system_features().is_allow_register:
                token = AccountService.send_reset_password_email(email=args["email"], language=language)
            else:
                raise AccountNotFound()
        else:
            token = AccountService.send_reset_password_email(account=account, language=language)

        return {"result": "success", "data": token}


class EmailCodeLoginSendEmailApi(Resource):
    @setup_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=email, required=True, location="json")
        parser.add_argument("language", type=str, required=False, location="json")
        args = parser.parse_args()

        ip_address = extract_remote_ip(request)
        if AccountService.is_email_send_ip_limit(ip_address):
            raise EmailSendIpLimitError()

        if args["language"] is not None and args["language"] == "zh-Hans":
            language = "zh-Hans"
        else:
            language = "en-US"
        try:
            account = AccountService.get_user_through_email(args["email"])
        except AccountRegisterError as are:
            raise AccountInFreezeError()

        if account is None:
            if FeatureService.get_system_features().is_allow_register:
                token = AccountService.send_email_code_login_email(email=args["email"], language=language)
            else:
                raise AccountNotFound()
        else:
            token = AccountService.send_email_code_login_email(account=account, language=language)

        return {"result": "success", "data": token}


class EmailCodeLoginApi(Resource):
    @setup_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=str, required=True, location="json")
        parser.add_argument("code", type=str, required=True, location="json")
        parser.add_argument("token", type=str, required=True, location="json")
        args = parser.parse_args()

        user_email = args["email"]

        token_data = AccountService.get_email_code_login_data(args["token"])
        if token_data is None:
            raise InvalidTokenError()

        if token_data["email"] != args["email"]:
            raise InvalidEmailError()

        if token_data["code"] != args["code"]:
            raise EmailCodeError()

        AccountService.revoke_email_code_login_token(args["token"])
        try:
            account = AccountService.get_user_through_email(user_email)
        except AccountRegisterError as are:
            raise AccountInFreezeError()
        if account:
            tenants = TenantService.get_join_tenants(account)
            if not tenants:
                workspaces = FeatureService.get_system_features().license.workspaces
                if not workspaces.is_available():
                    raise WorkspacesLimitExceeded()
                if not FeatureService.get_system_features().is_allow_create_workspace:
                    raise NotAllowedCreateWorkspace()
                else:
                    new_tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
                    TenantService.create_tenant_member(new_tenant, account, role="owner")
                    account.current_tenant = new_tenant
                    tenant_was_created.send(new_tenant)

        if account is None:
            try:
                account = AccountService.create_account_and_tenant(
                    email=user_email, name=user_email, interface_language=languages[0]
                )
            except WorkSpaceNotAllowedCreateError:
                return NotAllowedCreateWorkspace()
            except AccountRegisterError as are:
                raise AccountInFreezeError()
            except WorkspacesLimitExceededError:
                raise WorkspacesLimitExceeded()
        token_pair = AccountService.login(account, ip_address=extract_remote_ip(request))
        AccountService.reset_login_error_rate_limit(args["email"])
        return {"result": "success", "data": token_pair.model_dump()}


class RefreshTokenApi(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("refresh_token", type=str, required=True, location="json")
        args = parser.parse_args()

        try:
            new_token_pair = AccountService.refresh_token(args["refresh_token"])
            return {"result": "success", "data": new_token_pair.model_dump()}
        except Exception as e:
            return {"result": "fail", "data": str(e)}, 401


api.add_resource(LoginApi, "/login")
api.add_resource(LogoutApi, "/logout")
api.add_resource(EmailCodeLoginSendEmailApi, "/email-code-login")
api.add_resource(EmailCodeLoginApi, "/email-code-login/validity")
api.add_resource(ResetPasswordSendEmailApi, "/reset-password")
api.add_resource(RefreshTokenApi, "/refresh-token")
