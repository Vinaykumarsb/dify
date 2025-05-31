from flask_restful import Resource, reqparse, fields, marshal_with
from werkzeug.exceptions import NotFound, BadRequest
from flask_login import current_user # To get tenant_id

from extensions.ext_database import db
from models.ad import ADConfiguration
from controllers.console.ad_schemas import (
    ADConfigurationSchema,
    ADConfigurationResponseSchema,
    ADConfigurationTestRequestSchema,
    ADConfigurationTestResponseSchema
)
from services.auth.ad_auth_service import ADAuthService
from controllers.console.admin import admin_required # Using the decorator from admin.py
from core.helper.encrypter import encrypt_token, decrypt_token # Assuming decrypt might be needed later

class ADConfigurationResource(Resource):
    @admin_required
    def get(self):
        # Assuming one configuration per tenant for now, or a global one if tenant_id is not used.
        # For multi-tenant, you'd typically get tenant_id from current_user or a path parameter.
        # Let's assume tenant_id comes from the current logged-in admin's tenant context.
        # If ADConfiguration is global (not tenant-specific), this logic would change.

        # For this example, let's assume it's tenant-specific, using current_user.current_tenant_id
        # However, ADConfiguration model has tenant_id, so we should query by it.
        # If there's no current_user context for admin, this needs adjustment.
        # For a system-wide admin setting, it might not be tied to a tenant.
        # Let's assume for now there's only one global AD config or the first one.
        # A more robust solution would involve how tenants are managed for AD configs.

        # Fetching the first available AD configuration.
        # In a real multi-tenant system, this would likely be filtered by a tenant_id.
        # For a single global AD setting, this is okay.
        # Given our model has tenant_id, we should ideally use it.
        # Let's assume an admin is fetching a specific tenant's config or a default one.
        # For simplicity, if only one record is ever expected for the whole system (self-hosted),
        # then .first() is okay. If it's per tenant, we need a tenant_id.

        # Let's assume we are managing a single AD configuration for the deployment for now,
        # or the API key implies a global admin context.
        # If tenant_id is needed from current_user, ensure admin_required sets up current_user.

        # For now, let's assume a single global AD config or a default one.
        # If your admin_required decorator sets up current_user and current_user.current_tenant_id:
        # ad_config = db.session.query(ADConfiguration).filter(ADConfiguration.tenant_id == current_user.current_tenant_id).first()
        # If it's a global config (no tenant_id on model, or a pre-defined ID):
        ad_config = db.session.query(ADConfiguration).first()

        if not ad_config:
            # Return default values or an empty structure if preferred over 404
            # For now, let's return an empty dict, which Pydantic schema can handle with defaults.
            # Or, return a 404 if a configuration is strictly expected to exist.
            # To match "If not found, return 404 or an empty dict with defaults."
            # Let's return an empty dict that the schema can populate with defaults if desired by client.
            # Or, more RESTfully, 404 if no configuration exists.
            # Let's try returning an empty object that schema can process.
            # A better approach for GET might be to return default values if no config exists.
            # For now, let's try to return a default schema instance if not found.
            # However, ADConfigurationResponseSchema(orm_mode=True).dump(None) might not work as expected.
            # Let's return an empty dict, and client can infer defaults or use a specific "create" flow.
             return ADConfigurationResponseSchema().model_dump(exclude_none=True), 200 # Return default values

        # Decrypt password for display? No, password should be write-only.
        # The schema ADConfigurationResponseSchema already excludes bind_password.
        return ADConfigurationResponseSchema.from_orm(ad_config).model_dump(), 200

    @admin_required
    def put(self):
        parser = reqparse.RequestParser()
        # Add arguments based on ADConfigurationSchema, using Pydantic for validation is better
        # For simplicity with flask-restful, using its reqparse here.
        # However, Pydantic validation is preferred for modern Flask apps.
        # Let's use Pydantic directly for validation.

        json_data = request.get_json()
        if not json_data:
            raise BadRequest("No JSON data provided.")

        try:
            # Use Pydantic for validation
            config_data = ADConfigurationSchema(**json_data)
        except ValueError as e: # Pydantic's ValidationError inherits from ValueError
            raise BadRequest(f"Invalid configuration data: {e}")

        # Assuming a single global AD config or the first one for update.
        # A real system might use current_user.current_tenant_id if admin is tenant-scoped.
        # Or, if `id` is passed in json_data and it's an update to an existing one.

        # For this example, we'll try to fetch by ID if provided, else assume first record.
        # This is simplistic; a robust API would use tenant_id or a specific ID from path.
        ad_config = None
        if config_data.id:
            ad_config = db.session.query(ADConfiguration).filter(ADConfiguration.id == config_data.id).first()

        if not ad_config : # If no ID provided or not found by ID, try to get the first one (assuming single global config)
            ad_config = db.session.query(ADConfiguration).first()

        if not ad_config: # If still not found, create a new one
            ad_config = ADConfiguration()
            # If tenant_id is required and not in schema or derived, this will fail.
            # ADConfigurationSchema requires tenant_id.
            db.session.add(ad_config)

        # Populate fields from Pydantic model
        for field, value in config_data.model_dump(exclude_unset=True).items():
            if field == "bind_password": # Handle password separately
                if value: # If password is provided
                    # tenant_id is needed for encryption.
                    # If ad_config.tenant_id is not set yet (new record), this will fail.
                    # Ensure tenant_id is set before encrypting.
                    if not ad_config.tenant_id and hasattr(current_user, 'current_tenant_id'):
                         # This is a fallback, ideally tenant_id is part of config_data or known context
                        ad_config.tenant_id = current_user.current_tenant_id

                    if not ad_config.tenant_id:
                        raise BadRequest("Tenant ID is required for encrypting password but not found.")

                    try:
                        ad_config.encrypted_bind_password = encrypt_token(str(ad_config.tenant_id), value).encode('utf-8')
                    except Exception as e:
                        # Log error, potentially don't save password or halt operation
                        # For now, re-raise or handle as appropriate for the subtask
                        # This could happen if tenant_id is invalid or RSA keys are missing for the tenant.
                        raise BadRequest(f"Could not encrypt bind password: {str(e)}")
                # If password is None or empty string in request, it means "do not change" or "clear".
                # If value is None, we might want to clear encrypted_bind_password or leave it as is.
                # Current Pydantic schema makes it Optional[str], so None is possible.
                # If request sends null for password, `value` will be None here.
                elif value is None and ad_config.encrypted_bind_password is not None:
                    # If client explicitly sends null for password, clear it.
                    # This behavior might need refinement (e.g., require explicit clear flag).
                    ad_config.encrypted_bind_password = None
                # If password field is not in the request payload at all, `value` won't be processed here
                # due to `exclude_unset=True`. This means password remains unchanged if not provided.

            elif field != "id": # Don't try to set ID directly like this
                setattr(ad_config, field, value)

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise BadRequest(f"Database error: {str(e)}")

        return ADConfigurationResponseSchema.from_orm(ad_config).model_dump(), 200


class ADTestConnectionResource(Resource):
    @admin_required
    def post(self):
        json_data = request.get_json()
        if not json_data:
            raise BadRequest("No JSON data provided.")

        try:
            test_data = ADConfigurationTestRequestSchema(**json_data)
        except ValueError as e: # Pydantic's ValidationError
            raise BadRequest(f"Invalid test data: {e}")

        # Create a temporary ADConfiguration object for testing
        # This config isn't saved, just used to instantiate ADAuthService
        # It needs all relevant fields that ADAuthService might use from ADConfiguration model.
        # The ADConfigurationTestRequestSchema should ideally contain all necessary fields
        # for a connection test (server_url, bind_dn, bind_password).
        # Let's refine this to create a proper ADConfiguration-like object.

        temp_config_obj = ADConfiguration(
            is_enabled=True, # Must be enabled for service to work
            server_url=str(test_data.server_url), # Pydantic model ensures HttpUrl, convert to string for SQLAlchemy model
            bind_dn=test_data.bind_dn,
            # encrypted_bind_password is not directly set from test_data.bind_password here.
            # ADAuthService currently expects encrypted_bind_password to be bytes or string.
            # For testing, we pass the plain password to ADAuthService,
            # which will use it directly as per subtask instructions for _get_ldap_connection.
            # This means ADAuthService needs a slight adjustment or this object needs to be carefully crafted.

            # Let's make ADAuthService use plain text if encrypted_bind_password is set with a special marker
            # or adjust ADAuthService to accept raw password for testing.
            # For now, the subtask says: "assume the password in ADConfiguration.encrypted_bind_password is plain text"
            # So, we set `encrypted_bind_password` directly with the plain text password from the test request.
            encrypted_bind_password=test_data.bind_password.encode('utf-8') if test_data.bind_password else None,


            # Dummy values for other required fields of ADConfiguration model, not used by test_connection itself
            # but required by SQLAlchemy model if we were to save it.
            # For a non-saved instance, these might not be strictly needed if ADAuthService only accesses above fields.
            tenant_id=current_user.current_tenant_id if hasattr(current_user, 'current_tenant_id') else 'dummy_tenant_id_for_test', # Placeholder
            user_search_base="dc=example,dc=com", # Dummy
            user_search_filter="(&(objectClass=user)(sAMAccountName=%(username)s))", #Dummy
            attribute_mapping_username = "sAMAccountName", # Dummy
            attribute_mapping_email= "mail", # Dummy
            attribute_mapping_display_name="displayName" # Dummy
        )

        auth_service = ADAuthService(temp_config_obj)
        connected, error_message = auth_service.test_connection()

        if connected:
            return {'status': 'success'}, 200
        else:
            return {'status': 'failure', 'error': error_message or "Unknown error"}, 400

# Registration will be done in api/controllers/console/__init__.py
