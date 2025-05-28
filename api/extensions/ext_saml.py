import os
from authlib.integrations.flask_client import AuthlibIntegrationsFlaskClient
from flask import Flask
from api.configs import saml_config

saml_client = AuthlibIntegrationsFlaskClient()

def read_file_content(path: str) -> str | None:
    """Reads content from a file path."""
    if path and os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return f.read()
        except IOError:
            # Log this error appropriately in a real application
            print(f"Warning: Could not read file at {path}")
    return None

def init_app(app: Flask):
    if saml_config.SAML_ENABLED:
        # Construct full URLs
        server_name = app.config.get('SERVER_NAME') or 'localhost:5001'
        scheme = 'http' if 'localhost' in server_name or '127.0.0.1' in server_name else 'https'
        
        # Ensure APPLICATION_ROOT is handled correctly, default to '/' if not set
        application_root = app.config.get('APPLICATION_ROOT') or '/'
        if not application_root.startswith('/'):
            application_root = '/' + application_root
        if application_root.endswith('/'):
            application_root = application_root[:-1]

        base_url = f"{scheme}://{server_name}{application_root}"
        
        acs_url = f"{base_url}{saml_config.SAML_ACS_URL_PATH}"
        slo_url = f"{base_url}{saml_config.SAML_SLO_URL_PATH}"

        sp_settings = {
            "entity_id": saml_config.SAML_SP_ENTITY_ID,
            "acs_url": acs_url,
            "slo_url": slo_url,
            "certificate": read_file_content(saml_config.SAML_SP_X509_CERT_PATH),
            "private_key": read_file_content(saml_config.SAML_SP_PRIVATE_KEY_PATH),
            "idp_metadata_url": saml_config.SAML_IDP_METADATA_URL,
            "idp_entity_id": saml_config.SAML_IDP_ENTITY_ID,
            "sign_request": saml_config.SAML_SIGN_REQUEST,
            "want_assertions_signed": saml_config.SAML_WANT_ASSERTIONS_SIGNED,
            "want_response_signed": saml_config.SAML_WANT_RESPONSE_SIGNED,
            "encrypt_assertion": saml_config.SAML_ENCRYPT_ASSERTION,
            "debug": saml_config.SAML_DEBUG,
            "metadata_cache_lifetime": saml_config.SAML_METADATA_CACHE_LIFETIME,
        }

        # Remove None values for certificate and private_key if files are not found
        if sp_settings["certificate"] is None:
            print(f"Warning: SAML SP certificate not found at {saml_config.SAML_SP_X509_CERT_PATH}. Proceeding without it.")
            del sp_settings["certificate"]
        
        if sp_settings["private_key"] is None:
            print(f"Warning: SAML SP private key not found at {saml_config.SAML_SP_PRIVATE_KEY_PATH}. Proceeding without it.")
            del sp_settings["private_key"]

        saml_client.register(
            name=saml_config.SAML_PROVIDER_NAME,
            client_kwargs={
                "saml_sp_settings": sp_settings
            },
            # Authlib uses the 'metadata_url' parameter in client_kwargs for SAML,
            # but it's more common to pass all SAML SP settings together.
            # We are passing idp_metadata_url within saml_sp_settings.
            # If Authlib requires it separately, this might need adjustment.
            # For now, assuming saml_sp_settings is the primary way.
        )
        saml_client.init_app(app)
