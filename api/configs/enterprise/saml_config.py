from pydantic import BaseSettings, Field

class SAMLConfig(BaseSettings):
    SAML_IDP_METADATA_URL: str = Field(default="", env="SAML_IDP_METADATA_URL")
    SAML_IDP_ENTITY_ID: str = Field(default="", env="SAML_IDP_ENTITY_ID")
    SAML_SP_ENTITY_ID: str = Field(default="dify-sp", env="SAML_SP_ENTITY_ID")
    SAML_ACS_URL_PATH: str = Field(default="/sso/saml/acs", env="SAML_ACS_URL_PATH")
    SAML_SLO_URL_PATH: str = Field(default="/sso/saml/slo", env="SAML_SLO_URL_PATH")
    SAML_SP_X509_CERT_PATH: str = Field(default="", env="SAML_SP_X509_CERT_PATH")
    SAML_SP_PRIVATE_KEY_PATH: str = Field(default="", env="SAML_SP_PRIVATE_KEY_PATH")
    SAML_METADATA_CACHE_LIFETIME: int = Field(default=3600, env="SAML_METADATA_CACHE_LIFETIME")
    SAML_SIGN_REQUEST: bool = Field(default=False, env="SAML_SIGN_REQUEST")
    SAML_WANT_ASSERTIONS_SIGNED: bool = Field(default=False, env="SAML_WANT_ASSERTIONS_SIGNED")
    SAML_WANT_RESPONSE_SIGNED: bool = Field(default=False, env="SAML_WANT_RESPONSE_SIGNED")
    SAML_ENCRYPT_ASSERTION: bool = Field(default=False, env="SAML_ENCRYPT_ASSERTION")
    SAML_DEBUG: bool = Field(default=False, env="SAML_DEBUG")
    SAML_ENABLED: bool = Field(default=False, env="SAML_ENABLED")
    SAML_DEFAULT_USER_ROLE: str = Field(default="normal", env="SAML_DEFAULT_USER_ROLE")
    SAML_PROVIDER_NAME: str = Field(default="AzureAD_SAML", env="SAML_PROVIDER_NAME")

    class Config:
        env_prefix = "SAML_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
