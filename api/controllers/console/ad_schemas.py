from typing import Optional, Dict
import uuid

from pydantic import BaseModel, Field, HttpUrl


class ADConfigurationSchema(BaseModel):
    id: Optional[uuid.UUID] = Field(None, description="Unique identifier for the AD configuration")
    tenant_id: uuid.UUID = Field(description="Tenant ID associated with this configuration")
    is_enabled: bool = Field(False, description="Enable or disable AD authentication")
    server_url: HttpUrl = Field(description="LDAP server URL (e.g., ldap://ldap.example.com:389 or ldaps://ldap.example.com:636)")
    bind_dn: Optional[str] = Field(None, description="Distinguished Name (DN) for binding to the LDAP server. Optional if anonymous bind is allowed for search.")
    bind_password: Optional[str] = Field(None, description="Password for the Bind DN. Write-only.", write_only=True)
    user_search_base: str = Field(description="Base DN for user searches (e.g., ou=users,dc=example,dc=com)")
    user_search_filter: str = Field(
        default='(&(objectClass=user)(sAMAccountName=%(username)s))',
        description="LDAP filter for user searches. Use %(username)s as a placeholder for the username."
    )
    group_search_base: Optional[str] = Field(None, description="Base DN for group searches (e.g., ou=groups,dc=example,dc=com)")
    group_search_filter: Optional[str] = Field(
        default='(&(objectClass=group)(member=%(user_dn)s))',
        description="LDAP filter for group searches. Use %(user_dn)s as a placeholder for the user's DN."
    )

    attribute_mapping_username: str = Field(
        default='sAMAccountName',
        description="LDAP attribute to map to the username."
    )
    attribute_mapping_email: str = Field(
        default='mail',
        description="LDAP attribute to map to the user's email."
    )
    attribute_mapping_display_name: str = Field(
        default='displayName',
        description="LDAP attribute to map to the user's display name."
    )

    created_at: Optional[str] = Field(None, description="Timestamp of creation")
    updated_at: Optional[str] = Field(None, description="Timestamp of last update")

    class Config:
        orm_mode = True
        extra = 'ignore' # Ignore extra fields from input
        # Ensure password is not included when serializing to dict (e.g. for GET responses)
        # The `write_only=True` on the field itself should handle this for Pydantic v2,
        # but this is an additional layer for older Pydantic or other serialization methods.
        # For Pydantic v2, `model_dump(exclude={'bind_password'})` would be used in the API logic.
        # However, Pydantic's `write_only` is the more idiomatic way for v2.


class ADConfigurationResponseSchema(ADConfigurationSchema):
    bind_password: Optional[str] = Field(None, exclude=True) # Ensure password is not in response


class ADConfigurationListResponseSchema(BaseModel):
    data: list[ADConfigurationResponseSchema] = Field(description="List of AD configurations")

class ADConfigurationTestRequestSchema(BaseModel):
    server_url: HttpUrl
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    # No need for other fields, as this is just a connection test / simple bind test

class ADConfigurationTestResponseSchema(BaseModel):
    connected: bool
    error: Optional[str] = None
