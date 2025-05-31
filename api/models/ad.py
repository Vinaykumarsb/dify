from sqlalchemy import Column, String, Boolean, DateTime, LargeBinary, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()

class ADConfiguration(Base):
    __tablename__ = 'ad_configurations'
    __table_args__ = ({'schema': 'extensions'}) # Assuming 'extensions' schema as per other models

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    is_enabled = Column(Boolean, nullable=False, default=False)
    server_url = Column(String(255), nullable=False)
    bind_dn = Column(String(255), nullable=True)
    encrypted_bind_password = Column(LargeBinary, nullable=True) # For storing encrypted password
    user_search_base = Column(String(255), nullable=False)
    user_search_filter = Column(String(1024), nullable=False, default='(&(objectClass=user)(sAMAccountName=%(username)s))')
    group_search_base = Column(String(255), nullable=True)
    group_search_filter = Column(String(1024), nullable=True, default='(&(objectClass=group)(member=%(user_dn)s))')

    # Attribute mapping
    attribute_mapping_username = Column(String(255), nullable=False, default='sAMAccountName')
    attribute_mapping_email = Column(String(255), nullable=False, default='mail')
    attribute_mapping_display_name = Column(String(255), nullable=False, default='displayName')

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<ADConfiguration(id={self.id}, tenant_id={self.tenant_id}, is_enabled={self.is_enabled}, server_url='{self.server_url}')>"
