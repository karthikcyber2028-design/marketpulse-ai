from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Integer,
    String,
    Text,
)
from app.database import Base


class IntegrationType(str, enum.Enum):
    WEBHOOK = "webhook"
    SIEM = "siem"
    TICKETING = "ticketing"
    ASSET_MANAGEMENT = "asset_management"


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    url = Column(String(512), nullable=False)
    secret = Column(String(255))
    is_active = Column(Boolean, default=True, nullable=False)
    event_types = Column(Text, nullable=False)  # JSON array: ["vuln_new", "alert_critical", etc.]
    headers = Column(Text)  # JSON object for custom headers
    retry_count = Column(Integer, default=3)
    timeout_seconds = Column(Integer, default=30)
    last_triggered_at = Column(DateTime(timezone=True))
    failure_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class SIEMIntegration(Base):
    __tablename__ = "siem_integrations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    siem_type = Column(String(50), nullable=False)  # splunk, elasticsearch, sentinel, qradar
    endpoint_url = Column(String(512), nullable=False)
    api_key = Column(String(255))
    index_name = Column(String(100))
    is_active = Column(Boolean, default=True, nullable=False)
    event_format = Column(String(50), default="CEF")  # CEF, LEEF, JSON, Syslog
    last_synced_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class TicketingIntegration(Base):
    __tablename__ = "ticketing_integrations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)  # jira, servicenow, github, azure_devops
    base_url = Column(String(512), nullable=False)
    api_token = Column(String(255))
    project_key = Column(String(50))
    default_assignee = Column(String(255))
    auto_create_tickets = Column(Boolean, default=False)
    severity_to_priority_map = Column(Text)  # JSON: {"critical": "P1", "high": "P2", ...}
    is_active = Column(Boolean, default=True, nullable=False)
    last_synced_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class AssetManagementSync(Base):
    __tablename__ = "asset_management_syncs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)  # cmdb, snipeit, netbox, custom
    endpoint_url = Column(String(512), nullable=False)
    api_key = Column(String(255))
    sync_interval_minutes = Column(Integer, default=60)
    is_active = Column(Boolean, default=True, nullable=False)
    last_synced_at = Column(DateTime(timezone=True))
    device_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
