from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
)
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        {"extend_existing": True},
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    actor = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)  # create, update, delete, alert_sent, escalation, etc.
    entity_type = Column(String(100), nullable=False)  # vulnerability, manufacturer, alert, etc.
    entity_id = Column(Integer)
    details = Column(Text)  # JSON with change details
    ip_address = Column(String(45))
    user_agent = Column(String(512))


class DataRetentionPolicy(Base):
    __tablename__ = "data_retention_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String(100), nullable=False, unique=True)
    retention_days = Column(Integer, nullable=False)
    archive_before_delete = Column(Integer, default=0)  # days to archive
    is_active = Column(Integer, default=1)
    last_cleanup_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
