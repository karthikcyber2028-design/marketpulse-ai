from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


class AlertSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    DISMISSED = "dismissed"


class DeliveryChannel(str, enum.Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"
    DASHBOARD = "dashboard"
    TICKETING = "ticketing"


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_severity", "severity"),
        Index("ix_alert_status", "status"),
        Index("ix_alert_vuln", "vulnerability_id"),
        Index("ix_alert_created", "created_at"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    rule_id = Column(Integer, ForeignKey("alert_rules.id", ondelete="SET NULL"))
    severity = Column(Enum(AlertSeverity), nullable=False)
    status = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    title = Column(String(512), nullable=False)
    message = Column(Text, nullable=False)
    affected_devices_summary = Column(Text)
    assigned_to = Column(String(255))
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    escalation_level = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    vulnerability = relationship("Vulnerability", back_populates="alerts")
    rule = relationship("AlertRule", back_populates="alerts")
    deliveries = relationship("AlertDelivery", back_populates="alert", cascade="all, delete-orphan")


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        Index("ix_rule_active", "is_active"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    is_active = Column(Boolean, default=True, nullable=False)

    # Trigger conditions (JSON)
    conditions = Column(Text, nullable=False)
    # Example: {"min_severity": "high", "manufacturer_ids": [1,2], "categories": ["router"],
    #           "min_risk_score": 7.0, "deployment_contexts": ["critical_infrastructure"]}

    # Notification settings
    notification_channels = Column(Text, nullable=False)  # JSON array
    escalation_timeout_minutes = Column(Integer, default=60)
    auto_escalate = Column(Boolean, default=False)

    # Rate limiting
    cooldown_minutes = Column(Integer, default=60)
    max_alerts_per_day = Column(Integer, default=50)

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    alerts = relationship("Alert", back_populates="rule")


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    channel = Column(Enum(DeliveryChannel), nullable=False)
    recipient = Column(String(255))
    status = Column(String(50), nullable=False)  # pending, sent, failed, bounced
    delivered_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    alert = relationship("Alert", back_populates="deliveries")


class EscalationPath(Base):
    __tablename__ = "escalation_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    severity_trigger = Column(Enum(AlertSeverity), nullable=False)
    levels = Column(Text, nullable=False)  # JSON: [{"level": 0, "recipients": [...], "timeout": 30}]
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
