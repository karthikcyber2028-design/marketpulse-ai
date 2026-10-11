from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

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


class SupportStatus(str, enum.Enum):
    ACTIVE = "active"
    LIMITED = "limited"
    END_OF_LIFE = "end_of_life"
    END_OF_SERVICE = "end_of_service"
    UNKNOWN = "unknown"


class Manufacturer(Base):
    __tablename__ = "manufacturers"
    __table_args__ = (
        Index("ix_mfg_name", "name"),
        Index("ix_mfg_security_posture", "security_posture_score"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    website = Column(String(512))
    headquarters_country = Column(String(100))
    founded_year = Column(Integer)
    logo_url = Column(String(512))

    # Security posture metrics (rolling averages)
    security_posture_score = Column(Float, default=50.0)  # 0-100
    avg_time_to_patch_hours = Column(Float)
    patch_availability_rate = Column(Float)  # % of vulns patched
    avg_disclosure_transparency = Column(Float)  # 0-100
    total_vulnerabilities = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    active_vulnerabilities = Column(Integer, default=0)

    # Overall assessment
    risk_rating = Column(String(20))  # exemplary, good, average, poor, critical
    assessment_notes = Column(Text)
    last_assessment_date = Column(DateTime(timezone=True))

    # Support status
    default_support_status = Column(Enum(SupportStatus), default=SupportStatus.ACTIVE)

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="manufacturer")
    product_lines = relationship("ProductLine", back_populates="manufacturer", cascade="all, delete-orphan")
    metrics_history = relationship(
        "ManufacturerMetric", back_populates="manufacturer", cascade="all, delete-orphan"
    )


class ProductLine(Base):
    __tablename__ = "product_lines"
    __table_args__ = (
        Index("ix_pl_manufacturer", "manufacturer_id"),
        UniqueConstraint("manufacturer_id", "name", name="uq_product_line"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    manufacturer_id = Column(
        Integer, ForeignKey("manufacturers.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String(255), nullable=False)
    category = Column(String(100))  # router, camera, sensor, gateway, controller, etc.
    description = Column(Text)
    website = Column(String(512))
    support_status = Column(Enum(SupportStatus), default=SupportStatus.ACTIVE)
    eol_date = Column(DateTime(timezone=True))
    eol_announcement_date = Column(DateTime(timezone=True))
    total_devices_estimated = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    manufacturer = relationship("Manufacturer", back_populates="product_lines")
    devices = relationship("Device", back_populates="product_line", cascade="all, delete-orphan")


class ManufacturerMetric(Base):
    __tablename__ = "manufacturer_metrics"
    __table_args__ = (
        Index("ix_mfg_metric_manufacturer", "manufacturer_id"),
        Index("ix_mfg_metric_date", "recorded_date"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    manufacturer_id = Column(
        Integer, ForeignKey("manufacturers.id", ondelete="CASCADE"), nullable=False
    )
    recorded_date = Column(DateTime(timezone=True), nullable=False)

    total_vulnerabilities = Column(Integer, default=0)
    new_vulnerabilities = Column(Integer, default=0)
    patched_vulnerabilities = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    active_vulnerabilities = Column(Integer, default=0)

    avg_time_to_patch_hours = Column(Float)
    patch_availability_rate = Column(Float)
    disclosure_transparency_score = Column(Float)
    security_posture_score = Column(Float)

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    manufacturer = relationship("Manufacturer", back_populates="metrics_history")
