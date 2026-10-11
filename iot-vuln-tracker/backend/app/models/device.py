from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


class DeviceLifecycleStatus(str, enum.Enum):
    ACTIVE = "active"
    MATURING = "maturing"
    END_OF_SALE = "end_of_sale"
    END_OF_SUPPORT = "end_of_support"
    END_OF_LIFE = "end_of_life"


# Association table for vulnerability-device many-to-many
vulnerability_device_map = Table(
    "vulnerability_device_map",
    Base.metadata,
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
    Column("device_id", Integer, ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime(timezone=True), default=datetime.utcnow),
)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_device_manufacturer", "manufacturer_id"),
        Index("ix_device_product_line", "product_line_id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    manufacturer_id = Column(
        Integer, ForeignKey("manufacturers.id", ondelete="CASCADE"), nullable=False
    )
    product_line_id = Column(Integer, ForeignKey("product_lines.id", ondelete="SET NULL"))

    model_name = Column(String(255), nullable=False)
    model_number = Column(String(100))
    hardware_revision = Column(String(50))
    description = Column(Text)
    category = Column(String(100))  # router, camera, sensor, gateway, controller
    lifecycle_status = Column(Enum(DeviceLifecycleStatus), default=DeviceLifecycleStatus.ACTIVE)

    # Deployment context
    deployment_context = Column(Enum("DeploymentContext", create_constraint=False), nullable=False)

    # Device population estimate
    estimated_units_deployed = Column(Integer)
    deployment_regions = Column(Text)  # JSON array

    # Protocol support
    default_protocols = Column(Text)  # JSON array: MQTT, CoAP, HTTP, Zigbee, Z-Wave, BLE, etc.

    # Product URL
    product_url = Column(String(512))

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    product_line = relationship("ProductLine", back_populates="devices")
    firmware_versions = relationship(
        "DeviceFirmware", back_populates="device", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship(
        "Vulnerability", secondary=vulnerability_device_map, back_populates="device_mappings"
    )


class DeviceFirmware(Base):
    __tablename__ = "device_firmware"
    __table_args__ = (
        Index("ix_firmware_device", "device_id"),
        UniqueConstraint("device_id", "version", name="uq_firmware_version"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    version = Column(String(100), nullable=False)
    release_date = Column(DateTime(timezone=True))
    is_latest = Column(Integer, default=0)
    end_of_support_date = Column(DateTime(timezone=True))
    changelog_url = Column(String(512))
    security_notes = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="firmware_versions")


class DeviceProtocol(Base):
    __tablename__ = "device_protocols"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False, unique=True)
    category = Column(String(50))  # application, transport, network
    description = Column(Text)
    security_features = Column(Text)  # TLS, encryption, auth methods
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
