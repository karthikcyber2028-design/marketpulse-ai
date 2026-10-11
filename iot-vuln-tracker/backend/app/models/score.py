from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        Index("ix_risk_vuln", "vulnerability_id"),
        Index("ix_risk_score", "composite_score"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    composite_score = Column(Float, nullable=False)  # 0.0 - 10.0
    calculated_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    vulnerability = relationship("Vulnerability", uselist=False)


class ScoreBreakdown(Base):
    __tablename__ = "score_breakdowns"
    __table_args__ = (
        Index("ix_breakdown_vuln", "vulnerability_id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # Component scores (all normalized 0-10)
    cvss_component = Column(Float, default=0.0)
    exploit_availability_component = Column(Float, default=0.0)
    wild_exploitation_component = Column(Float, default=0.0)
    manufacturer_response_component = Column(Float, default=0.0)
    device_population_component = Column(Float, default=0.0)
    deployment_context_component = Column(Float, default=0.0)
    age_component = Column(Float, default=0.0)

    # Weights used for calculation
    cvss_weight = Column(Float, default=0.30)
    exploit_weight = Column(Float, default=0.15)
    wild_exploit_weight = Column(Float, default=0.15)
    manufacturer_weight = Column(Float, default=0.10)
    population_weight = Column(Float, default=0.10)
    context_weight = Column(Float, default=0.10)
    age_weight = Column(Float, default=0.10)

    # Impact category scores
    data_breach_score = Column(Float, default=0.0)
    device_compromise_score = Column(Float, default=0.0)
    botnet_score = Column(Float, default=0.0)
    lateral_movement_score = Column(Float, default=0.0)
    physical_safety_score = Column(Float, default=0.0)

    # Metadata
    calculation_notes = Column(Text)
    calculated_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="risk_score_detail")
