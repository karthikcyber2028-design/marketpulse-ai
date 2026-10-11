from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.vulnerability import (
    DataSource,
    DeploymentContext,
    ImpactCategory,
    VulnSeverity,
    VulnStatus,
)
from app.models.alert import AlertSeverity, AlertStatus, DeliveryChannel
from app.models.manufacturer import SupportStatus
from app.models.device import DeviceLifecycleStatus


# --- Vulnerability Schemas ---
class VulnerabilityBase(BaseModel):
    cve_id: str = Field(..., max_length=20)
    cve_description: str
    severity: VulnSeverity = VulnSeverity.UNKNOWN
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v2_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_description: Optional[str] = None
    affected_cpe: Optional[str] = None
    affected_product_names: Optional[str] = None
    references: Optional[str] = None
    exploit_available: bool = False
    actively_exploited: bool = False
    first_known_exploitation: Optional[datetime] = None


class VulnerabilityCreate(VulnerabilityBase):
    source_name: Optional[str] = None
    manufacturer_id: Optional[int] = None
    published_date: Optional[datetime] = None
    confidence_score: float = Field(0.5, ge=0, le=1)
    confidence_reasoning: Optional[str] = None


class VulnerabilityUpdate(BaseModel):
    severity: Optional[VulnSeverity] = None
    status: Optional[VulnStatus] = None
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_v2_score: Optional[float] = Field(None, ge=0, le=10)
    exploit_available: Optional[bool] = None
    actively_exploited: Optional[bool] = None
    confidence_score: Optional[float] = Field(None, ge=0, le=1)
    confidence_reasoning: Optional[str] = None
    manufacturer_id: Optional[int] = None
    composite_risk_score: Optional[float] = None


class VulnerabilityResponse(VulnerabilityBase):
    id: int
    status: VulnStatus
    source_id: Optional[int] = None
    manufacturer_id: Optional[int] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    composite_risk_score: Optional[float] = None
    confidence_score: float = 0.5
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityResponse]
    total: int
    page: int
    page_size: int
    pages: int


# --- Manufacturer Schemas ---
class ManufacturerBase(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    website: Optional[str] = None
    headquarters_country: Optional[str] = None
    founded_year: Optional[int] = None
    logo_url: Optional[str] = None


class ManufacturerCreate(ManufacturerBase):
    pass


class ManufacturerResponse(ManufacturerBase):
    id: int
    slug: str
    security_posture_score: Optional[float] = 50.0
    avg_time_to_patch_hours: Optional[float] = None
    patch_availability_rate: Optional[float] = None
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    active_vulnerabilities: int = 0
    risk_rating: Optional[str] = None
    default_support_status: SupportStatus = SupportStatus.ACTIVE
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Device Schemas ---
class DeviceBase(BaseModel):
    model_name: str = Field(..., max_length=255)
    model_number: Optional[str] = None
    hardware_revision: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    deployment_context: str = "consumer"
    estimated_units_deployed: Optional[int] = None
    default_protocols: Optional[str] = None


class DeviceCreate(DeviceBase):
    manufacturer_id: int
    product_line_id: Optional[int] = None


class DeviceResponse(DeviceBase):
    id: int
    manufacturer_id: int
    product_line_id: Optional[int] = None
    lifecycle_status: DeviceLifecycleStatus = DeviceLifecycleStatus.ACTIVE
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Alert Schemas ---
class AlertRuleBase(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    conditions: str  # JSON string
    notification_channels: str  # JSON array string
    escalation_timeout_minutes: int = 60
    auto_escalate: bool = False
    cooldown_minutes: int = 60
    max_alerts_per_day: int = 50


class AlertRuleCreate(AlertRuleBase):
    pass


class AlertRuleResponse(AlertRuleBase):
    id: int
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    id: int
    vulnerability_id: int
    rule_id: Optional[int] = None
    severity: AlertSeverity
    status: AlertStatus
    title: str
    message: str
    affected_devices_summary: Optional[str] = None
    assigned_to: Optional[str] = None
    escalation_level: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Score Schemas ---
class ScoreBreakdownResponse(BaseModel):
    vulnerability_id: int
    composite_score: float
    cvss_component: float
    exploit_availability_component: float
    wild_exploitation_component: float
    manufacturer_response_component: float
    device_population_component: float
    deployment_context_component: float
    age_component: float
    data_breach_score: float
    device_compromise_score: float
    botnet_score: float
    lateral_movement_score: float
    physical_safety_score: float
    calculated_at: datetime

    model_config = {"from_attributes": True}


# --- Dashboard Schemas ---
class DashboardSummary(BaseModel):
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    active_alerts: int
    manufacturers_tracked: int
    devices_tracked: int
    avg_risk_score: Optional[float] = None
    recently_patched: int = 0
    actively_exploited: int = 0


class ManufacturerRanking(BaseModel):
    manufacturer_id: int
    manufacturer_name: str
    slug: str
    security_posture_score: float
    total_vulnerabilities: int
    critical_vulnerabilities: int
    avg_time_to_patch_hours: Optional[float]
    patch_availability_rate: Optional[float]
    risk_rating: Optional[str]


class TrendData(BaseModel):
    date: str
    count: int
    severity: Optional[str] = None


# --- Common ---
class PaginatedParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)
    sort_by: Optional[str] = "created_at"
    sort_order: str = "desc"


class APIResponse(BaseModel):
    success: bool = True
    message: str = "OK"
    data: Optional[dict | list | None] = None
