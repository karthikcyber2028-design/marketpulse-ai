from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.vulnerability import (
    VulnSeverity,
    VulnStatus,
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityTag,
    VulnerabilityMitigation,
    DisputedVulnerability,
)
from app.models.manufacturer import Manufacturer, ProductLine
from app.models.device import Device, DeviceFirmware
from app.models.score import RiskScore, ScoreBreakdown
from app.models.alert import Alert, AlertRule, AlertStatus, AlertSeverity
from app.models.audit import AuditLog
from app.schemas import (
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnerabilityResponse,
    VulnerabilityListResponse,
    PaginatedParams,
    APIResponse,
    ScoreBreakdownResponse,
)
from app.scoring.engine import RiskScoringEngine
from app.alerts.service import AlertingService

logger = logging.getLogger(__name__)

router = APIRouter()


def _paginate(query, page: int, page_size: int):
    offset = (page - 1) * page_size
    return query.offset(offset).limit(page_size)


# --- Vulnerability Endpoints ---
@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: VulnSeverity | None = None,
    status: VulnStatus | None = None,
    manufacturer_id: int | None = None,
    min_risk_score: float | None = None,
    actively_exploited: bool | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))
    filters = []

    if severity:
        filters.append(Vulnerability.severity == severity)
    if status:
        filters.append(Vulnerability.status == status)
    if manufacturer_id:
        filters.append(Vulnerability.manufacturer_id == manufacturer_id)
    if min_risk_score is not None:
        filters.append(Vulnerability.composite_risk_score >= min_risk_score)
    if actively_exploited is not None:
        filters.append(Vulnerability.actively_exploited == actively_exploited)
    if search:
        filters.append(
            Vulnerability.cve_description.ilike(f"%{search}%")
            | Vulnerability.cve_id.ilike(f"%{search}%")
            | Vulnerability.affected_product_names.ilike(f"%{search}%")
        )

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    sort_col = getattr(Vulnerability, sort_by, Vulnerability.created_at)
    if sort_order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    query = _paginate(query, page, page_size)
    result = await db.execute(query)
    vulns = result.scalars().all()

    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(v) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnerabilityResponse.model_validate(vuln)


@router.post("/vulnerabilities", response_model=APIResponse)
async def create_vulnerability(
    data: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == data.cve_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"CVE {data.cve_id} already exists")

    vuln_data = data.model_dump()
    source_name = vuln_data.pop("source_name", None)

    if source_name:
        src_result = await db.execute(
            select(VulnerabilitySource).where(VulnerabilitySource.name == source_name)
        )
        source = src_result.scalar_one_or_none()
        if source:
            vuln_data["source_id"] = source.id

    vuln = Vulnerability(**vuln_data)
    db.add(vuln)
    await db.flush()

    engine = RiskScoringEngine(db)
    await engine.score_vulnerability(vuln)

    alert_svc = AlertingService(db)
    await alert_svc.evaluate_vulnerability(vuln)

    return APIResponse(message=f"Created {vuln.cve_id}", data={"id": vuln.id})


@router.patch("/vulnerabilities/{vuln_id}", response_model=APIResponse)
async def update_vulnerability(
    vuln_id: int,
    data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)
    vuln.updated_at = datetime.utcnow()

    engine = RiskScoringEngine(db)
    await engine.score_vulnerability(vuln)

    await db.flush()
    return APIResponse(message=f"Updated {vuln.cve_id}")


@router.delete("/vulnerabilities/{vuln_id}", response_model=APIResponse)
async def delete_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    await db.delete(vuln)
    await db.flush()
    return APIResponse(message=f"Deleted {vuln.cve_id}")


# --- Vulnerability Detail Endpoints ---
@router.get("/vulnerabilities/{vuln_id}/score")
async def get_vulnerability_score(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScoreBreakdown).where(ScoreBreakdown.vulnerability_id == vuln_id)
    )
    breakdown = result.scalar_one_or_none()
    if not breakdown:
        raise HTTPException(status_code=404, detail="Score breakdown not found")
    vuln_result = await db.execute(
        select(Vulnerability.composite_risk_score).where(Vulnerability.id == vuln_id)
    )
    composite = vuln_result.scalar_one_or_none() or 0.0
    data = {
        "vulnerability_id": breakdown.vulnerability_id,
        "composite_score": composite,
        "cvss_component": breakdown.cvss_component,
        "exploit_availability_component": breakdown.exploit_availability_component,
        "wild_exploitation_component": breakdown.wild_exploitation_component,
        "manufacturer_response_component": breakdown.manufacturer_response_component,
        "device_population_component": breakdown.device_population_component,
        "deployment_context_component": breakdown.deployment_context_component,
        "age_component": breakdown.age_component,
        "data_breach_score": breakdown.data_breach_score,
        "device_compromise_score": breakdown.device_compromise_score,
        "botnet_score": breakdown.botnet_score,
        "lateral_movement_score": breakdown.lateral_movement_score,
        "physical_safety_score": breakdown.physical_safety_score,
        "calculated_at": breakdown.calculated_at,
    }
    return ScoreBreakdownResponse.model_validate(data)


@router.post("/vulnerabilities/{vuln_id}/rescore", response_model=APIResponse)
async def rescore_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    engine = RiskScoringEngine(db)
    await engine.score_vulnerability(vuln)
    return APIResponse(message=f"Rescored {vuln.cve_id}: {vuln.composite_risk_score:.2f}")


@router.get("/vulnerabilities/{vuln_id}/mitigations")
async def get_mitigations(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(VulnerabilityMitigation).where(
            VulnerabilityMitigation.vulnerability_id == vuln_id
        )
    )
    mitigations = result.scalars().all()
    return [
        {
            "id": m.id,
            "type": m.mitigation_type,
            "description": m.description,
            "url": m.url,
            "verified": m.verified,
            "affected_versions": m.affected_versions,
            "fixed_versions": m.fixed_versions,
        }
        for m in mitigations
    ]


@router.post("/vulnerabilities/{vuln_id}/mitigations", response_model=APIResponse)
async def add_mitigation(
    vuln_id: int,
    mitigation_type: str,
    description: str,
    url: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    mit = VulnerabilityMitigation(
        vulnerability_id=vuln_id,
        mitigation_type=mitigation_type,
        description=description,
        url=url,
    )
    db.add(mit)
    await db.flush()
    return APIResponse(message="Mitigation added", data={"id": mit.id})


@router.post("/vulnerabilities/{vuln_id}/dispute", response_model=APIResponse)
async def dispute_vulnerability(
    vuln_id: int,
    disputed_by: str,
    dispute_reason: str,
    evidence: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    dispute = DisputedVulnerability(
        vulnerability_id=vuln_id,
        disputed_by=disputed_by,
        dispute_reason=dispute_reason,
        evidence=evidence,
        resolution="pending",
    )
    vuln.status = VulnStatus.DISPUTED
    db.add(dispute)
    await db.flush()
    return APIResponse(message="Dispute recorded", data={"id": dispute.id})


@router.patch("/vulnerabilities/{vuln_id}/dispute/{dispute_id}/resolve")
async def resolve_dispute(
    vuln_id: int,
    dispute_id: int,
    resolution: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DisputedVulnerability).where(
            DisputedVulnerability.id == dispute_id,
            DisputedVulnerability.vulnerability_id == vuln_id,
        )
    )
    dispute = result.scalar_one_or_none()
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")

    dispute.resolution = resolution
    dispute.resolved_at = datetime.utcnow()

    if resolution == "retracted":
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.id == vuln_id)
        )
        vuln = vuln_result.scalar_one_or_none()
        if vuln:
            vuln.status = VulnStatus.RETRACTED

    await db.flush()
    return APIResponse(message=f"Dispute resolved: {resolution}")
