from __future__ import annotations

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.vulnerability import VulnSeverity, VulnStatus, Vulnerability
from app.models.manufacturer import Manufacturer, ManufacturerMetric
from app.models.device import Device
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.schemas import DashboardSummary, ManufacturerRanking, TrendData

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    severity_counts = {}
    for sev in VulnSeverity:
        count = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.severity == sev)
            )
        ).scalar() or 0
        severity_counts[sev.value] = count

    active_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_([
                    AlertStatus.NEW,
                    AlertStatus.ACKNOWLEDGED,
                    AlertStatus.INVESTIGATING,
                    AlertStatus.ESCALATED,
                ])
            )
        )
    ).scalar() or 0

    mfg_count = (await db.execute(select(func.count(Manufacturer.id)))).scalar() or 0
    device_count = (await db.execute(select(func.count(Device.id)))).scalar() or 0

    avg_risk = (
        await db.execute(
            select(func.avg(Vulnerability.composite_risk_score)).where(
                Vulnerability.composite_risk_score.isnot(None)
            )
        )
    ).scalar()

    recently_patched = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status == VulnStatus.PATCHED,
                Vulnerability.updated_at >= datetime.utcnow() - timedelta(days=30),
            )
        )
    ).scalar() or 0

    actively_exploited = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.actively_exploited == True
            )
        )
    ).scalar() or 0

    return DashboardSummary(
        total_vulnerabilities=total,
        critical_vulnerabilities=severity_counts.get("critical", 0),
        high_vulnerabilities=severity_counts.get("high", 0),
        medium_vulnerabilities=severity_counts.get("medium", 0),
        low_vulnerabilities=severity_counts.get("low", 0),
        active_alerts=active_alerts,
        manufacturers_tracked=mfg_count,
        devices_tracked=device_count,
        avg_risk_score=round(avg_risk, 2) if avg_risk else None,
        recently_patched=recently_patched,
        actively_exploited=actively_exploited,
    )


@router.get("/dashboard/manufacturer-rankings")
async def manufacturer_rankings(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Manufacturer)
        .where(Manufacturer.total_vulnerabilities > 0)
        .order_by(Manufacturer.security_posture_score.asc())
        .limit(limit)
    )
    manufacturers = result.scalars().all()

    return [
        ManufacturerRanking(
            manufacturer_id=m.id,
            manufacturer_name=m.name,
            slug=m.slug,
            security_posture_score=m.security_posture_score or 50.0,
            total_vulnerabilities=m.total_vulnerabilities or 0,
            critical_vulnerabilities=m.critical_vulnerabilities or 0,
            avg_time_to_patch_hours=m.avg_time_to_patch_hours,
            patch_availability_rate=m.patch_availability_rate,
            risk_rating=m.risk_rating,
        )
        for m in manufacturers
    ]


@router.get("/dashboard/vulnerability-trends")
async def vulnerability_trends(
    days: int = Query(90, ge=7, le=365),
    group_by: str = Query("day", regex="^(day|week|month)$"),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.created_at >= cutoff)
        .order_by(Vulnerability.created_at.asc())
    )
    vulns = result.scalars().all()

    bucket_counts = {}
    for v in vulns:
        if group_by == "day":
            key = v.created_at.strftime("%Y-%m-%d")
        elif group_by == "week":
            key = v.created_at.strftime("%Y-W%W")
        else:
            key = v.created_at.strftime("%Y-%m")

        if key not in bucket_counts:
            bucket_counts[key] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        bucket_counts[key]["total"] += 1
        bucket_counts[key][v.severity.value] += 1

    return [
        {
            "date": k,
            "total": v["total"],
            "critical": v["critical"],
            "high": v["high"],
            "medium": v["medium"],
            "low": v["low"],
        }
        for k, v in sorted(bucket_counts.items())
    ]


@router.get("/dashboard/risk-distribution")
async def risk_distribution(db: AsyncSession = Depends(get_db)):
    ranges = [
        ("critical", 9.0, 10.0),
        ("high", 7.0, 8.99),
        ("medium", 4.0, 6.99),
        ("low", 0.0, 3.99),
        ("unscored", None, None),
    ]

    result = []
    for label, low, high in ranges:
        if low is None:
            count = (
                await db.execute(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.composite_risk_score.is_(None)
                    )
                )
            ).scalar() or 0
        else:
            count = (
                await db.execute(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.composite_risk_score.between(low, high)
                    )
                )
            ).scalar() or 0
        result.append({"range": label, "count": count})

    return result


@router.get("/dashboard/compliance-mapping")
async def compliance_mapping(db: AsyncSession = Depends(get_db)):
    """Map vulnerabilities to compliance frameworks."""
    total = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    critical = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == VulnSeverity.CRITICAL
            )
        )
    ).scalar() or 0

    actively_exploited = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.actively_exploited == True
            )
        )
    ).scalar() or 0

    unpatched = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status.in_([VulnStatus.UNPATCHED, VulnStatus.ANALYZING])
            )
        )
    ).scalar() or 0

    return {
        "nist_csf": {
            "identify": {
                "total_tracked_vulnerabilities": total,
                "manufacturer_profiles": (
                    await db.execute(select(func.count(Manufacturer.id)))
                ).scalar() or 0,
            },
            "protect": {
                "patched_vulnerabilities": (
                    await db.execute(
                        select(func.count(Vulnerability.id)).where(
                            Vulnerability.status == VulnStatus.PATCHED
                        )
                    )
                ).scalar() or 0,
                "unpatched_vulnerabilities": unpatched,
            },
            "detect": {
                "actively_exploited": actively_exploited,
                "critical_unpatched": critical,
            },
            "respond": {
                "active_alerts": (
                    await db.execute(
                        select(func.count(Alert.id)).where(
                            Alert.status.in_([
                                AlertStatus.NEW,
                                AlertStatus.INVESTIGATING,
                            ])
                        )
                    )
                ).scalar() or 0,
            },
        },
        "iec_62443": {
            "industrial_iot_exposure": (
                await db.execute(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.actively_exploited == True
                    )
                )
            ).scalar() or 0,
            "critical_infrastructure_vulns": critical,
        },
        "iso_27001": {
            "total_vulnerability_management_coverage": total,
            "response_effectiveness": round(
                (
                    (
                        await db.execute(
                            select(func.count(Vulnerability.id)).where(
                                Vulnerability.status.in_([
                                    VulnStatus.PATCHED,
                                    VulnStatus.PARTIALLY_PATCHED,
                                ])
                            )
                        )
                    ).scalar() or 0
                )
                / max(total, 1)
                * 100,
                1,
            ),
        },
    }


@router.get("/dashboard/top-risk-devices")
async def top_risk_devices(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    from app.models.vulnerability import vulnerability_device_map

    result = await db.execute(
        select(
            Device.id,
            Device.model_name,
            Device.category,
            Device.manufacturer_id,
            Device.estimated_units_deployed,
            func.count(Vulnerability.id).label("vuln_count"),
            func.avg(Vulnerability.composite_risk_score).label("avg_risk"),
        )
        .join(vulnerability_device_map, Device.id == vulnerability_device_map.c.device_id)
        .join(Vulnerability, Vulnerability.id == vulnerability_device_map.c.vulnerability_id)
        .group_by(Device.id)
        .order_by(desc("avg_risk"))
        .limit(limit)
    )
    rows = result.all()

    return [
        {
            "device_id": r.id,
            "model_name": r.model_name,
            "category": r.category,
            "vulnerability_count": r.vuln_count,
            "avg_risk_score": round(r.avg_risk, 2) if r.avg_risk else None,
            "estimated_units": r.estimated_units_deployed,
        }
        for r in rows
    ]
