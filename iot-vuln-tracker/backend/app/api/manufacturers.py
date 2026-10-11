from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.manufacturer import Manufacturer, ManufacturerMetric, ProductLine
from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.device import Device, DeviceFirmware
from app.schemas import (
    ManufacturerCreate,
    ManufacturerResponse,
    DeviceCreate,
    DeviceResponse,
    APIResponse,
)
from app.scoring.engine import RiskScoringEngine

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Manufacturer Endpoints ---
@router.get("/manufacturers")
async def list_manufacturers(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: str = "security_posture_score",
    sort_order: str = "asc",
    risk_rating: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Manufacturer)
    count_query = select(func.count(Manufacturer.id))
    filters = []

    if risk_rating:
        filters.append(Manufacturer.risk_rating == risk_rating)
    if search:
        filters.append(Manufacturer.name.ilike(f"%{search}%"))

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    sort_col = getattr(Manufacturer, sort_by, Manufacturer.security_posture_score)
    if sort_order == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    manufacturers = result.scalars().all()

    return {
        "items": [ManufacturerResponse.model_validate(m) for m in manufacturers],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/manufacturers/{mfg_id}")
async def get_manufacturer(mfg_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Manufacturer).where(Manufacturer.id == mfg_id))
    mfg = result.scalar_one_or_none()
    if not mfg:
        raise HTTPException(status_code=404, detail="Manufacturer not found")
    return ManufacturerResponse.model_validate(mfg)


@router.post("/manufacturers", response_model=APIResponse)
async def create_manufacturer(data: ManufacturerCreate, db: AsyncSession = Depends(get_db)):
    slug = data.name.lower().replace(" ", "-").replace(".", "")
    existing = await db.execute(
        select(Manufacturer).where(Manufacturer.slug == slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Manufacturer already exists")

    mfg = Manufacturer(**data.model_dump(), slug=slug)
    db.add(mfg)
    await db.flush()
    return APIResponse(message=f"Created {mfg.name}", data={"id": mfg.id})


@router.get("/manufacturers/{mfg_id}/vulnerabilities")
async def get_manufacturer_vulnerabilities(
    mfg_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: VulnSeverity | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability).where(Vulnerability.manufacturer_id == mfg_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    query = query.order_by(Vulnerability.composite_risk_score.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    vulns = result.scalars().all()
    return [{"id": v.id, "cve_id": v.cve_id, "severity": v.severity.value,
             "risk_score": v.composite_risk_score, "status": v.status.value} for v in vulns]


@router.get("/manufacturers/{mfg_id}/metrics")
async def get_manufacturer_metrics(
    mfg_id: int,
    days: int = Query(90, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(ManufacturerMetric)
        .where(
            ManufacturerMetric.manufacturer_id == mfg_id,
            ManufacturerMetric.recorded_date >= cutoff,
        )
        .order_by(ManufacturerMetric.recorded_date.asc())
    )
    metrics = result.scalars().all()
    return [
        {
            "date": m.recorded_date.isoformat(),
            "total_vulns": m.total_vulnerabilities,
            "new_vulns": m.new_vulnerabilities,
            "patched": m.patched_vulnerabilities,
            "critical": m.critical_vulnerabilities,
            "posture_score": m.security_posture_score,
            "avg_ttp": m.avg_time_to_patch_hours,
        }
        for m in metrics
    ]


@router.post("/manufacturers/rescore", response_model=APIResponse)
async def rescore_all_manufacturers(db: AsyncSession = Depends(get_db)):
    engine = RiskScoringEngine(db)
    await engine.update_manufacturer_scores()
    return APIResponse(message="Manufacturer scores updated")


# --- Product Line Endpoints ---
@router.get("/manufacturers/{mfg_id}/product-lines")
async def list_product_lines(mfg_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ProductLine).where(ProductLine.manufacturer_id == mfg_id)
    )
    lines = result.scalars().all()
    return [
        {
            "id": pl.id,
            "name": pl.name,
            "category": pl.category,
            "support_status": pl.support_status.value if pl.support_status else None,
            "eol_date": pl.eol_date.isoformat() if pl.eol_date else None,
            "total_devices_estimated": pl.total_devices_estimated,
        }
        for pl in lines
    ]


@router.post("/manufacturers/{mfg_id}/product-lines", response_model=APIResponse)
async def create_product_line(
    mfg_id: int,
    name: str,
    category: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    pl = ProductLine(manufacturer_id=mfg_id, name=name, category=category)
    db.add(pl)
    await db.flush()
    return APIResponse(message=f"Created product line {name}", data={"id": pl.id})


# --- Device Endpoints ---
@router.get("/devices")
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    manufacturer_id: int | None = None,
    category: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Device)
    if manufacturer_id:
        query = query.where(Device.manufacturer_id == manufacturer_id)
    if category:
        query = query.where(Device.category == category)

    total_result = await db.execute(select(func.count(Device.id)))
    total = total_result.scalar()

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    devices = result.scalars().all()

    return {
        "items": [DeviceResponse.model_validate(d) for d in devices],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/devices", response_model=APIResponse)
async def create_device(data: DeviceCreate, db: AsyncSession = Depends(get_db)):
    device = Device(**data.model_dump())
    db.add(device)
    await db.flush()
    return APIResponse(message=f"Created device {device.model_name}", data={"id": device.id})


@router.get("/devices/{device_id}/firmware")
async def list_firmware_versions(device_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DeviceFirmware)
        .where(DeviceFirmware.device_id == device_id)
        .order_by(DeviceFirmware.release_date.desc())
    )
    versions = result.scalars().all()
    return [
        {
            "id": f.id,
            "version": f.version,
            "release_date": f.release_date.isoformat() if f.release_date else None,
            "is_latest": f.is_latest,
            "end_of_support_date": f.end_of_support_date.isoformat() if f.end_of_support_date else None,
        }
        for f in versions
    ]


@router.post("/devices/{device_id}/firmware", response_model=APIResponse)
async def add_firmware_version(
    device_id: int,
    version: str,
    release_date: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    rd = datetime.fromisoformat(release_date) if release_date else None
    fw = DeviceFirmware(device_id=device_id, version=version, release_date=rd)
    db.add(fw)
    await db.flush()
    return APIResponse(message=f"Added firmware {version}", data={"id": fw.id})
