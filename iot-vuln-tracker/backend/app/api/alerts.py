from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import (
    Alert,
    AlertRule,
    AlertDelivery,
    AlertStatus,
    AlertSeverity,
    EscalationPath,
)
from app.schemas import (
    AlertRuleCreate,
    AlertRuleResponse,
    AlertResponse,
    APIResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/alerts")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: AlertSeverity | None = None,
    status: AlertStatus | None = None,
    assigned_to: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))
    filters = []

    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if assigned_to:
        filters.append(Alert.assigned_to == assigned_to)

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(Alert.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "items": [AlertResponse.model_validate(a) for a in alerts],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/alerts/summary")
async def alert_summary(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(
            Alert.severity,
            Alert.status,
            func.count(Alert.id),
        ).group_by(Alert.severity, Alert.status)
    )
    rows = result.all()

    summary = {
        "by_severity": {},
        "by_status": {},
        "total": 0,
        "active": 0,
    }

    for sev, status, count in rows:
        sev_val = sev.value if hasattr(sev, "value") else str(sev)
        status_val = status.value if hasattr(status, "value") else str(status)
        summary["by_severity"][sev_val] = summary["by_severity"].get(sev_val, 0) + count
        summary["by_status"][status_val] = summary["by_status"].get(status_val, 0) + count
        summary["total"] += count
        if status_val in ("new", "acknowledged", "investigating", "escalated"):
            summary["active"] += count

    return summary


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    deliveries_result = await db.execute(
        select(AlertDelivery).where(AlertDelivery.alert_id == alert_id)
    )
    deliveries = deliveries_result.scalars().all()

    return {
        "alert": AlertResponse.model_validate(alert),
        "deliveries": [
            {
                "id": d.id,
                "channel": d.channel.value,
                "recipient": d.recipient,
                "status": d.status,
                "delivered_at": d.delivered_at.isoformat() if d.delivered_at else None,
            }
            for d in deliveries
        ],
    }


@router.patch("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    assigned_to: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.utcnow()
    if assigned_to:
        alert.assigned_to = assigned_to
    alert.updated_at = datetime.utcnow()
    await db.flush()
    return APIResponse(message="Alert acknowledged")


@router.patch("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    resolution_notes: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = datetime.utcnow()
    alert.updated_at = datetime.utcnow()
    await db.flush()
    return APIResponse(message="Alert resolved")


@router.patch("/alerts/{alert_id}/assign")
async def assign_alert(
    alert_id: int,
    assigned_to: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.assigned_to = assigned_to
    alert.updated_at = datetime.utcnow()
    await db.flush()
    return APIResponse(message=f"Alert assigned to {assigned_to}")


# --- Alert Rules ---
@router.get("/alert-rules")
async def list_alert_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()
    return [AlertRuleResponse.model_validate(r) for r in rules]


@router.post("/alert-rules", response_model=APIResponse)
async def create_alert_rule(data: AlertRuleCreate, db: AsyncSession = Depends(get_db)):
    rule = AlertRule(**data.model_dump())
    db.add(rule)
    await db.flush()
    return APIResponse(message=f"Created rule {rule.name}", data={"id": rule.id})


@router.patch("/alert-rules/{rule_id}/toggle")
async def toggle_alert_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_active = not rule.is_active
    await db.flush()
    return APIResponse(message=f"Rule {'activated' if rule.is_active else 'deactivated'}")


# --- Escalation Paths ---
@router.get("/escalation-paths")
async def list_escalation_paths(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(EscalationPath))
    paths = result.scalars().all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "severity_trigger": p.severity_trigger.value,
            "levels": json.loads(p.levels) if p.levels else [],
            "is_active": p.is_active,
        }
        for p in paths
    ]
