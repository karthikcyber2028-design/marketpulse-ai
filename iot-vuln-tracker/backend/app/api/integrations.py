from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.integration import (
    WebhookEndpoint,
    SIEMIntegration,
    TicketingIntegration,
    AssetManagementSync,
)
from app.schemas import APIResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Webhooks ---
@router.get("/webhooks")
async def list_webhooks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(WebhookEndpoint))
    endpoints = result.scalars().all()
    return [
        {
            "id": w.id,
            "name": w.name,
            "url": w.url,
            "is_active": w.is_active,
            "event_types": json.loads(w.event_types) if w.event_types else [],
            "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
            "failure_count": w.failure_count,
        }
        for w in endpoints
    ]


@router.post("/webhooks", response_model=APIResponse)
async def create_webhook(
    name: str,
    url: str,
    event_types: str,
    secret: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    webhook = WebhookEndpoint(
        name=name, url=url, event_types=event_types, secret=secret
    )
    db.add(webhook)
    await db.flush()
    return APIResponse(message=f"Created webhook {name}", data={"id": webhook.id})


@router.delete("/webhooks/{webhook_id}", response_model=APIResponse)
async def delete_webhook(webhook_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id)
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(wh)
    await db.flush()
    return APIResponse(message="Webhook deleted")


@router.post("/webhooks/{webhook_id}/test", response_model=APIResponse)
async def test_webhook(webhook_id: int, db: AsyncSession = Depends(get_db)):
    import httpx

    result = await db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id)
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                wh.url,
                json={"event": "test", "timestamp": datetime.utcnow().isoformat()},
            )
            resp.raise_for_status()
            wh.last_triggered_at = datetime.utcnow()
            wh.failure_count = 0
            return APIResponse(message=f"Webhook test successful (HTTP {resp.status_code})")
        except Exception as e:
            wh.failure_count += 1
            return APIResponse(
                success=False, message=f"Webhook test failed: {str(e)}"
            )


# --- SIEM Integrations ---
@router.get("/siem")
async def list_siem_integrations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SIEMIntegration))
    siems = result.scalars().all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "siem_type": s.siem_type,
            "is_active": s.is_active,
            "last_synced_at": s.last_synced_at.isoformat() if s.last_synced_at else None,
        }
        for s in siems
    ]


@router.post("/siem", response_model=APIResponse)
async def create_siem_integration(
    name: str,
    siem_type: str,
    endpoint_url: str,
    api_key: str | None = None,
    index_name: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    siem = SIEMIntegration(
        name=name,
        siem_type=siem_type,
        endpoint_url=endpoint_url,
        api_key=api_key,
        index_name=index_name,
    )
    db.add(siem)
    await db.flush()
    return APIResponse(message=f"Created SIEM integration {name}", data={"id": siem.id})


# --- Ticketing ---
@router.get("/ticketing")
async def list_ticketing_integrations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TicketingIntegration))
    tickets = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "platform": t.platform,
            "is_active": t.is_active,
            "auto_create_tickets": t.auto_create_tickets,
        }
        for t in tickets
    ]


@router.post("/ticketing", response_model=APIResponse)
async def create_ticketing_integration(
    name: str,
    platform: str,
    base_url: str,
    api_token: str | None = None,
    project_key: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    ticket = TicketingIntegration(
        name=name,
        platform=platform,
        base_url=base_url,
        api_token=api_token,
        project_key=project_key,
    )
    db.add(ticket)
    await db.flush()
    return APIResponse(message=f"Created ticketing integration {name}", data={"id": ticket.id})


# --- Asset Management ---
@router.get("/asset-management")
async def list_asset_management(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AssetManagementSync))
    syncs = result.scalars().all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "platform": a.platform,
            "is_active": a.is_active,
            "device_count": a.device_count,
            "last_synced_at": a.last_synced_at.isoformat() if a.last_synced_at else None,
        }
        for a in syncs
    ]


# --- Data Sources ---
@router.get("/data-sources")
async def list_data_sources(db: AsyncSession = Depends(get_db)):
    from app.models.vulnerability import VulnerabilitySource

    result = await db.execute(select(VulnerabilitySource))
    sources = result.scalars().all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "source_type": s.source_type.value,
            "is_active": s.is_active,
            "reliability_score": s.reliability_score,
            "last_synced_at": s.last_synced_at.isoformat() if s.last_synced_at else None,
        }
        for s in sources
    ]


# --- Sync Trigger ---
@router.post("/sync/nvd", response_model=APIResponse)
async def trigger_nvd_sync(days_back: int = 1, db: AsyncSession = Depends(get_db)):
    from app.services.collectors import NVDCollector

    collector = NVDCollector(db)
    try:
        vulns = await collector.sync_recent(days_back)
        return APIResponse(
            message=f"NVD sync complete: {len(vulns)} vulnerabilities processed"
        )
    except Exception as e:
        return APIResponse(success=False, message=f"NVD sync failed: {str(e)}")
    finally:
        await collector.close()


@router.post("/sync/ics-cert", response_model=APIResponse)
async def trigger_ics_cert_sync(days_back: int = 7, db: AsyncSession = Depends(get_db)):
    from app.services.collectors import ICSCERTCollector

    collector = ICSCERTCollector(db)
    try:
        vulns = await collector.sync_recent(days_back)
        return APIResponse(
            message=f"ICS-CERT sync complete: {len(vulns)} vulnerabilities processed"
        )
    except Exception as e:
        return APIResponse(success=False, message=f"ICS-CERT sync failed: {str(e)}")
    finally:
        await collector.close()
