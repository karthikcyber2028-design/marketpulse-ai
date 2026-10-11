from __future__ import annotations

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.config import settings
from app.database import async_session_factory
from app.services.collectors import NVDCollector, ICSCERTCollector
from app.scoring.engine import RiskScoringEngine
from app.alerts.service import AlertingService

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def sync_nvd():
    """Periodic NVD sync."""
    logger.info("Starting scheduled NVD sync")
    async with async_session_factory() as session:
        try:
            collector = NVDCollector(session)
            vulns = await collector.sync_recent(days_back=1)
            await session.commit()

            if vulns:
                engine = RiskScoringEngine(session)
                await engine.score_batch(vulns)
                await session.commit()

                alert_svc = AlertingService(session)
                for vuln in vulns:
                    await alert_svc.evaluate_vulnerability(vuln)
                await session.commit()

            logger.info("NVD sync complete: %d vulnerabilities", len(vulns))
        except Exception as e:
            logger.error("NVD sync failed: %s", e)
            await session.rollback()


async def sync_ics_cert():
    """Periodic ICS-CERT sync."""
    logger.info("Starting scheduled ICS-CERT sync")
    async with async_session_factory() as session:
        try:
            collector = ICSCERTCollector(session)
            vulns = await collector.sync_recent(days_back=7)
            await session.commit()

            if vulns:
                engine = RiskScoringEngine(session)
                await engine.score_batch(vulns)
                await session.commit()

                alert_svc = AlertingService(session)
                for vuln in vulns:
                    await alert_svc.evaluate_vulnerability(vuln)
                await session.commit()

            logger.info("ICS-CERT sync complete: %d vulnerabilities", len(vulns))
        except Exception as e:
            logger.error("ICS-CERT sync failed: %s", e)
            await session.rollback()


async def rescore_vulnerabilities():
    """Recalculate risk scores for unscored or stale vulnerabilities."""
    logger.info("Starting scheduled rescore")
    async with async_session_factory() as session:
        try:
            result = await session.execute(
                select(Vulnerability).where(
                    Vulnerability.composite_risk_score.is_(None)
                )
            )
            vulns = result.scalars().all()
            if vulns:
                engine = RiskScoringEngine(session)
                count = await engine.score_batch(vulns)
                await session.commit()
                logger.info("Rescored %d vulnerabilities", count)
        except Exception as e:
            logger.error("Rescore failed: %s", e)
            await session.rollback()


async def update_manufacturer_scores():
    """Update manufacturer security posture scores."""
    logger.info("Starting scheduled manufacturer score update")
    async with async_session_factory() as session:
        try:
            engine = RiskScoringEngine(session)
            await engine.update_manufacturer_scores()
            await session.commit()
            logger.info("Manufacturer scores updated")
        except Exception as e:
            logger.error("Manufacturer score update failed: %s", e)
            await session.rollback()


async def process_escalations():
    """Process alert escalations."""
    async with async_session_factory() as session:
        try:
            alert_svc = AlertingService(session)
            count = await alert_svc.process_escalations()
            await session.commit()
            if count:
                logger.info("Escalated %d alerts", count)
        except Exception as e:
            logger.error("Escalation processing failed: %s", e)
            await session.rollback()


async def record_daily_metrics():
    """Record daily manufacturer metrics."""
    from app.models.manufacturer import Manufacturer, ManufacturerMetric
    from app.models.vulnerability import VulnSeverity, VulnStatus

    logger.info("Recording daily manufacturer metrics")
    async with async_session_factory() as session:
        try:
            result = await session.execute(select(Manufacturer))
            manufacturers = result.scalars().all()

            for mfg in manufacturers:
                from app.models.vulnerability import Vulnerability
                vuln_result = await session.execute(
                    select(Vulnerability).where(Vulnerability.manufacturer_id == mfg.id)
                )
                vulns = vuln_result.scalars().all()

                total = len(vulns)
                critical = sum(1 for v in vulns if v.severity == VulnSeverity.CRITICAL)
                active = sum(
                    1 for v in vulns
                    if v.status.value in ("analyzing", "unpatched")
                )

                metric = ManufacturerMetric(
                    manufacturer_id=mfg.id,
                    recorded_date=datetime.utcnow(),
                    total_vulnerabilities=total,
                    critical_vulnerabilities=critical,
                    active_vulnerabilities=active,
                    security_posture_score=mfg.security_posture_score,
                    avg_time_to_patch_hours=mfg.avg_time_to_patch_hours,
                    patch_availability_rate=mfg.patch_availability_rate,
                )
                session.add(metric)

            await session.commit()
            logger.info("Daily metrics recorded for %d manufacturers", len(manufacturers))
        except Exception as e:
            logger.error("Daily metrics recording failed: %s", e)
            await session.rollback()


from app.models.vulnerability import Vulnerability  # noqa: E402


def start_scheduler() -> AsyncIOScheduler:
    scheduler.add_job(
        sync_nvd,
        IntervalTrigger(seconds=settings.nvd_sync_interval),
        id="nvd_sync",
        name="NVD Vulnerability Sync",
        replace_existing=True,
    )
    scheduler.add_job(
        sync_ics_cert,
        IntervalTrigger(seconds=settings.ics_cert_sync_interval),
        id="ics_cert_sync",
        name="ICS-CERT Advisory Sync",
        replace_existing=True,
    )
    scheduler.add_job(
        rescore_vulnerabilities,
        IntervalTrigger(hours=6),
        id="rescore",
        name="Vulnerability Rescoring",
        replace_existing=True,
    )
    scheduler.add_job(
        update_manufacturer_scores,
        IntervalTrigger(hours=12),
        id="mfg_scores",
        name="Manufacturer Score Update",
        replace_existing=True,
    )
    scheduler.add_job(
        process_escalations,
        IntervalTrigger(minutes=15),
        id="escalations",
        name="Alert Escalation Processing",
        replace_existing=True,
    )
    scheduler.add_job(
        record_daily_metrics,
        IntervalTrigger(hours=24),
        id="daily_metrics",
        name="Daily Manufacturer Metrics",
        replace_existing=True,
    )

    scheduler.start()
    logger.info("Scheduler started with %d jobs", len(scheduler.get_jobs()))
    return scheduler
