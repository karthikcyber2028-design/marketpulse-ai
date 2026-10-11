from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import (
    DeploymentContext,
    VulnSeverity,
    Vulnerability,
)
from app.models.device import Device, vulnerability_device_map
from app.models.score import RiskScore, ScoreBreakdown
from app.models.manufacturer import Manufacturer

logger = logging.getLogger(__name__)

# Severity base scores for CVSS fallback
SEVERITY_BASE_SCORES = {
    VulnSeverity.CRITICAL: 9.0,
    VulnSeverity.HIGH: 7.5,
    VulnSeverity.MEDIUM: 5.0,
    VulnSeverity.LOW: 2.5,
    VulnSeverity.UNKNOWN: 5.0,
}

# Deployment context risk multipliers
CONTEXT_MULTIPLIERS = {
    "consumer": 0.7,
    "commercial": 0.9,
    "industrial": 1.2,
    "critical_infrastructure": 1.5,
    "medical": 1.4,
    "government": 1.3,
}


class RiskScoringEngine:
    """
    Composite risk scoring engine that weights CVSS base scores against:
    - Manufacturer response history
    - Exploit availability in the wild
    - Affected device population estimates
    - Deployment context (consumer vs. industrial vs. critical infrastructure)

    Score range: 0.0 (no risk) to 10.0 (maximum risk)
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def calculate_score(self, vuln: Vulnerability) -> tuple[float, ScoreBreakdown]:
        """Calculate composite risk score for a vulnerability."""
        breakdown = ScoreBreakdown(vulnerability_id=vuln.id)

        # 1. CVSS Component (30%)
        cvss_score = vuln.cvss_v3_score or vuln.cvss_v2_score
        if cvss_score is None:
            cvss_score = SEVERITY_BASE_SCORES.get(vuln.severity, 5.0)
        breakdown.cvss_component = min(cvss_score, 10.0)
        breakdown.cvss_weight = 0.30

        # 2. Exploit Availability Component (15%)
        breakdown.exploit_availability_component = 8.0 if vuln.exploit_available else 2.0
        breakdown.exploit_weight = 0.15

        # 3. Wild Exploitation Component (15%)
        if vuln.actively_exploited:
            breakdown.wild_exploitation_component = 9.5
        elif vuln.first_known_exploitation:
            days_since = (datetime.utcnow() - vuln.first_known_exploitation).days
            breakdown.wild_exploitation_component = max(2.0, 9.5 - (days_since * 0.02))
        else:
            breakdown.wild_exploitation_component = 1.0
        breakdown.wild_exploit_weight = 0.15

        # 4. Manufacturer Response Component (10%)
        breakdown.manufacturer_response_component = await self._manufacturer_response_score(vuln)
        breakdown.manufacturer_weight = 0.10

        # 5. Device Population Component (10%)
        breakdown.device_population_component = await self._population_score(vuln)
        breakdown.population_weight = 0.10

        # 6. Deployment Context Component (10%)
        breakdown.deployment_context_component = await self._context_score(vuln)
        breakdown.context_weight = 0.10

        # 7. Age Component (10%)
        breakdown.age_component = self._age_score(vuln)
        breakdown.age_weight = 0.10

        # Calculate composite
        composite = (
            breakdown.cvss_component * breakdown.cvss_weight
            + breakdown.exploit_availability_component * breakdown.exploit_weight
            + breakdown.wild_exploitation_component * breakdown.wild_exploit_weight
            + breakdown.manufacturer_response_component * breakdown.manufacturer_weight
            + breakdown.device_population_component * breakdown.population_weight
            + breakdown.deployment_context_component * breakdown.context_weight
            + breakdown.age_component * breakdown.age_weight
        )

        composite = round(min(max(composite, 0.0), 10.0), 2)
        breakdown.calculated_at = datetime.utcnow()
        breakdown.calculation_notes = json.dumps({
            "methodology": "weighted_composite_v1",
            "components": {
                "cvss": breakdown.cvss_component,
                "exploit": breakdown.exploit_availability_component,
                "wild_exploit": breakdown.wild_exploitation_component,
                "manufacturer": breakdown.manufacturer_response_component,
                "population": breakdown.device_population_component,
                "context": breakdown.deployment_context_component,
                "age": breakdown.age_component,
            },
        })

        return composite, breakdown

    async def _manufacturer_response_score(self, vuln: Vulnerability) -> float:
        """Score based on manufacturer's historical response behavior."""
        if not vuln.manufacturer_id:
            return 5.0  # neutral if unknown manufacturer

        result = await self.session.execute(
            select(Manufacturer).where(Manufacturer.id == vuln.manufacturer_id)
        )
        mfg = result.scalar_one_or_none()
        if not mfg:
            return 5.0

        score = 5.0

        # Patch availability rate: higher rate = lower risk
        if mfg.patch_availability_rate is not None:
            score += (50 - mfg.patch_availability_rate) / 10.0

        # Time to patch: faster = lower risk
        if mfg.avg_time_to_patch_hours is not None:
            if mfg.avg_time_to_patch_hours < 24:
                score -= 2.0
            elif mfg.avg_time_to_patch_hours < 168:  # 1 week
                score -= 1.0
            elif mfg.avg_time_to_patch_hours > 720:  # 30 days
                score += 2.0

        return min(max(score, 0.0), 10.0)

    async def _population_score(self, vuln: Vulnerability) -> float:
        """Score based on estimated affected device population."""
        devices = await self._load_mapped_devices(vuln)
        if not devices:
            return 3.0

        total_devices = 0
        for device in devices:
            if device.estimated_units_deployed:
                total_devices += device.estimated_units_deployed

        if total_devices == 0:
            return 3.0
        if total_devices > 10_000_000:
            return 9.5
        if total_devices > 1_000_000:
            return 8.0
        if total_devices > 100_000:
            return 6.5
        if total_devices > 10_000:
            return 5.0
        return 3.5

    async def _context_score(self, vuln: Vulnerability) -> float:
        """Score based on deployment context risk multiplier."""
        devices = await self._load_mapped_devices(vuln)
        if not devices:
            return 5.0

        max_multiplier = 0.7
        for device in devices:
            ctx = device.deployment_context
            multiplier = CONTEXT_MULTIPLIERS.get(ctx.value if hasattr(ctx, "value") else ctx, 0.7)
            max_multiplier = max(max_multiplier, multiplier)

        return min(max_multiplier * 10.0 / 1.5, 10.0)

    async def _load_mapped_devices(self, vuln: Vulnerability) -> list[Device]:
        """Asynchronously load devices mapped to a vulnerability."""
        if not vuln.id:
            return []
        result = await self.session.execute(
            select(Device)
            .join(vulnerability_device_map, vulnerability_device_map.c.device_id == Device.id)
            .where(vulnerability_device_map.c.vulnerability_id == vuln.id)
        )
        return list(result.scalars().all())

    def _age_score(self, vuln: Vulnerability) -> float:
        """Score based on vulnerability age. Unpatched old vulns score higher."""
        if not vuln.published_date:
            return 5.0

        age_days = (datetime.utcnow() - vuln.published_date).days
        if age_days < 7:
            return 8.0  # New vulns are high risk
        if age_days < 30:
            return 7.0
        if age_days < 90:
            return 5.0
        if age_days < 365:
            return 4.0
        return 3.0

    async def score_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """Score a vulnerability and persist results."""
        composite, breakdown = await self.calculate_score(vuln)

        vuln.composite_risk_score = composite
        vuln.risk_score_updated_at = datetime.utcnow()

        existing_breakdown = await self.session.execute(
            select(ScoreBreakdown).where(ScoreBreakdown.vulnerability_id == vuln.id)
        )
        existing = existing_breakdown.scalar_one_or_none()
        if existing:
            for attr in vars(breakdown):
                if attr != "_sa_instance_state" and attr != "id":
                    setattr(existing, attr, getattr(breakdown, attr))
        else:
            self.session.add(breakdown)

        # Also upsert RiskScore
        existing_risk = await self.session.execute(
            select(RiskScore).where(RiskScore.vulnerability_id == vuln.id)
        )
        risk = existing_risk.scalar_one_or_none()
        if risk:
            risk.composite_score = composite
            risk.calculated_at = datetime.utcnow()
        else:
            self.session.add(
                RiskScore(
                    vulnerability_id=vuln.id,
                    composite_score=composite,
                    calculated_at=datetime.utcnow(),
                )
            )

        await self.session.flush()
        logger.info("Scored %s: %.2f", vuln.cve_id, composite)
        return vuln

    async def score_batch(self, vulns: list[Vulnerability]) -> int:
        """Score a batch of vulnerabilities. Returns count scored."""
        count = 0
        for vuln in vulns:
            try:
                await self.score_vulnerability(vuln)
                count += 1
            except Exception as e:
                logger.error("Failed to score %s: %s", vuln.cve_id, e)
        return count

    async def update_manufacturer_scores(self) -> None:
        """Recalculate manufacturer security posture scores."""
        result = await self.session.execute(select(Manufacturer))
        manufacturers = result.scalars().all()

        for mfg in manufacturers:
            vulns_result = await self.session.execute(
                select(Vulnerability).where(Vulnerability.manufacturer_id == mfg.id)
            )
            vulns = vulns_result.scalars().all()

            if not vulns:
                mfg.security_posture_score = 75.0
                mfg.risk_rating = "exemplary"
                continue

            total = len(vulns)
            critical = sum(1 for v in vulns if v.severity == VulnSeverity.CRITICAL)
            active = sum(
                1 for v in vulns if v.status.value in ("analyzing", "unpatched")
            )
            avg_score = sum(v.composite_risk_score or 0 for v in vulns) / total

            # Security posture = inverse of average risk
            posture = max(0, min(100, 100 - (avg_score * 10)))
            mfg.security_posture_score = round(posture, 1)

            mfg.total_vulnerabilities = total
            mfg.critical_vulnerabilities = critical
            mfg.active_vulnerabilities = active

            if posture >= 80:
                mfg.risk_rating = "exemplary"
            elif posture >= 65:
                mfg.risk_rating = "good"
            elif posture >= 50:
                mfg.risk_rating = "average"
            elif posture >= 35:
                mfg.risk_rating = "poor"
            else:
                mfg.risk_rating = "critical"

            mfg.last_assessment_date = datetime.utcnow()

        await self.session.flush()
        logger.info("Updated security posture for %d manufacturers", len(manufacturers))
