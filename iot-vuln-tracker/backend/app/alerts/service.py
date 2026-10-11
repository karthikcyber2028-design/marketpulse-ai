from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.alert import (
    Alert,
    AlertDelivery,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    DeliveryChannel,
    EscalationPath,
)
from app.models.vulnerability import VulnSeverity, Vulnerability

logger = logging.getLogger(__name__)


class AlertingService:
    """Handles alert rule evaluation, alert creation, and multi-channel delivery."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.client = httpx.AsyncClient(timeout=settings.webhook_timeout)

    async def close(self):
        await self.client.aclose()

    async def evaluate_vulnerability(self, vuln: Vulnerability) -> list[Alert]:
        """Evaluate all active alert rules against a new/updated vulnerability."""
        result = await self.session.execute(
            select(AlertRule).where(AlertRule.is_active == True)
        )
        rules = result.scalars().all()
        created_alerts = []

        for rule in rules:
            if await self._rule_matches(rule, vuln):
                if await self._cooldown_ok(rule, vuln):
                    alert = await self._create_alert(rule, vuln)
                    created_alerts.append(alert)
                    await self._deliver_alert(alert, rule)

        return created_alerts

    async def _rule_matches(self, rule: AlertRule, vuln: Vulnerability) -> bool:
        """Check if a vulnerability triggers an alert rule based on conditions."""
        try:
            conditions = json.loads(rule.conditions)
        except json.JSONDecodeError:
            return False

        # Severity filter
        min_severity = conditions.get("min_severity")
        if min_severity:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            vuln_sev = severity_order.get(vuln.severity.value, 0)
            required_sev = severity_order.get(min_severity, 0)
            if vuln_sev < required_sev:
                return False

        # Risk score filter
        min_risk_score = conditions.get("min_risk_score")
        if min_risk_score and vuln.composite_risk_score:
            if vuln.composite_risk_score < min_risk_score:
                return False

        # Manufacturer filter
        manufacturer_ids = conditions.get("manufacturer_ids")
        if manufacturer_ids and vuln.manufacturer_id:
            if vuln.manufacturer_id not in manufacturer_ids:
                return False

        # Product category filter
        categories = conditions.get("categories")
        if categories and vuln.affected_product_names:
            vuln_cats = vuln.affected_product_names.lower()
            if not any(cat.lower() in vuln_cats for cat in categories):
                return False

        # Actively exploited filter
        if conditions.get("actively_exploited_only") and not vuln.actively_exploited:
            return False

        # Exploit availability filter
        if conditions.get("exploit_available_only") and not vuln.exploit_available:
            return False

        # CWE filter
        cwe_filters = conditions.get("cwe_ids")
        if cwe_filters and vuln.cwe_id:
            if vuln.cwe_id not in cwe_filters:
                return False

        return True

    async def _cooldown_ok(self, rule: AlertRule, vuln: Vulnerability) -> bool:
        """Check if the rule is within its cooldown period."""
        cooldown = timedelta(minutes=rule.cooldown_minutes)
        cutoff = datetime.utcnow() - cooldown

        result = await self.session.execute(
            select(func.count(Alert.id)).where(
                Alert.rule_id == rule.id,
                Alert.vulnerability_id == vuln.id,
                Alert.created_at >= cutoff,
            )
        )
        count = result.scalar()
        return count == 0

    async def _create_alert(self, rule: AlertRule, vuln: Vulnerability) -> Alert:
        """Create a new alert."""
        severity = self._alert_severity_from_risk(vuln.composite_risk_score or 0)

        title = f"[{severity.value.upper()}] {vuln.cve_id} - IoT Vulnerability Alert"
        message = self._build_alert_message(vuln, severity)

        alert = Alert(
            vulnerability_id=vuln.id,
            rule_id=rule.id,
            severity=severity,
            status=AlertStatus.NEW,
            title=title,
            message=message,
            affected_devices_summary=self._summarize_affected_devices(vuln),
        )
        self.session.add(alert)
        await self.session.flush()
        return alert

    def _alert_severity_from_risk(self, score: float) -> AlertSeverity:
        if score >= settings.critical_alert_threshold:
            return AlertSeverity.CRITICAL
        if score >= settings.high_alert_threshold:
            return AlertSeverity.HIGH
        if score >= 4.0:
            return AlertSeverity.MEDIUM
        if score >= 2.0:
            return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _build_alert_message(self, vuln: Vulnerability, severity: AlertSeverity) -> str:
        parts = [
            f"CVE: {vuln.cve_id}",
            f"Severity: {vuln.severity.value.upper()}",
            f"Composite Risk Score: {vuln.composite_risk_score:.2f}/10.0",
            f"Status: {vuln.status.value}",
            "",
            f"Description: {vuln.cve_description[:500]}",
        ]

        if vuln.exploit_available:
            parts.append("⚠ EXPLOIT AVAILABLE")
        if vuln.actively_exploited:
            parts.append("⚠ ACTIVELY EXPLOITED IN THE WILD")
        if vuln.cvss_v3_score:
            parts.append(f"CVSS v3.1: {vuln.cvss_v3_score}")
        if vuln.affected_product_names:
            parts.append(f"Affected Products: {vuln.affected_product_names[:200]}")

        return "\n".join(parts)

    def _summarize_affected_devices(self, vuln: Vulnerability) -> str | None:
        if not vuln.device_mappings:
            return None
        total = sum(
            d.estimated_units_deployed or 0 for d in vuln.device_mappings
        )
        models = [d.model_name for d in vuln.device_mappings[:5]]
        summary = f"{len(vuln.device_mappings)} device models, ~{total:,} estimated units"
        if models:
            summary += f" ({', '.join(models)})"
        return summary

    async def _deliver_alert(self, alert: Alert, rule: AlertRule) -> None:
        """Deliver alert through configured channels."""
        try:
            channels = json.loads(rule.notification_channels)
        except json.JSONDecodeError:
            channels = ["dashboard"]

        for channel_name in channels:
            try:
                channel = DeliveryChannel(channel_name)
            except ValueError:
                continue

            delivery = AlertDelivery(
                alert_id=alert.id,
                channel=channel,
                status="pending",
            )
            self.session.add(delivery)

            try:
                if channel == DeliveryChannel.WEBHOOK:
                    await self._send_webhook(alert, delivery)
                elif channel == DeliveryChannel.EMAIL:
                    await self._send_email(alert, delivery)
                elif channel == DeliveryChannel.DASHBOARD:
                    delivery.status = "sent"
                    delivery.delivered_at = datetime.utcnow()
                elif channel == DeliveryChannel.TICKETING:
                    await self._create_ticket(alert, delivery)
                elif channel == DeliveryChannel.SIEM:
                    await self._send_to_siem(alert, delivery)
            except Exception as e:
                delivery.status = "failed"
                delivery.error_message = str(e)
                logger.error("Failed to deliver alert %d via %s: %s", alert.id, channel_name, e)

        await self.session.flush()

    async def _send_webhook(self, alert: Alert, delivery: AlertDelivery) -> None:
        """Send alert via webhook."""
        from app.models.integration import WebhookEndpoint

        result = await self.session.execute(
            select(WebhookEndpoint).where(WebhookEndpoint.is_active == True)
        )
        endpoints = result.scalars().all()

        for endpoint in endpoints:
            try:
                payload = {
                    "event": "alert",
                    "alert_id": alert.id,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "message": alert.message,
                    "vulnerability_id": alert.vulnerability_id,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                response = await self.client.post(
                    endpoint.url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                delivery.status = "sent"
                delivery.delivered_at = datetime.utcnow()
                endpoint.last_triggered_at = datetime.utcnow()
                endpoint.failure_count = 0
            except Exception as e:
                delivery.status = "failed"
                delivery.error_message = str(e)
                delivery.retry_count += 1
                endpoint.failure_count += 1

    async def _send_email(self, alert: Alert, delivery: AlertDelivery) -> None:
        """Send alert via email."""
        delivery.status = "sent"
        delivery.delivered_at = datetime.utcnow()
        delivery.recipient = settings.smtp_from
        logger.info("Email alert %d (email delivery placeholder)", alert.id)

    async def _create_ticket(self, alert: Alert, delivery: AlertDelivery) -> None:
        """Create a ticket in the integrated ticketing system."""
        delivery.status = "sent"
        delivery.delivered_at = datetime.utcnow()
        logger.info("Ticket created for alert %d (integration placeholder)", alert.id)

    async def _send_to_siem(self, alert: Alert, delivery: AlertDelivery) -> None:
        """Send event to SIEM integration."""
        delivery.status = "sent"
        delivery.delivered_at = datetime.utcnow()
        logger.info("SIEM event sent for alert %d (integration placeholder)", alert.id)

    async def process_escalations(self) -> int:
        """Process escalation paths for unresolved critical alerts."""
        result = await self.session.execute(
            select(EscalationPath).where(EscalationPath.is_active == True)
        )
        paths = result.scalars().all()
        escalated = 0

        for path in paths:
            try:
                severity_map = {
                    "critical": AlertSeverity.CRITICAL,
                    "high": AlertSeverity.HIGH,
                    "medium": AlertSeverity.MEDIUM,
                    "low": AlertSeverity.LOW,
                }
                trigger_severity = severity_map.get(path.severity_trigger.value)
                if not trigger_severity:
                    continue

                levels = json.loads(path.levels)
                unresolved = await self.session.execute(
                    select(Alert).where(
                        Alert.severity == trigger_severity,
                        Alert.status.in_([
                            AlertStatus.NEW,
                            AlertStatus.ACKNOWLEDGED,
                            AlertStatus.INVESTIGATING,
                        ]),
                    )
                )
                alerts = unresolved.scalars().all()

                for alert in alerts:
                    elapsed = (datetime.utcnow() - alert.created_at).total_seconds() / 60
                    current_level = alert.escalation_level

                    for level_info in levels:
                        level_num = level_info.get("level", 0)
                        timeout = level_info.get("timeout", 60)
                        if level_num > current_level and elapsed >= timeout:
                            alert.escalation_level = level_num
                            alert.status = AlertStatus.ESCALATED
                            escalated += 1
                            logger.info(
                                "Alert %d escalated to level %d", alert.id, level_num
                            )
                            break
            except Exception as e:
                logger.error("Escalation path %s failed: %s", path.name, e)
                continue

        await self.session.flush()
        return escalated
