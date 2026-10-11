"""Seed database with sample data for development and testing."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

from app.database import init_db, async_session_factory
from app.models.vulnerability import (
    DataSource,
    VulnSeverity,
    VulnStatus,
    Vulnerability,
    VulnerabilitySource,
)
from app.models.manufacturer import Manufacturer, ProductLine
from app.models.device import Device, DeviceFirmware, DeviceLifecycleStatus
from app.models.alert import AlertRule, EscalationPath, AlertSeverity
from app.models.audit import DataRetentionPolicy
from app.scoring.engine import RiskScoringEngine


MANUFACTURERS = [
    {
        "name": "Siemens",
        "slug": "siemens",
        "description": "Industrial automation and IoT manufacturer",
        "website": "https://www.siemens.com",
        "headquarters_country": "Germany",
        "security_posture_score": 72.0,
        "risk_rating": "good",
        "patch_availability_rate": 85.0,
        "avg_time_to_patch_hours": 168.0,
    },
    {
        "name": "Hikvision",
        "slug": "hikvision",
        "description": "Video surveillance and IoT devices",
        "website": "https://www.hikvision.com",
        "headquarters_country": "China",
        "security_posture_score": 38.0,
        "risk_rating": "poor",
        "patch_availability_rate": 45.0,
        "avg_time_to_patch_hours": 720.0,
    },
    {
        "name": "Ubiquiti",
        "slug": "ubiquiti",
        "description": "Networking and IoT equipment",
        "website": "https://www.ui.com",
        "headquarters_country": "United States",
        "security_posture_score": 65.0,
        "risk_rating": "average",
        "patch_availability_rate": 78.0,
        "avg_time_to_patch_hours": 240.0,
    },
    {
        "name": "Bosch",
        "slug": "bosch",
        "description": "Industrial IoT and smart home devices",
        "website": "https://www.bosch.com",
        "headquarters_country": "Germany",
        "security_posture_score": 78.0,
        "risk_rating": "good",
        "patch_availability_rate": 90.0,
        "avg_time_to_patch_hours": 96.0,
    },
    {
        "name": "Xiaomi",
        "slug": "xiaomi",
        "description": "Consumer IoT and smart home devices",
        "website": "https://www.mi.com",
        "headquarters_country": "China",
        "security_posture_score": 45.0,
        "risk_rating": "poor",
        "patch_availability_rate": 55.0,
        "avg_time_to_patch_hours": 480.0,
    },
    {
        "name": "Cisco",
        "slug": "cisco",
        "description": "Networking infrastructure and IoT gateways",
        "website": "https://www.cisco.com",
        "headquarters_country": "United States",
        "security_posture_score": 82.0,
        "risk_rating": "exemplary",
        "patch_availability_rate": 95.0,
        "avg_time_to_patch_hours": 48.0,
    },
    {
        "name": "Honeywell",
        "slug": "honeywell",
        "description": "Building automation and industrial IoT",
        "website": "https://www.honeywell.com",
        "headquarters_country": "United States",
        "security_posture_score": 70.0,
        "risk_rating": "good",
        "patch_availability_rate": 82.0,
        "avg_time_to_patch_hours": 200.0,
    },
    {
        "name": "Dahua",
        "slug": "dahua",
        "description": "Video surveillance and IoT devices",
        "website": "https://www.dahuasecurity.com",
        "headquarters_country": "China",
        "security_posture_score": 35.0,
        "risk_rating": "critical",
        "patch_availability_rate": 40.0,
        "avg_time_to_patch_hours": 960.0,
    },
]

SAMPLE_VULNS = [
    ("CVE-2026-1001", "Critical buffer overflow in Siemens S7-1500 PLC firmware allowing remote code execution via crafted Profinet packets", VulnSeverity.CRITICAL, 9.8, "siemens", True, True),
    ("CVE-2026-1002", "Authentication bypass in Hikvision IP cameras allowing unauthenticated access to video streams", VulnSeverity.CRITICAL, 9.1, "hikvision", True, True),
    ("CVE-2026-1003", "SQL injection in Ubiquiti UniFi controller enabling database extraction and admin takeover", VulnSeverity.HIGH, 8.6, "ubiquiti", True, False),
    ("CVE-2026-1004", "Firmware update mechanism flaw in Bosch Smart Home Controller allows unsigned code execution", VulnSeverity.HIGH, 8.2, "bosch", False, False),
    ("CVE-2026-1005", "XSS vulnerability in Xiaomi Mi Home app allowing session hijacking of user accounts", VulnSeverity.MEDIUM, 6.1, "xiaomi", False, False),
    ("CVE-2026-1006", "Privilege escalation in Cisco IOS XE via Netconf API allowing root access on IoT gateway devices", VulnSeverity.CRITICAL, 9.8, "cisco", True, True),
    ("CVE-2026-1007", "Default credential vulnerability in Honeywell building automation controllers", VulnSeverity.HIGH, 7.5, "honeywell", True, True),
    ("CVE-2026-1008", "Hardcoded encryption keys in Dahua camera firmware enabling TLS interception", VulnSeverity.CRITICAL, 9.0, "dahua", True, False),
    ("CVE-2026-1009", "Denial of service via malformed MQTT packets in Siemens Industrial Edge devices", VulnSeverity.MEDIUM, 5.3, "siemens", False, False),
    ("CVE-2026-1010", "Information disclosure through debug endpoints in Hikvision NVR firmware", VulnSeverity.MEDIUM, 5.0, "hikvision", False, False),
    ("CVE-2026-1011", "Remote code execution via UPnP in Ubiquiti EdgeRouter series", VulnSeverity.CRITICAL, 9.4, "ubiquiti", True, True),
    ("CVE-2026-1012", "Insecure firmware signing in Xiaomi smart speakers allowing custom firmware injection", VulnSeverity.HIGH, 7.8, "xiaomi", True, False),
    ("CVE-2026-1013", "Memory corruption in Cisco IOS XR affecting IoT aggregation routers", VulnSeverity.HIGH, 8.1, "cisco", False, False),
    ("CVE-2026-1014", "Insufficient input validation in Honeywell Tridium Niagara allowing RCE", VulnSeverity.CRITICAL, 9.6, "honeywell", True, True),
    ("CVE-2026-1015", "Botnet recruitment vulnerability in Dahua cameras via exposed Telnet service", VulnSeverity.HIGH, 8.0, "dahua", True, True),
    ("CVE-2026-1016", "Side-channel attack on Siemens LOGO! PLC enabling credential extraction", VulnSeverity.MEDIUM, 6.5, "siemens", False, False),
    ("CVE-2026-1017", "Firmware downgrade attack on Hikvision door access controllers", VulnSeverity.HIGH, 7.3, "hikvision", True, False),
    ("CVE-2026-1018", "API key exposure in Ubiquiti cloud management platform", VulnSeverity.HIGH, 7.7, "ubiquiti", False, False),
    ("CVE-2026-1019", "Broken access control in Bosch BME280 environmental sensor hub", VulnSeverity.MEDIUM, 5.5, "bosch", False, False),
    ("CVE-2026-1020", "DNS rebinding vulnerability in Xiaomi Mi Router enabling LAN access", VulnSeverity.HIGH, 7.2, "xiaomi", False, False),
]


async def seed():
    await init_db()
    async with async_session_factory() as session:
        # Data sources
        for name, stype, url, reliability in [
            ("NIST NVD", DataSource.NVD, "https://services.nvd.nist.gov/rest/json/cves/2.0", 0.95),
            ("CISA ICS-CERT", DataSource.ICS_CERT, "https://www.cisa.gov/news-events/cybersecurity-advisories", 0.98),
            ("CVE Program", DataSource.CVE, "https://cve.org", 0.99),
            ("Manufacturer Bulletins", DataSource.MANUFACTURER_BULLETIN, "", 0.90),
            ("Security Research", DataSource.SECURITY_RESEARCH, "", 0.70),
        ]:
            session.add(VulnerabilitySource(
                name=name, source_type=stype, api_url=url,
                reliability_score=reliability, is_active=True,
            ))

        # Manufacturers and products
        mfg_ids = {}
        for mfg_data in MANUFACTURERS:
            mfg = Manufacturer(**mfg_data)
            session.add(mfg)
            await session.flush()
            mfg_ids[mfg_data["slug"]] = mfg.id

            session.add(ProductLine(
                manufacturer_id=mfg.id,
                name=f"{mfg_data['name']} IoT Line",
                category="industrial_iot" if mfg_data["security_posture_score"] > 60 else "consumer_iot",
            ))

        await session.flush()

        # Devices
        device_map = {}
        for slug, mfg_id in mfg_ids.items():
            dev = Device(
                manufacturer_id=mfg_id,
                model_name=f"{slug.title()} IoT Gateway",
                model_number=f"{slug.upper()}-GW-100",
                category="gateway",
                deployment_context="industrial" if slug in ("siemens", "honeywell", "bosch") else "consumer",
                estimated_units_deployed=100000 + hash(slug) % 900000,
                lifecycle_status=DeviceLifecycleStatus.ACTIVE,
            )
            session.add(dev)
            await session.flush()
            device_map[slug] = dev.id

            session.add(DeviceFirmware(
                device_id=dev.id, version="3.2.1", is_latest=1,
                release_date=datetime.utcnow() - timedelta(days=30),
            ))

        # Vulnerabilities
        for cve_id, desc, severity, cvss, mfg_slug, exploit, active in SAMPLE_VULNS:
            vuln = Vulnerability(
                cve_id=cve_id,
                cve_description=desc,
                severity=severity,
                status=VulnStatus.UNPATCHED if exploit else VulnStatus.ANALYZING,
                cvss_v3_score=cvss,
                manufacturer_id=mfg_ids.get(mfg_slug),
                exploit_available=exploit,
                actively_exploited=active,
                published_date=datetime.utcnow() - timedelta(days=hash(cve_id) % 90 + 1),
                confidence_score=0.95 if exploit else 0.7,
            )
            session.add(vuln)
            await session.flush()

        # Alert rules
        session.add(AlertRule(
            name="Critical IoT Vulnerabilities",
            description="Alert on all critical severity IoT vulnerabilities",
            conditions=json.dumps({"min_severity": "critical", "actively_exploited_only": True}),
            notification_channels=json.dumps(["dashboard", "webhook"]),
            auto_escalate=True,
            escalation_timeout_minutes=30,
        ))
        session.add(AlertRule(
            name="Industrial IoT High Risk",
            description="Alert on high-risk vulnerabilities affecting industrial IoT devices",
            conditions=json.dumps({
                "min_severity": "high",
                "categories": ["industrial", "critical infrastructure"],
                "min_risk_score": 7.0,
            }),
            notification_channels=json.dumps(["dashboard", "email"]),
        ))
        session.add(AlertRule(
            name="Exploit Available",
            description="Alert when an exploit becomes available",
            conditions=json.dumps({"exploit_available_only": True}),
            notification_channels=json.dumps(["dashboard"]),
            cooldown_minutes=30,
        ))

        # Escalation path
        session.add(EscalationPath(
            name="Critical Infrastructure Escalation",
            severity_trigger=AlertSeverity.CRITICAL,
            levels=json.dumps([
                {"level": 0, "timeout": 15, "recipients": ["soc-team"]},
                {"level": 1, "timeout": 60, "recipients": ["security-manager", "cto"]},
                {"level": 2, "timeout": 120, "recipients": ["executive-team", "incident-response"]},
            ]),
        ))

        # Retention policies
        for entity, days in [
            ("vulnerability", 2555), ("alert", 365), ("audit_log", 2555), ("metric", 1095),
        ]:
            session.add(DataRetentionPolicy(
                entity_type=entity, retention_days=days, is_active=1,
            ))

        await session.commit()

        # Score all vulnerabilities
        vulns_result = await session.execute(select(Vulnerability))
        all_vulns = vulns_result.scalars().all()
        engine = RiskScoringEngine(session)
        await engine.score_batch(list(all_vulns))
        await engine.update_manufacturer_scores()
        await session.commit()

        print(f"Seeded {len(MANUFACTURERS)} manufacturers")
        print(f"Seeded {len(SAMPLE_VULNS)} vulnerabilities")
        print("Seeded 3 alert rules, 1 escalation path, 4 retention policies")
        print("Database ready!")


from sqlalchemy import select  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402

if __name__ == "__main__":
    asyncio.run(seed())
