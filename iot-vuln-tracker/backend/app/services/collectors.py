from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.vulnerability import DataSource, VulnSeverity, VulnStatus, Vulnerability, VulnerabilitySource

logger = logging.getLogger(__name__)


class BaseCollector:
    """Base class for vulnerability data collectors."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.client = httpx.AsyncClient(timeout=60.0)

    async def close(self):
        await self.client.aclose()

    def _normalize_severity(self, cvss_score: float | None) -> VulnSeverity:
        if cvss_score is None:
            return VulnSeverity.UNKNOWN
        if cvss_score >= 9.0:
            return VulnSeverity.CRITICAL
        if cvss_score >= 7.0:
            return VulnSeverity.HIGH
        if cvss_score >= 4.0:
            return VulnSeverity.MEDIUM
        return VulnSeverity.LOW

    def _parse_cvss_vector(self, vector_str: str | None) -> dict[str, Any]:
        if not vector_str:
            return {}
        parts = {}
        for item in vector_str.split("/"):
            if ":" in item:
                key, value = item.split(":", 1)
                parts[key] = value
        return parts

    async def _upsert_vulnerability(self, vuln_data: dict[str, Any]) -> Vulnerability:
        existing = await self.session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == vuln_data["cve_id"])
        )
        vuln = existing.scalar_one_or_none()

        if vuln:
            for key, value in vuln_data.items():
                if value is not None and hasattr(vuln, key):
                    setattr(vuln, key, value)
            vuln.updated_at = datetime.utcnow()
        else:
            vuln = Vulnerability(**vuln_data)
            self.session.add(vuln)

        await self.session.flush()
        return vuln


class NVDCollector(BaseCollector):
    """Collector for NIST National Vulnerability Database (NVD 2.0 API)."""

    BASE_URL = settings.nvd_api_url
    RATE_LIMIT_DELAY = 1.0 / settings.nvd_requests_per_second

    async def get_source(self) -> VulnerabilitySource:
        result = await self.session.execute(
            select(VulnerabilitySource).where(VulnerabilitySource.source_type == DataSource.NVD)
        )
        source = result.scalar_one_or_none()
        if not source:
            source = VulnerabilitySource(
                name="NIST NVD",
                source_type=DataSource.NVD,
                api_url=self.BASE_URL,
                reliability_score=0.95,
                sync_interval_seconds=settings.nvd_sync_interval,
            )
            self.session.add(source)
            await self.session.flush()
        return source

    async def sync_recent(self, days_back: int = 1) -> list[Vulnerability]:
        """Sync vulnerabilities published/modified in the last N days."""
        source = await self.get_source()
        last_pub_start = datetime.utcnow() - timedelta(days=days_back)
        last_pub_end = datetime.utcnow()

        params = {
            "lastModStartDate": last_pub_start.isoformat() + "Z",
            "lastModEndDate": last_pub_end.isoformat() + "Z",
            "resultsPerPage": 200,
            "startIndex": 0,
        }

        if settings.nvd_api_key:
            params["apiKey"] = settings.nvd_api_key

        synced = []
        total_results = None

        while True:
            try:
                response = await self.client.get(self.BASE_URL, params=params)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPStatusError as e:
                logger.error("NVD API error %d: %s", e.response.status_code, e.response.text)
                break
            except httpx.RequestError as e:
                logger.error("NVD API request failed: %s", e)
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)

            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve = item.get("cve", {})
                vuln_data = self._parse_nvd_cve(cve, source.id)
                if vuln_data:
                    vuln = await self._upsert_vulnerability(vuln_data)
                    synced.append(vuln)

            start_index = params["startIndex"] + len(vulnerabilities)
            if start_index >= total_results:
                break

            params["startIndex"] = start_index
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        source.last_synced_at = datetime.utcnow()
        await self.session.flush()
        logger.info("NVD sync complete: %d vulnerabilities processed", len(synced))
        return synced

    def _parse_nvd_cve(self, cve: dict, source_id: int) -> dict[str, Any] | None:
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_v30 = metrics.get("cvssMetricV30", [{}])
        cvss_v2 = metrics.get("cvssMetricV2", [{}])

        cvss_v3_score = None
        cvss_v3_vector = None
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
        elif cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")

        cvss_v2_score = None
        cvss_v2_vector = None
        if cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            cvss_v2_score = cvss_data.get("baseScore")
            cvss_v2_vector = cvss_data.get("vectorString")

        severity = self._normalize_severity(cvss_v3_score or cvss_v2_score)

        # Extract CWE
        weaknesses = cve.get("weaknesses", [])
        cwe_id = None
        cwe_desc = None
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_id = desc["value"]
                    cwe_desc = desc["value"]
                    break

        # Extract references
        refs = cve.get("references", [])
        ref_urls = json.dumps([r.get("url", "") for r in refs])

        # Parse CPE
        configurations = cve.get("configurations", [])
        affected_cpe = self._extract_cpe(configurations)

        # Check for known exploits
        exploit_refs = [r for r in refs if any(
            kw in r.get("tags", [])
            for kw in ["Exploit", "Third Party Advisory"]
        )]
        exploit_available = len(exploit_refs) > 0

        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        return {
            "cve_id": cve_id,
            "cve_description": description,
            "severity": severity,
            "status": VulnStatus.ANALYZING,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2_score,
            "cvss_v2_vector": cvss_v2_vector,
            "cwe_id": cwe_id,
            "cwe_description": cwe_desc,
            "affected_cpe": affected_cpe,
            "references": ref_urls,
            "exploit_available": exploit_available,
            "source_id": source_id,
            "published_date": datetime.fromisoformat(published.replace("Z", "+00:00"))
            if published
            else None,
            "last_modified_date": datetime.fromisoformat(modified.replace("Z", "+00:00"))
            if modified
            else None,
            "confidence_score": settings.verified_disclosure_confidence,
        }

    def _extract_cpe(self, configurations: list) -> str:
        cpes = []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        cpes.append(cpe)
        return "\n".join(cpes)


class ICSCERTCollector(BaseCollector):
    """Collector for CISA ICS-CERT advisories."""

    BASE_URL = settings.ics_cert_url

    async def get_source(self) -> VulnerabilitySource:
        result = await self.session.execute(
            select(VulnerabilitySource).where(VulnerabilitySource.source_type == DataSource.ICS_CERT)
        )
        source = result.scalar_one_or_none()
        if not source:
            source = VulnerabilitySource(
                name="CISA ICS-CERT",
                source_type=DataSource.ICS_CERT,
                api_url=self.BASE_URL,
                reliability_score=0.98,
                sync_interval_seconds=settings.ics_cert_sync_interval,
            )
            self.session.add(source)
            await self.session.flush()
        return source

    async def sync_recent(self, days_back: int = 7) -> list[Vulnerability]:
        """Sync recent ICS-CERT advisories."""
        source = await self.get_source()
        synced = []

        try:
            response = await self.client.get(
                f"{self.BASE_URL}/api/advisories",
                params={"daysBack": days_back, "format": "json"},
            )
            response.raise_for_status()
            advisories = response.json()
        except Exception as e:
            logger.error("ICS-CERT fetch failed: %s", e)
            source.last_synced_at = datetime.utcnow()
            await self.session.flush()
            return synced

        for advisory in advisories:
            cve_ids = advisory.get("cveIds", [])
            for cve_id in cve_ids:
                vuln_data = self._parse_advisory(advisory, cve_id, source.id)
                if vuln_data:
                    vuln = await self._upsert_vulnerability(vuln_data)
                    synced.append(vuln)

        source.last_synced_at = datetime.utcnow()
        await self.session.flush()
        logger.info("ICS-CERT sync complete: %d vulnerabilities processed", len(synced))
        return synced

    def _parse_advisory(self, advisory: dict, cve_id: str, source_id: int) -> dict[str, Any] | None:
        title = advisory.get("title", "")
        vendor = advisory.get("vendor", "")
        product = advisory.get("product", "")
        description = advisory.get("description", "")
        severity = advisory.get("severity", "").lower()
        published = advisory.get("publishDate", "")
        icsa_id = advisory.get("id", "")

        severity_map = {
            "critical": VulnSeverity.CRITICAL,
            "high": VulnSeverity.HIGH,
            "medium": VulnSeverity.MEDIUM,
            "low": VulnSeverity.LOW,
        }
        severity_enum = severity_map.get(severity, VulnSeverity.UNKNOWN)

        cpe = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:*:*:*:*:*:*:*:*"

        mitigation_notes = advisory.get("mitigation", "")
        references = json.dumps([
            f"https://www.cisa.gov/news-events/cybersecurity-advisories/{icsa_id}",
            *(advisory.get("refs", [])),
        ])

        return {
            "cve_id": cve_id,
            "cve_description": f"{title}. {description}",
            "severity": severity_enum,
            "status": VulnStatus.ANALYZING,
            "affected_cpe": cpe,
            "affected_product_names": f"{vendor} {product}",
            "references": references,
            "source_id": source_id,
            "published_date": datetime.fromisoformat(published) if published else None,
            "confidence_score": settings.verified_disclosure_confidence,
        }
