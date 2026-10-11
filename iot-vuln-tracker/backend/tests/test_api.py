"""Tests for the IoT Vulnerability Tracker."""
from __future__ import annotations

import json
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import init_db, engine
from app.database import Base


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.asyncio
async def test_create_vulnerability(client):
    payload = {
        "cve_id": "CVE-2026-9999",
        "cve_description": "Test vulnerability in IoT device firmware",
        "severity": "high",
        "cvss_v3_score": 8.5,
        "exploit_available": False,
        "actively_exploited": False,
        "confidence_score": 0.8,
    }
    resp = await client.post("/api/v1/vulnerabilities", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True

    # Verify it exists
    resp = await client.get("/api/v1/vulnerabilities/1")
    assert resp.status_code == 200
    assert resp.json()["cve_id"] == "CVE-2026-9999"


@pytest.mark.asyncio
async def test_create_duplicate_vulnerability(client):
    payload = {
        "cve_id": "CVE-2026-8888",
        "cve_description": "Duplicate test",
        "severity": "low",
    }
    resp1 = await client.post("/api/v1/vulnerabilities", json=payload)
    assert resp1.status_code == 200

    resp2 = await client.post("/api/v1/vulnerabilities", json=payload)
    assert resp2.status_code == 409


@pytest.mark.asyncio
async def test_list_vulnerabilities(client):
    # Create a few
    for i in range(3):
        await client.post("/api/v1/vulnerabilities", json={
            "cve_id": f"CVE-2026-{7000+i}",
            "cve_description": f"Test vuln {i}",
            "severity": ["critical", "high", "medium"][i],
        })

    resp = await client.get("/api/v1/vulnerabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3


@pytest.mark.asyncio
async def test_filter_by_severity(client):
    for sev in ["critical", "high", "medium", "low"]:
        await client.post("/api/v1/vulnerabilities", json={
            "cve_id": f"CVE-2026-{sev[:3].upper()}000",
            "cve_description": f"Test {sev}",
            "severity": sev,
        })

    resp = await client.get("/api/v1/vulnerabilities?severity=critical")
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_update_vulnerability(client):
    await client.post("/api/v1/vulnerabilities", json={
        "cve_id": "CVE-2026-7777",
        "cve_description": "Update test",
        "severity": "medium",
    })

    resp = await client.patch("/api/v1/vulnerabilities/1", json={
        "severity": "critical",
        "actively_exploited": True,
    })
    assert resp.status_code == 200

    resp = await client.get("/api/v1/vulnerabilities/1")
    assert resp.json()["severity"] == "critical"
    assert resp.json()["actively_exploited"] is True


@pytest.mark.asyncio
async def test_create_manufacturer(client):
    resp = await client.post("/api/v1/manufacturers", json={
        "name": "Test Corp",
        "website": "https://test.com",
    })
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    resp = await client.get("/api/v1/manufacturers")
    assert resp.json()["total"] == 1


@pytest.mark.asyncio
async def test_alert_summary(client):
    resp = await client.get("/api/v1/alerts/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "by_severity" in data


@pytest.mark.asyncio
async def test_dashboard_summary(client):
    resp = await client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_vulnerabilities" in data
    assert "manufacturers_tracked" in data


@pytest.mark.asyncio
async def test_dispute_vulnerability(client):
    await client.post("/api/v1/vulnerabilities", json={
        "cve_id": "CVE-2026-5555",
        "cve_description": "Dispute test",
        "severity": "high",
    })

    resp = await client.post(
        "/api/v1/vulnerabilities/1/dispute",
        params={"disputed_by": "Test Vendor", "dispute_reason": "Not reproducible"},
    )
    assert resp.status_code == 200

    resp = await client.get("/api/v1/vulnerabilities/1")
    assert resp.json()["status"] == "disputed"


@pytest.mark.asyncio
async def test_score_breakdown(client):
    await client.post("/api/v1/vulnerabilities", json={
        "cve_id": "CVE-2026-4444",
        "cve_description": "Score test",
        "severity": "critical",
        "cvss_v3_score": 9.5,
        "exploit_available": True,
        "actively_exploited": True,
    })

    resp = await client.get("/api/v1/vulnerabilities/1/score")
    assert resp.status_code == 200
    data = resp.json()
    assert data["composite_score"] > 0
    assert "cvss_component" in data
    assert "exploit_availability_component" in data


@pytest.mark.asyncio
async def test_data_sources(client):
    resp = await client.get("/api/v1/data-sources")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_compliance_mapping(client):
    resp = await client.get("/api/v1/dashboard/compliance-mapping")
    assert resp.status_code == 200
    data = resp.json()
    assert "nist_csf" in data
    assert "iec_62443" in data
    assert "iso_27001" in data
