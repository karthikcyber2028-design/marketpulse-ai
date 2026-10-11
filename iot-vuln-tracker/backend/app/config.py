from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    app_name: str = "IoT Vulnerability Tracker"
    app_version: str = "1.0.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = True

    # Database
    database_url: str = "sqlite+aiosqlite:///./iot_vuln_tracker.db"
    database_echo: bool = False

    # API
    api_prefix: str = "/api/v1"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    allowed_origins: list[str] = ["http://localhost:8000", "http://localhost:3000"]

    # Auth
    secret_key: str = os.getenv("SECRET_KEY", "change-me-in-production-use-env-var")
    access_token_expire_minutes: int = 60

    # Data Collection Intervals (seconds)
    nvd_sync_interval: int = 3600  # 1 hour
    cve_sync_interval: int = 3600
    ics_cert_sync_interval: int = 7200  # 2 hours
    manufacturer_bulletin_interval: int = 14400  # 4 hours
    zero_day_scan_interval: int = 1800  # 30 minutes

    # NVD API
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = os.getenv("NVD_API_KEY", "")
    nvd_requests_per_second: int = 5

    # ICS-CERT
    ics_cert_url: str = "https://www.cisa.gov/news-events/cybersecurity-advisories"

    # Alert thresholds
    critical_alert_threshold: float = 9.0
    high_alert_threshold: float = 7.0

    # Data retention (days)
    vulnerability_retention_days: int = 2555  # 7 years
    alert_retention_days: int = 365  # 1 year
    audit_log_retention_days: int = 2555
    metrics_retention_days: int = 1095  # 3 years

    # Confidence scoring
    min_disclosure_confidence: float = 0.3
    verified_disclosure_confidence: float = 1.0

    # Email
    smtp_host: str = os.getenv("SMTP_HOST", "localhost")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "vuln-tracker@localhost")
    smtp_use_tls: bool = True

    # Webhook
    webhook_timeout: int = 30
    webhook_retry_count: int = 3

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()
