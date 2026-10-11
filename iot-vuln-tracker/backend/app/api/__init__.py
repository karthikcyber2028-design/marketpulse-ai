from app.api.vulnerabilities import router as vuln_router
from app.api.manufacturers import router as mfg_router
from app.api.alerts import router as alert_router
from app.api.dashboard import router as dashboard_router
from app.api.integrations import router as integration_router

__all__ = [
    "vuln_router",
    "mfg_router",
    "alert_router",
    "dashboard_router",
    "integration_router",
]
