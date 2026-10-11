from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from app.config import settings
from app.database import init_db, close_db

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)
    await init_db()
    logger.info("Database initialized")
    from app.scheduler import start_scheduler
    scheduler = start_scheduler()
    yield
    scheduler.shutdown()
    await close_db()
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="IoT Manufacturer Vulnerability Tracker - Monitor, assess, and respond to cybersecurity vulnerabilities across IoT device manufacturers",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.vulnerabilities import router as vuln_router
from app.api.manufacturers import router as mfg_router
from app.api.alerts import router as alert_router
from app.api.dashboard import router as dashboard_router
from app.api.integrations import router as integration_router

app.include_router(vuln_router, prefix=settings.api_prefix, tags=["Vulnerabilities"])
app.include_router(mfg_router, prefix=settings.api_prefix, tags=["Manufacturers & Devices"])
app.include_router(alert_router, prefix=settings.api_prefix, tags=["Alerts"])
app.include_router(dashboard_router, prefix=settings.api_prefix, tags=["Dashboard"])
app.include_router(integration_router, prefix=settings.api_prefix, tags=["Integrations"])


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/", response_class=HTMLResponse)
async def root():
    index = FRONTEND_DIR / "index.html"
    with open(index, "r") as f:
        return HTMLResponse(content=f.read())


app.mount(
    "/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static"
)


def main():
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
