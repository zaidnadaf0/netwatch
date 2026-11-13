"""API v1 router."""

from fastapi import APIRouter

from app.api.v1.endpoints import health, detection, ingestion, security_audit

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(detection.router, prefix="/detection", tags=["detection"])
api_router.include_router(ingestion.router, prefix="/ingestion", tags=["ingestion"])
api_router.include_router(security_audit.router, prefix="/security-audit", tags=["security_audit"])