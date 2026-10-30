"""Aggregates every v1 route module. Mounted in main.py under settings.api_v1_prefix."""

from fastapi import APIRouter

from riskreveal.api.v1.routes import assets, auth, findings, scans

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(assets.router)
