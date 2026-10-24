from fastapi import APIRouter

from backend.app.api.routes import alerts, auth, dashboard, findings, health, hosts, ml, reports, scans, settings, traffic, ws

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(hosts.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(alerts.router)
api_router.include_router(traffic.router)
api_router.include_router(ml.router)
api_router.include_router(reports.router)
api_router.include_router(settings.router)
api_router.include_router(ws.router)
