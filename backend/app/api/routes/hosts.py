from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import Finding
from backend.app.services.host_service import compare_scans, host_detail, list_hosts

router = APIRouter(tags=["hosts"])


@router.get("/hosts")
def hosts(_: AuthDep, db: DbDep):
    rows = list_hosts(db)
    out = []
    for host in rows:
        out.append(
            {
                "id": host.id,
                "ip": host.ip,
                "hostname": host.hostname,
                "mac": host.mac,
                "state": host.state,
                "os_guess": host.os_guess,
                "os_accuracy": host.os_accuracy,
                "os_label": "guess" if host.os_guess else None,
                "last_seen": host.last_seen.isoformat() if host.last_seen else None,
                "scan_id": host.scan_id,
                "data_source": host.data_source,
                "services": [
                    {
                        "id": s.id,
                        "protocol": s.protocol,
                        "port": s.port,
                        "state": s.state,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                        "detection_source": s.detection_source,
                    }
                    for s in host.services
                ],
            }
        )
    return {"items": out, "count": len(out)}


@router.get("/hosts/{host_id}")
def host(_: AuthDep, db: DbDep, host_id: int):
    row = host_detail(db, host_id)
    if not row:
        raise AppError("Host not found", status_code=404, code="not_found")
    findings = db.query(Finding).filter(
        Finding.host_ip == row.ip,
        Finding.data_source != "demo",
    ).all()
    return {
        "id": row.id,
        "ip": row.ip,
        "hostname": row.hostname,
        "mac": row.mac,
        "state": row.state,
        "os_guess": row.os_guess,
        "os_accuracy": row.os_accuracy,
        "data_source": row.data_source,
        "services": [
            {
                "protocol": s.protocol,
                "port": s.port,
                "state": s.state,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "scripts": s.scripts,
            }
            for s in row.services
        ],
        "findings": [{"id": f.id, "title": f.title, "validation_status": f.validation_status} for f in findings],
    }


@router.get("/topology")
def topology(_: AuthDep, db: DbDep):
    from backend.app.core.config import get_settings
    from backend.app.models import Host, Setting

    settings = get_settings()
    stored = {row.key: row.value for row in db.query(Setting).all()}
    scanner_name = stored.get("scanner_name", settings.scanner_name)
    scanner_ip = stored.get("scanner_ip", settings.scanner_ip)
    nodes = []
    edges = []
    if scanner_ip or scanner_name:
        nodes.append(
            {
                "id": "scanner",
                "label": scanner_name or scanner_ip,
                "role": "scanner",
                "ip": scanner_ip or None,
                "provenance": "configured_scanner_identity",
            }
        )
    q = db.query(Host)
    q = q.filter(Host.data_source != "demo")
    for host in q.all():
        nodes.append(
            {
                "id": f"host-{host.id}",
                "label": host.hostname or host.ip,
                "role": "observed_host",
                "ip": host.ip,
                "state": host.state,
                "os_guess": host.os_guess,
                "provenance": host.provenance,
                "data_source": host.data_source,
            }
        )
        if scanner_ip or scanner_name:
            edges.append(
                {
                    "from": "scanner",
                    "to": f"host-{host.id}",
                    "provenance": "scan_relationship" if host.scan_id else "unspecified",
                    "scan_id": host.scan_id,
                }
            )
    return {"nodes": nodes, "edges": edges, "note": "Edges are created only from stored scan relationships plus configured scanner identity."}


@router.get("/scans/compare")
def compare(_: AuthDep, db: DbDep, left: str, right: str):
    return compare_scans(db, left, right)
