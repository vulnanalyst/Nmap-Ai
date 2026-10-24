from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from backend.app.models import Finding, Host, ScanJob, Service
from backend.app.services.vulnerability_service import findings_from_service, persist_findings


def persist_parsed_scan(db: Session, scan: ScanJob, parsed: dict, data_source: str) -> None:
    now = datetime.now(timezone.utc)
    scan.nmap_version = parsed.get("version")
    scan.duration_seconds = parsed.get("elapsed")
    scan.hosts_up = parsed.get("hosts_up") or 0
    scan.hosts_down = parsed.get("hosts_down") or 0
    counts = parsed.get("port_counts") or {}
    scan.ports_open = counts.get("open") or 0
    scan.ports_closed = counts.get("closed") or 0
    scan.ports_filtered = counts.get("filtered") or 0

    for host_data in parsed.get("hosts") or []:
        ip = host_data.get("ip")
        if not ip:
            continue
        hostnames = host_data.get("hostnames") or []
        hostname = hostnames[0]["name"] if hostnames else None
        guesses = host_data.get("os_guesses") or []
        os_guess = guesses[0]["name"] if guesses else None
        os_acc = guesses[0]["accuracy"] if guesses else None
        host = Host(
            scan_id=scan.id,
            ip=ip,
            hostname=hostname,
            mac=host_data.get("mac"),
            mac_vendor=host_data.get("mac_vendor"),
            state=host_data.get("state") or "unknown",
            os_guess=os_guess,
            os_accuracy=os_acc,
            reason=host_data.get("reason"),
            first_seen=now,
            last_seen=now,
            provenance="nmap_xml",
            data_source=data_source,
        )
        db.add(host)
        db.flush()
        for port in host_data.get("ports") or []:
            svc_meta = port.get("service") or {}
            service = Service(
                host_id=host.id,
                protocol=port.get("protocol") or "tcp",
                port=port.get("port") or 0,
                state=port.get("state") or "unknown",
                reason=port.get("reason"),
                name=svc_meta.get("name"),
                product=svc_meta.get("product"),
                version=svc_meta.get("version"),
                extra=svc_meta.get("extrainfo"),
                tunnel=svc_meta.get("tunnel"),
                method=svc_meta.get("method"),
                conf=svc_meta.get("conf"),
                scripts=port.get("scripts") or [],
                detection_source="nmap",
                data_source=data_source,
            )
            db.add(service)
            db.flush()
            if service.state == "open":
                persist_findings(
                    db,
                    findings_from_service(service, ip, scan.id, data_source),
                    port_state=service.state,
                )
    db.flush()


def list_hosts(db: Session) -> list[Host]:
    q = (
        db.query(Host)
        .filter(Host.data_source != "demo")
        .options(joinedload(Host.services))
        .order_by(Host.last_seen.desc())
    )
    return q.all()


def host_detail(db: Session, host_id: int) -> Host | None:
    return (
        db.query(Host)
        .options(joinedload(Host.services))
        .filter(Host.id == host_id, Host.data_source != "demo")
        .one_or_none()
    )


def compare_scans(db: Session, left_id: str, right_id: str) -> dict:
    left = db.query(ScanJob).filter(ScanJob.id == left_id, ScanJob.data_source != "demo").one_or_none()
    right = db.query(ScanJob).filter(ScanJob.id == right_id, ScanJob.data_source != "demo").one_or_none()
    if not left or not right:
        return {"error": "One or both scans were not found"}

    def snapshot(scan_id: str) -> set[tuple]:
        rows = (
            db.query(Host.ip, Service.protocol, Service.port, Service.state)
            .join(Service, Service.host_id == Host.id)
            .filter(Host.scan_id == scan_id, Host.data_source != "demo", Service.data_source != "demo")
            .all()
        )
        return {(ip, proto, port, state) for ip, proto, port, state in rows}

    a, b = snapshot(left_id), snapshot(right_id)
    return {
        "left": left_id,
        "right": right_id,
        "added": sorted(list(b - a)),
        "removed": sorted(list(a - b)),
        "unchanged": len(a & b),
        "provenance": "database_scan_comparison",
    }
