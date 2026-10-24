from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.models import Alert, Finding, Host, ScanJob, Service, TrafficEvent
from ml.inference.predict import latest_artifact


def dashboard_summary(db: Session, include_demo: bool = False) -> dict:
    def scoped(query, model):
        if include_demo:
            return query
        return query.filter(model.data_source != "demo")

    hosts = scoped(db.query(Host), Host)
    services = scoped(db.query(Service), Service)
    findings = scoped(db.query(Finding), Finding)
    alerts = scoped(db.query(Alert), Alert)
    scans = scoped(db.query(ScanJob), ScanJob)
    latest_scan = scans.order_by(ScanJob.created_at.desc()).first()
    model = latest_artifact()
    traffic_counts = (
        scoped(db.query(TrafficEvent.ml_label, func.count()), TrafficEvent)
        .group_by(TrafficEvent.ml_label)
        .all()
    )
    return {
        "hosts_total": hosts.count(),
        "hosts_up": hosts.filter(Host.state == "up").count(),
        "ports_open": services.filter(Service.state == "open").count(),
        "ports_closed": services.filter(Service.state == "closed").count(),
        "ports_filtered": services.filter(Service.state == "filtered").count(),
        "services_observed": services.filter(Service.state == "open", Service.name.isnot(None)).count(),
        "findings_by_severity": dict(
            scoped(db.query(Finding.severity, func.count()), Finding).group_by(Finding.severity).all()
        ),
        "findings_by_validation": dict(
            scoped(db.query(Finding.validation_status, func.count()), Finding).group_by(Finding.validation_status).all()
        ),
        "latest_scan": None
        if not latest_scan
        else {
            "id": latest_scan.id,
            "status": latest_scan.status,
            "profile": latest_scan.profile,
            "created_at": latest_scan.created_at.isoformat() if latest_scan.created_at else None,
            "duration_seconds": latest_scan.duration_seconds,
            "error": latest_scan.error,
            "data_source": latest_scan.data_source,
        },
        "model": {
            "version": model.get("version") if model else None,
            "trained_at": model.get("trained_at") if model else None,
            "metrics": (model.get("metrics") or {}).get("random_forest") if model else None,
            "disclaimer": "Offline CIC-IDS2017 metrics do not guarantee live-lab accuracy.",
        },
        "traffic_ml_labels": {str(k): v for k, v in traffic_counts if k},
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "detection_method": a.detection_method,
                "data_source": a.data_source,
            }
            for a in alerts.order_by(Alert.timestamp.desc()).limit(10).all()
        ],
        "scan_trend": [
            {
                "id": s.id,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "ports_open": s.ports_open,
                "status": s.status,
            }
            for s in scans.order_by(ScanJob.created_at.asc()).limit(20).all()
        ],
        "data_source_filter": "live+import" if not include_demo else "all",
    }
