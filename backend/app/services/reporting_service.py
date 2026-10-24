from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models import Alert, Finding, Host, ModelVersion, ReportRecord, ScanJob, Service, Setting


def build_report(db: Session) -> ReportRecord:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    report_id = str(uuid.uuid4())
    stored = {row.key: row.value for row in db.query(Setting).all()}
    hosts = db.query(Host).filter(Host.data_source != "demo").all()
    services = db.query(Service).filter(Service.data_source != "demo").all()
    findings = db.query(Finding).filter(Finding.data_source != "demo").all()
    alerts = db.query(Alert).filter(Alert.data_source != "demo").order_by(Alert.timestamp.desc()).limit(200).all()
    scans = db.query(ScanJob).filter(ScanJob.data_source != "demo").order_by(ScanJob.created_at.desc()).limit(20).all()
    model = db.query(ModelVersion).filter_by(is_active=True).one_or_none()
    payload = {
        "id": report_id,
        "generated_at": now.isoformat(),
        "title": "Nmap-AI Lab Security Report",
        "scanner": {
            "name": stored.get("scanner_name", settings.scanner_name) or None,
            "ip": stored.get("scanner_ip", settings.scanner_ip) or None,
        },
        "intended_target": {
            "name": stored.get("target_name", settings.target_name) or None,
            "ip": stored.get("target_ip", settings.target_ip) or None,
        },
        "limitations": [
            "Only stored database records are included.",
            "Closed ports are not services. Open ports are not automatically vulnerabilities.",
            "ML scores are offline-trained classifier outputs, not proof of compromise.",
            "Exploitation is not claimed.",
        ],
        "scans": [
            {
                "id": s.id,
                "profile": s.profile,
                "targets": s.targets,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "error": s.error,
            }
            for s in scans
        ],
        "hosts": [{"ip": h.ip, "hostname": h.hostname, "state": h.state, "os_guess": h.os_guess} for h in hosts],
        "services": [
            {
                "host_id": s.host_id,
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "name": s.name,
                "product": s.product,
                "version": s.version,
            }
            for s in services
        ],
        "findings": [
            {
                "id": f.id,
                "host_ip": f.host_ip,
                "title": f.title,
                "cve": f.cve,
                "severity": f.severity,
                "validation_status": f.validation_status,
                "evidence": f.evidence,
                "risk_score": f.risk_score,
            }
            for f in findings
        ],
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "detection_method": a.detection_method,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in alerts
        ],
        "model": {
            "version": model.version if model else None,
            "metrics": model.metrics if model else None,
            "note": "Offline evaluation does not guarantee live-lab accuracy.",
        },
        "omitted": {
            "demo_records": "Demo fixtures are excluded from live reports.",
            "secrets": "API tokens and passwords are never exported.",
        },
    }
    out_dir = settings.data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{report_id}.json"
    pdf_path = out_dir / f"{report_id}.pdf"
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    _write_pdf(pdf_path, payload)
    record = ReportRecord(
        id=report_id,
        title=payload["title"],
        json_path=str(json_path),
        pdf_path=str(pdf_path),
        scope={"host_count": len(hosts), "finding_count": len(findings)},
        data_source="live",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def _write_pdf(path: Path, payload: dict) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter)
    story = [
        Paragraph(escape(payload["title"]), styles["Title"]),
        Paragraph(f"Generated at {escape(payload['generated_at'])}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(
            f"Hosts stored: {len(payload['hosts'])}. Findings stored: {len(payload['findings'])}. "
            f"Alerts included: {len(payload['alerts'])}.",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Limitations", styles["Heading2"]),
    ]
    for note in payload["limitations"]:
        story.append(Paragraph(f"• {note}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Prioritized findings", styles["Heading2"]))
    ranked = sorted(payload["findings"], key=lambda f: f.get("risk_score") or 0, reverse=True)[:25]
    if not ranked:
        story.append(Paragraph("No stored findings.", styles["Normal"]))
    for item in ranked:
        story.append(
            Paragraph(
                escape(
                    f"{item['id']} {item['host_ip']} — {item['title']} "
                    f"[{item['validation_status']}] risk={item.get('risk_score')}"
                ),
                styles["Normal"],
            )
        )
    doc.build(story)
