from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    targets: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    argv: Mapped[list] = mapped_column(JSON, default=list)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    data_source: Mapped[str] = mapped_column(String(32), default="live")
    progress_pct: Mapped[float] = mapped_column(Float, default=0)
    nmap_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    xml_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    json_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    authorized_by: Mapped[str] = mapped_column(String(128), default="lab-operator")
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    hosts_down: Mapped[int] = mapped_column(Integer, default=0)
    ports_open: Mapped[int] = mapped_column(Integer, default=0)
    ports_closed: Mapped[int] = mapped_column(Integer, default=0)
    ports_filtered: Mapped[int] = mapped_column(Integer, default=0)

    hosts: Mapped[list["Host"]] = relationship(back_populates="scan")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mac_vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="unknown")
    os_guess: Mapped[str | None] = mapped_column(String(256), nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    provenance: Mapped[str] = mapped_column(String(64), default="nmap_xml")
    data_source: Mapped[str] = mapped_column(String(32), default="live")

    scan: Mapped[ScanJob | None] = relationship(back_populates="hosts")
    services: Mapped[list["Service"]] = relationship(back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    extra: Mapped[str | None] = mapped_column(Text, nullable=True)
    tunnel: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conf: Mapped[str | None] = mapped_column(String(16), nullable=True)
    scripts: Mapped[list] = mapped_column(JSON, default=list)
    detection_source: Mapped[str] = mapped_column(String(64), default="nmap")
    data_source: Mapped[str] = mapped_column(String(32), default="live")

    host: Mapped[Host] = relationship(back_populates="services")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)
    host_ip: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    detection_source: Mapped[str] = mapped_column(String(64), default="catalog")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    validation_status: Mapped[str] = mapped_column(String(64), default="suspected")
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    workflow_status: Mapped[str] = mapped_column(String(32), default="new")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    data_source: Mapped[str] = mapped_column(String(32), default="live")
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    src_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detection_method: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_or_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="low")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    message: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    data_source: Mapped[str] = mapped_column(String(32), default="live")
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    notes: Mapped[list["AlertNote"]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)
    author: Mapped[str] = mapped_column(String(128), default="analyst")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alert: Mapped[Alert] = relationship(back_populates="notes")


class TrafficEvent(Base):
    __tablename__ = "traffic_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    adapter: Mapped[str] = mapped_column(String(64), default="unknown")
    src_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    packet_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    feature_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    ml_status: Mapped[str] = mapped_column(String(64), default="skipped_insufficient")
    ml_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ml_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signatures: Mapped[list] = mapped_column(JSON, default=list)
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_source: Mapped[str] = mapped_column(String(32), default="live")


class IngestionHealth(Base):
    __tablename__ = "ingestion_health"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    adapter: Mapped[str] = mapped_column(String(64), default="none")
    state: Mapped[str] = mapped_column(String(32), default="stopped")
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    packets_processed: Mapped[int] = mapped_column(Integer, default=0)
    flows_processed: Mapped[int] = mapped_column(Integer, default=0)
    dropped_events: Mapped[int] = mapped_column(Integer, default=0)
    parse_errors: Mapped[int] = mapped_column(Integer, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    permission_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    guidance: Mapped[str | None] = mapped_column(Text, nullable=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), unique=True)
    path: Mapped[str] = mapped_column(Text)
    schema_path: Mapped[str] = mapped_column(Text)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dataset_source: Mapped[str] = mapped_column(Text, default="")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    feature_names: Mapped[list] = mapped_column(JSON, default=list)
    classes: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)


class TrainingRun(Base):
    __tablename__ = "training_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dataset_path: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    title: Mapped[str] = mapped_column(String(256), default="Lab Security Report")
    json_path: Mapped[str] = mapped_column(Text)
    pdf_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    data_source: Mapped[str] = mapped_column(String(32), default="live")
