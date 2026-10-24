from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.models import TrafficEvent
from backend.app.schemas.api import PacketIngest
from backend.app.services.traffic_ingestion import health_row, ingest_packet_dict

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("/status")
def status(_: AuthDep, db: DbDep):
    row = health_row(db)
    return {
        "adapter": row.adapter,
        "state": row.state,
        "interface": row.interface,
        "packets_processed": row.packets_processed,
        "flows_processed": row.flows_processed,
        "dropped_events": row.dropped_events,
        "parse_errors": row.parse_errors,
        "last_event_at": row.last_event_at.isoformat() if row.last_event_at else None,
        "last_error": row.last_error,
        "permission_ok": row.permission_ok,
        "guidance": row.guidance
        or "Packet capture requires root/admin and a configured interface. Live events appear only when telemetry is received.",
    }


@router.get("/events")
def events(_: AuthDep, db: DbDep):
    q = db.query(TrafficEvent)
    q = q.filter(TrafficEvent.data_source != "demo")
    rows = q.order_by(TrafficEvent.timestamp.desc()).limit(200).all()
    return {
        "items": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "src_addr": e.src_addr,
                "dst_addr": e.dst_addr,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "feature_complete": e.feature_complete,
                "ml_status": e.ml_status,
                "ml_label": e.ml_label,
                "ml_confidence": e.ml_confidence,
                "model_version": e.model_version,
                "signatures": e.signatures,
                "features": e.features,
                "parse_error": e.parse_error,
                "data_source": e.data_source,
            }
            for e in rows
        ]
    }


@router.post("/ingest")
def ingest(_: AuthDep, db: DbDep, body: PacketIngest):
    event = ingest_packet_dict(db, body.model_dump(), adapter="http")
    db.commit()
    return {"id": event.id, "ml_status": event.ml_status, "feature_complete": event.feature_complete}
