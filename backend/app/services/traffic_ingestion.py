from __future__ import annotations

import struct
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models import IngestionHealth, TrafficEvent
from backend.app.services.alert_service import create_or_bump, signature_alerts
from backend.app.services.feature_extractor import FlowTable
from ml.inference.predict import FeatureSchemaError, latest_artifact, load_model, predict

MAX_FRAME = 65535


class IngestionState:
    def __init__(self) -> None:
        self.flows = FlowTable()
        self.recent_ports: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.model = None
        self.schema = None
        self._try_load_model()

    def _try_load_model(self) -> None:
        try:
            if latest_artifact():
                self.model, self.schema = load_model()
        except Exception:
            self.model, self.schema = None, None


STATE = IngestionState()


def health_row(db: Session) -> IngestionHealth:
    row = db.query(IngestionHealth).filter_by(id=1).one_or_none()
    if not row:
        row = IngestionHealth(id=1, state="stopped", guidance="Capture is idle until an adapter is started.")
        db.add(row)
        db.flush()
    return row


def decode_length_prefixed(buffer: bytes) -> tuple[list[bytes], bytes, int]:
    """Split length-prefixed frames. Returns (frames, remainder, error_count)."""
    frames = []
    errors = 0
    view = memoryview(buffer)
    offset = 0
    while len(view) - offset >= 4:
        (length,) = struct.unpack_from("!I", view, offset)
        if length <= 0 or length > MAX_FRAME:
            errors += 1
            offset += 4
            continue
        if len(view) - offset - 4 < length:
            break
        frames.append(bytes(view[offset + 4 : offset + 4 + length]))
        offset += 4 + length
    return frames, bytes(view[offset:]), errors


def ingest_packet_dict(db: Session, pkt: dict[str, Any], adapter: str = "local") -> TrafficEvent:
    health = health_row(db)
    now = datetime.now(timezone.utc)
    flow = STATE.flows.add_packet(pkt)
    features, complete, reason = flow.features()
    ml_status = "skipped_insufficient"
    ml_label = None
    ml_conf = None
    model_version = None
    if complete:
        try:
            if STATE.model is None:
                STATE._try_load_model()
            if STATE.model is None:
                ml_status = "skipped_no_model"
            else:
                result = predict(features, STATE.model, STATE.schema)
                ml_status = "inferred"
                ml_label = result["predicted_label"]
                ml_conf = result["confidence"]
                model_version = result["model_version"]
        except FeatureSchemaError as exc:
            ml_status = "skipped_schema"
            reason = str(exc)
        except Exception as exc:  # persist real inference errors
            ml_status = "error"
            reason = str(exc)
    else:
        ml_status = "skipped_insufficient"

    src = pkt.get("src_addr")
    if pkt.get("dst_port") is not None:
        STATE.recent_ports[str(src)].append(int(pkt["dst_port"]))
    sigs = signature_alerts(
        {
            **pkt,
            "packets_per_sec": (flow.fwd_pkts + flow.bwd_pkts) / max((flow.last - flow.start).total_seconds(), 0.001),
        },
        list(STATE.recent_ports[str(src)]),
    )
    event = TrafficEvent(
        timestamp=now,
        adapter=adapter,
        src_addr=pkt.get("src_addr"),
        dst_addr=pkt.get("dst_addr"),
        src_port=pkt.get("src_port"),
        dst_port=pkt.get("dst_port"),
        protocol=pkt.get("protocol"),
        packet_length=pkt.get("packet_length"),
        features=features,
        feature_complete=complete,
        ml_status=ml_status,
        ml_label=ml_label,
        ml_confidence=ml_conf,
        model_version=model_version,
        signatures=[s["title"] for s in sigs],
        parse_error=reason if not complete or ml_status in {"error", "skipped_schema"} else None,
        data_source="live",
    )
    db.add(event)
    for sig in sigs:
        create_or_bump(
            db,
            {
                "timestamp": now,
                "src_addr": sig.get("src_addr"),
                "dst_addr": sig.get("dst_addr"),
                "src_port": pkt.get("src_port"),
                "dst_port": sig.get("dst_port"),
                "protocol": sig.get("protocol"),
                "detection_method": sig["detection_method"],
                "rule_or_model": sig.get("rule_or_model"),
                "evidence_ref": f"traffic:{adapter}",
                "severity": sig["severity"],
                "confidence": sig.get("confidence"),
                "title": sig["title"],
                "message": sig["message"],
                "status": "open",
                "fingerprint": sig["fingerprint"],
                "data_source": "live",
                "extra": {"event_features_complete": complete},
            },
        )
    if ml_status == "inferred" and ml_label and ml_label != "BENIGN":
        create_or_bump(
            db,
            {
                "timestamp": now,
                "src_addr": pkt.get("src_addr"),
                "dst_addr": pkt.get("dst_addr"),
                "src_port": pkt.get("src_port"),
                "dst_port": pkt.get("dst_port"),
                "protocol": pkt.get("protocol"),
                "detection_method": "ml",
                "rule_or_model": model_version,
                "evidence_ref": "ml_inference",
                "severity": "medium",
                "confidence": ml_conf,
                "title": f"ML classification: {ml_label}",
                "message": "Supervised model prediction on computed flow features. This is not proof of compromise.",
                "status": "open",
                "fingerprint": f"ml-{pkt.get('src_addr')}-{pkt.get('dst_addr')}-{ml_label}",
                "data_source": "live",
                "extra": {"features": features},
            },
        )
    health.packets_processed += 1
    health.flows_processed = len(STATE.flows.flows)
    health.last_event_at = now
    health.adapter = adapter
    health.state = "running"
    db.flush()
    return event


def record_parse_error(db: Session, message: str) -> None:
    health = health_row(db)
    health.parse_errors += 1
    health.last_error = message
    db.flush()
