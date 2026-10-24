from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ml.preprocessing.schema import FEATURE_NAMES


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    start: datetime
    last: datetime
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_len: int = 0
    bwd_len: int = 0
    fwd_max: int = 0
    bwd_max: int = 0
    sizes: list[int] = field(default_factory=list)

    def duration_us(self) -> float:
        return max((self.last - self.start).total_seconds() * 1_000_000, 0.0)

    def features(self) -> tuple[dict[str, float], bool, str | None]:
        duration = self.duration_us()
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_len = self.fwd_len + self.bwd_len
        if total_pkts < 2 or duration <= 0:
            return {}, False, "insufficient_flow_features"
        avg = total_len / total_pkts if total_pkts else 0.0
        seconds = duration / 1_000_000
        feats = {
            "Destination Port": float(self.dport),
            "Flow Duration": float(duration),
            "Total Fwd Packets": float(self.fwd_pkts),
            "Total Backward Packets": float(self.bwd_pkts),
            "Total Length of Fwd Packets": float(self.fwd_len),
            "Fwd Packet Length Max": float(self.fwd_max),
            "Bwd Packet Length Max": float(self.bwd_max),
            "Flow Bytes/s": float(total_len / seconds),
            "Flow Packets/s": float(total_pkts / seconds),
            "Average Packet Size": float(avg),
        }
        if list(feats) != FEATURE_NAMES:
            return {}, False, "feature_schema_mismatch"
        return feats, True, None


class FlowTable:
    def __init__(self) -> None:
        self.flows: dict[tuple, Flow] = {}

    def add_packet(self, pkt: dict[str, Any]) -> Flow:
        src, dst = pkt["src_addr"], pkt["dst_addr"]
        sport, dport = int(pkt.get("src_port") or 0), int(pkt.get("dst_port") or 0)
        proto = pkt.get("protocol") or "TCP"
        key_fwd = (src, dst, sport, dport, proto)
        key_rev = (dst, src, dport, sport, proto)
        now = pkt.get("timestamp") or datetime.now(timezone.utc)
        length = int(pkt.get("packet_length") or 0)
        if key_fwd in self.flows:
            flow = self.flows[key_fwd]
            direction = "fwd"
        elif key_rev in self.flows:
            flow = self.flows[key_rev]
            direction = "bwd"
        else:
            flow = Flow(src, dst, sport, dport, proto, now, now)
            self.flows[key_fwd] = flow
            direction = "fwd"
        flow.last = now
        flow.sizes.append(length)
        if direction == "fwd":
            flow.fwd_pkts += 1
            flow.fwd_len += length
            flow.fwd_max = max(flow.fwd_max, length)
        else:
            flow.bwd_pkts += 1
            flow.bwd_len += length
            flow.bwd_max = max(flow.bwd_max, length)
        return flow
