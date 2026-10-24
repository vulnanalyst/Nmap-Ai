"""Length-prefixed packet ingest listener. Does not treat TCP chunks as Ethernet frames."""

from __future__ import annotations

import os
import socket
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.core.config import get_settings
from backend.app.db.session import get_session_factory, init_db
from backend.app.services.traffic_ingestion import decode_length_prefixed, ingest_packet_dict, record_parse_error


def _parse_ip_tcp(frame: bytes) -> dict | None:
    try:
        from scapy.all import Ether, IP, TCP, IPv6, UDP  # type: ignore
    except ImportError:
        print("Scapy is not installed. HTTP ingest (/api/v1/traffic/ingest) still works.")
        return None
    pkt = Ether(frame)
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if ip is None or l4 is None:
        return None
    return {
        "src_addr": ip.src,
        "dst_addr": ip.dst,
        "src_port": int(l4.sport),
        "dst_port": int(l4.dport),
        "protocol": l4.name,
        "packet_length": len(frame),
    }


def main() -> None:
    settings = get_settings()
    host = settings.ingest_host
    port = settings.ingest_port
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"Listening for length-prefixed frames on {host}:{port}")
    conn, addr = server.accept()
    print(f"Connected: {addr}")
    buffer = b""
    db = get_session_factory()()
    try:
        while True:
            chunk = conn.recv(65535)
            if not chunk:
                break
            buffer += chunk
            frames, buffer, errors = decode_length_prefixed(buffer)
            for _ in range(errors):
                record_parse_error(db, "invalid frame length")
            for frame in frames:
                parsed = _parse_ip_tcp(frame)
                if not parsed:
                    record_parse_error(db, "frame did not contain IP/TCP or UDP")
                    continue
                ingest_packet_dict(db, parsed, adapter="tcp-framed")
            db.commit()
    except KeyboardInterrupt:
        print("Monitor stopped")
    finally:
        db.close()
        conn.close()
        server.close()


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
