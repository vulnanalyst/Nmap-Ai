"""Compatibility wrapper. Sensitive-port access is observational, not an attack by itself."""

from backend.app.services.alert_service import signature_alerts


def check_signature(packet_info: dict) -> list[str]:
    alerts = signature_alerts(
        {
            "dst_port": packet_info.get("dst_port"),
            "src_addr": packet_info.get("src_addr"),
            "dst_addr": packet_info.get("dst_addr"),
            "protocol": packet_info.get("protocol", "TCP"),
            "packets_per_sec": packet_info.get("packets_per_sec"),
        },
        packet_info.get("recent_dst_ports") or [],
    )
    return [item["title"] + " — " + item["message"] for item in alerts]
