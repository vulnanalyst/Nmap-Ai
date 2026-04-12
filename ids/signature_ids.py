

SUSPICIOUS_PORTS = [22, 23, 3389, 445, 135, 21, 3306]

def check_signature(packet_info):
    alerts = []
    
    # Rule 1: Sensitive port access
    if packet_info.get('dst_port') in SUSPICIOUS_PORTS:
        alerts.append(f"⚠️  ALERT: Sensitive port {packet_info['dst_port']} accessed!")
    
    # Rule 2: Port scan detection (100+ ports in 1 sec)
    if packet_info.get('packets_per_sec', 0) > 100:
        alerts.append("🚨 ALERT: Port scan detected — high packet rate!")
    
    # Rule 3: Large flow size
    if packet_info.get('flow_bytes', 0) > 1000000:
        alerts.append("⚠️  ALERT: Unusually large data flow!")
    
    return alerts