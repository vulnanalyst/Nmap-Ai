
from ids.signature_ids import check_signature
from ids.ml_ids import predict_traffic
from alerts.alert_engine import send_alert

print("🛡️  AI-IDS Starting...")

# Test run (VM setup ke baad live data aayega)
test_packet = {
    'dst_port': 22,
    'packets_per_sec': 150,
    'flow_bytes': 500,
}

test_features = [22, 5000, 150, 20, 3000, 800, 200, 15000, 150, 250]

# Signature check
sig_alerts = check_signature(test_packet)
for alert in sig_alerts:
    send_alert(alert, source="SIGNATURE-IDS")

# ML check
ml_result = predict_traffic(test_features)
send_alert(ml_result, source="ML-IDS")