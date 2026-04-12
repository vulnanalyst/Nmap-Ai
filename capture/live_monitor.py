import warnings
warnings.filterwarnings('ignore')
import sys
import socket
import numpy as np
import joblib
from scapy.all import IP, TCP, Raw
from scapy.packet import Packet

sys.path.append('N:\\MAIN\\Projects\\Nmap Ai')
from ids.signature_ids import check_signature
from alerts.alert_engine import send_alert

model = joblib.load('N:\\MAIN\\Projects\\Nmap Ai\\model\\ids_model.pkl')

print("🛡️  Live Monitor Starting...")
print("📡 Ubuntu se traffic receive ho raha hai...\n")

# Windows pe port 9999 pe listen karo
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 9999))
server.listen(1)
print("Ubuntu ka intezaar hai...\n")

conn, addr = server.accept()
print(f"Connected: {addr}\n")

from scapy.all import sniff
from io import BytesIO

buffer = b""

try:
    while True:
        data = conn.recv(65535)
        if not data:
            break
        buffer += data
        
        # Packet parse karo
        from scapy.all import Ether
        try:
            pkt = Ether(buffer)
            if IP in pkt and TCP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport

                packet_info = {
                    'dst_port': dport,
                    'packets_per_sec': 1,
                    'flow_bytes': len(pkt),
                }

                sig_alerts = check_signature(packet_info)
                for alert in sig_alerts:
                    send_alert(f"{src} -> {dst} | {alert}", source="SIGNATURE-IDS")

                features = [
                    float(dport), 1000.0, 1.0, 0.0,
                    float(len(pkt)), float(len(pkt)),
                    0.0, 1000.0, 1.0, float(len(pkt))
                ]

                X = np.array(features).reshape(1, -1)
                pred = model.predict(X)[0]
                prob = model.predict_proba(X)[0][1]

                if pred == 1:
                    send_alert(
                        f"Attack! {src}->{dst}:{dport} Confidence:{prob:.1%}",
                        source="ML-IDS"
                    )
            buffer = b""
        except:
            pass

except KeyboardInterrupt:
    print("\n⛔ Monitor stopped.")
    conn.close()
    server.close()