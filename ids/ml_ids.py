
import joblib
import numpy as np

model = joblib.load('model/ids_model.pkl')

def predict_traffic(features: list):
    """
    features = [dst_port, flow_duration, total_fwd_pkts,
                total_bwd_pkts, total_len_fwd, fwd_pkt_max,
                bwd_pkt_max, flow_bytes_s, flow_pkts_s, avg_pkt_size]
    """
    X = np.array(features).reshape(1, -1)
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0][1]
    
    if pred == 1:
        return f"🚨 ML ALERT: Attack detected! Confidence: {prob:.1%}"
    else:
        return f"✅ Normal traffic (attack prob: {prob:.1%})"