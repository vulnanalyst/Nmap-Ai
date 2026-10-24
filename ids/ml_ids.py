"""Compatibility wrapper around the schema-validated inference pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.inference.predict import predict
from ml.preprocessing.schema import FEATURE_NAMES


def predict_traffic(features: list):
    result = predict(features)
    label = result["predicted_label"]
    conf = result["confidence"]
    conf_txt = f"{conf:.1%}" if conf is not None else "n/a"
    if label != "BENIGN":
        return f"ML classification: {label} (class confidence {conf_txt}; not proof of compromise)"
    return f"ML classification: BENIGN (class confidence {conf_txt})"


FEATURE_ORDER = FEATURE_NAMES
