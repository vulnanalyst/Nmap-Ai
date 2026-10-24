from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from backend.app.core.paths import repo_root
from ml.preprocessing.schema import CLASS_NAMES, FEATURE_NAMES


class FeatureSchemaError(ValueError):
    pass


def latest_artifact() -> dict[str, Any] | None:
    path = repo_root() / "ml" / "artifacts" / "latest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_model(model_path: Path | None = None, schema_path: Path | None = None):
    latest = latest_artifact()
    if model_path is None:
        if not latest:
            raise FileNotFoundError("No trained model artifact is available. Train with python -m ml.training.train")
        model_path = Path(latest["model_path"])
        schema_path = Path(latest["schema_path"])
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8")) if schema_path else {}
    model = joblib.load(model_path)
    return model, schema


def validate_features(features: dict[str, float] | list[float], expected: list[str] | None = None) -> np.ndarray:
    expected = expected or FEATURE_NAMES
    if isinstance(features, dict):
        missing = [name for name in expected if name not in features]
        extra = [name for name in features if name not in expected]
        if missing:
            raise FeatureSchemaError(f"Missing features: {missing}")
        if extra:
            raise FeatureSchemaError(f"Unexpected features: {extra}")
        values = [float(features[name]) for name in expected]
    else:
        if len(features) != len(expected):
            raise FeatureSchemaError(f"Expected {len(expected)} features in order {expected}, got {len(features)}")
        values = [float(x) for x in features]
    arr = np.array(values, dtype=float).reshape(1, -1)
    if not np.isfinite(arr).all():
        raise FeatureSchemaError("Feature vector contains NaN or inf")
    return arr


def predict(features: dict[str, float] | list[float], model=None, schema: dict | None = None) -> dict[str, Any]:
    if model is None:
        model, schema = load_model()
    schema = schema or {}
    expected = schema.get("feature_names") or FEATURE_NAMES
    X = validate_features(features, expected)
    pred = int(model.predict(X)[0])
    proba = None
    class_probs = {}
    if hasattr(model, "predict_proba"):
        raw = model.predict_proba(X)[0]
        classes = [int(c) for c in getattr(model, "classes_", schema.get("classes") or [])]
        for cls, p in zip(classes, raw):
            class_probs[str(cls)] = float(p)
        if pred in classes:
            proba = float(raw[list(classes).index(pred)])
    return {
        "predicted_class": pred,
        "predicted_label": (schema.get("class_names") or CLASS_NAMES).get(str(pred), CLASS_NAMES.get(pred, str(pred))),
        "confidence": proba,
        "class_probabilities": class_probs,
        "model_version": schema.get("version"),
        "disclaimer": "A class probability is not the probability that a real-world attack occurred.",
        "features_used": expected,
    }
