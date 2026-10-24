import json

import joblib
import pytest

from ml.inference.predict import FeatureSchemaError, predict, validate_features
from ml.preprocessing.schema import FEATURE_NAMES
from ml.training.train import train


def test_missing_features_rejected():
    with pytest.raises(FeatureSchemaError):
        validate_features({"Destination Port": 80})


def test_reordered_dict_keeps_schema_order():
    feats = {name: 1.0 for name in reversed(FEATURE_NAMES)}
    arr = validate_features(feats)
    assert arr.shape == (1, 10)


def test_training_and_inference_use_real_metrics(tmp_path, monkeypatch):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr("ml.training.train.artifacts_dir", lambda: artifact_dir)
    result = train(compare_gbdt=False)
    assert result["metrics"]["random_forest"]["f1_macro"] >= 0
    assert "classification_report" in result["metrics"]["random_forest"]
    sample = {name: 1.0 for name in FEATURE_NAMES}
    sample["Destination Port"] = 80
    model = joblib.load(result["model_path"])
    out = predict(sample, model=model, schema=result)
    assert out["predicted_class"] in (0, 1)
    assert out["class_probabilities"]
    # class index 1 is not assumed blindly
    assert "0" in out["class_probabilities"] or "1" in out["class_probabilities"]


def test_prepare_does_not_require_balanced_classes(tmp_path):
    csv = tmp_path / "tiny.csv"
    header = ",".join(FEATURE_NAMES + ["Label"])
    rows = [header]
    rows.append(",".join(["80", "10", "1", "1", "10", "10", "10", "1", "1", "10", "BENIGN"]))
    csv.write_text("\n".join(rows) + "\n", encoding="utf-8")
    from ml.preprocessing.prepare import prepare_dataset

    report = prepare_dataset(raw_path=csv, output_path=tmp_path / "out.csv", per_class_cap=1000)
    assert report["rows"] == 1
    assert report["prepared_label_counts"][0] == 1
